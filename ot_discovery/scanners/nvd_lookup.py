"""Cross-manufacturer CVE lookup via the NVD (National Vulnerability Database) API.

One generic mechanism instead of a per-vendor vulnerability feed: NVD covers
Siemens, Festo, ifm and effectively every other manufacturer through the same
public REST API, keyword-searchable and free, no API key required (a key
just raises the rate limit - see RATE_LIMIT_WINDOW/RATE_LIMIT_MAX below,
which match the public, no-key tier: 5 requests per rolling 30s window).
Verified live against a real query - keywordSearch=Siemens SIMATIC S7-1500
returned 12 real CVEs with structured version ranges, e.g.:

    "criteria": "cpe:2.3:o:siemens:simatic_s7-1500_cpu_firmware:*:*:*:*:*:*:*:*",
    "versionEndIncluding": "1.1.2"

That structured range is what lets this filter to CVEs the device's actual
firmware is affected by, rather than just "some CVE mentions this product
family at some point in its history" - the latter would be mostly noise for
a device running current firmware with old CVEs long since patched.

This is a best-effort approximation of proper CPE matching, not a full
implementation of it: a real CPE match also matches structured product
identifiers against NVD's own CPE dictionary, not a free-text keyword
search. Treat results as a lead to verify, not a certified vulnerability
report - said explicitly since this is security-sensitive output.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ot_discovery.scanners.nvd_lookup")

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Public, no-API-key tier: NVD documents this as 5 requests per rolling 30s
# window. Queued/paced here so a scan with several Siemens/Festo/ifm devices
# doesn't burst past it and get temporarily blocked.
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 30.0

_request_times: list[float] = []


class NvdLookupError(Exception):
    """Raised when the NVD API request itself fails (network, HTTP status, bad JSON)."""


@dataclass
class CveMatch:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]


def _wait_for_rate_limit() -> None:
    """Block (briefly) until sending another request stays within the public rate limit."""
    now = time.monotonic()
    while _request_times and now - _request_times[0] > RATE_LIMIT_WINDOW:
        _request_times.pop(0)
    if len(_request_times) >= RATE_LIMIT_MAX:
        sleep_for = RATE_LIMIT_WINDOW - (now - _request_times[0]) + 0.1
        if sleep_for > 0:
            logger.debug("NVD rate limit reached, waiting %.1fs", sleep_for)
            time.sleep(sleep_for)
    _request_times.append(time.monotonic())


def _parse_firmware(firmware: str) -> Optional[tuple[int, ...]]:
    """Parse a firmware string like 'V2.9.4' or '1.0.0' into a comparable tuple."""
    match = re.search(r"(\d+(?:\.\d+)+)", firmware or "")
    if not match:
        return None
    try:
        return tuple(int(p) for p in match.group(1).split("."))
    except ValueError:
        return None


def _parse_version(version: str) -> Optional[tuple[int, ...]]:
    if not version or version in ("*", "-"):
        return None
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return None


def _cpe_match_applies(cpe_match: dict, firmware_tuple: tuple[int, ...]) -> bool:
    criteria_parts = cpe_match.get("criteria", "").split(":")
    version_field = criteria_parts[5] if len(criteria_parts) > 5 else ""
    exact = _parse_version(version_field)
    if exact is not None:
        return firmware_tuple == exact

    start_inc = _parse_version(cpe_match.get("versionStartIncluding", ""))
    start_exc = _parse_version(cpe_match.get("versionStartExcluding", ""))
    end_inc = _parse_version(cpe_match.get("versionEndIncluding", ""))
    end_exc = _parse_version(cpe_match.get("versionEndExcluding", ""))

    if start_inc is not None and firmware_tuple < start_inc:
        return False
    if start_exc is not None and firmware_tuple <= start_exc:
        return False
    if end_inc is not None and firmware_tuple > end_inc:
        return False
    if end_exc is not None and firmware_tuple >= end_exc:
        return False
    # Every bound present was satisfied (or there were none at all, meaning
    # the CPE criteria used "*" for version - "every version").
    return True


def _node_satisfied(node: dict, firmware_tuple: Optional[tuple[int, ...]]) -> bool:
    """A node's cpeMatch entries are OR'd - any vulnerable, applicable one satisfies it."""
    cpe_matches = node.get("cpeMatch", [])
    if not cpe_matches:
        return True
    for cpe_match in cpe_matches:
        if not cpe_match.get("vulnerable"):
            continue
        criteria_parts = cpe_match.get("criteria", "").split(":")
        cpe_part = criteria_parts[2] if len(criteria_parts) > 2 else "?"
        if cpe_part == "h":
            # Hardware/model entry (e.g. "simatic_s7-1513-1_pn_cpu") - no
            # firmware-version semantics of its own, and we don't reliably
            # know the device's exact model string to check it against, so
            # treat it as satisfied. When this node is AND-combined with a
            # real firmware-version node (the common case for a CVE scoped
            # to specific hardware), that other node still correctly gates
            # the result - this just avoids this node wrongly vetoing or
            # (if mishandled) always allowing the match by itself.
            return True
        if firmware_tuple is None:
            return True
        if _cpe_match_applies(cpe_match, firmware_tuple):
            return True
    return False


def _configuration_applies(config: dict, firmware_tuple: Optional[tuple[int, ...]]) -> bool:
    """A configuration's nodes combine via its own operator (AND/OR, default OR)."""
    nodes = config.get("nodes", [])
    if not nodes:
        return True
    results = [_node_satisfied(node, firmware_tuple) for node in nodes]
    return all(results) if config.get("operator") == "AND" else any(results)


def search_cves(keyword: str, timeout: float = 10.0, results_per_page: int = 20) -> list[dict]:
    """Query the NVD CVE API by keyword. Raises NvdLookupError on failure."""
    _wait_for_rate_limit()
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": results_per_page})
    url = f"{NVD_CVE_API}?{params}"
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; ot-discovery)"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as e:
        raise NvdLookupError(f"NVD request failed: {e}") from e
    return data.get("vulnerabilities", [])


def find_applicable_cves(keyword: str, firmware: Optional[str], timeout: float = 10.0) -> list[CveMatch]:
    """Search NVD for `keyword` and filter to CVEs whose version range covers `firmware`.

    If `firmware` can't be parsed, every CVE the keyword search returns is
    treated as applicable (better a false positive to check by hand than
    silently reporting nothing for a device whose firmware we don't know).
    """
    vulnerabilities = search_cves(keyword, timeout=timeout)
    firmware_tuple = _parse_firmware(firmware) if firmware else None

    matches = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "?")

        configurations = cve.get("configurations", [])
        # A CVE with no configurations/CPE data at all can't be version-checked -
        # keep it (as a lead to verify) rather than silently dropping it.
        # Otherwise, each configuration is its own independent applicability
        # clause (OR'd together across configurations); within one
        # configuration, its nodes combine via that configuration's own
        # AND/OR operator (see _configuration_applies).
        if not configurations:
            applies = True
        else:
            applies = any(_configuration_applies(config, firmware_tuple) for config in configurations)
        if not applies:
            continue

        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break

        matches.append(CveMatch(cve_id=cve_id, description=description, cvss_score=cvss_score, severity=severity))

    return matches
