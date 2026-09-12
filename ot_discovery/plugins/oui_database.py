"""OUI (Organizationally Unique Identifier) database for MAC address manufacturer lookup.

Manufacturer lookup is backed entirely by the official IEEE MA-L OUI registry,
cached locally as data/ieee_oui.csv (~40k entries) and (re-)downloaded on demand
if that file is missing.
Source: IEEE Standards Association OUI Registry (https://standards-oui.ieee.org/).
"""

import csv
import logging
import urllib.request
from functools import lru_cache

from ..paths import DATA_DIR

logger = logging.getLogger("ot_discovery.plugins.oui_database")

# Official IEEE registry endpoint, used to (re-)fetch data/ieee_oui.csv if it is missing.
_IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_IEEE_OUI_CSV = DATA_DIR / "ieee_oui.csv"

# Confidence assigned to a manufacturer determined purely from an OUI lookup,
# as opposed to one confirmed via an active protocol query (DCP name, vendor ID,
# HTTP banner, ...). The OUI only identifies the NIC/chipset vendor, which may
# differ from the actual product manufacturer (e.g. white-label devices).
OUI_LOOKUP_CONFIDENCE = 0.6


def _fetch_ieee_oui_database(dest) -> bool:
    """Download the official IEEE registry and cache it as a compact local CSV."""
    logger.info("IEEE OUI database not found at %s, downloading from %s", dest, _IEEE_OUI_URL)
    try:
        request = urllib.request.Request(
            _IEEE_OUI_URL,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ot-discovery)"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8-sig")
    except Exception as e:
        logger.warning("Could not download IEEE OUI database: %s", e)
        return False

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    count = 0
    with open(tmp, "w", encoding="utf-8", newline="") as f_out:
        writer = csv.writer(f_out)
        for row in csv.DictReader(raw.splitlines()):
            oui_hex = row.get("Assignment", "").strip().upper()
            org = row.get("Organization Name", "").strip()
            if len(oui_hex) == 6 and org:
                writer.writerow([oui_hex, org])
                count += 1
    tmp.replace(dest)
    logger.info("Cached %d IEEE OUI entries to %s", count, dest)
    return True


@lru_cache(maxsize=1)
def _load_ieee_oui_database() -> dict[str, str]:
    """Lazily load the full IEEE MA-L OUI registry, fetching it if not present locally."""
    if not _IEEE_OUI_CSV.exists():
        _fetch_ieee_oui_database(_IEEE_OUI_CSV)

    db: dict[str, str] = {}
    try:
        with open(_IEEE_OUI_CSV, encoding="utf-8", newline="") as f:
            for oui_hex, org in csv.reader(f):
                db[oui_hex.upper()] = org
    except FileNotFoundError:
        logger.warning("IEEE OUI database unavailable (no local file, download failed)")
    return db


def ensure_ieee_database_loaded() -> int:
    """Force the IEEE OUI database to load/download now, returning its entry count.

    Call this once before a burst of concurrent lookup_manufacturer() calls (e.g.
    at the start of a scan) so a first-time download doesn't block whichever
    caller happens to trigger it lazily.
    """
    return len(_load_ieee_oui_database())


def lookup_manufacturer(mac: str) -> str | None:
    """Look up manufacturer by MAC address (first 3 bytes/OUI) via the IEEE registry."""
    if not mac:
        return None
    oui = mac[:8].upper().replace(':', '')  # e.g. "000C7E"
    return _load_ieee_oui_database().get(oui)


@lru_cache(maxsize=None)
def get_all_ouis_for_manufacturer(manufacturer: str) -> list[str]:
    """Get all OUIs whose IEEE organization name contains the given manufacturer name."""
    if not manufacturer:
        return []
    needle = manufacturer.lower()
    return [
        f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
        for oui, org in _load_ieee_oui_database().items()
        if needle in org.lower()
    ]
