"""PROFINET Vendor ID database for manufacturer lookup by DCP/I&M vendor_id.

Vendor IDs are centrally assigned by PROFIBUS & PROFINET International (PI) -
unlike Device IDs, which each manufacturer manages internally with no public
registry (see the GSDML files vendors publish per device, not aggregated
anywhere). Mirrors oui_database.py's approach for MAC addresses: cached
locally as data/pi_vendor_ids.csv (~2200 entries) and (re-)downloaded on
demand if that file is missing.

A vendor_id match is actually more authoritative than an OUI match for a
PROFINET device: it's what the device itself reports, whereas the OUI only
identifies the NIC/chipset maker, which can differ from the actual product
manufacturer (white-label modules, purchased network chips, etc.).
Source: PROFIBUS & PROFINET International (https://www.profibus.com/IM/Man_ID_Table.xml).
"""

import csv
import logging
import urllib.request
import xml.etree.ElementTree as ET
from functools import lru_cache

from ..paths import DATA_DIR

logger = logging.getLogger("ot_discovery.plugins.vendor_id_database")

_PI_VENDOR_ID_URL = "https://www.profibus.com/IM/Man_ID_Table.xml"
_PI_VENDOR_ID_CSV = DATA_DIR / "pi_vendor_ids.csv"
_XML_NS = {"m": "http://www.profibus.com/IM/2003/11/Man_ID"}

# Confidence for a manufacturer determined from a PROFINET vendor_id, as
# opposed to one confirmed via a device-specific query (DCP station name,
# I&M OrderID prefix, ...). Higher than a pure OUI lookup since the vendor_id
# is reported by the device itself, not inferred from its NIC hardware.
VENDOR_ID_LOOKUP_CONFIDENCE = 0.7


def _fetch_pi_vendor_id_database(dest) -> bool:
    """Download the official PI Manufacturer ID Table and cache it as a compact local CSV."""
    logger.info("PI vendor ID database not found at %s, downloading from %s", dest, _PI_VENDOR_ID_URL)
    try:
        request = urllib.request.Request(
            _PI_VENDOR_ID_URL,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ot-discovery)"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except Exception as e:
        logger.warning("Could not download PI vendor ID database: %s", e)
        return False

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        logger.warning("PI vendor ID database download was not valid XML: %s", e)
        return False

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    count = 0
    with open(tmp, "w", encoding="utf-8", newline="") as f_out:
        writer = csv.writer(f_out)
        for manufacturer in root.findall("m:Manufacturer", _XML_NS):
            vendor_id = manufacturer.get("ID")
            name_elem = manufacturer.find("m:ManufacturerInfo/m:ManufacturerName", _XML_NS)
            name = name_elem.text.strip() if name_elem is not None and name_elem.text else ""
            if vendor_id and vendor_id.isdigit() and name:
                writer.writerow([int(vendor_id), name])
                count += 1
    tmp.replace(dest)
    logger.info("Cached %d PI vendor ID entries to %s", count, dest)
    return True


@lru_cache(maxsize=1)
def _load_pi_vendor_id_database() -> dict[int, str]:
    """Lazily load the full PI vendor ID table, fetching it if not present locally."""
    if not _PI_VENDOR_ID_CSV.exists():
        _fetch_pi_vendor_id_database(_PI_VENDOR_ID_CSV)

    db: dict[int, str] = {}
    try:
        with open(_PI_VENDOR_ID_CSV, encoding="utf-8", newline="") as f:
            for vendor_id, name in csv.reader(f):
                db[int(vendor_id)] = name
    except FileNotFoundError:
        logger.warning("PI vendor ID database unavailable (no local file, download failed)")
    return db


def ensure_vendor_id_database_loaded() -> int:
    """Force the PI vendor ID database to load/download now, returning its entry count."""
    return len(_load_pi_vendor_id_database())


def lookup_vendor_name(vendor_id: int | None) -> str | None:
    """Look up a manufacturer name by PROFINET vendor_id via the PI registry."""
    if not vendor_id:
        return None
    return _load_pi_vendor_id_database().get(vendor_id)
