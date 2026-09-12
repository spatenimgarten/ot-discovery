"""GSDML-derived device family/model lookup from locally-provided files.

Unlike the PI vendor ID and IEEE OUI registries, there's no central,
downloadable "Device ID -> model name" database - each manufacturer
publishes their own GSDML files per product line instead. This only knows
whatever .zip archives (as downloaded from a manufacturer's GSDML portal,
unmodified) have been dropped into data/gsdml/. The directory is rescanned
on every lookup based on a (filename, mtime) fingerprint - cheap given the
handful of files a real setup would have, and it means dropping in a new
file takes effect immediately without restarting anything.

A caveat found examining ifm's own AL140x GSDML: several sibling models
(AL1400, AL1401, AL1402, ...) share the exact same VendorID+DeviceID at the
wire protocol level - only I&M0's OrderID string, read live from the device,
actually distinguishes them. So what this gives is a product family/type
name at best, not necessarily the precise model - most useful as a fallback
for devices whose live I&M0/S7comm read failed or isn't implemented at all
(this is exactly the ifm vs. Festo split found in the same investigation:
ifm's live I&M0 already gives everything precisely, so its GSDML entry here
adds little; Festo's live read is currently rejected by the device, so its
GSDML entry - "Festo CPX-Terminal" - is the only device-type information
available for it).
"""

import logging
import xml.etree.ElementTree as ET
import zipfile
from functools import lru_cache
from typing import Optional

from ..paths import DATA_DIR

logger = logging.getLogger("ot_discovery.plugins.gsdml_database")

GSDML_DIR = DATA_DIR / "gsdml"
_GSDML_NS = {"g": "http://www.profibus.com/GSDML/2003/11/DeviceProfile"}


def _dir_fingerprint() -> tuple:
    if not GSDML_DIR.is_dir():
        return ()
    return tuple(sorted((f.name, f.stat().st_mtime_ns) for f in GSDML_DIR.glob("*.zip")))


def _parse_gsdml_xml(data: bytes) -> Optional[tuple[int, int, str]]:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    identity = root.find(".//g:DeviceIdentity", _GSDML_NS)
    if identity is None:
        return None
    try:
        vendor_id = int(identity.get("VendorID", "0"), 16)
        device_id = int(identity.get("DeviceID", "0"), 16)
    except ValueError:
        return None
    if not vendor_id or not device_id:
        return None

    family = root.find(".//g:DeviceFunction/g:Family", _GSDML_NS)
    product_family = family.get("ProductFamily") if family is not None else None
    vendor_name_elem = identity.find("g:VendorName", _GSDML_NS)
    vendor_name = vendor_name_elem.get("Value") if vendor_name_elem is not None else None
    name = product_family or vendor_name
    if not name:
        return None
    return vendor_id, device_id, name


@lru_cache(maxsize=1)
def _load_gsdml_database(fingerprint: tuple) -> dict[tuple[int, int], str]:
    """Parse every .zip in data/gsdml/, keyed by the fingerprint so a changed
    directory (new/removed/modified file) invalidates the cache automatically."""
    db: dict[tuple[int, int], str] = {}
    if not GSDML_DIR.is_dir():
        return db

    for zpath in GSDML_DIR.glob("*.zip"):
        try:
            with zipfile.ZipFile(zpath) as zf:
                for member in zf.namelist():
                    if not member.lower().endswith(".xml"):
                        continue
                    try:
                        data = zf.read(member)
                    except Exception as e:
                        logger.warning("Could not read %s from %s: %s", member, zpath.name, e)
                        continue
                    parsed = _parse_gsdml_xml(data)
                    if parsed:
                        vendor_id, device_id, name = parsed
                        db.setdefault((vendor_id, device_id), name)
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("Could not read GSDML archive %s: %s", zpath, e)

    logger.info("Loaded %d GSDML device entries from %s", len(db), GSDML_DIR)
    return db


def ensure_gsdml_database_loaded() -> int:
    """Force the local GSDML directory to be (re-)scanned now, returning its entry count."""
    return len(_load_gsdml_database(_dir_fingerprint()))


def lookup_model_name(vendor_id: Optional[int], device_id: Optional[int]) -> Optional[str]:
    """Look up a device family/model name by (vendor_id, device_id) from local GSDML files."""
    if not vendor_id or not device_id:
        return None
    return _load_gsdml_database(_dir_fingerprint()).get((vendor_id, device_id))
