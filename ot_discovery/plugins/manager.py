"""Plugin manager for loading and running manufacturer plugins.

Manufacturer is resolved generically (PI vendor ID registry, then MAC OUI)
before any plugin runs; a plugin is then picked purely by matching its NAME
against that manufacturer string. Plugins don't compete to claim a device -
there's nothing left for them to decide about identity, only about what
further detail they can extract once the manufacturer is already known.
"""

import logging
from typing import Optional

from ..models.device import Device, Protocol
from ..scanners.pnio_im import PnioImError, read_im0
from .base import PluginBase
from .gsdml_database import lookup_model_name
from .oui_database import lookup_manufacturer, OUI_LOOKUP_CONFIDENCE
from .vendor_id_database import lookup_vendor_name, VENDOR_ID_LOOKUP_CONFIDENCE


logger = logging.getLogger("ot_discovery.plugins.manager")


class PluginManager:
    """Manages manufacturer plugins."""

    def __init__(self):
        self._plugins: list[PluginBase] = []
        self._plugin_map: dict[str, PluginBase] = {}

    def register(self, plugin: PluginBase) -> None:
        """Register a plugin."""
        self._plugins.append(plugin)
        self._plugin_map[plugin.name] = plugin
        logger.debug("Registered plugin: %s", plugin.name)

    def unregister(self, plugin_name: str) -> bool:
        """Unregister a plugin by name."""
        if plugin_name in self._plugin_map:
            plugin = self._plugin_map.pop(plugin_name)
            self._plugins.remove(plugin)
            logger.debug("Unregistered plugin: %s", plugin_name)
            return True
        return False

    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Get plugin by name."""
        return self._plugin_map.get(name)

    def list_plugins(self) -> list[str]:
        """List all registered plugin names."""
        return [p.name for p in self._plugins]

    def _resolve_manufacturer(self, device: Device) -> Device:
        """Determine device.manufacturer generically, if not already known.

        ARP may already have set it via OUI inline during the scan itself;
        this only fills the gap - PI vendor ID first (reported by the device
        itself via DCP/I&M, so more authoritative than the OUI, which only
        identifies the NIC/chipset maker and can differ from the actual
        product vendor), then OUI as a fallback.
        """
        if device.manufacturer and device.manufacturer != "Unknown":
            return device

        vendor_mfr = lookup_vendor_name(device.vendor_id)
        if vendor_mfr:
            logger.info("  Manufacturer set to %s via PI vendor_id database", vendor_mfr)
            device.manufacturer = vendor_mfr
            device.manufacturer_confidence = VENDOR_ID_LOOKUP_CONFIDENCE
            device.manufacturer_source = "PI Vendor ID"
            return device

        oui_mfr = lookup_manufacturer(device.mac) if device.mac else None
        if oui_mfr:
            logger.info("  Manufacturer set to %s via OUI database", oui_mfr)
            device.manufacturer = oui_mfr
            device.manufacturer_confidence = OUI_LOOKUP_CONFIDENCE
            device.manufacturer_source = "OUI"
        return device

    def _find_plugin_for_manufacturer(self, manufacturer: Optional[str]) -> Optional[PluginBase]:
        """Match a plugin by manufacturer name, e.g. "SIEMENS AG" -> SiemensPlugin."""
        if not manufacturer:
            return None
        needle = manufacturer.lower()
        for plugin in self._plugins:
            if plugin.name != "Generic" and plugin.name.lower() in needle:
                return plugin
        return None

    def _read_generic_im0(self, device: Device) -> Device:
        """Read PROFINET I&M0 (order number, serial, hardware/firmware revision).

        Vendor-neutral, unlike a plugin's details() (e.g. Siemens' S7comm/SZL
        reader) - only attempted for devices that already answered DCP, since
        I&M0 is a PROFINET-specific read that non-PROFINET devices won't have
        a listener for at all.
        """
        if Protocol.PROFINET not in device.protocols:
            return device
        try:
            im0 = read_im0(device.ip)
        except (PnioImError, OSError) as e:
            logger.debug("  I&M0 read failed for %s: %s", device.ip, e)
            return device
        device.vendor_id = device.vendor_id or im0.vendor_id
        device.order_number = device.order_number or im0.order_id or None
        device.serial_number = device.serial_number or im0.serial_number or None
        device.hardware_revision = device.hardware_revision or (
            str(im0.hardware_revision) if im0.hardware_revision else None
        )
        device.firmware = device.firmware or im0.firmware or None
        device.raw_data.setdefault("im0_profile_id", im0.profile_id)
        device.raw_data.setdefault("im0_version", im0.im_version)
        logger.info("  I&M0 read for %s: order=%s serial=%s hw_rev=%s firmware=%s",
                    device.ip, im0.order_id, im0.serial_number, im0.hardware_revision, im0.firmware)
        return device

    def _resolve_device_family(self, device: Device) -> Device:
        """Look up a device family/model name from locally-provided GSDML files.

        There's no central registry for this (unlike vendor_id/OUI) - only
        useful when the user has actually dropped the relevant manufacturer's
        GSDML .zip into data/gsdml/. Mainly a fallback for devices whose live
        I&M0/S7comm read didn't give a usable name.
        """
        if "gsdml_product_family" in device.raw_data:
            return device
        name = lookup_model_name(device.vendor_id, device.device_id)
        if name:
            device.raw_data["gsdml_product_family"] = name
        return device

    def run_full_identification(self, device: Device) -> Device:
        """Resolve manufacturer, read generic I&M0, then run the matching plugin's details()."""
        logger.info("Starting full identification for %s", device.ip)

        device = self._resolve_manufacturer(device)
        device = self._read_generic_im0(device)
        # I&M0 may have just filled in vendor_id where DCP didn't - retry if
        # the manufacturer still isn't known.
        if not device.manufacturer or device.manufacturer == "Unknown":
            device = self._resolve_manufacturer(device)
        device = self._resolve_device_family(device)

        plugin = self._find_plugin_for_manufacturer(device.manufacturer) or self._plugin_map.get("Generic")
        if plugin:
            try:
                old_type = device.device_type
                device = plugin.details(device)
                if device.device_type != old_type:
                    logger.info("  Identified %s as %s (was %s)", device.ip,
                                device.device_type.value if device.device_type else "None",
                                old_type.value if old_type else "None")
                logger.debug("  Plugin '%s' details() completed", plugin.name)
            except Exception as e:
                logger.error("  Plugin '%s' details() failed: %s", plugin.name, e)

        logger.info("Final: %s -> Manufacturer: %s, Type: %s, Firmware: %s",
                    device.ip,
                    device.manufacturer,
                    device.device_type.value if device.device_type else "Unknown",
                    device.firmware or "Unknown")
        return device
