"""Plugin manager for loading and running manufacturer plugins."""

import logging
from typing import Optional
from ipaddress import IPv4Address

from ..models.device import Device, Protocol
from ..scanners.pnio_im import PnioImError, read_im0
from .base import PluginBase, PluginMatchResult
from .oui_database import lookup_manufacturer, OUI_LOOKUP_CONFIDENCE


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

    def match_device(self, device: Device) -> list[PluginMatchResult]:
        """Run match() on all plugins, return sorted by confidence."""
        logger.info("=== Matching device %s (MAC: %s, OUI: %s) ===", 
                    device.ip, device.mac, device.oui)
        
        # Also check OUI database directly
        oui_mfr = lookup_manufacturer(device.mac) if device.mac else None
        if oui_mfr:
            logger.info("OUI database lookup for %s: %s", device.mac, oui_mfr)
        
        results = []
        for plugin in self._plugins:
            try:
                result = plugin.match(device)
                if result.matched:
                    results.append(result)
                    logger.debug("  Plugin '%s' matched: confidence=%.2f, type_hint=%s",
                                plugin.name, result.confidence, 
                                result.device_type_hint.value if result.device_type_hint else "None")
                else:
                    logger.debug("  Plugin '%s' did not match", plugin.name)
            except Exception as e:
                logger.warning("  Plugin '%s' raised exception: %s", plugin.name, e)
        
        results.sort(key=lambda r: r.confidence, reverse=True)
        
        if results:
            top = results[0]
            logger.info("Top match: %s (confidence=%.2f)", top.manufacturer, top.confidence)
            if len(results) > 1:
                logger.info("  Runner-up: %s (confidence=%.2f)", 
                           results[1].manufacturer, results[1].confidence)
        else:
            logger.warning("No plugin matched device %s", device.ip)
        
        return results

    def identify_device(self, device: Device) -> Device:
        """Run identify() on the TOP matching plugin only."""
        matches = self.match_device(device)
        if matches:
            # Only use top match, and only if it's a strong one (vendor_id/OUI/
            # hostname). A port-only match is true of most devices for most
            # plugins at once (everyone has 80/443/161 open) and isn't real
            # evidence of manufacturer - letting it win would just be a coin
            # flip between whichever industrial plugins happen to share a port.
            top_match = matches[0]
            plugin = self._plugin_map.get(top_match.manufacturer) if top_match.strong else None
            if plugin:
                try:
                    old_type = device.device_type
                    old_mfr = device.manufacturer
                    device = plugin.identify(device)
                    if device.device_type != old_type:
                        logger.info("  Identified %s as %s (was %s)",
                                   device.ip,
                                   device.device_type.value if device.device_type else "None",
                                   old_type.value if old_type else "None")
                    # Only plugins that actually confirm a manufacturer set it to
                    # their own name (e.g. Siemens, AVM); Generic never does. Compare
                    # against the plugin name rather than old_mfr, since a plugin
                    # confirming the same manufacturer the OUI already guessed should
                    # still upgrade it from an OUI guess to a verified match.
                    if device.manufacturer == plugin.name:
                        upgraded = device.manufacturer != old_mfr or device.manufacturer_source != "Plugin"
                        device.manufacturer_confidence = top_match.confidence
                        device.manufacturer_source = "Plugin"
                        if upgraded:
                            logger.info("  Manufacturer set to %s (was %s, confidence=%.2f)",
                                       device.manufacturer, old_mfr or "None", top_match.confidence)
                except Exception as e:
                    logger.error("  Plugin '%s' identify() failed: %s", plugin.name, e)

        # No dedicated plugin covers every OUI in the database (e.g. ABB, Rockwell,
        # Espressif). Fall back to the raw OUI lookup whenever no plugin gave a
        # real manufacturer.
        if not device.manufacturer or device.manufacturer == "Unknown":
            oui_mfr = lookup_manufacturer(device.mac) if device.mac else None
            if oui_mfr:
                logger.info("  Manufacturer set to %s via OUI database fallback", oui_mfr)
                device.manufacturer = oui_mfr
                device.manufacturer_confidence = OUI_LOOKUP_CONFIDENCE
                device.manufacturer_source = "OUI"

        return device

    def get_details(self, device: Device) -> Device:
        """Run details() on the TOP matching plugin only."""
        matches = self.match_device(device)
        if not matches:
            return device
        
        # Only use top match, and only if it's a strong one (see identify_device).
        top_match = matches[0]
        plugin = self._plugin_map.get(top_match.manufacturer) if top_match.strong else None
        if plugin:
            try:
                device = plugin.details(device)
                logger.debug("  Plugin '%s' details() completed", plugin.name)
            except Exception as e:
                logger.error("  Plugin '%s' details() failed: %s", plugin.name, e)
        return device

    def _read_generic_im0(self, device: Device) -> Device:
        """Read PROFINET I&M0 (order number, serial, hardware/firmware revision).

        Vendor-neutral, unlike plugin.details() (e.g. Siemens' S7comm/SZL
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

    def run_full_identification(self, device: Device) -> Device:
        """Run complete plugin pipeline: match -> identify -> generic I&M0 -> vendor details."""
        logger.info("Starting full identification for %s", device.ip)
        device = self.identify_device(device)
        device = self._read_generic_im0(device)
        device = self.get_details(device)
        logger.info("Final: %s -> Manufacturer: %s, Type: %s, Firmware: %s",
                    device.ip,
                    device.manufacturer,
                    device.device_type.value if device.device_type else "Unknown",
                    device.firmware or "Unknown")
        return device