"""Base plugin class for manufacturer-specific device detail extraction.

Manufacturer identification is no longer a plugin concern: device.manufacturer
is resolved generically before any plugin runs, via DCP/I&M vendor_id against
the PI vendor ID registry, or MAC OUI as a fallback (see
PluginManager._resolve_manufacturer). A plugin is then selected purely by
matching its NAME against that already-known manufacturer string - it never
decides "is this my device", only "given that this is my device, what else
can I find out about it" (device type, firmware, serial number, and
eventually vulnerabilities).
"""

from abc import ABC, abstractmethod

from ..models.device import Device


class PluginBase(ABC):
    """Base class for manufacturer plugins."""

    NAME: str = "Base Plugin"

    def __init__(self):
        self._name = self.NAME

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    def details(self, device: Device) -> Device:
        """Fill in device_type and any vendor-specific details (firmware,
        serial number, order number, vulnerabilities, ...). May perform
        network queries. Only called once device.manufacturer already
        matches this plugin's name - must not set it to a *different*
        manufacturer, though resetting it to None/"Unknown" is fine if
        something discovered here contradicts the earlier identification.
        """
        raise NotImplementedError
