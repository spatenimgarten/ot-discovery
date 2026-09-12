"""Manufacturer-specific plugins."""

from ipaddress import IPv4Address
from typing import Optional

from ..models.device import Device, DeviceType, Protocol
from .base import PluginBase, PluginMatchResult
from .oui_database import lookup_manufacturer, get_all_ouis_for_manufacturer


class SiemensPlugin(PluginBase):
    NAME = "Siemens"
    VENDOR_IDS = [42]  # Siemens Vendor ID
    OUIS = ["00:0C:7E", "00:1B:1B", "00:1F:BC", "28:63:36", "3C:97:0E", "84:18:26", "B8:27:EB"]
    TCP_PORTS = [102, 502, 443, 80, 161, 4840, 34962, 34963, 34964]
    UDP_PORTS = [161, 34962, 34963, 34964]
    HTTP_HEADERS = {"Server": "Siemens", "X-Powered-By": "Siemens"}
    SNMP_OIDS = {"1.3.6.1.4.1.4329": "Siemens"}

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        if device.vendor_id == 42:
            if 102 in device.tcp_ports:
                return DeviceType.PLC
            elif 443 in device.tcp_ports or 80 in device.tcp_ports:
                return DeviceType.HMI
            elif 161 in device.tcp_ports:
                return DeviceType.SWITCH
        return DeviceType.PLC

    def identify(self, device: Device) -> Device:
        if device.vendor_id == 42:
            if 102 in device.tcp_ports:
                device.device_type = DeviceType.PLC
            elif 443 in device.tcp_ports or 80 in device.tcp_ports:
                device.device_type = DeviceType.HMI
            elif 161 in device.tcp_ports:
                device.device_type = DeviceType.SWITCH
        device.manufacturer = "Siemens"
        device.protocols.append(Protocol.PROFINET)
        return device

    def details(self, device: Device) -> Device:
        device.raw_data.setdefault("siemens", {})
        return device


class IFMPlugin(PluginBase):
    NAME = "IFM"
    VENDOR_IDS = [310]
    OUIS = ["00:0F:7A", "00:1C:2D", "00:21:7C", "00:25:9B", "00:30:DE", "3C:B9:AA"]
    TCP_PORTS = [502, 80, 443, 4840]
    UDP_PORTS = [161]
    HTTP_HEADERS = {"Server": "IFM"}

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.IO_MODULE

    def identify(self, device: Device) -> Device:
        device.manufacturer = "IFM"
        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device

    def details(self, device: Device) -> Device:
        return device


class FestoPlugin(PluginBase):
    NAME = "Festo"
    VENDOR_IDS = [26]
    OUIS = ["00:0F:3D", "00:1A:4A", "00:1C:2E", "00:21:7D", "3C:B9:AB"]
    TCP_PORTS = [502, 80, 443, 4840, 102]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.CONTROLLER

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Festo"
        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device

    def details(self, device: Device) -> Device:
        return device


class PhoenixPlugin(PluginBase):
    NAME = "Phoenix Contact"
    VENDOR_IDS = [138]
    OUIS = ["00:0A:5E", "00:1B:4F", "00:20:4A", "00:21:7E", "00:25:9C", "3C:B9:AC"]
    TCP_PORTS = [502, 80, 443, 4840, 102, 161]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.IO_MODULE

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Phoenix Contact"
        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device

    def details(self, device: Device) -> Device:
        return device


class WagoPlugin(PluginBase):
    NAME = "Wago"
    VENDOR_IDS = [35]
    OUIS = ["00:0C:7D", "00:1B:4E", "00:20:4B", "00:21:7F", "00:25:9D", "3C:B9:AD"]
    TCP_PORTS = [502, 80, 443, 4840, 102, 161]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.PLC

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Wago"
        device.protocols.append(Protocol.MODBUS_TCP)
        device.protocols.append(Protocol.PROFINET)
        return device

    def details(self, device: Device) -> Device:
        return device


class BeckhoffPlugin(PluginBase):
    NAME = "Beckhoff"
    VENDOR_IDS = [19]
    OUIS = ["00:0C:7F", "00:1B:50", "00:20:4C", "00:21:80", "00:25:9E", "3C:B9:AE"]
    TCP_PORTS = [48898, 80, 443, 4840, 102, 502]
    UDP_PORTS = [161, 48898]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.PLC

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Beckhoff"
        device.protocols.append(Protocol.ETHERNET_IP)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device

    def details(self, device: Device) -> Device:
        return device


class MoxaPlugin(PluginBase):
    NAME = "Moxa"
    VENDOR_IDS = [246]
    OUIS = ["00:90:E8", "00:1B:51", "00:20:4D", "00:21:81", "00:25:9F"]
    TCP_PORTS = [80, 443, 161, 502, 4840]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.SWITCH

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Moxa"
        device.protocols.append(Protocol.SNMP)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device

    def details(self, device: Device) -> Device:
        return device


class HirschmannPlugin(PluginBase):
    NAME = "Hirschmann"
    VENDOR_IDS = [207]
    OUIS = ["00:80:63", "00:1B:52", "00:20:4E", "00:21:82"]
    TCP_PORTS = [80, 443, 161, 502, 4840, 22, 23]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.SWITCH

    def identify(self, device: Device) -> Device:
        device.manufacturer = "Hirschmann"
        device.protocols.append(Protocol.SNMP)
        device.protocols.append(Protocol.HTTP)
        return device

    def details(self, device: Device) -> Device:
        return device


class AVMPlugin(PluginBase):
    NAME = "AVM"
    VENDOR_IDS = []
    # AVM FRITZ!Box OUIs
    TCP_PORTS = [80, 443, 53, 67, 68, 1900, 5060, 5061]
    UDP_PORTS = [53, 67, 68, 1900, 5060, 5061]
    HOSTNAME_PATTERNS = ["fritz.box", "fritz.box.", "fritz", "avm"]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.ROUTER

    def identify(self, device: Device) -> Device:
        device.manufacturer = "AVM"
        device.device_type = DeviceType.ROUTER
        device.protocols.append(Protocol.HTTP)
        device.protocols.append(Protocol.HTTPS)
        return device

    def details(self, device: Device) -> Device:
        return device


class GenericPlugin(PluginBase):
    NAME = "Generic"
    VENDOR_IDS = []
    OUIS = []
    TCP_PORTS = [502, 102, 4840, 80, 443, 161, 22, 23, 48898]
    UDP_PORTS = [161]

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        return DeviceType.UNKNOWN

    def identify(self, device: Device) -> Device:
        if 502 in device.tcp_ports:
            device.protocols.append(Protocol.MODBUS_TCP)
        if 102 in device.tcp_ports:
            device.protocols.append(Protocol.PROFINET)
        if 4840 in device.tcp_ports:
            device.protocols.append(Protocol.OPC_UA)
        if 161 in device.tcp_ports:
            device.protocols.append(Protocol.SNMP)
        if 80 in device.tcp_ports:
            device.protocols.append(Protocol.HTTP)
        if 443 in device.tcp_ports:
            device.protocols.append(Protocol.HTTPS)
        return device

    def details(self, device: Device) -> Device:
        return device


def create_default_plugin_manager() -> "PluginManager":
    """Create plugin manager with all default plugins."""
    from .manager import PluginManager
    manager = PluginManager()
    manager.register(SiemensPlugin())
    manager.register(IFMPlugin())
    manager.register(FestoPlugin())
    manager.register(PhoenixPlugin())
    manager.register(WagoPlugin())
    manager.register(BeckhoffPlugin())
    manager.register(MoxaPlugin())
    manager.register(HirschmannPlugin())
    manager.register(AVMPlugin())
    manager.register(GenericPlugin())
    return manager