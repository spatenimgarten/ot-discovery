"""Manufacturer-specific plugins.

Each plugin is selected by matching its NAME against a device.manufacturer
already resolved generically (PI vendor ID registry, then MAC OUI - see
PluginManager._resolve_manufacturer). From there, details() fills in
device_type and whatever vendor-specific data can actually be extracted;
most of these do nothing more than tag protocols and guess a device type
from open ports, since no further extraction has been implemented for them
yet. Siemens is the exception, with a real S7comm/SZL read.
"""

import logging

from ..models.device import Device, DeviceType, Protocol
from ..scanners.s7comm import S7CommError, read_identity
from .base import PluginBase

logger = logging.getLogger("ot_discovery.plugins.manufacturers")


class SiemensPlugin(PluginBase):
    NAME = "Siemens"

    def details(self, device: Device) -> Device:
        if 102 in device.tcp_ports:
            device.device_type = DeviceType.PLC
        elif 443 in device.tcp_ports or 80 in device.tcp_ports:
            device.device_type = DeviceType.HMI
        elif 161 in device.tcp_ports:
            device.device_type = DeviceType.SWITCH
        else:
            device.device_type = DeviceType.PLC
        device.protocols.append(Protocol.PROFINET)

        if 102 not in device.tcp_ports:
            return device
        try:
            identity = read_identity(device.ip)
        except (S7CommError, OSError) as e:
            logger.debug("  S7comm SZL read failed for %s: %s", device.ip, e)
            return device
        device.order_number = identity.order_number or device.order_number
        device.hardware_revision = (
            str(identity.hardware_revision) if identity.hardware_revision is not None else device.hardware_revision
        )
        device.firmware = identity.firmware or device.firmware
        device.serial_number = identity.serial_number or device.serial_number
        if identity.module_type:
            device.raw_data["s7_module_type"] = identity.module_type
        return device


class IFMPlugin(PluginBase):
    NAME = "IFM"

    def details(self, device: Device) -> Device:
        device.device_type = DeviceType.IO_MODULE
        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device


class FestoPlugin(PluginBase):
    NAME = "Festo"

    def details(self, device: Device) -> Device:
        device.device_type = DeviceType.CONTROLLER
        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.MODBUS_TCP)
        return device


class GenericPlugin(PluginBase):
    """Fallback for devices whose manufacturer didn't match a plugin above -
    just tags likely protocols from whichever common ports are open."""

    NAME = "Generic"

    def details(self, device: Device) -> Device:
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


def create_default_plugin_manager() -> "PluginManager":
    """Create plugin manager with all default plugins."""
    from .manager import PluginManager
    manager = PluginManager()
    manager.register(SiemensPlugin())
    manager.register(IFMPlugin())
    manager.register(FestoPlugin())
    manager.register(GenericPlugin())
    return manager
