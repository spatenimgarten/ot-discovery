"""Base plugin classes for manufacturer identification."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from ipaddress import IPv4Address

from ..models.device import Device, DeviceType


@dataclass
class PluginMatchResult:
    """Result of plugin match() check."""
    matched: bool
    confidence: float = 0.0
    manufacturer: Optional[str] = None
    device_type_hint: Optional[DeviceType] = None
    metadata: dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class PluginBase(ABC):
    """Base class for manufacturer plugins."""

    NAME: str = "Base Plugin"
    VENDOR_IDS: list[int] = []
    # OUIs are now in the central database
    TCP_PORTS: list[int] = []
    UDP_PORTS: list[int] = []
    HTTP_HEADERS: dict[str, str] = {}
    SNMP_OIDS: dict[str, str] = {}
    OPC_UA_SERVERS: list[str] = []

    def __init__(self):
        self._name = self.NAME

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    def match(self, device: Device) -> PluginMatchResult:
        """
        Fast check if this plugin matches the device.
        Should be lightweight - no network I/O.
        """
        pass

    @abstractmethod
    def identify(self, device: Device) -> Device:
        """
        Determine device type and basic info.
        May perform network queries.
        """
        pass

    @abstractmethod
    def details(self, device: Device) -> Device:
        """
        Extract detailed information: firmware, serial, order number, etc.
        May perform extensive network queries.
        """
        pass

    def _check_vendor_id(self, device: Device) -> bool:
        return device.vendor_id in self.VENDOR_IDS if device.vendor_id else False

    def _check_oui(self, device: Device) -> bool:
        """Check if device MAC matches any OUI for this manufacturer."""
        if not device.oui:
            return False
        # Use central OUI database
        from .oui_database import get_all_ouis_for_manufacturer
        return device.oui.upper() in [oui.upper() for oui in get_all_ouis_for_manufacturer(self.NAME)]

    def _check_hostname(self, device: Device) -> bool:
        """Check if device hostname matches manufacturer patterns."""
        if not device.hostname:
            return False
        hostname = device.hostname.lower()
        patterns = getattr(self, 'HOSTNAME_PATTERNS', [])
        return any(p.lower() in hostname for p in patterns)

    def _check_tcp_ports(self, device: Device) -> bool:
        if not self.TCP_PORTS:
            return False
        return any(port in device.tcp_ports for port in self.TCP_PORTS)

    def _check_udp_ports(self, device: Device) -> bool:
        if not self.UDP_PORTS:
            return False
        return any(port in device.udp_ports for port in self.UDP_PORTS)

    def _calculate_confidence(self, checks: list[bool]) -> float:
        if not checks:
            return 0.0
        return sum(checks) / len(checks)

    def match(self, device: Device) -> PluginMatchResult:
        """
        Default match implementation:
        - Strong match: vendor_id OR OUI match OR hostname match (high confidence)
        - Weak match: port match only (low confidence)
        """
        vendor_match = self._check_vendor_id(device)
        oui_match = self._check_oui(device)
        hostname_match = self._check_hostname(device)
        tcp_match = self._check_tcp_ports(device)
        udp_match = self._check_udp_ports(device)

        # Strong indicators
        strong_checks = [vendor_match, oui_match, hostname_match]
        # Weak indicators
        weak_checks = [tcp_match, udp_match]

        has_strong = any(strong_checks)
        has_weak = any(weak_checks)

        if has_strong:
            # High confidence if vendor/OUi/hostname matches
            confidence = self._calculate_confidence(strong_checks) * 0.8 + self._calculate_confidence(weak_checks) * 0.2
            return PluginMatchResult(
                matched=True,
                confidence=confidence,
                manufacturer=self.NAME,
                device_type_hint=self._get_device_type_hint(device),
            )
        elif has_weak:
            # Low confidence for port-only matches
            confidence = self._calculate_confidence(weak_checks) * 0.3
            return PluginMatchResult(
                matched=True,
                confidence=confidence,
                manufacturer=self.NAME if self.NAME != "Generic" else "Unknown",
                device_type_hint=self._get_device_type_hint(device),
            )
        else:
            return PluginMatchResult(matched=False, confidence=0.0)

    def _get_device_type_hint(self, device: Device) -> Optional[DeviceType]:
        """Override in subclass for device type hints."""
        return None