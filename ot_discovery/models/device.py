"""Device data model for OT Discovery."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from ipaddress import IPv4Address


class DeviceType(Enum):
    """Known OT device types."""
    PLC = "PLC"
    HMI = "HMI"
    SWITCH = "Switch"
    ROUTER = "Router"
    GATEWAY = "Gateway"
    IO_MODULE = "I/O Module"
    DRIVE = "Drive"
    SENSOR = "Sensor"
    ACTUATOR = "Actuator"
    CONTROLLER = "Controller"
    PANEL = "Panel"
    SCADA = "SCADA"
    UNKNOWN = "Unknown"


class Protocol(Enum):
    """Supported industrial protocols."""
    PROFINET = "PROFINET"
    PROFIBUS = "PROFIBUS"
    ETHERNET_IP = "EtherNet/IP"
    MODBUS_TCP = "Modbus TCP"
    OPC_UA = "OPC UA"
    SNMP = "SNMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    TELNET = "Telnet"
    BACNET = "BACnet"
    DCP = "DCP"
    ARP = "ARP"
    UNKNOWN = "Unknown"


@dataclass
class Device:
    """Represents a discovered OT device."""
    ip: IPv4Address
    mac: Optional[str] = None
    hostname: Optional[str] = None
    dcp_name: Optional[str] = None
    dcp_role: Optional[str] = None
    manufacturer: Optional[str] = None
    manufacturer_confidence: Optional[float] = None
    manufacturer_source: Optional[str] = None
    device_type: Optional[DeviceType] = None
    firmware: Optional[str] = None
    serial_number: Optional[str] = None
    order_number: Optional[str] = None
    hardware_revision: Optional[str] = None
    tcp_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    protocols: list[Protocol] = field(default_factory=list)
    vendor_id: Optional[int] = None
    device_id: Optional[int] = None
    oui: Optional[str] = None
    mac_locally_administered: bool = False
    duplicate_mac: bool = False
    risk_score: float = 0.0
    vulnerabilities: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.mac and not self.oui:
            self.oui = self.mac[:8].upper()

    def to_dict(self) -> dict:
        """Convert device to dictionary for export."""
        return {
            "IP": str(self.ip),
            "Hostname": self.hostname or "",
            "DCP Name": self.dcp_name or "",
            "DCP Rolle": self.dcp_role or "",
            "Hersteller": self.manufacturer or "",
            "Erkennungssicherheit": f"{self.manufacturer_confidence * 100:.0f}%" if self.manufacturer_confidence is not None else "",
            "Erkennungsquelle": self.manufacturer_source or "",
            "Gerätetyp": self.device_type.value if self.device_type else "",
            "Firmware": self.firmware or "",
            "Seriennummer": self.serial_number or "",
            "Bestellnummer": self.order_number or "",
            "MAC": self.mac or "",
            "MAC zufällig/virtuell": "Ja" if self.mac_locally_administered else "",
            "Duplikat-MAC": "Ja" if self.duplicate_mac else "",
            "TCP Ports": ", ".join(map(str, self.tcp_ports)),
            "UDP Ports": ", ".join(map(str, self.udp_ports)),
            "Protokolle": ", ".join(p.value for p in self.protocols),
            "Risikobewertung": self.risk_score,
            "Bekannte Schwachstellen": ", ".join(self.vulnerabilities),
        }

    def merge(self, other: "Device") -> None:
        """Merge data from another device (same IP)."""
        if other.mac and not self.mac:
            self.mac = other.mac
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.dcp_name and not self.dcp_name:
            self.dcp_name = other.dcp_name
        if other.dcp_role and not self.dcp_role:
            self.dcp_role = other.dcp_role
        if other.manufacturer and not self.manufacturer:
            self.manufacturer = other.manufacturer
            self.manufacturer_confidence = other.manufacturer_confidence
            self.manufacturer_source = other.manufacturer_source
        if other.device_type and not self.device_type:
            self.device_type = other.device_type
        if other.firmware and not self.firmware:
            self.firmware = other.firmware
        if other.serial_number and not self.serial_number:
            self.serial_number = other.serial_number
        if other.order_number and not self.order_number:
            self.order_number = other.order_number
        if other.hardware_revision and not self.hardware_revision:
            self.hardware_revision = other.hardware_revision
        self.tcp_ports = list(set(self.tcp_ports + other.tcp_ports))
        self.udp_ports = list(set(self.udp_ports + other.udp_ports))
        self.protocols = list(set(self.protocols + other.protocols))
        if other.vendor_id and not self.vendor_id:
            self.vendor_id = other.vendor_id
        if other.device_id and not self.device_id:
            self.device_id = other.device_id
        if other.oui and not self.oui:
            self.oui = other.oui
        self.mac_locally_administered = self.mac_locally_administered or other.mac_locally_administered
        self.duplicate_mac = self.duplicate_mac or other.duplicate_mac
        if other.vulnerabilities and not self.vulnerabilities:
            self.vulnerabilities = other.vulnerabilities
        self.risk_score = max(self.risk_score, other.risk_score)
        self.raw_data.update(other.raw_data)