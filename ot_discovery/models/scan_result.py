"""Scan result models for OT Discovery."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from ipaddress import IPv4Address
from datetime import datetime


class ScanType(Enum):
    """Types of scans performed."""
    ARP = "ARP"
    DCP = "DCP"
    TCP = "TCP"
    UDP = "UDP"
    HOSTNAME = "Hostname"
    PLUGIN_IDENTIFY = "Plugin Identify"
    PLUGIN_DETAILS = "Plugin Details"
    VULNERABILITY = "Vulnerability"


@dataclass
class ScanResult:
    """Result of a single scan operation."""
    scan_type: ScanType
    target_ip: IPv4Address
    success: bool
    timestamp: datetime = field(default_factory=datetime.now)
    duration_ms: float = 0.0
    data: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scan_type": self.scan_type.value,
            "target_ip": str(self.target_ip),
            "success": self.success,
            "timestamp": self.timestamp.isoformat(),
            "duration_ms": self.duration_ms,
            "data": self.data,
            "error": self.error,
        }