"""Data models for OT Discovery."""

from .device import Device, DeviceType, Protocol
from .scan_result import ScanResult, ScanType

__all__ = ["Device", "DeviceType", "Protocol", "ScanResult", "ScanType"]