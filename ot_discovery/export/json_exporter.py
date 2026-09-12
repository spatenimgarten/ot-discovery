"""JSON Exporter for OT Discovery results."""

import json
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..models.device import Device
from ..models.scan_result import ScanResult


class JSONExporter:
    """Export devices to JSON format."""

    def __init__(self, filepath: Path, pretty: bool = True):
        self.filepath = filepath
        self.pretty = pretty

    def export(self, devices: list[Device], scan_results: list[ScanResult] = None) -> None:
        """Export devices to JSON file."""
        data = {
            "export_info": {
                "timestamp": datetime.now().isoformat(),
                "device_count": len(devices),
                "scan_count": len(scan_results) if scan_results else 0,
            },
            "devices": [self._device_to_dict(d) for d in devices],
        }
        if scan_results:
            data["scan_results"] = [r.to_dict() for r in scan_results]

        with open(self.filepath, 'w', encoding='utf-8') as f:
            if self.pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)

    def _device_to_dict(self, device: Device) -> dict:
        d = device.to_dict()
        d["Hardwarestand"] = device.hardware_revision or ""
        d["Vendor ID"] = device.vendor_id or ""
        d["Device ID"] = device.device_id or ""
        d["OUI"] = device.oui or ""
        return d