"""CSV Exporter for OT Discovery results."""

import csv
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..models.device import Device


class CSVExporter:
    """Export devices to CSV format."""

    HEADERS = [
        "IP",
        "Hostname",
        "DCP Name",
        "Hersteller",
        "Gerätetyp",
        "Firmware",
        "Seriennummer",
        "Bestellnummer",
        "MAC",
        "TCP Ports",
        "UDP Ports",
        "Protokolle",
        "Risikobewertung",
        "Bekannte Schwachstellen",
    ]

    def __init__(self, filepath: Path):
        self.filepath = filepath

    def export(self, devices: list[Device]) -> None:
        """Export devices to CSV file."""
        with open(self.filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow(self.HEADERS)
            for device in devices:
                writer.writerow(self._device_to_row(device))

    def _device_to_row(self, device: Device) -> list[str]:
        return [
            str(device.ip),
            device.hostname or "",
            device.dcp_name or "",
            device.manufacturer or "",
            device.device_type.value if device.device_type else "",
            device.firmware or "",
            device.serial_number or "",
            device.order_number or "",
            device.mac or "",
            ", ".join(map(str, sorted(device.tcp_ports))),
            ", ".join(map(str, sorted(device.udp_ports))),
            ", ".join(p.value for p in sorted(device.protocols, key=lambda x: x.value)),
            str(device.risk_score),
            ", ".join(device.vulnerabilities),
        ]