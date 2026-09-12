"""Main OT Discovery scanner orchestrator."""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Network
from pathlib import Path
from typing import Optional, Callable, Awaitable

from ..models.device import Device
from ..models.scan_result import ScanResult, ScanType
from ..scanners import ARPScanner, DCPScanner, TCPScanner, UDPScanner
from ..plugins import PluginManager, create_default_plugin_manager
from ..plugins.gsdml_database import ensure_gsdml_database_loaded
from ..plugins.vendor_id_database import ensure_vendor_id_database_loaded
from ..export import CSVExporter, JSONExporter


logger = logging.getLogger("ot_discovery.core.scanner")


class ScanMode(Enum):
    """Scan mode presets."""
    FAST = "fast"
    DEEP = "deep"
    CUSTOM = "custom"


@dataclass
class ScanConfig:
    """Configuration for scan."""
    network: IPv4Network
    mode: ScanMode = ScanMode.FAST
    interface: Optional[str] = None

    # Step toggles
    do_arp: bool = True
    do_dcp: bool = True
    do_tcp: bool = True
    do_udp: bool = False
    do_plugins: bool = True

    # Scanner settings
    arp_timeout: float = 2.0
    arp_retries: int = 2  # power-saving devices (phones, tablets) often miss a single ARP request
    dcp_timeout: float = 3.0
    tcp_timeout: float = 2.0
    udp_timeout: float = 1.0
    hostname_timeout: float = 1.5  # reverse-DNS lookup done inline by the ARP scan

    # Port lists
    tcp_ports: Optional[list[int]] = None
    udp_ports: Optional[list[int]] = None

    # Concurrency
    tcp_concurrency: int = 100
    udp_concurrency: int = 50

    # Export
    export_csv: Optional[Path] = None
    export_json: Optional[Path] = None

    # Progress callback: (current, total, step_name)
    progress_callback: Optional[Callable[[int, int, str], Awaitable[None]]] = None
    # Device found callback
    device_callback: Optional[Callable[[Device], Awaitable[None]]] = None


class OTScanner:
    """Main OT Discovery scanner."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.devices: dict[IPv4Address, Device] = {}
        self.scan_results: list[ScanResult] = []
        self._plugin_manager = create_default_plugin_manager()

    async def run(self) -> list[Device]:
        """Run the complete scan pipeline."""
        logger.info("Starting OT Discovery scan on %s", self.config.network)
        logger.info("Scan config: ARP=%s, DCP=%s, TCP=%s, UDP=%s, Plugins=%s",
                    self.config.do_arp, self.config.do_dcp, self.config.do_tcp,
                    self.config.do_udp, self.config.do_plugins)

        # Step 1: ARP Scan
        if self.config.do_arp:
            await self._run_arp()

        # Step 2: DCP Scan
        if self.config.do_dcp:
            await self._run_dcp()

        # Step 3: Merge devices (already merged by IP in dict)
        device_list = list(self.devices.values())
        logger.info("After ARP/DCP: %d devices discovered", len(device_list))

        # Step 4: TCP Scan
        if self.config.do_tcp and device_list:
            await self._run_tcp(device_list)

        # Step 5: UDP Scan
        if self.config.do_udp and device_list:
            await self._run_udp(device_list)

        # Step 6: Plugin-based identification
        if self.config.do_plugins and device_list:
            await self._run_plugins(device_list)

        # Step 7: Export
        if self.config.export_csv:
            self._export_csv()
        if self.config.export_json:
            self._export_json()

        logger.info("Scan complete. Total devices: %d", len(self.devices))
        return list(self.devices.values())

    async def _run_arp(self) -> None:
        """Run ARP scan."""
        logger.info("Starting ARP scan...")
        scanner = ARPScanner(
            interface=self.config.interface,
            timeout=self.config.arp_timeout,
            retries=self.config.arp_retries,
            hostname_timeout=self.config.hostname_timeout,
            progress_callback=self._make_progress("ARP Scan"),
        )
        devices = await scanner.scan(self.config.network)
        logger.info("ARP scan found %d devices", len(devices))
        for d in devices:
            self._merge_device(d)
            if self.config.device_callback:
                await self.config.device_callback(d)

    async def _run_dcp(self) -> None:
        """Run DCP scan."""
        logger.info("Starting DCP scan...")
        scanner = DCPScanner(
            interface=self.config.interface,
            timeout=self.config.dcp_timeout,
            progress_callback=self._make_progress("DCP Scan"),
        )
        devices = await scanner.scan(self.config.network)
        logger.info("DCP scan found %d devices", len(devices))
        for d in devices:
            self._merge_device(d)
            if self.config.device_callback:
                await self.config.device_callback(d)

    async def _run_tcp(self, devices: list[Device]) -> None:
        """Run TCP port scan."""
        logger.info("Starting TCP scan on %d devices...", len(devices))
        scanner = TCPScanner(
            ports=self.config.tcp_ports,
            timeout=self.config.tcp_timeout,
            concurrency=self.config.tcp_concurrency,
            progress_callback=self._make_progress("TCP Scan"),
        )
        updated = await scanner.scan(devices)
        for d in updated:
            self._merge_device(d)
        logger.info("TCP scan complete")

    async def _run_udp(self, devices: list[Device]) -> None:
        """Run UDP port scan."""
        logger.info("Starting UDP scan on %d devices...", len(devices))
        scanner = UDPScanner(
            ports=self.config.udp_ports,
            timeout=self.config.udp_timeout,
            concurrency=self.config.udp_concurrency,
            progress_callback=self._make_progress("UDP Scan"),
        )
        updated = await scanner.scan(devices)
        for d in updated:
            self._merge_device(d)
        logger.info("UDP scan complete")

    async def _run_plugins(self, devices: list[Device]) -> None:
        """Run plugin identification."""
        # Loads (and downloads if missing) the PI vendor ID database up front,
        # so a first-time fetch doesn't block the event loop mid-identification
        # when the first unmatched device triggers a lazy lookup.
        loop = asyncio.get_event_loop()
        vendor_id_count = await loop.run_in_executor(None, ensure_vendor_id_database_loaded)
        logger.debug("PI vendor ID database ready: %d entries", vendor_id_count)
        gsdml_count = await loop.run_in_executor(None, ensure_gsdml_database_loaded)
        logger.debug("Local GSDML database ready: %d entries", gsdml_count)

        for i, device in enumerate(devices):
            if self.config.progress_callback:
                await self.config.progress_callback(i + 1, len(devices), "Plugin Identification")

            identified = self._plugin_manager.run_full_identification(device)
            self._merge_device(identified)

    def _merge_device(self, device: Device) -> None:
        """Merge device into internal dict by IP."""
        existing = self.devices.get(device.ip)
        if existing:
            existing.merge(device)
        else:
            self.devices[device.ip] = device

    def _make_progress(self, step_name: str) -> Callable[[int, int], Awaitable[None]]:
        """Create progress callback for a step."""
        async def callback(current: int, total: int):
            if self.config.progress_callback:
                await self.config.progress_callback(current, total, step_name)
        return callback

    def _export_csv(self) -> None:
        """Export to CSV."""
        exporter = CSVExporter(self.config.export_csv)
        exporter.export(list(self.devices.values()))

    def _export_json(self) -> None:
        """Export to JSON."""
        exporter = JSONExporter(self.config.export_json)
        exporter.export(list(self.devices.values()), self.scan_results)

    def get_plugin_manager(self) -> PluginManager:
        """Get the plugin manager for custom plugin registration."""
        return self._plugin_manager