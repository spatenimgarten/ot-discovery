"""TCP Port Scanner using asyncio."""

import asyncio
import socket
from ipaddress import IPv4Address
from typing import Optional, Callable, Awaitable

from ..models.device import Device
from ..models.scan_result import ScanResult, ScanType

COMMON_OT_PORTS = [
    22, 23, 80, 102, 161, 443, 502, 4840,
    34962, 34963, 34964, 44818, 48898, 1089, 1090,
    20000, 20001, 44819, 44820, 44821, 44822, 44823, 44824
]

DEFAULT_PORTS = list(range(1, 1025)) + COMMON_OT_PORTS


class TCPScanner:
    """TCP port scanner."""

    def __init__(
        self,
        ports: Optional[list[int]] = None,
        timeout: float = 2.0,
        concurrency: int = 100,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ):
        self.ports = ports or DEFAULT_PORTS
        self.timeout = timeout
        self.concurrency = concurrency
        self.progress_callback = progress_callback

    async def scan(self, devices: list[Device]) -> list[Device]:
        """Scan TCP ports on devices."""
        # `concurrency` bounds the total number of simultaneous connection
        # attempts across the whole scan (devices x ports combined). Gating it
        # per-device only, as before, let a single device with 1000+ ports open
        # them all at once regardless of `concurrency` — harmless on a
        # responsive LAN where closed ports RST instantly, but on a network
        # that silently drops probes to closed/filtered ports (common on
        # firewalled OT networks) that can hit OS-level connection limits and
        # stall the whole scan for many times self.timeout.
        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_device(device: Device) -> Device:
            open_ports = await self._scan_ports(device.ip, semaphore)
            device.tcp_ports = open_ports
            if self.progress_callback:
                await self.progress_callback(1, 1)
            return device

        tasks = [scan_device(d) for d in devices]
        return await asyncio.gather(*tasks)

    async def _scan_ports(self, ip: IPv4Address, semaphore: asyncio.Semaphore) -> list[int]:
        """Scan ports on a single IP."""
        open_ports = []

        async def check_port(port: int) -> Optional[int]:
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(str(ip), port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [check_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]