"""UDP Port Scanner using asyncio."""

import asyncio
import socket
from ipaddress import IPv4Address
from typing import Optional, Callable, Awaitable

from ..models.device import Device
from ..models.scan_result import ScanResult, ScanType

COMMON_OT_UDP_PORTS = [161, 34962, 34963, 34964, 44818, 48898, 1089, 1090]

# "fast": just the OT/industrial list above - a quick check for known
# protocols, same philosophy as tcp.py's FAST_PORTS.
FAST_PORTS = COMMON_OT_UDP_PORTS

# "deep": the OT list plus common network-service ports worth knowing about
# on an OT network (DNS/DHCP/TFTP/NTP - firmware/config delivery -, SNMP
# traps, BACnet). Deliberately not a 1-1024 sweep the way tcp.py's DEEP_PORTS
# is - UDP has no RST equivalent, so a closed/filtered port is only ever
# detected by timeout, making a broad UDP sweep far slower per port than the
# TCP equivalent for comparatively little OT-relevant benefit.
DEEP_PORTS = COMMON_OT_UDP_PORTS + [53, 67, 68, 69, 123, 137, 162, 500, 1900, 47808]


class UDPScanner:
    """UDP port scanner."""

    def __init__(
        self,
        ports: Optional[list[int]] = None,
        timeout: float = 1.0,
        retries: int = 1,
        concurrency: int = 50,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ):
        self.ports = ports or COMMON_OT_UDP_PORTS
        self.timeout = timeout
        self.retries = retries
        self.concurrency = concurrency
        self.progress_callback = progress_callback

    async def scan(self, devices: list[Device]) -> list[Device]:
        """Scan UDP ports on devices."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_device(device: Device) -> Device:
            async with semaphore:
                open_ports = await self._scan_ports(device.ip)
                device.udp_ports = open_ports
                if self.progress_callback:
                    await self.progress_callback(1, 1)
            return device

        tasks = [scan_device(d) for d in devices]
        return await asyncio.gather(*tasks)

    async def _scan_ports(self, ip: IPv4Address) -> list[int]:
        """Scan UDP ports on a single IP."""
        open_ports = []

        # UDP probe payloads for common protocols
        probes = {
            161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\x8b\x45\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
            34962: b'\xfe\xfe\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            44818: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            48898: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        }

        async def check_port(port: int) -> Optional[int]:
            for _ in range(self.retries):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setblocking(False)

                    probe = probes.get(port, b'\x00' * 16)
                    sock.sendto(probe, (str(ip), port))

                    loop = asyncio.get_event_loop()
                    data, _ = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 1024),
                        timeout=self.timeout
                    )
                    sock.close()
                    if data:
                        return port
                except (asyncio.TimeoutError, OSError):
                    continue
            return None

        tasks = [check_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]