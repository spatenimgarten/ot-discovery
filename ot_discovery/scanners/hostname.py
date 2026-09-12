"""Hostname resolver for reverse DNS and NetBIOS."""

import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from typing import Optional, Callable, Awaitable

from ..models.device import Device


class HostnameResolver:
    """Resolve hostnames via reverse DNS and NetBIOS."""

    def __init__(
        self,
        timeout: float = 2.0,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ):
        self.timeout = timeout
        self.progress_callback = progress_callback

    async def resolve(self, devices: list[Device]) -> list[Device]:
        """Resolve hostnames for devices."""
        if not devices:
            return devices

        # socket.gethostbyaddr() is a blocking syscall; the default executor is
        # capped at min(32, cpu_count+4) workers, which throttles concurrency
        # well below len(devices) on a slow/unresponsive DNS server. Use a
        # dedicated pool sized to match, as with the SendARP path.
        #
        # Not a `with` block: a genuinely hung lookup (no NXDOMAIN, just a dead
        # target) is abandoned by asyncio.wait_for's timeout below, but the
        # underlying gethostbyaddr() call keeps running in its worker thread —
        # `with` would block here on shutdown(wait=True) until it eventually
        # finishes, silently re-introducing the same delay the timeout exists
        # to avoid. shutdown(wait=False) lets any such thread finish unattended
        # in the background instead.
        executor = ThreadPoolExecutor(max_workers=min(50, len(devices)))
        try:
            async def resolve_device(device: Device) -> Device:
                if not device.hostname:
                    hostname = await self._reverse_dns(device.ip, executor)
                    if hostname:
                        device.hostname = hostname
                if self.progress_callback:
                    await self.progress_callback(1, 1)
                return device

            tasks = [resolve_device(d) for d in devices]
            return await asyncio.gather(*tasks)
        finally:
            executor.shutdown(wait=False)

    async def _reverse_dns(self, ip: IPv4Address, executor: ThreadPoolExecutor) -> Optional[str]:
        """Perform reverse DNS lookup."""
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(executor, socket.gethostbyaddr, str(ip)),
                timeout=self.timeout
            )
            return result[0]
        except (asyncio.TimeoutError, socket.herror, OSError):
            return None