"""ARP Scanner - cross-platform (Linux AF_PACKET, Windows via iphlpapi SendARP)."""

import asyncio
import ctypes
import logging
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, Callable, Awaitable, List

from ..models.device import Device
from ..plugins.oui_database import lookup_manufacturer, ensure_ieee_database_loaded, OUI_LOOKUP_CONFIDENCE
from .hostname import HostnameResolver

logger = logging.getLogger("ot_discovery.scanners.arp")

try:
    from scapy.all import ARP, Ether, sendp, AsyncSniffer, conf as _scapy_conf
    _scapy_conf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

if sys.platform == "win32":
    _IPHLPAPI = ctypes.windll.iphlpapi
else:
    _IPHLPAPI = None


def _get_interface_info(interface: str) -> tuple[Optional[bytes], Optional[IPv4Address]]:
    """Get MAC and IP for an interface (cross-platform).

    On Windows, `interface` is the connection name shown throughout this app
    and to scapy (e.g. "WLAN", "Ethernet 9" - what get_windows_if_list()
    returns as 'name', and what sendp()/AsyncSniffer() accept as `iface`).
    netifaces instead keys interfaces by hardware *description* ("Intel(R)
    Wi-Fi 6E AX210 160MHz"), so netifaces.ifaddresses(interface) reliably
    raises for any name this app actually uses - caught below, silently
    falling through to the b'\\x00'*6 fallback in every caller. Try scapy's
    own list first so a MAC actually gets resolved.
    """
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if iface.get("name") == interface:
                    mac = bytes(int(b, 16) for b in iface["mac"].split(':')) if iface.get("mac") else None
                    ip = None
                    for addr in iface.get("ips", []):
                        if ':' not in addr and not addr.startswith('127.'):
                            ip = IPv4Address(addr)
                            break
                    if mac:
                        return mac, ip
                    break
        except Exception:
            pass

    try:
        import netifaces
        addrs = netifaces.ifaddresses(interface)
        mac = None
        ip = None
        if netifaces.AF_LINK in addrs:
            for addr in addrs[netifaces.AF_LINK]:
                if 'addr' in addr:
                    mac_str = addr['addr']
                    mac = bytes(int(b, 16) for b in mac_str.split(':'))
                    break
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr and not addr['addr'].startswith('127.'):
                    ip = IPv4Address(addr['addr'])
                    break
        return mac, ip
    except Exception:
        pass

    if sys.platform != "win32":
        try:
            import fcntl
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifr = struct.pack('256s', interface[:15].encode())
            try:
                info = fcntl.ioctl(s.fileno(), 0x8927, ifr)
                mac = info[18:24]
            except OSError:
                mac = None
            try:
                info = fcntl.ioctl(s.fileno(), 0x8915, ifr)
                ip = IPv4Address(socket.inet_ntoa(info[20:24]))
            except OSError:
                ip = None
            return mac, ip
        except Exception:
            pass

    return None, None


def _get_default_interface_info() -> tuple[Optional[bytes], Optional[IPv4Address]]:
    """Get MAC and IP for default interface (cross-platform)."""
    try:
        import netifaces
        gateways = netifaces.gateways()
        default_iface = gateways['default'][netifaces.AF_INET][1]
        return _get_interface_info(default_iface)
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = IPv4Address(s.getsockname()[0])
        s.close()
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr['addr'] == str(ip):
                            mac = None
                            if netifaces.AF_LINK in addrs:
                                for a in addrs[netifaces.AF_LINK]:
                                    if 'addr' in a:
                                        mac_str = a['addr']
                                        mac = bytes(int(b, 16) for b in mac_str.split(':'))
                                        break
                            return mac, ip
        except Exception:
            pass
        return None, ip
    except Exception:
        pass

    return None, None


def _is_locally_administered(mac: str) -> bool:
    """Check the U/L bit of the MAC's first octet.

    A set bit means the address was assigned locally (randomized Wi-Fi privacy
    MACs on phones/laptops, VM NICs, manually configured addresses) rather than
    burned in by a registered vendor — an OUI lookup for it is meaningless.
    """
    first_octet = int(mac.split(':')[0], 16)
    return bool(first_octet & 0x02)


def _make_device(ip: IPv4Address, mac: str) -> Device:
    """Build a Device from a resolved MAC, with a best-effort OUI manufacturer guess."""
    device = Device(ip=ip, mac=mac, oui=mac[:8].upper())
    device.mac_locally_administered = _is_locally_administered(mac)

    if device.mac_locally_administered:
        device.manufacturer_source = "Randomisierte/virtuelle MAC"
        logger.debug("%s (%s): locally administered MAC, skipping OUI lookup", ip, mac)
        return device

    manufacturer = lookup_manufacturer(mac)
    if manufacturer:
        device.manufacturer = manufacturer
        device.manufacturer_confidence = OUI_LOOKUP_CONFIDENCE
        device.manufacturer_source = "OUI"
        logger.debug("%s (%s): resolved manufacturer '%s' via OUI lookup", ip, mac, manufacturer)
    else:
        logger.debug("%s (%s): no manufacturer match for OUI %s", ip, mac, device.oui)
    return device


class ARPScanner:
    """ARP scanner for local network discovery."""

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: float = 2.0,
        retries: int = 1,
        resolve_hostnames: bool = True,
        hostname_timeout: float = 5.0,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.retries = retries
        self.resolve_hostnames = resolve_hostnames
        self.hostname_timeout = hostname_timeout
        self.progress_callback = progress_callback
        self._src_mac: Optional[bytes] = None
        self._src_ip: Optional[IPv4Address] = None

    async def scan(self, network: IPv4Network) -> list[Device]:
        """Scan network via ARP requests."""
        logger.info("ARP scan starting on %s (interface=%s, timeout=%.1fs)",
                    network, self.interface or "auto-detect", self.timeout)
        # Loads (and downloads if missing) the IEEE OUI database up front, so a
        # first-time fetch doesn't block the event loop mid-sweep when the first
        # resolved device triggers a lazy lookup.
        loop = asyncio.get_event_loop()
        oui_count = await loop.run_in_executor(None, ensure_ieee_database_loaded)
        logger.debug("IEEE OUI database ready: %d entries", oui_count)

        await self._initialize_interface()
        logger.debug("Using source IP=%s, MAC=%s", self._src_ip,
                     self._src_mac.hex(':') if self._src_mac else None)

        if sys.platform == "win32":
            devices = await self._scan_windows(network)
        else:
            devices = await self._scan_linux(network)

        if devices and self.resolve_hostnames:
            logger.debug("Resolving hostnames for %d device(s)", len(devices))
            resolver = HostnameResolver(timeout=self.hostname_timeout)
            devices = await resolver.resolve(devices)
            resolved = sum(1 for d in devices if d.hostname)
            logger.debug("Hostnames resolved: %d/%d", resolved, len(devices))

        self._flag_duplicate_macs(devices)

        logger.info("ARP scan finished on %s: %d device(s) found", network, len(devices))
        return devices

    def _flag_duplicate_macs(self, devices: list[Device]) -> None:
        """Mark devices whose MAC address appears on more than one IP.

        Legitimate on a load balancer or proxy-ARP setup, but also how ARP
        spoofing / a duplicate-IP conflict looks from a single ARP sweep — worth
        flagging either way.
        """
        mac_to_ips: dict[str, list[IPv4Address]] = {}
        for d in devices:
            if d.mac:
                mac_to_ips.setdefault(d.mac, []).append(d.ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                logger.warning("Duplicate MAC %s seen on multiple IPs: %s",
                               mac, ", ".join(str(ip) for ip in ips))
                for d in devices:
                    if d.mac == mac:
                        d.duplicate_mac = True

    async def _initialize_interface(self) -> None:
        """Get source MAC and IP for the interface."""
        if self.interface:
            self._src_mac, self._src_ip = _get_interface_info(self.interface)
        else:
            self._src_mac, self._src_ip = _get_default_interface_info()

        if not self._src_mac:
            logger.warning("Could not determine local MAC address, using 00:00:00:00:00:00")
            self._src_mac = b'\x00' * 6
        if not self._src_ip:
            logger.warning("Could not determine local IP address, using 0.0.0.0")
            self._src_ip = IPv4Address("0.0.0.0")

    async def _scan_linux(self, network: IPv4Network) -> list[Device]:
        """Linux ARP scan using AF_PACKET raw sockets."""
        devices = []
        ips = [ip for ip in network.hosts()]
        total = len(ips)

        for i, ip in enumerate(ips):
            if self.progress_callback:
                await self.progress_callback(i + 1, total)

            device = await self._arp_request_linux(ip)
            if device:
                logger.debug("%s answered ARP with MAC %s", ip, device.mac)
                devices.append(device)

        return devices

    async def _scan_windows(self, network: IPv4Network) -> list[Device]:
        """Windows ARP scan: Npcap broadcast sweep if available, else per-host SendARP."""
        if HAVE_SCAPY:
            try:
                return await self._scan_windows_scapy(network)
            except Exception as e:
                logger.warning("Scapy/Npcap ARP sweep failed (%s), falling back to SendARP", e)
        return await self._scan_windows_sendarp(network)

    async def _scan_windows_scapy(self, network: IPv4Network) -> list[Device]:
        """Fast ARP sweep via Npcap: one broadcast request per host, replies collected
        concurrently within the timeout window (like nmap -sn), instead of one blocking
        SendARP syscall per host.
        """
        loop = asyncio.get_event_loop()
        logger.debug("Npcap broadcast ARP sweep on %s (timeout=%.1fs, retries=%d)",
                     network, self.timeout, self.retries)
        answered = await loop.run_in_executor(None, self._arp_sweep_scapy, network)

        devices = [_make_device(IPv4Address(psrc), hwsrc.lower()) for psrc, hwsrc in answered]
        if self.progress_callback:
            await self.progress_callback(len(devices), len(devices))
        return devices

    # How long to keep listening after the most recent reply before concluding
    # no more are coming, and the minimum time to always wait first. Mirrors
    # nmap's adaptive host-discovery timing instead of a fixed sleep(timeout).
    _QUIET_WINDOW = 0.3
    _MIN_WAIT = 0.5

    def _arp_sweep_scapy(self, network: IPv4Network) -> list[tuple[str, str]]:
        """Blocking scapy broadcast ARP sweep, run in a worker thread.

        Sends broadcast requests and listens continuously; each round stops as
        soon as replies go quiet for _QUIET_WINDOW seconds (after at least
        _MIN_WAIT) rather than always waiting the full self.timeout. self.timeout
        remains a hard per-round cap in case nothing responds at all. Retries
        only re-probe hosts that haven't answered yet.
        """
        results: dict[str, str] = {}
        last_reply = [0.0]

        def on_packet(pkt) -> None:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                results[pkt[ARP].psrc] = pkt[ARP].hwsrc
                last_reply[0] = time.monotonic()

        sniffer = AsyncSniffer(filter="arp", prn=on_packet, store=False)
        sniffer.start()
        time.sleep(0.1)  # let the sniffer attach before the first broadcast

        try:
            targets = str(network)
            for attempt in range(1, max(1, self.retries) + 1):
                before = len(results)
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets), verbose=0)

                start = time.monotonic()
                last_reply[0] = start
                while True:
                    time.sleep(0.05)
                    now = time.monotonic()
                    if now - start >= self.timeout:
                        break
                    if now - start >= self._MIN_WAIT and now - last_reply[0] >= self._QUIET_WINDOW:
                        break

                logger.debug("ARP sweep round %d/%d: %d new repl%s in %.1fs",
                             attempt, self.retries, len(results) - before,
                             "y" if len(results) - before == 1 else "ies", time.monotonic() - start)

                remaining = [str(ip) for ip in network.hosts() if str(ip) not in results]
                if not remaining:
                    break
                targets = remaining
        finally:
            sniffer.stop()

        return list(results.items())

    async def _scan_windows_sendarp(self, network: IPv4Network) -> list[Device]:
        """Windows ARP scan using the iphlpapi SendARP API (fallback when Npcap is unavailable).

        SendARP triggers a real Layer-2 ARP request/reply for each target IP,
        unlike a ping sweep it does not depend on the target responding to ICMP
        (many OT devices and hardened hosts block ping but still answer ARP).
        """
        ips = list(network.hosts())
        total = len(ips)
        devices: list[Device] = []
        concurrency = 50
        semaphore = asyncio.Semaphore(concurrency)
        loop = asyncio.get_event_loop()
        progress_lock = asyncio.Lock()
        completed = 0

        logger.debug("SendARP sweep: %d hosts, concurrency=%d", total, concurrency)

        # SendARP is a blocking syscall; the default executor is capped at
        # min(32, cpu_count+4) workers, which throttles well below `concurrency`
        # on typical machines. Use a dedicated pool sized to match.
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            async def arp_one(ip: IPv4Address) -> None:
                nonlocal completed
                async with semaphore:
                    mac = await loop.run_in_executor(executor, self._send_arp, ip)
                async with progress_lock:
                    completed += 1
                    if self.progress_callback:
                        await self.progress_callback(completed, total)
                if mac:
                    logger.debug("%s answered ARP with MAC %s", ip, mac)
                    devices.append(_make_device(ip, mac))

            await asyncio.gather(*(arp_one(ip) for ip in ips))
        return devices

    def _send_arp(self, target_ip: IPv4Address) -> Optional[str]:
        """Resolve a MAC address via a real ARP request (Windows SendARP).

        Retries self.retries times: power-saving devices (phones, tablets in
        sleep mode) often drop or delay a single ARP request.
        """
        dest_addr = struct.unpack("<L", socket.inet_aton(str(target_ip)))[0]
        src_addr = 0
        if self._src_ip and str(self._src_ip) != "0.0.0.0":
            src_addr = struct.unpack("<L", socket.inet_aton(str(self._src_ip)))[0]

        for attempt in range(1, max(1, self.retries) + 1):
            mac_buffer = (ctypes.c_ubyte * 6)()
            mac_len = ctypes.c_ulong(6)

            result = _IPHLPAPI.SendARP(
                ctypes.c_ulong(dest_addr),
                ctypes.c_ulong(src_addr),
                ctypes.byref(mac_buffer),
                ctypes.byref(mac_len),
            )

            if result == 0 and mac_len.value == 6:
                return ':'.join(f'{b:02x}' for b in mac_buffer)
            logger.debug("SendARP for %s attempt %d/%d returned error code %d (no reply)",
                         target_ip, attempt, self.retries, result)

        return None

    async def _arp_request_linux(self, target_ip: IPv4Address) -> Optional[Device]:
        """Send ARP request and wait for reply (Linux AF_PACKET)."""
        if not self._src_mac or not self._src_ip:
            return None

        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.setblocking(False)
        sock.bind((self.interface or "eth0", 0))

        try:
            request = self._build_arp_request(target_ip)
            sock.send(request)

            for _ in range(self.retries):
                try:
                    data, _ = await asyncio.wait_for(
                        loop.sock_recv(sock, 4096),
                        timeout=self.timeout
                    )
                    reply = self._parse_arp_reply(data, target_ip)
                    if reply:
                        return reply
                except asyncio.TimeoutError:
                    continue
        finally:
            sock.close()

        return None

    def _build_arp_request(self, target_ip: IPv4Address) -> bytes:
        """Build ARP request packet."""
        eth_dst = b'\xff' * 6
        eth_src = self._src_mac
        eth_type = struct.pack('!H', 0x0806)  # ARP

        htype = struct.pack('!H', 1)      # Ethernet
        ptype = struct.pack('!H', 0x0800) # IPv4
        hlen = struct.pack('!B', 6)
        plen = struct.pack('!B', 4)
        oper = struct.pack('!H', 1)       # Request

        sha = self._src_mac
        spa = struct.pack('!I', int(self._src_ip))
        tha = b'\x00' * 6
        tpa = struct.pack('!I', int(target_ip))

        arp = htype + ptype + hlen + plen + oper + sha + spa + tha + tpa
        return eth_dst + eth_src + eth_type + arp

    def _parse_arp_reply(self, data: bytes, target_ip: IPv4Address) -> Optional[Device]:
        """Parse ARP reply packet."""
        if len(data) < 42:
            return None

        eth_type = struct.unpack('!H', data[12:14])[0]
        if eth_type != 0x0806:
            return None

        oper = struct.unpack('!H', data[20:22])[0]
        if oper != 2:  # Reply
            return None

        spa = struct.unpack('!I', data[28:32])[0]
        if spa != int(target_ip):
            return None

        sha = data[22:28]
        mac = ':'.join(f'{b:02x}' for b in sha)

        return _make_device(target_ip, mac)