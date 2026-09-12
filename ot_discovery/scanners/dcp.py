"""DCP (Discovery and Configuration Protocol) Scanner for Profinet."""

import asyncio
import logging
import socket
import struct
import sys
import time
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, Callable, Awaitable

from ..models.device import Device, Protocol
from .arp import _get_interface_info, _get_default_interface_info

logger = logging.getLogger("ot_discovery.scanners.dcp")

try:
    from scapy.all import Raw, sendp, AsyncSniffer, conf as _scapy_conf
    _scapy_conf.verb = 0
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


DCP_MULTICAST_MAC = b'\x01\x0e\xcf\x00\x00\x00'
DCP_ETHERTYPE = 0x8892

# Profinet DCP device role bitmask (DCP_OPTION_DEVICE_ROLE block)
DCP_ROLE_BITS = {
    0x01: "IO-Device",
    0x02: "IO-Controller",
    0x04: "IO-Multidevice",
    0x08: "PN-Supervisor",
}

DCP_SERVICE_ID = 0x01
DCP_BLOCK_QUALIFIER = 0x0001
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE_NAME = 0x02
DCP_OPTION_VENDOR_ID = 0x03
DCP_OPTION_DEVICE_ID = 0x04
DCP_OPTION_DEVICE_ROLE = 0x05
DCP_OPTION_ALIAS_NAME = 0x06

DCP_FRAME_ID = 0xfefe
DCP_SERVICE_REQUEST = 0x01
DCP_SERVICE_RESPONSE = 0x02


class DCPScanner:
    """DCP scanner for Profinet device discovery."""

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: float = 3.0,
        retries: int = 2,
        progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.retries = retries
        self.progress_callback = progress_callback
        self._src_mac: Optional[bytes] = None

    async def scan(self, network: IPv4Network) -> list[Device]:
        """Scan network via DCP Identify requests."""
        await self._initialize_interface()

        if sys.platform == "win32":
            if HAVE_SCAPY:
                try:
                    return await self._scan_windows()
                except Exception as e:
                    logger.warning("Scapy/Npcap DCP sweep failed (%s), skipping DCP", e)
            else:
                logger.debug("Scapy not available, skipping DCP scan on Windows")
            if self.progress_callback:
                await self.progress_callback(1, 1)
            return []

        return await self._scan_linux(network)

    async def _scan_windows(self) -> list[Device]:
        """DCP Identify sweep via Npcap: multicast the request, collect responses."""
        loop = asyncio.get_event_loop()
        logger.debug("DCP Identify sweep via Npcap (timeout=%.1fs, retries=%d)",
                     self.timeout, self.retries)
        devices = await loop.run_in_executor(None, self._dcp_sweep_scapy)
        if self.progress_callback:
            await self.progress_callback(len(devices), max(1, len(devices)))
        logger.info("DCP sweep found %d device(s)", len(devices))
        return devices

    def _dcp_sweep_scapy(self) -> list[Device]:
        """Blocking scapy DCP sweep, run in a worker thread."""
        found: dict[str, Device] = {}

        def on_packet(pkt) -> None:
            device = self._parse_dcp_response(bytes(pkt))
            if device:
                found[device.mac] = device
                logger.debug("DCP response from %s (%s): name=%s vendor_id=%s device_id=%s",
                             device.ip, device.mac, device.dcp_name,
                             device.vendor_id, device.device_id)

        sniffer = AsyncSniffer(filter="ether proto 0x8892", prn=on_packet, store=False)
        sniffer.start()
        time.sleep(0.1)  # let the sniffer attach before the first request

        try:
            request = self._build_dcp_identify()
            for _ in range(max(1, self.retries)):
                sendp(Raw(request), verbose=0)
                time.sleep(0.1)
            time.sleep(self.timeout)
        finally:
            sniffer.stop()

        return list(found.values())

    async def _initialize_interface(self) -> None:
        """Get source MAC for the interface."""
        if self.interface:
            self._src_mac, _ = _get_interface_info(self.interface)
        else:
            self._src_mac, _ = _get_default_interface_info()

        if not self._src_mac:
            self._src_mac = b'\x00' * 6

    async def _scan_linux(self, network: IPv4Network) -> list[Device]:
        """Linux DCP scan using AF_PACKET raw sockets."""
        devices = []

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(DCP_ETHERTYPE))
        sock.setblocking(False)
        sock.bind((self.interface or "eth0", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)

        loop = asyncio.get_event_loop()

        try:
            request = self._build_dcp_identify()
            for _ in range(self.retries):
                sock.send(request)
                await asyncio.sleep(0.1)

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, _ = await asyncio.wait_for(
                        loop.sock_recv(sock, 4096),
                        timeout=0.5
                    )
                    device = self._parse_dcp_response(data)
                    if device and device not in devices:
                        devices.append(device)
                        if self.progress_callback:
                            await self.progress_callback(len(devices), 1)
                except asyncio.TimeoutError:
                    continue
        finally:
            sock.close()

        return devices

    def _build_dcp_identify(self) -> bytes:
        """Build DCP Identify Request frame."""
        eth_dst = DCP_MULTICAST_MAC
        eth_src = self._src_mac
        eth_type = struct.pack('!H', DCP_ETHERTYPE)

        frame_id = struct.pack('!H', DCP_FRAME_ID)
        service_id = struct.pack('!B', DCP_SERVICE_ID)
        service_type = struct.pack('!B', DCP_SERVICE_REQUEST)
        xid = struct.pack('!I', 0x12345678)
        reserved = struct.pack('!H', 0)

        block_qualifier = struct.pack('!H', DCP_BLOCK_QUALIFIER)
        block_info = struct.pack('!H', 0)

        options = b''
        for opt in [DCP_OPTION_IP, DCP_OPTION_DEVICE_NAME, DCP_OPTION_VENDOR_ID,
                    DCP_OPTION_DEVICE_ID, DCP_OPTION_DEVICE_ROLE, DCP_OPTION_ALIAS_NAME]:
            options += struct.pack('!B', opt) + struct.pack('!B', 0)

        block_len = struct.pack('!H', len(options))
        block = block_qualifier + block_info + block_len + options

        dcp_data = block
        dcp_header = frame_id + service_id + service_type + xid + reserved + struct.pack('!H', len(dcp_data))
        return eth_dst + eth_src + eth_type + dcp_header + dcp_data

    def _parse_dcp_response(self, data: bytes) -> Optional[Device]:
        """Parse DCP Identify Response."""
        if len(data) < 30:
            return None

        eth_type = struct.unpack('!H', data[12:14])[0]
        if eth_type != DCP_ETHERTYPE:
            return None

        frame_id = struct.unpack('!H', data[14:16])[0]
        if frame_id != DCP_FRAME_ID:
            return None

        service_type = data[17]
        if service_type != DCP_SERVICE_RESPONSE:
            return None

        src_mac = data[6:12]
        mac = ':'.join(f'{b:02x}' for b in src_mac)

        offset = 24
        device = Device(ip=IPv4Address("0.0.0.0"), mac=mac)

        while offset < len(data) - 4:
            if offset + 4 > len(data):
                break
            block_qual = struct.unpack('!H', data[offset:offset+2])[0]
            block_info = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4

            if offset + 2 > len(data):
                break
            block_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2

            block_data = data[offset:offset+block_len]
            offset += block_len

            self._parse_dcp_block(device, block_data)

        if device.ip == IPv4Address("0.0.0.0"):
            return None

        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.DCP)
        return device

    def _parse_dcp_block(self, device: Device, data: bytes) -> None:
        """Parse DCP block options."""
        offset = 0
        while offset < len(data) - 2:
            if offset + 2 > len(data):
                break
            option = data[offset]
            suboption = data[offset + 1]
            offset += 2

            if offset + 2 > len(data):
                break
            length = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2

            if offset + length > len(data):
                break
            value = data[offset:offset+length]
            offset += length

            if option == DCP_OPTION_IP and suboption == 0x01:
                if length == 4:
                    device.ip = IPv4Address(struct.unpack('!I', value)[0])
            elif option == DCP_OPTION_DEVICE_NAME:
                device.dcp_name = value.decode('ascii', errors='ignore')
            elif option == DCP_OPTION_VENDOR_ID and length == 2:
                device.vendor_id = struct.unpack('!H', value)[0]
            elif option == DCP_OPTION_DEVICE_ID and length == 2:
                device.device_id = struct.unpack('!H', value)[0]
            elif option == DCP_OPTION_DEVICE_ROLE and length == 2:
                role_bits = struct.unpack('!H', value)[0]
                device.raw_data['dcp_role_bits'] = role_bits
                roles = [name for bit, name in DCP_ROLE_BITS.items() if role_bits & bit]
                if roles:
                    device.dcp_role = ", ".join(roles)
            elif option == DCP_OPTION_ALIAS_NAME:
                device.raw_data['dcp_alias_name'] = value.decode('ascii', errors='ignore')