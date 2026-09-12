"""DCP (Discovery and Configuration Protocol) Scanner for Profinet."""

import asyncio
import logging
import random
import socket
import struct
import sys
import time
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, Callable, Awaitable

from ..models.device import Device, Protocol
from ..plugins.gsdml_database import lookup_model_name
from ..plugins.vendor_id_database import lookup_vendor_name, VENDOR_ID_LOOKUP_CONFIDENCE
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

# Frame IDs (IEC 61158-6-10 sec. 4.10.3.2) - request and response use different values.
DCP_FRAME_ID_REQUEST = 0xfefe
DCP_FRAME_ID_RESPONSE = 0xfeff

# Service IDs (sec. 4.3.1.4.4) - 0x05 is "Identify"; a device ignores anything else here.
DCP_SERVICE_ID_IDENTIFY = 0x05
# ServiceType is a bitfield; bit 0 is the request(0)/response(1) selector (sec. 4.3.1.4.5).
DCP_SERVICE_TYPE_REQUEST = 0x00
DCP_SERVICE_TYPE_RESPONSE_BIT = 0x01

# Top-level block options (sec. 4.3.1.3.1). Device name/ID/role are *suboptions* of
# DCP_OPTION_DEVICE, not options in their own right.
DCP_OPTION_IP = 0x01
DCP_OPTION_DEVICE = 0x02
DCP_OPTION_ALL_SELECTOR = 0xff

DCP_SUBOPTION_IP_PARAMETER = 0x02

DCP_SUBOPTION_DEVICE_NAMEOFSTATION = 0x02
DCP_SUBOPTION_DEVICE_ID = 0x03
DCP_SUBOPTION_DEVICE_ROLE = 0x04
DCP_SUBOPTION_DEVICE_ALIAS_NAME = 0x06

DCP_SUBOPTION_ALL_SELECTOR = 0xff

# Profinet DCP device role bitmask (DCP_SUBOPTION_DEVICE_ROLE block)
DCP_ROLE_BITS = {
    0x01: "IO-Device",
    0x02: "IO-Controller",
    0x04: "IO-Multidevice",
    0x08: "PN-Supervisor",
}


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

        sniffer = AsyncSniffer(
            filter="ether proto 0x8892", prn=on_packet, store=False, iface=self.interface,
        )
        sniffer.start()
        time.sleep(0.1)  # let the sniffer attach before the first request

        try:
            request = self._build_dcp_identify()
            for _ in range(max(1, self.retries)):
                sendp(Raw(request), iface=self.interface, verbose=0)
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
        """Build a DCP Identify Request frame using the "All Selector" block,
        which asks every listening device to report everything it knows
        (IP, name, vendor/device ID, role, ...) in one response."""
        eth_dst = DCP_MULTICAST_MAC
        eth_src = self._src_mac
        eth_type = struct.pack('!H', DCP_ETHERTYPE)

        frame_id = struct.pack('!H', DCP_FRAME_ID_REQUEST)
        service_id = struct.pack('!B', DCP_SERVICE_ID_IDENTIFY)
        service_type = struct.pack('!B', DCP_SERVICE_TYPE_REQUEST)
        # Randomized so repeated scans aren't mistaken for retransmits/duplicates
        # of an earlier request by devices that dedupe on (source MAC, Xid).
        xid = struct.pack('!I', random.getrandbits(32))
        # Some devices don't answer at all when this is 0; 128ms (observed from a
        # real TIA Portal "accessible devices" scan) is a safe, widely-used value.
        response_delay = struct.pack('!H', 128)

        block = struct.pack('!BBH', DCP_OPTION_ALL_SELECTOR, DCP_SUBOPTION_ALL_SELECTOR, 0)

        dcp_header = (frame_id + service_id + service_type + xid + response_delay
                      + struct.pack('!H', len(block)))
        return eth_dst + eth_src + eth_type + dcp_header + block

    def _parse_dcp_response(self, data: bytes) -> Optional[Device]:
        """Parse a DCP Identify Response frame."""
        if len(data) < 26:
            return None

        eth_type = struct.unpack('!H', data[12:14])[0]
        if eth_type != DCP_ETHERTYPE:
            return None

        frame_id = struct.unpack('!H', data[14:16])[0]
        if frame_id != DCP_FRAME_ID_RESPONSE:
            return None

        service_id = data[16]
        service_type = data[17]
        if service_id != DCP_SERVICE_ID_IDENTIFY or not (service_type & DCP_SERVICE_TYPE_RESPONSE_BIT):
            return None

        src_mac = data[6:12]
        mac = ':'.join(f'{b:02x}' for b in src_mac)

        data_length = struct.unpack('!H', data[24:26])[0]
        offset = 26
        end = min(len(data), offset + data_length)
        device = Device(ip=IPv4Address("0.0.0.0"), mac=mac)

        while offset + 4 <= end:
            option = data[offset]
            suboption = data[offset + 1]
            block_len = struct.unpack('!H', data[offset + 2:offset + 4])[0]
            block_start = offset + 4
            block_data = data[block_start:block_start + block_len]

            self._parse_dcp_block(device, option, suboption, block_data)

            offset = block_start + block_len
            if block_len % 2:
                offset += 1  # blocks are padded to an even length

        if device.ip == IPv4Address("0.0.0.0") and not device.dcp_name:
            return None

        device.protocols.append(Protocol.PROFINET)
        device.protocols.append(Protocol.DCP)

        # Resolve manufacturer/product family from vendor_id/device_id right
        # here, same as the ARP scanner does inline for OUI - so both work
        # standalone (e.g. a DCP-only scan) without depending on the later,
        # skippable Plugin Identification step.
        vendor_name = lookup_vendor_name(device.vendor_id)
        if vendor_name:
            device.manufacturer = vendor_name
            device.manufacturer_confidence = VENDOR_ID_LOOKUP_CONFIDENCE
            device.manufacturer_source = "PI Vendor ID"
            logger.debug("%s (%s): resolved manufacturer '%s' via PI vendor_id %s",
                         device.ip, mac, vendor_name, device.vendor_id)
        product_family = lookup_model_name(device.vendor_id, device.device_id)
        if product_family:
            device.raw_data["gsdml_product_family"] = product_family

        return device

    def _parse_dcp_block(self, device: Device, option: int, suboption: int, data: bytes) -> None:
        """Parse one DCP block's payload (Identify responses prefix IP/Device blocks
        with a 2-byte BlockInfo field ahead of the actual value)."""
        payload = data[2:] if option in (DCP_OPTION_IP, DCP_OPTION_DEVICE) else data

        if option == DCP_OPTION_IP and suboption == DCP_SUBOPTION_IP_PARAMETER:
            if len(payload) >= 4:
                device.ip = IPv4Address(struct.unpack('!I', payload[:4])[0])
        elif option == DCP_OPTION_DEVICE:
            if suboption == DCP_SUBOPTION_DEVICE_NAMEOFSTATION:
                device.dcp_name = payload.decode('ascii', errors='ignore')
            elif suboption == DCP_SUBOPTION_DEVICE_ID and len(payload) >= 4:
                device.vendor_id, device.device_id = struct.unpack('!HH', payload[:4])
            elif suboption == DCP_SUBOPTION_DEVICE_ROLE and len(payload) >= 1:
                role_bits = payload[0]
                device.raw_data['dcp_role_bits'] = role_bits
                roles = [name for bit, name in DCP_ROLE_BITS.items() if role_bits & bit]
                if roles:
                    device.dcp_role = ", ".join(roles)
            elif suboption == DCP_SUBOPTION_DEVICE_ALIAS_NAME:
                device.raw_data['dcp_alias_name'] = payload.decode('ascii', errors='ignore')