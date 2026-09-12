"""Generic PROFINET I&M0 reader - works across manufacturers, unlike the
Siemens-specific S7comm/SZL reader (scanners/s7comm.py).

I&M0 (Identification & Maintenance record 0) carries VendorID, OrderID,
SerialNumber, HardwareRevision, SoftwareRevision, RevisionCounter, ProfileID,
ProfileSpecificType and IMVersion/IMSupported - every PROFINET-conformant
device is required to support reading it. This module reads it over PN-IO's
DCE/RPC-over-UDP transport with a single stateless "Read" call - no
Application Relationship (Connect) needed, since I&M0 access doesn't require
one on the devices this was verified against.

Every byte layout here was captured live from Siemens PRONETA reading two
real devices - an ifm IO-Link Master AL1402 and a Siemens PN/BACnet LINK -
and decoded field-by-field, not implemented from the PN-IO spec alone. Using
two different devices mattered: the ifm one happened to listen for the
actual Read call on port 49152, which looked at first like a fixed
convention, until the BACnet LINK turned out to use 49155 instead. So the
port is genuinely dynamic and has to be looked up per device via a DCE/RPC
Endpoint Mapper (ept_map) query first - both captures agree on exactly where
in that response the port sits (a `00 08 02 00` marker followed by the port
as a big-endian uint16).

Verified against exactly two manufacturers (ifm, Siemens). Other PROFINET
stacks might still differ in ways neither capture exercised. Every failure
mode raises PnioImError or a plain OSError (socket timeout/refusal), so a
caller can treat both as "no data available" and move on.
"""

from __future__ import annotations

import socket
import struct
import uuid
from dataclasses import dataclass
from ipaddress import IPv4Address

PNIO_DEVICE_INTERFACE_UUID = uuid.UUID("DEA00001-6C97-11D1-8271-00A02442DF7D")
ENDPOINT_MAPPER_INTERFACE_UUID = uuid.UUID("E1AF8308-5D1F-11C9-91A4-08002B14A0FA")
EPM_PORT = 34964
IM0_INDEX = 0xAFF0

_OPNUM_EPT_MAP = 2
_OPNUM_READ = 5

# Marks the start of the UDP-port protocol floor in an ept_map response's
# "towers" data; the port itself is the big-endian uint16 right after it.
_PORT_FLOOR_MARKER = bytes.fromhex("00080200")


class PnioImError(Exception):
    """Raised when the I&M0 read fails or the response can't be parsed."""


@dataclass
class Im0Record:
    vendor_id: int
    order_id: str
    serial_number: str
    hardware_revision: int
    firmware: str
    revision_counter: int
    profile_id: int
    profile_specific_type: int
    im_version: str


def _dcerpc_dg_header(if_id: uuid.UUID, opnum: int, seqnum: int, body_len: int) -> bytes:
    """Build an 80-byte DCE/RPC connectionless (datagram) PDU header."""
    return (
        struct.pack("!BBBB", 4, 0, 0x20, 0x00)  # rpc_vers, ptype=REQUEST, flags1, flags2
        + struct.pack("!BBBB", 0x10, 0, 0, 0)  # drep (little-endian), serial_hi
        + b"\x00" * 16  # object UUID - zero, not tied to any established AR
        + if_id.bytes_le
        + uuid.uuid4().bytes_le  # activity UUID - unique per call, not otherwise checked
        + struct.pack("<IIIHHHHH", 0, 1, seqnum, opnum, 0xFFFF, 0xFFFF, body_len, 0)
        + struct.pack("!BB", 0, 0)  # auth_proto, serial_lo
    )


def _build_ept_map_request(seqnum: int) -> bytes:
    # Captured verbatim from a real PRONETA scan asking "who serves interface
    # DEA00001-...?" (that UUID appears little-endian-encoded in the body);
    # identical regardless of which device it's sent to.
    body = bytes.fromhex(
        "000000000100000000000000000000000000000000000000020000000100a0de976cd111"
        "827100a02442df7d0100000001000000000000000000000000000000000000000000000001000000"
    )
    return _dcerpc_dg_header(ENDPOINT_MAPPER_INTERFACE_UUID, _OPNUM_EPT_MAP, seqnum, len(body)) + body


def _build_read_im0_request(seqnum: int) -> bytes:
    # Captured verbatim from a real PRONETA I&M0 read; identical across every
    # device queried, so treated as a fixed template rather than reconstructed
    # field-by-field.
    body = bytes.fromhex(
        "40800000400000004080000000000000400000000009003c0100000000000000000000000000"
        "00000000000000000000000000010000aff000008000000000000000000000000000000000000000000000000000"
    )
    return _dcerpc_dg_header(PNIO_DEVICE_INTERFACE_UUID, _OPNUM_READ, seqnum, len(body)) + body


def _find_read_port(epm_response_body: bytes) -> int:
    idx = epm_response_body.find(_PORT_FLOOR_MARKER)
    if idx == -1:
        raise PnioImError("port floor not found in Endpoint Mapper response")
    port_offset = idx + len(_PORT_FLOOR_MARKER)
    port, = struct.unpack_from("!H", epm_response_body, port_offset)
    return port


def _parse_im0(payload: bytes) -> Im0Record:
    idx = payload.find(b"\xaf\xf0")
    if idx == -1:
        raise PnioImError("I&M0 index marker not found in response")
    record = payload[idx + 36: idx + 36 + 54]
    if len(record) < 54:
        raise PnioImError("response too short for a full I&M0 record")

    vendor_id, = struct.unpack_from("!H", record, 0)
    order_id = record[2:22].decode("ascii", errors="ignore").strip()
    serial_number = record[22:38].decode("ascii", errors="ignore").strip()
    hw_rev, = struct.unpack_from("!H", record, 38)
    sw = record[40:44]
    firmware = f"{chr(sw[0])}{sw[1]}.{sw[2]}.{sw[3]}" if sw[0:1].isalpha() else ""
    rev_counter, = struct.unpack_from("!H", record, 44)
    profile_id, = struct.unpack_from("!H", record, 46)
    profile_type, = struct.unpack_from("!H", record, 48)
    im_ver = record[50:52]

    return Im0Record(
        vendor_id=vendor_id, order_id=order_id, serial_number=serial_number,
        hardware_revision=hw_rev, firmware=firmware, revision_counter=rev_counter,
        profile_id=profile_id, profile_specific_type=profile_type,
        im_version=f"{im_ver[0]}.{im_ver[1]}",
    )


def _find_read_port_for(ip: IPv4Address, timeout: float, sock: socket.socket) -> int:
    sock.sendto(_build_ept_map_request(seqnum=1), (str(ip), EPM_PORT))
    payload, _ = sock.recvfrom(4096)
    if len(payload) < 80:
        raise PnioImError("Endpoint Mapper response shorter than a DCE/RPC header")
    return _find_read_port(payload[80:])


def read_im0(ip: IPv4Address, timeout: float = 2.0) -> Im0Record:
    """Read the device's I&M0 record over PN-IO RPC. Raises PnioImError/OSError on failure."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        port = _find_read_port_for(ip, timeout, sock)
        sock.sendto(_build_read_im0_request(seqnum=1), (str(ip), port))
        payload, _ = sock.recvfrom(4096)
    if len(payload) < 80:
        raise PnioImError("response shorter than a DCE/RPC header")
    return _parse_im0(payload[80:])
