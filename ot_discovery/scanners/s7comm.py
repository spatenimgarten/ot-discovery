"""Minimal S7comm client for reading SZL diagnostic data from Siemens PLCs.

Only the read path needed for asset diagnostics is implemented (no PLC
control, no memory read/write): connect, negotiate a PDU, and read a System
Status List (SZL) record. This gives the order number, serial number,
hardware revision and firmware version straight from the CPU.

Every byte layout here was verified against a live S7-1500 CPU (order number
6ES7 513-1AL02-0AB0, firmware V2.9.4) by capturing Siemens PRONETA's own
"Component Identification" scan and decoding it field by field - not
guessed from the S7comm spec alone.

Connects using the "PG" TSAP (0x0100/0x0100). That's notable because this
specific CPU has "Only secure PG/PC and HMI communication" enabled, which
forces TLS on the connection TIA Portal itself uses (see the DCP scanner's
history for how that was discovered) - but PRONETA's plain, unencrypted PG
connection was still accepted and returned full SZL data despite the CPU
also being read/write password-protected. Diagnostic SZL reads apparently
aren't gated by either of those protections.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Optional

SZL_MODULE_IDENTIFICATION = 0x0011
SZL_COMPONENT_IDENTIFICATION = 0x001C

_PG_TSAP = 0x0100
_COTP_CONNECT_CONFIRM = 0xD0
_S7_ROSCTR_USERDATA = 0x07


class S7CommError(Exception):
    """Raised when the S7comm handshake or a read fails."""


@dataclass
class S7Identity:
    order_number: Optional[str] = None
    hardware_revision: Optional[int] = None
    firmware: Optional[str] = None
    serial_number: Optional[str] = None
    module_type: Optional[str] = None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise S7CommError("connection closed while reading")
        buf += chunk
    return bytes(buf)


def _recv_tpkt(sock: socket.socket) -> bytes:
    """Read one TPKT-framed PDU, returning the payload after its 4-byte header."""
    header = _recv_exact(sock, 4)
    if header[0] != 3:
        raise S7CommError(f"unexpected TPKT version {header[0]}")
    length = struct.unpack("!H", header[2:4])[0]
    if length < 4:
        raise S7CommError(f"bogus TPKT length {length}")
    return _recv_exact(sock, length - 4)


def _cotp_connect(sock: socket.socket) -> None:
    """ISO-on-TCP (RFC1006) connection request/confirm, using the PG TSAP."""
    cotp = (
        b"\xe0"  # PDU type: CR (Connection Request)
        + b"\x00\x00"  # destination reference
        + b"\x00\x01"  # source reference
        + b"\x00"  # class/options
        + b"\xc0\x01\x0a"  # TPDU size = 2^10 = 1024
        + struct.pack("!BBH", 0xC1, 2, _PG_TSAP)  # calling TSAP
        + struct.pack("!BBH", 0xC2, 2, _PG_TSAP)  # called TSAP
    )
    body = struct.pack("!B", len(cotp)) + cotp
    tpkt = struct.pack("!BBH", 3, 0, 4 + len(body)) + body
    sock.sendall(tpkt)

    payload = _recv_tpkt(sock)
    if len(payload) < 2 or payload[1] != _COTP_CONNECT_CONFIRM:
        raise S7CommError("COTP connection refused (not a PLC, or PG access blocked)")


def _s7_setup_communication(sock: socket.socket) -> None:
    param = struct.pack("!BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 0x01E0)
    header = struct.pack("!BBHHHH", 0x32, 0x01, 0x0000, 0x0400, len(param), 0)
    body = struct.pack("!B", 2) + b"\xf0\x80" + header + param
    tpkt = struct.pack("!BBH", 3, 0, 4 + len(body)) + body
    sock.sendall(tpkt)
    _recv_tpkt(sock)  # ack - we don't need the negotiated PDU size for single small reads


def _build_read_szl_request(pdu_ref: int, szl_id: int, szl_index: int = 0) -> bytes:
    param = b"\x00\x01\x12" + struct.pack("!B", 4) + b"\x11\x44\x01\x00"
    data = b"\xff\x09" + struct.pack("!H", 4) + struct.pack("!HH", szl_id, szl_index)
    header = struct.pack("!BBHHHH", 0x32, _S7_ROSCTR_USERDATA, 0x0000, pdu_ref, len(param), len(data))
    body = struct.pack("!B", 2) + b"\xf0\x80" + header + param + data
    return struct.pack("!BBH", 3, 0, 4 + len(body)) + body


def _read_szl(sock: socket.socket, pdu_ref: int, szl_id: int) -> list[bytes]:
    """Send a Read SZL request and return the list of raw fixed-length entries."""
    sock.sendall(_build_read_szl_request(pdu_ref, szl_id))
    payload = _recv_tpkt(sock)

    # payload: COTP(3) + S7 header(10, starting with protocol id 0x32) + param + data
    if len(payload) < 13 or payload[3] != 0x32 or payload[4] != _S7_ROSCTR_USERDATA:
        raise S7CommError(f"unexpected Read SZL response for SZL 0x{szl_id:04x}")
    param_len, data_len = struct.unpack("!HH", payload[9:13])
    data = payload[13 + param_len: 13 + param_len + data_len]
    if len(data) < 8 or data[0] != 0xFF:
        raise S7CommError(f"Read SZL 0x{szl_id:04x} failed (return code 0x{data[0]:02x})")

    entry_len, count = struct.unpack("!HH", data[8:12])
    entries = []
    offset = 12
    for _ in range(count):
        entries.append(data[offset:offset + entry_len])
        offset += entry_len
    return entries


def _cotp_disconnect(sock: socket.socket) -> None:
    """Graceful COTP Disconnect Request (DR).

    CPUs hand out a limited number of PG communication resources; closing the
    raw TCP socket without this (an abrupt RST/FIN) can leave the CPU-side
    session in a stale state for a timeout period instead of freeing it right
    away, and rapid repeated scans can genuinely exhaust the pool - observed
    directly while developing this: back-to-back connection attempts started
    getting refused after Setup Communication until the CPU's own timeout
    (tens of seconds) released the earlier, uncleanly-closed sessions.
    """
    dr = b"\x80" + b"\x00\x00" + b"\x00\x01" + b"\x00"  # PDU type DR, dst-ref, src-ref, reason
    body = struct.pack("!B", len(dr)) + dr
    tpkt = struct.pack("!BBH", 3, 0, 4 + len(body)) + body
    try:
        sock.sendall(tpkt)
    except OSError:
        pass


def _entry_by_index(entries: list[bytes], index: int) -> Optional[bytes]:
    for entry in entries:
        if len(entry) >= 2 and struct.unpack("!H", entry[0:2])[0] == index:
            return entry
    return None


def _ascii(data: bytes) -> str:
    return data.decode("ascii", errors="ignore").strip(" \x00")


def read_identity(ip: IPv4Address, timeout: float = 2.0) -> S7Identity:
    """Read order number, hardware revision, firmware, and serial number via SZL."""
    identity = S7Identity()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((str(ip), 102))
        _cotp_connect(sock)
        _s7_setup_communication(sock)

        module_entries = _read_szl(sock, 0x0100, SZL_MODULE_IDENTIFICATION)
        cpu_module = _entry_by_index(module_entries, 0x0001)
        if cpu_module:
            identity.order_number = _ascii(cpu_module[2:22])
            identity.hardware_revision = struct.unpack("!H", cpu_module[24:26])[0]
        # Entry layout: index(2) + 20-byte order-number field + BGTyp(2) + version(4).
        # For the firmware entry the order-number field is blank and the version
        # bytes are 'V' followed by three raw (not ASCII-digit) version numbers.
        firmware_entry = _entry_by_index(module_entries, 0x0007)
        if firmware_entry and len(firmware_entry) >= 28 and firmware_entry[24] == ord("V"):
            identity.firmware = f"V{firmware_entry[25]}.{firmware_entry[26]}.{firmware_entry[27]}"

        component_entries = _read_szl(sock, 0x0101, SZL_COMPONENT_IDENTIFICATION)
        serial_entry = _entry_by_index(component_entries, 0x0005)
        if serial_entry:
            identity.serial_number = _ascii(serial_entry[2:])
        type_entry = _entry_by_index(component_entries, 0x0007)
        if type_entry:
            identity.module_type = _ascii(type_entry[2:])

        _cotp_disconnect(sock)

    return identity
