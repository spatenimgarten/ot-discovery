"""Generic PROFINET I&M0 reader - works across manufacturers, unlike the
Siemens-specific S7comm/SZL reader (scanners/s7comm.py).

I&M0 (Identification & Maintenance record 0) carries VendorID, OrderID,
SerialNumber, HardwareRevision, SoftwareRevision, RevisionCounter, ProfileID,
ProfileSpecificType and IMVersion/IMSupported - every PROFINET-conformant
device is required to support reading it. This module reads it over PN-IO's
DCE/RPC-over-UDP transport with a single stateless "Read" call - no
Application Relationship (Connect) needed, since I&M0 access doesn't require
one on the devices this was verified against.

Every byte layout here was captured live from Siemens PRONETA/TIA Portal
reading real devices - an ifm IO-Link Master (AL1304, firmware V3.1.97) and
a Siemens PN/BACnet LINK - and decoded field-by-field, not implemented from
the PN-IO spec alone. The port a device's actual Read call listens on is
genuinely dynamic (49152 on the ifm, 49155 on the BACnet LINK) and has to be
looked up per device via the DCE/RPC Endpoint Mapper first - the response
carries it at a `00 08 02 00` marker followed by a big-endian uint16.

Getting that Endpoint Mapper lookup right against the ifm AL1304 took three
corrections over a single-shot first attempt, found by diffing our own
capture against a live TIA Portal "Online & Diagnostics" read of the same
device:

  1. The Endpoint Mapper interface (E1AF8308-...) must be queried at
     interface version 3, not 1. Asking for version 1 gets an explicit
     DCE/RPC REJECT with status 0x1c010003 (nca_s_unk_if, "unknown
     interface") - it looks like the device flatly refuses I&M0, but it's
     really just refusing that interface *version*.
  2. This device's Endpoint Mapper is a paginated ept_lookup: each call
     returns exactly one registered interface, and the next call must echo
     back the 20-byte continuation handle from the previous response
     (verbatim, at a fixed offset) to advance to the next one. Naively
     resending the same "give me interface X" query repeatedly just
     re-returns entry #1 (the Endpoint Mapper's own self-registration)
     forever - advancing requires that handle *and* reusing the same
     activity UUID for every call in the sequence (a fresh UUID per call, as
     DCE/RPC datagram calls normally get, makes the server treat each call
     as an unrelated session and reset pagination back to entry #1).
  3. The actual Read call's "object" header field - normally zero for a
     stateless call not tied to any established Application Relationship -
     must instead be the device-specific object UUID that came back in the
     matching Endpoint Mapper entry (at a fixed offset relative to that
     entry's start). Leaving it zero still gets a normal-looking RESPONSE
     PDU back, not a REJECT, but with no I&M0 data in it - a silent failure
     that looks like success at the transport level.

Verified end-to-end (request format, paginated port/object lookup, and
response parsing) for ifm and Siemens. A third data point, a Festo
CPX-Terminal, matches the protocol exactly through the port lookup step but
then has its actual Read calls rejected - not silently ignored, an explicit
DCE/RPC REJECT PDU with status nca_server_too_busy, and consistently so
(every ~8s over a 5-minute capture, not a one-off collision). That looks
like a genuine capacity limit on that specific device rather than a format
mismatch, but it's unconfirmed without live access to retry against it -
_raise_if_rejected() at least surfaces this distinctly instead of it looking
like a parse failure.

Every failure mode raises PnioImError or a plain OSError (socket timeout/
refusal), so a caller can treat both as "no data available" and move on.
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

# The Endpoint Mapper interface itself is queried at version 3 (not the PNIO
# device interface's version 1) - see module docstring point 1.
_EPM_INTERFACE_VERSION = 3
_PNIO_INTERFACE_VERSION = 1

# One ept_lookup round per registered interface on this device (see module
# docstring point 2); capped so a device that never signals "done" can't
# hang a scan indefinitely.
_MAX_EPT_LOOKUP_ROUNDS = 16

# Marks the start of the UDP-port protocol floor in an ept_map response's
# "towers" data; the port itself is the big-endian uint16 right after it.
_PORT_FLOOR_MARKER = bytes.fromhex("00080200")

_PTYPE_REJECT = 6

# DCE 1.1 RPC reject status codes (little-endian uint32 body) worth naming;
# see The Open Group's "Reject Status Codes and Parameters". Encountered
# nca_server_too_busy consistently (every ~8s over a 5-minute capture, not a
# one-off) from a real Festo CPX-Terminal - the request format matches what
# works against ifm/Siemens devices, so this looks like a genuine capacity
# limit on that device's RPC handling rather than a compatibility problem.
# Also encountered nca_unk_if for real, from a real ifm AL1304 - not because
# the device rejects I&M0, but because the request asked for the Endpoint
# Mapper interface at the wrong version (see module docstring point 1).
_NCA_STATUS_NAMES = {
    0x1C010001: "nca_comm_failure",
    0x1C010002: "nca_op_rng_error (unsupported operation)",
    0x1C010003: "nca_unk_if (unknown interface, or unsupported interface version)",
    0x1C010006: "nca_wrong_boot_time",
    0x1C010014: "nca_server_too_busy",
}


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


def _dcerpc_dg_header(
    if_id: uuid.UUID,
    opnum: int,
    seqnum: int,
    body_len: int,
    act_id: uuid.UUID,
    if_vers: int = _PNIO_INTERFACE_VERSION,
    object_uuid: bytes = b"\x00" * 16,
) -> bytes:
    """Build an 80-byte DCE/RPC connectionless (datagram) PDU header.

    act_id must be the same UUID across every call in one Endpoint
    Mapper/Read conversation - see module docstring point 2.
    """
    return (
        struct.pack("!BBBB", 4, 0, 0x20, 0x00)  # rpc_vers, ptype=REQUEST, flags1, flags2
        + struct.pack("!BBBB", 0x10, 0, 0, 0)  # drep (little-endian), serial_hi
        + object_uuid
        + if_id.bytes_le
        + act_id.bytes_le
        + struct.pack("<IIIHHHHH", 0, if_vers, seqnum, opnum, 0xFFFF, 0xFFFF, body_len, 0)
        + struct.pack("!BB", 0, 0)  # auth_proto, serial_lo
    )


# Fixed part of an ept_lookup request body (object filter + tower search
# criteria, both wildcarded - i.e. "enumerate everything, I'll filter
# client-side"), captured verbatim from a real TIA Portal Endpoint Mapper
# query. The trailing 20 bytes are the continuation handle, which varies
# per round - see _EPT_LOOKUP_INITIAL_HANDLE and _find_read_target().
_EPT_LOOKUP_PREFIX = bytes.fromhex(
    "0000000001000000000000000000000000000000000000000200000000000000000000000000000000000000000000000100000000000000"
)
_EPT_LOOKUP_INITIAL_HANDLE = bytes.fromhex("0000000000000000000000000000000001000000")

# Captured verbatim from a real TIA Portal I&M0 read; identical across every
# device queried, so treated as a fixed template rather than reconstructed
# field-by-field.
_READ_IM0_BODY = bytes.fromhex(
    "8400000040000000840000000000000040000000000900"
    "3c010000010000000000000000000000000000000000000000000000010000aff000000044000000000000000000000000000000000000000000000000"
)


def _build_ept_map_request(seqnum: int, act_id: uuid.UUID, handle: bytes) -> bytes:
    body = _EPT_LOOKUP_PREFIX + handle
    return _dcerpc_dg_header(
        ENDPOINT_MAPPER_INTERFACE_UUID, _OPNUM_EPT_MAP, seqnum, len(body), act_id, if_vers=_EPM_INTERFACE_VERSION
    ) + body


def _build_read_im0_request(seqnum: int, act_id: uuid.UUID, object_uuid: bytes) -> bytes:
    return _dcerpc_dg_header(
        PNIO_DEVICE_INTERFACE_UUID, _OPNUM_READ, seqnum, len(_READ_IM0_BODY), act_id, object_uuid=object_uuid
    ) + _READ_IM0_BODY


def _find_read_port(epm_response_body: bytes) -> int:
    idx = epm_response_body.find(_PORT_FLOOR_MARKER)
    if idx == -1:
        raise PnioImError("port floor not found in Endpoint Mapper response")
    port_offset = idx + len(_PORT_FLOOR_MARKER)
    port, = struct.unpack_from("!H", epm_response_body, port_offset)
    return port


def _raise_if_rejected(payload: bytes) -> None:
    if payload[1] != _PTYPE_REJECT:
        return
    status = struct.unpack_from("<I", payload, 80)[0] if len(payload) >= 84 else None
    name = _NCA_STATUS_NAMES.get(status, f"0x{status:08x}" if status is not None else "unknown")
    raise PnioImError(f"device rejected the RPC call ({name})")


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


def _find_read_target(ip: IPv4Address, act_id: uuid.UUID, sock: socket.socket) -> tuple[int, bytes]:
    """Enumerate this device's registered PN-IO interfaces via a paginated
    Endpoint Mapper lookup (module docstring point 2) and return the
    (port, object_uuid) needed for the actual Read call (point 3).

    act_id must be the same activity UUID the caller will reuse for the
    subsequent Read call - the device ties both the lookup pagination and
    the object UUID to that one conversation.
    """
    handle = _EPT_LOOKUP_INITIAL_HANDLE
    for round_num in range(_MAX_EPT_LOOKUP_ROUNDS):
        sock.sendto(_build_ept_map_request(round_num, act_id, handle), (str(ip), EPM_PORT))
        payload, _ = sock.recvfrom(4096)
        if len(payload) < 80:
            raise PnioImError("Endpoint Mapper response shorter than a DCE/RPC header")
        _raise_if_rejected(payload)
        body = payload[80:]

        # status(4) + continuation handle(20) + num_ents(4) is the shortest a
        # response with an entry can be; anything shorter means the
        # enumeration ran out before finding our target interface.
        if len(body) < 52:
            break
        num_ents, = struct.unpack_from("<I", body, 24)
        if num_ents == 0:
            break

        if PNIO_DEVICE_INTERFACE_UUID.bytes_le in body:
            # This device returns one entry per round, its object UUID
            # always at this fixed offset - see module docstring point 3.
            return _find_read_port(body), body[36:52]

        handle = body[4:24]

    raise PnioImError("PN-IO device interface not found via Endpoint Mapper enumeration")


def read_im0(ip: IPv4Address, timeout: float = 2.0) -> Im0Record:
    """Read the device's I&M0 record over PN-IO RPC. Raises PnioImError/OSError on failure."""
    act_id = uuid.uuid4()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        port, object_uuid = _find_read_target(ip, act_id, sock)
        sock.sendto(_build_read_im0_request(seqnum=1, act_id=act_id, object_uuid=object_uuid), (str(ip), port))
        payload, _ = sock.recvfrom(4096)
    if len(payload) < 80:
        raise PnioImError("response shorter than a DCE/RPC header")
    _raise_if_rejected(payload)
    return _parse_im0(payload[80:])
