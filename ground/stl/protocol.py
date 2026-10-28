"""STL-1 wire protocol, ground-side implementation.

This is an independent implementation of docs/PROTOCOL.md, deliberately not a
port of the C++ code. Two implementations written from the same spec catch
ambiguities in the spec that a single implementation would silently paper over;
tools/vectors.cpp plus ground/tests/test_vectors.py prove the two agree
byte-for-byte.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

# --- sizes -----------------------------------------------------------------

PRIMARY_HEADER_SIZE = 6
SECONDARY_HEADER_SIZE = 12
HEADER_SIZE = PRIMARY_HEADER_SIZE + SECONDARY_HEADER_SIZE  # 18
MAC_TAG_SIZE = 16

MAX_USER_DATA = 1024
MIN_FRAME_SIZE = HEADER_SIZE + MAC_TAG_SIZE  # 34
MAX_FRAME_SIZE = HEADER_SIZE + MAX_USER_DATA + MAC_TAG_SIZE  # 1058
MIN_DATA_FIELD = SECONDARY_HEADER_SIZE + MAC_TAG_SIZE  # 28

KEY_SIZE = 32

CCSDS_VERSION = 0
SEQ_FLAGS_UNSEGMENTED = 3


class PacketType(IntEnum):
    TELEMETRY = 0
    TELECOMMAND = 1


class Apid(IntEnum):
    TM_HOUSEKEEPING = 0x001
    TM_ATTITUDE = 0x002
    TM_COMMAND_ACK = 0x003
    TM_EVENT = 0x004
    TC_COMMAND = 0x010


KNOWN_APIDS = frozenset(int(a) for a in Apid)


class Command(IntEnum):
    NOOP = 0x0001
    PING = 0x0002
    SET_MODE = 0x0003
    SET_TM_RATE = 0x0004
    SET_HEATER = 0x0005
    SAFE_MODE = 0x0006


class Mode(IntEnum):
    BOOT = 0
    IDLE = 1
    NOMINAL = 2
    SAFE = 3


class AckStatus(IntEnum):
    ACCEPTED = 0
    REJECTED_UNKNOWN_COMMAND = 1
    REJECTED_BAD_ARGUMENT = 2
    REJECTED_INVALID_IN_MODE = 3


MAX_COMMAND_ARG_LEN = 64
MIN_TM_RATE_HZ = 1
MAX_TM_RATE_HZ = 50

HOUSEKEEPING_PAYLOAD_SIZE = 24
ATTITUDE_PAYLOAD_SIZE = 36
COMMAND_ACK_PAYLOAD_SIZE = 8
EVENT_HEADER_SIZE = 2
MAX_EVENT_MESSAGE = 70
COMMAND_HEADER_SIZE = 4


class ParseResult(IntEnum):
    OK = 0
    TOO_SHORT = 1
    TOO_LONG = 2
    BAD_VERSION = 3
    NO_SECONDARY_HEADER = 4
    SEGMENTED = 5
    WRONG_DIRECTION = 6
    LENGTH_MISMATCH = 7
    DATA_FIELD_TOO_SMALL = 8
    AUTH_FAILURE = 9
    REPLAY_DUPLICATE = 10
    REPLAY_TOO_OLD = 11
    STALE_TIMESTAMP = 12
    UNKNOWN_APID = 13
    BAD_PAYLOAD_LENGTH = 14


# --- header ----------------------------------------------------------------


@dataclass(frozen=True)
class PacketHeader:
    packet_type: PacketType
    apid: int
    sequence_count: int
    data_length: int  # true octet count of the packet data field
    met_us: int
    frame_counter: int


def pack_primary_header(
    packet_type: PacketType, apid: int, sequence_count: int, data_field_len: int
) -> bytes:
    """Build the 6-byte CCSDS primary header."""
    if not (0 <= apid <= 0x7FF):
        raise ValueError(f"APID {apid} does not fit in 11 bits")
    if not (0 <= sequence_count <= 0x3FFF):
        raise ValueError("sequence count does not fit in 14 bits")
    if not (MIN_DATA_FIELD <= data_field_len <= (MAX_USER_DATA + MIN_DATA_FIELD)):
        raise ValueError(f"data field length {data_field_len} out of range")

    word0 = apid & 0x7FF
    word0 |= 1 << 11  # secondary header always present
    if packet_type == PacketType.TELECOMMAND:
        word0 |= 1 << 12
    # version bits 15..13 remain zero

    word1 = (SEQ_FLAGS_UNSEGMENTED << 14) | (sequence_count & 0x3FFF)

    # CCSDS length field is octets-minus-one.
    return struct.pack(">HHH", word0, word1, data_field_len - 1)


def pack_secondary_header(met_us: int, frame_counter: int) -> bytes:
    return struct.pack(">QI", met_us & 0xFFFFFFFFFFFFFFFF, frame_counter & 0xFFFFFFFF)


# --- payload codecs --------------------------------------------------------
#
# Each decoder checks the length against the exact expected size before
# unpacking. struct.unpack would raise on a short buffer, but it would happily
# accept a long one; an explicit equality check rejects trailing bytes that one
# implementation ignores and another might parse.


@dataclass(frozen=True)
class Housekeeping:
    mode: int
    heater_on: int
    telemetry_rate_hz: int
    bus_voltage_mv: int
    bus_current_ma: int
    battery_temp_mc: int
    payload_temp_mc: int
    uptime_s: int

    @property
    def bus_voltage_v(self) -> float:
        return self.bus_voltage_mv / 1000.0

    @property
    def bus_current_a(self) -> float:
        return self.bus_current_ma / 1000.0

    @property
    def battery_temp_c(self) -> float:
        return self.battery_temp_mc / 1000.0

    @property
    def payload_temp_c(self) -> float:
        return self.payload_temp_mc / 1000.0


_HK_STRUCT = struct.Struct(">BBHiiiiI")


def encode_housekeeping(hk: Housekeeping) -> bytes:
    return _HK_STRUCT.pack(
        hk.mode,
        hk.heater_on,
        hk.telemetry_rate_hz,
        hk.bus_voltage_mv,
        hk.bus_current_ma,
        hk.battery_temp_mc,
        hk.payload_temp_mc,
        hk.uptime_s,
    )


def decode_housekeeping(data: bytes) -> Housekeeping:
    if len(data) != HOUSEKEEPING_PAYLOAD_SIZE:
        raise ValueError(
            f"housekeeping payload must be {HOUSEKEEPING_PAYLOAD_SIZE} bytes, got {len(data)}"
        )
    return Housekeeping(*_HK_STRUCT.unpack(data))


@dataclass(frozen=True)
class Attitude:
    gyro: tuple[int, int, int]  # microrad/s
    accel: tuple[int, int, int]  # micro-g
    mag: tuple[int, int, int]  # nT


_ATT_STRUCT = struct.Struct(">9i")


def encode_attitude(att: Attitude) -> bytes:
    return _ATT_STRUCT.pack(*att.gyro, *att.accel, *att.mag)


def decode_attitude(data: bytes) -> Attitude:
    if len(data) != ATTITUDE_PAYLOAD_SIZE:
        raise ValueError(
            f"attitude payload must be {ATTITUDE_PAYLOAD_SIZE} bytes, got {len(data)}"
        )
    v = _ATT_STRUCT.unpack(data)
    return Attitude(gyro=v[0:3], accel=v[3:6], mag=v[6:9])


@dataclass(frozen=True)
class CommandAck:
    command_id: int
    frame_counter: int
    status: int

    @property
    def status_name(self) -> str:
        try:
            return AckStatus(self.status).name
        except ValueError:
            return f"UNKNOWN({self.status})"


_ACK_STRUCT = struct.Struct(">HIBB")


def encode_command_ack(ack: CommandAck) -> bytes:
    return _ACK_STRUCT.pack(ack.command_id, ack.frame_counter, ack.status, 0)


def decode_command_ack(data: bytes) -> CommandAck:
    if len(data) != COMMAND_ACK_PAYLOAD_SIZE:
        raise ValueError(
            f"ack payload must be {COMMAND_ACK_PAYLOAD_SIZE} bytes, got {len(data)}"
        )
    command_id, frame_counter, status, _reserved = _ACK_STRUCT.unpack(data)
    return CommandAck(command_id=command_id, frame_counter=frame_counter, status=status)


@dataclass(frozen=True)
class Event:
    severity: int
    message: str

    SEVERITY_NAMES = ("INFO", "WARNING", "ERROR", "CRITICAL")

    @property
    def severity_name(self) -> str:
        if 0 <= self.severity < len(self.SEVERITY_NAMES):
            return self.SEVERITY_NAMES[self.severity]
        return f"UNKNOWN({self.severity})"


def encode_event(ev: Event) -> bytes:
    raw = ev.message.encode("ascii", errors="replace")[:MAX_EVENT_MESSAGE]
    return bytes([ev.severity, len(raw)]) + raw


def decode_event(data: bytes) -> Event:
    if len(data) < EVENT_HEADER_SIZE:
        raise ValueError("event payload too short")
    severity = data[0]
    msg_len = data[1]
    if msg_len > MAX_EVENT_MESSAGE:
        raise ValueError(f"event message length {msg_len} exceeds maximum")
    if len(data) != EVENT_HEADER_SIZE + msg_len:
        raise ValueError("event payload length does not match declared message length")
    # Decoded with errors='replace' and never passed anywhere that interprets
    # control characters. Vehicle-sourced text is still untrusted input.
    return Event(
        severity=severity,
        message=data[EVENT_HEADER_SIZE:].decode("ascii", errors="replace"),
    )


@dataclass(frozen=True)
class CommandPacket:
    command_id: int
    args: bytes = b""

    def __post_init__(self) -> None:
        if len(self.args) > MAX_COMMAND_ARG_LEN:
            raise ValueError(
                f"command arguments exceed {MAX_COMMAND_ARG_LEN} bytes"
            )


def encode_command(cmd: CommandPacket) -> bytes:
    return struct.pack(">HH", cmd.command_id, len(cmd.args)) + cmd.args


def decode_command(data: bytes) -> CommandPacket:
    if len(data) < COMMAND_HEADER_SIZE:
        raise ValueError("command payload too short")
    command_id, arg_len = struct.unpack(">HH", data[:COMMAND_HEADER_SIZE])
    if arg_len > MAX_COMMAND_ARG_LEN:
        raise ValueError(f"declared argument length {arg_len} exceeds maximum")
    if len(data) != COMMAND_HEADER_SIZE + arg_len:
        raise ValueError("command payload length does not match declared argument length")
    return CommandPacket(command_id=command_id, args=data[COMMAND_HEADER_SIZE:])
