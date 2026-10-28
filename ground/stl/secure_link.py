"""Secure link layer, ground side: seal on transmit, validate on receive.

Mirrors flight/src/secure_link.cpp. The validation order in `open` is the
security argument and is specified in docs/PROTOCOL.md section 5.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field

from . import protocol as p
from .counter_store import CounterStore
from .replay import ReplayVerdict, ReplayWindow

DEFAULT_FRESHNESS_WINDOW_US = 30 * 1_000_000


def now_us() -> int:
    """Wall-clock microseconds. The mission epoch here is the Unix epoch."""
    return time.time_ns() // 1000


def mac_tag(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 truncated to the leftmost 16 bytes."""
    return hmac.new(key, data, hashlib.sha256).digest()[: p.MAC_TAG_SIZE]


@dataclass
class LinkStats:
    accepted: int = 0
    malformed: int = 0
    auth_failures: int = 0
    replay_rejects: int = 0
    stale_rejects: int = 0
    unknown_apid: int = 0
    bad_payload: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "accepted": self.accepted,
            "malformed": self.malformed,
            "auth_failures": self.auth_failures,
            "replay_rejects": self.replay_rejects,
            "stale_rejects": self.stale_rejects,
            "unknown_apid": self.unknown_apid,
            "bad_payload": self.bad_payload,
        }


@dataclass
class ReceivedFrame:
    header: p.PacketHeader
    payload: bytes


class SecureLink:
    """One end of an STL-1 link.

    `tx_key` authenticates what this end sends, `rx_key` what it receives. The
    two ends of a link construct these in opposite order.
    """

    def __init__(
        self,
        tx_key: bytes,
        rx_key: bytes,
        tx_type: p.PacketType,
        freshness_enabled: bool = True,
        freshness_window_us: int = DEFAULT_FRESHNESS_WINDOW_US,
        counter_store: CounterStore | None = None,
    ) -> None:
        if len(tx_key) != p.KEY_SIZE or len(rx_key) != p.KEY_SIZE:
            raise ValueError(f"keys must be {p.KEY_SIZE} bytes")

        self._tx_key = tx_key
        self._rx_key = rx_key
        self._tx_type = tx_type
        self._expected_rx_type = (
            p.PacketType.TELECOMMAND
            if tx_type == p.PacketType.TELEMETRY
            else p.PacketType.TELEMETRY
        )

        # Without a counter store the transmit counter starts at zero on every
        # run, which a receiver that did not also restart correctly rejects as
        # a replay. See counter_store.py.
        self._counter_store = counter_store
        self._tx_counter = counter_store.peek if counter_store else 0
        self._seq_counts: dict[int, int] = {}
        self._replay = ReplayWindow()
        self._freshness_enabled = freshness_enabled
        self._freshness_window_us = freshness_window_us
        self.stats = LinkStats()

    # -- transmit ----------------------------------------------------------

    @property
    def tx_frame_counter(self) -> int:
        return self._tx_counter

    @property
    def replay_window(self) -> ReplayWindow:
        return self._replay

    def _next_sequence(self, apid: int) -> int:
        value = self._seq_counts.get(apid, 0)
        self._seq_counts[apid] = (value + 1) & 0x3FFF
        return value

    def seal(self, apid: int, payload: bytes, met_us: int | None = None) -> bytes:
        """Build an authenticated frame."""
        if len(payload) > p.MAX_USER_DATA:
            raise ValueError(
                f"payload of {len(payload)} bytes exceeds {p.MAX_USER_DATA}"
            )
        if met_us is None:
            met_us = now_us()

        data_field_len = p.SECONDARY_HEADER_SIZE + len(payload) + p.MAC_TAG_SIZE
        primary = p.pack_primary_header(
            self._tx_type, apid, self._next_sequence(apid), data_field_len
        )
        if self._counter_store is not None:
            counter = self._counter_store.next()
            self._tx_counter = counter + 1
        else:
            counter = self._tx_counter
            self._tx_counter += 1

        secondary = p.pack_secondary_header(met_us, counter)

        body = primary + secondary + payload
        return body + mac_tag(self._tx_key, body)

    # -- receive -----------------------------------------------------------

    def open(
        self, data: bytes, now: int | None = None
    ) -> tuple[p.ParseResult, ReceivedFrame | None]:
        """Validate a received datagram.

        Returns (ParseResult.OK, frame) on success, or (reason, None).
        """
        if now is None:
            now = now_us()

        # Step 1: bounds.
        if len(data) < p.MIN_FRAME_SIZE:
            self.stats.malformed += 1
            return p.ParseResult.TOO_SHORT, None
        if len(data) > p.MAX_FRAME_SIZE:
            self.stats.malformed += 1
            return p.ParseResult.TOO_LONG, None

        # Step 2: primary header.
        word0, word1, declared_minus_one = struct.unpack(">HHH", data[:6])

        version = (word0 >> 13) & 0x07
        type_bit = (word0 >> 12) & 0x01
        sec_hdr_flag = (word0 >> 11) & 0x01
        apid = word0 & 0x7FF

        if version != p.CCSDS_VERSION:
            self.stats.malformed += 1
            return p.ParseResult.BAD_VERSION, None
        if sec_hdr_flag != 1:
            self.stats.malformed += 1
            return p.ParseResult.NO_SECONDARY_HEADER, None

        seq_flags = (word1 >> 14) & 0x03
        seq_count = word1 & 0x3FFF
        if seq_flags != p.SEQ_FLAGS_UNSEGMENTED:
            self.stats.malformed += 1
            return p.ParseResult.SEGMENTED, None

        packet_type = p.PacketType(type_bit)
        if packet_type != self._expected_rx_type:
            self.stats.malformed += 1
            return p.ParseResult.WRONG_DIRECTION, None

        # Step 3: the declared length must describe this datagram exactly.
        declared = declared_minus_one + 1
        if (p.PRIMARY_HEADER_SIZE + declared) != len(data):
            self.stats.malformed += 1
            return p.ParseResult.LENGTH_MISMATCH, None

        # Step 4: minimum data field.
        if declared < p.MIN_DATA_FIELD:
            self.stats.malformed += 1
            return p.ParseResult.DATA_FIELD_TOO_SMALL, None

        # Step 5: authenticate before interpreting anything variable-length.
        mac_offset = len(data) - p.MAC_TAG_SIZE
        expected = mac_tag(self._rx_key, data[:mac_offset])
        # compare_digest, not ==. CPython's bytes comparison short-circuits on
        # the first differing byte, which leaks how much of a forged tag was
        # correct through timing.
        if not hmac.compare_digest(expected, data[mac_offset:]):
            self.stats.auth_failures += 1
            return p.ParseResult.AUTH_FAILURE, None

        met_us, frame_counter = struct.unpack(">QI", data[6:18])

        # Step 6: freshness (stateless) before replay (stateful), so a frame
        # that fails freshness never advances the replay window.
        if self._freshness_enabled and abs(met_us - now) > self._freshness_window_us:
            self.stats.stale_rejects += 1
            return p.ParseResult.STALE_TIMESTAMP, None

        # Step 7: replay.
        verdict = self._replay.check_and_update(frame_counter)
        if verdict is ReplayVerdict.DUPLICATE:
            self.stats.replay_rejects += 1
            return p.ParseResult.REPLAY_DUPLICATE, None
        if verdict is ReplayVerdict.TOO_OLD:
            self.stats.replay_rejects += 1
            return p.ParseResult.REPLAY_TOO_OLD, None

        # Step 8: APID.
        if apid not in p.KNOWN_APIDS:
            self.stats.unknown_apid += 1
            return p.ParseResult.UNKNOWN_APID, None

        header = p.PacketHeader(
            packet_type=packet_type,
            apid=apid,
            sequence_count=seq_count,
            data_length=declared,
            met_us=met_us,
            frame_counter=frame_counter,
        )
        self.stats.accepted += 1
        return p.ParseResult.OK, ReceivedFrame(
            header=header, payload=data[p.HEADER_SIZE : mac_offset]
        )
