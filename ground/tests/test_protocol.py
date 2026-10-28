"""Ground-side unit tests for the protocol, replay window, and counter store."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ground"))

from stl import PacketType, ParseResult, SecureLink  # noqa: E402
from stl import protocol as p  # noqa: E402
from stl.counter_store import BLOCK_SIZE, CounterStore  # noqa: E402
from stl.replay import ReplayVerdict, ReplayWindow, WINDOW_SIZE  # noqa: E402

K_TM = bytes(range(0x11, 0x11 + 32))
K_TC = bytes((0x42 + i * 7) & 0xFF for i in range(32))


def tm_sender() -> SecureLink:
    return SecureLink(K_TM, K_TC, PacketType.TELEMETRY, freshness_enabled=False)


def tm_receiver() -> SecureLink:
    return SecureLink(K_TC, K_TM, PacketType.TELECOMMAND, freshness_enabled=False)


# --- replay window ---------------------------------------------------------


class TestReplayWindow:
    def test_sequential_accepts_once(self) -> None:
        w = ReplayWindow()
        for i in range(100):
            assert w.check_and_update(i) is ReplayVerdict.ACCEPT
            assert w.check_and_update(i) is not ReplayVerdict.ACCEPT

    def test_reordering_within_window(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(10) is ReplayVerdict.ACCEPT
        assert w.check_and_update(13) is ReplayVerdict.ACCEPT
        assert w.check_and_update(11) is ReplayVerdict.ACCEPT
        assert w.check_and_update(12) is ReplayVerdict.ACCEPT
        assert w.check_and_update(11) is ReplayVerdict.DUPLICATE
        assert w.highest == 13

    def test_window_edge(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(100) is ReplayVerdict.ACCEPT
        assert w.check_and_update(100 + WINDOW_SIZE - 1) is ReplayVerdict.ACCEPT
        assert w.check_and_update(100) is ReplayVerdict.DUPLICATE
        assert w.check_and_update(100 + WINDOW_SIZE) is ReplayVerdict.ACCEPT
        assert w.check_and_update(100) is ReplayVerdict.TOO_OLD

    def test_large_jump_clears_stale_bits(self) -> None:
        """A jump past the window must not leave bits that reject fresh counters."""
        w = ReplayWindow()
        assert w.check_and_update(5) is ReplayVerdict.ACCEPT
        assert w.check_and_update(5000) is ReplayVerdict.ACCEPT
        assert w.check_and_update(4999) is ReplayVerdict.ACCEPT
        assert w.check_and_update(4999) is ReplayVerdict.DUPLICATE
        assert w.check_and_update(5) is ReplayVerdict.TOO_OLD

    def test_bitmap_never_exceeds_window_width(self) -> None:
        """Python ints are unbounded; the shift must be masked explicitly."""
        w = ReplayWindow()
        for i in range(0, 100_000, 7):
            w.check_and_update(i)
        assert w._bitmap < (1 << WINDOW_SIZE)  # noqa: SLF001

    def test_near_uint32_max(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0xFFFFFFF0) is ReplayVerdict.ACCEPT
        assert w.check_and_update(0xFFFFFFFF) is ReplayVerdict.ACCEPT
        assert w.check_and_update(0xFFFFFFF0) is ReplayVerdict.DUPLICATE

    def test_out_of_range_counter_raises(self) -> None:
        w = ReplayWindow()
        with pytest.raises(ValueError):
            w.check_and_update(0x1_0000_0000)
        with pytest.raises(ValueError):
            w.check_and_update(-1)


# --- framing ---------------------------------------------------------------


class TestFraming:
    def test_round_trip(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        hk = p.Housekeeping(2, 1, 4, 27850, 1432, -4250, 12750, 86399)
        frame = tx.seal(p.Apid.TM_HOUSEKEEPING, p.encode_housekeeping(hk))

        result, received = rx.open(frame)
        assert result is ParseResult.OK
        assert received is not None
        assert p.decode_housekeeping(received.payload) == hk

    def test_frame_size_bounds(self) -> None:
        tx = tm_sender()
        assert len(tx.seal(p.Apid.TM_EVENT, b"")) == p.MIN_FRAME_SIZE
        assert len(tx.seal(p.Apid.TM_EVENT, b"\x00" * p.MAX_USER_DATA)) == p.MAX_FRAME_SIZE

    def test_oversized_payload_rejected(self) -> None:
        tx = tm_sender()
        with pytest.raises(ValueError):
            tx.seal(p.Apid.TM_EVENT, b"\x00" * (p.MAX_USER_DATA + 1))

    def test_truncation_rejected_at_every_length(self) -> None:
        tx = tm_sender()
        frame = tx.seal(p.Apid.TM_EVENT, b"hello")
        for length in range(len(frame)):
            rx = tm_receiver()
            result, received = rx.open(frame[:length])
            assert result is not ParseResult.OK, f"truncation to {length} accepted"
            assert received is None

    def test_trailing_bytes_rejected(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        frame = tx.seal(p.Apid.TM_EVENT, b"hello")
        result, _ = rx.open(frame + b"\x00")
        assert result is ParseResult.LENGTH_MISMATCH

    def test_wrong_direction_rejected(self) -> None:
        tx = tm_sender()
        frame = tx.seal(p.Apid.TM_EVENT, b"x")
        # A telemetry receiver handed a telemetry frame.
        wrong = SecureLink(K_TM, K_TC, PacketType.TELEMETRY, freshness_enabled=False)
        result, _ = wrong.open(frame)
        assert result is ParseResult.WRONG_DIRECTION

    def test_wrong_key_rejected(self) -> None:
        tx = tm_sender()
        frame = tx.seal(p.Apid.TM_EVENT, b"x")
        other = SecureLink(K_TC, bytes([0xAA] * 32), PacketType.TELECOMMAND,
                           freshness_enabled=False)
        result, _ = other.open(frame)
        assert result is ParseResult.AUTH_FAILURE

    def test_bad_version_rejected(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        frame = bytearray(tx.seal(p.Apid.TM_EVENT, b"x"))
        frame[0] |= 0x20  # set a version bit
        result, _ = rx.open(bytes(frame))
        assert result is ParseResult.BAD_VERSION

    def test_segmented_rejected(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        frame = bytearray(tx.seal(p.Apid.TM_EVENT, b"x"))
        frame[2] &= 0x3F  # clear the sequence flags
        result, _ = rx.open(bytes(frame))
        assert result is ParseResult.SEGMENTED

    def test_unknown_apid_counted_separately(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        frame = tx.seal(0x123, b"\x00\x00")
        result, _ = rx.open(frame)
        assert result is ParseResult.UNKNOWN_APID
        assert rx.stats.auth_failures == 0
        assert rx.stats.unknown_apid == 1

    def test_replay_rejected(self) -> None:
        tx, rx = tm_sender(), tm_receiver()
        first = tx.seal(p.Apid.TM_EVENT, b"a")
        second = tx.seal(p.Apid.TM_EVENT, b"b")
        assert rx.open(first)[0] is ParseResult.OK
        assert rx.open(second)[0] is ParseResult.OK
        assert rx.open(first)[0] is ParseResult.REPLAY_DUPLICATE
        assert rx.stats.replay_rejects == 1

    def test_stale_rejected_without_touching_replay_window(self) -> None:
        tx = tm_sender()
        rx = SecureLink(K_TC, K_TM, PacketType.TELECOMMAND, freshness_enabled=True)
        now = 2_000_000_000
        stale = tx.seal(p.Apid.TM_EVENT, b"x", met_us=now - 60_000_000)
        result, _ = rx.open(stale, now=now)
        assert result is ParseResult.STALE_TIMESTAMP
        assert not rx.replay_window.started

    def test_key_length_validated(self) -> None:
        with pytest.raises(ValueError):
            SecureLink(b"short", K_TC, PacketType.TELEMETRY)


# --- payload codecs --------------------------------------------------------


class TestPayloadCodecs:
    def test_decoders_reject_wrong_length(self) -> None:
        for length in range(0, 64):
            if length != p.HOUSEKEEPING_PAYLOAD_SIZE:
                with pytest.raises(ValueError):
                    p.decode_housekeeping(b"\x00" * length)
            if length != p.ATTITUDE_PAYLOAD_SIZE:
                with pytest.raises(ValueError):
                    p.decode_attitude(b"\x00" * length)
            if length != p.COMMAND_ACK_PAYLOAD_SIZE:
                with pytest.raises(ValueError):
                    p.decode_command_ack(b"\x00" * length)

    def test_signed_extremes_round_trip(self) -> None:
        att = p.Attitude(
            gyro=(-2147483648, 0, 2147483647),
            accel=(2147483647, -1, -2147483648),
            mag=(0, 1, -1),
        )
        assert p.decode_attitude(p.encode_attitude(att)) == att

    def test_event_length_must_match(self) -> None:
        assert p.decode_event(b"\x00\x03abc").message == "abc"
        with pytest.raises(ValueError):
            p.decode_event(b"\x00\x05abc")  # declares 5, carries 3
        with pytest.raises(ValueError):
            p.decode_event(b"\x00\x02abc")  # declares 2, carries 3
        with pytest.raises(ValueError):
            p.decode_event(bytes([0, 200]) + b"x" * 200)  # over the maximum

    def test_command_length_must_match(self) -> None:
        good = p.encode_command(p.CommandPacket(p.Command.SET_MODE, b"\x02"))
        assert p.decode_command(good).args == b"\x02"
        with pytest.raises(ValueError):
            p.decode_command(b"\x00\x03\x00\x64")  # declares 100 args, carries 0
        with pytest.raises(ValueError):
            p.decode_command(b"\x00\x03\x00\x01\x02\x03")  # declares 1, carries 2

    def test_command_args_bounded_at_construction(self) -> None:
        with pytest.raises(ValueError):
            p.CommandPacket(p.Command.SET_MODE, b"\x00" * (p.MAX_COMMAND_ARG_LEN + 1))

    def test_header_field_bounds(self) -> None:
        with pytest.raises(ValueError):
            p.pack_primary_header(PacketType.TELEMETRY, 0x800, 0, 28)  # 12-bit APID
        with pytest.raises(ValueError):
            p.pack_primary_header(PacketType.TELEMETRY, 1, 0x4000, 28)  # 15-bit seq


# --- counter store ---------------------------------------------------------


class TestCounterStore:
    def test_counters_are_monotonic_across_restarts(self, tmp_path: Path) -> None:
        path = tmp_path / "tx.ctr"

        store = CounterStore(path)
        used = [store.next() for _ in range(10)]
        assert used == list(range(10))

        # Simulate a restart: the new run must start above everything the
        # previous one could have transmitted.
        restarted = CounterStore(path)
        assert restarted.next() == BLOCK_SIZE

    def test_block_boundary(self, tmp_path: Path) -> None:
        store = CounterStore(tmp_path / "tx.ctr")
        values = [store.next() for _ in range(BLOCK_SIZE + 5)]
        assert values == list(range(BLOCK_SIZE + 5))
        assert len(set(values)) == len(values)

    def test_corrupt_state_file_does_not_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "tx.ctr"
        path.write_bytes(b"\x01\x02")  # truncated
        store = CounterStore(path)
        assert store.next() == 0

    def test_persisted_before_use(self, tmp_path: Path) -> None:
        """The reservation must be on disk before any counter is handed out."""
        path = tmp_path / "tx.ctr"
        store = CounterStore(path)
        assert path.exists()
        import struct

        assert struct.unpack(">I", path.read_bytes())[0] == BLOCK_SIZE
        store.next()


# --- the property the whole design rests on --------------------------------


def test_no_modification_survives_authentication() -> None:
    """Every single-bit flip in a frame must be rejected."""
    tx = tm_sender()
    frame = tx.seal(p.Apid.TM_HOUSEKEEPING, p.encode_housekeeping(
        p.Housekeeping(2, 1, 4, 27850, 1432, -4250, 12750, 100)
    ))

    for index in range(len(frame)):
        for bit in range(8):
            corrupted = bytearray(frame)
            corrupted[index] ^= 1 << bit
            rx = tm_receiver()
            result, received = rx.open(bytes(corrupted))
            assert result is not ParseResult.OK
            assert received is None
