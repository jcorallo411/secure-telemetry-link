"""Cross-implementation agreement tests.

Runs the C++ vector generator and checks that the Python implementation
produces byte-identical frames and reaches identical verdicts.

This is the test that justifies having two implementations. Each side can be
internally consistent and still disagree about the wire format; only a
byte-for-byte comparison catches that.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ground"))

from stl import PacketType, ParseResult, SecureLink  # noqa: E402
from stl import protocol as p  # noqa: E402

VECTORS_BIN = ROOT / "build" / "vectors"


@pytest.fixture(scope="module")
def vectors() -> dict:
    if not VECTORS_BIN.exists():
        pytest.skip(f"{VECTORS_BIN} not built; run `make` first")
    out = subprocess.run(
        [str(VECTORS_BIN)], capture_output=True, text=True, check=True, cwd=ROOT
    )
    return json.loads(out.stdout)


def make_link(vectors: dict, direction: str) -> SecureLink:
    k_tm = bytes.fromhex(vectors["k_tm"])
    k_tc = bytes.fromhex(vectors["k_tc"])
    if direction == "tm":
        return SecureLink(tx_key=k_tm, rx_key=k_tc, tx_type=PacketType.TELEMETRY,
                          freshness_enabled=False)
    return SecureLink(tx_key=k_tc, rx_key=k_tm, tx_type=PacketType.TELECOMMAND,
                      freshness_enabled=False)


def receiver_for(vectors: dict, direction: str) -> SecureLink:
    """A link that *receives* frames produced in `direction`."""
    k_tm = bytes.fromhex(vectors["k_tm"])
    k_tc = bytes.fromhex(vectors["k_tc"])
    if direction == "tm":
        # Ground receives telemetry: verifies with K_TM, signs with K_TC.
        return SecureLink(tx_key=k_tc, rx_key=k_tm, tx_type=PacketType.TELECOMMAND,
                          freshness_enabled=False)
    return SecureLink(tx_key=k_tm, rx_key=k_tc, tx_type=PacketType.TELEMETRY,
                      freshness_enabled=False)


def test_vector_file_shape(vectors: dict) -> None:
    assert len(vectors["frames"]) >= 8
    assert len(bytes.fromhex(vectors["k_tm"])) == 32
    assert len(bytes.fromhex(vectors["k_tc"])) == 32
    assert vectors["k_tm"] != vectors["k_tc"]


def test_python_seal_matches_cpp_byte_for_byte(vectors: dict) -> None:
    """The headline test: identical bytes out of both implementations."""
    for vec in vectors["frames"]:
        link = make_link(vectors, vec["dir"])
        payload = bytes.fromhex(vec["payload"])
        produced = link.seal(vec["apid"], payload, met_us=vec["met"])
        expected = bytes.fromhex(vec["frame"])
        assert produced == expected, (
            f"vector '{vec['name']}' differs.\n"
            f"  python: {produced.hex()}\n"
            f"  c++   : {expected.hex()}"
        )


def test_python_opens_every_cpp_frame(vectors: dict) -> None:
    for vec in vectors["frames"]:
        rx = receiver_for(vectors, vec["dir"])
        frame_bytes = bytes.fromhex(vec["frame"])
        result, frame = rx.open(frame_bytes)
        assert result is ParseResult.OK, f"'{vec['name']}' rejected: {result.name}"
        assert frame is not None
        assert frame.header.apid == vec["apid"]
        assert frame.header.met_us == vec["met"]
        assert frame.header.frame_counter == vec["counter"]
        assert frame.payload == bytes.fromhex(vec["payload"])


def test_payload_round_trips(vectors: dict) -> None:
    """Decoded payloads survive a decode/encode cycle unchanged."""
    by_name = {v["name"]: v for v in vectors["frames"]}

    hk = p.decode_housekeeping(bytes.fromhex(by_name["housekeeping"]["payload"]))
    assert hk.mode == 2
    assert hk.bus_voltage_mv == 27850
    assert hk.battery_temp_mc == -4250  # signed value survives the wire
    assert hk.uptime_s == 86399
    assert p.encode_housekeeping(hk) == bytes.fromhex(by_name["housekeeping"]["payload"])

    att = p.decode_attitude(bytes.fromhex(by_name["attitude_extremes"]["payload"]))
    assert att.gyro[2] == 2147483647   # INT32_MAX
    assert att.accel[0] == -2147483648  # INT32_MIN
    assert att.accel[2] == -1
    assert p.encode_attitude(att) == bytes.fromhex(
        by_name["attitude_extremes"]["payload"]
    )

    ack = p.decode_command_ack(bytes.fromhex(by_name["command_ack"]["payload"]))
    assert ack.frame_counter == 0xFFFFFFFF
    assert ack.status_name == "REJECTED_INVALID_IN_MODE"

    cmd = p.decode_command(bytes.fromhex(by_name["command_max_args"]["payload"]))
    assert len(cmd.args) == p.MAX_COMMAND_ARG_LEN

    ev = p.decode_event(bytes.fromhex(by_name["event_empty"]["payload"]))
    assert ev.severity_name == "CRITICAL"
    assert ev.message == ""


def test_boundary_frame_sizes(vectors: dict) -> None:
    by_name = {v["name"]: v for v in vectors["frames"]}
    assert len(bytes.fromhex(by_name["min_frame"]["frame"])) == p.MIN_FRAME_SIZE
    assert len(bytes.fromhex(by_name["max_frame"]["frame"])) == p.MAX_FRAME_SIZE


def test_met_max_survives(vectors: dict) -> None:
    """A 64-bit MET of all ones must not be mangled by sign handling."""
    by_name = {v["name"]: v for v in vectors["frames"]}
    vec = by_name["met_max"]
    rx = receiver_for(vectors, vec["dir"])
    result, frame = rx.open(bytes.fromhex(vec["frame"]))
    assert result is ParseResult.OK
    assert frame is not None
    assert frame.header.met_us == 0xFFFFFFFFFFFFFFFF


def test_every_single_bit_flip_is_detected(vectors: dict) -> None:
    """Flipping any one bit anywhere in a frame must cause a rejection.

    This is the property the MAC exists to provide, and it covers the header
    as well as the payload: a frame whose APID or length was altered in flight
    is just as dangerous as one whose sensor values were.
    """
    by_name = {v["name"]: v for v in vectors["frames"]}
    vec = by_name["housekeeping"]
    original = bytes.fromhex(vec["frame"])

    for byte_index in range(len(original)):
        for bit in range(8):
            corrupted = bytearray(original)
            corrupted[byte_index] ^= 1 << bit

            rx = receiver_for(vectors, vec["dir"])
            result, frame = rx.open(bytes(corrupted))

            assert result is not ParseResult.OK, (
                f"bit {bit} of byte {byte_index} flipped but the frame was accepted"
            )
            assert frame is None
