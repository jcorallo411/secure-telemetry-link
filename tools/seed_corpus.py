#!/usr/bin/env python3
"""Seed the fuzzing corpus with structurally valid frames.

A fuzzer started on random bytes spends most of its budget failing the length
check in the first six bytes. Seeding it with real frames means its mutations
begin from valid structure, so it reaches the interesting code immediately.

Each corpus file carries the 4-byte mode prefix the harness expects:
  byte 0: bit 0 = re-sign the frame, bit 1 = fix the declared length
  byte 1: bit 0 = enable the freshness check
  bytes 2-3: reserved
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ground"))

from stl import PacketType, SecureLink  # noqa: E402
from stl import protocol as p  # noqa: E402

K_TM = bytes((0x11 + i * 7) & 0xFF for i in range(32))
K_TC = bytes((0x42 + i * 7) & 0xFF for i in range(32))

CORPUS = ROOT / "fuzz" / "corpus"


def write(name: str, mode: int, flags: int, frame: bytes) -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    (CORPUS / name).write_bytes(bytes([mode, flags, 0, 0]) + frame)


def main() -> int:
    tm = SecureLink(K_TM, K_TC, PacketType.TELEMETRY, freshness_enabled=False)
    tc = SecureLink(K_TC, K_TM, PacketType.TELECOMMAND, freshness_enabled=False)

    met = 1_700_000_000_000_000

    frames: list[tuple[str, bytes]] = [
        (
            "housekeeping",
            tm.seal(
                p.Apid.TM_HOUSEKEEPING,
                p.encode_housekeeping(
                    p.Housekeeping(2, 1, 4, 27850, 1432, -4250, 12750, 86399)
                ),
                met_us=met,
            ),
        ),
        (
            "attitude",
            tm.seal(
                p.Apid.TM_ATTITUDE,
                p.encode_attitude(
                    p.Attitude(
                        gyro=(-123456, 0, 2147483647),
                        accel=(-2147483648, 9810, -1),
                        mag=(25000, -25000, -42000),
                    )
                ),
                met_us=met,
            ),
        ),
        (
            "command_ack",
            tm.seal(
                p.Apid.TM_COMMAND_ACK,
                p.encode_command_ack(p.CommandAck(0x0004, 0xFFFFFFFF, 3)),
                met_us=met,
            ),
        ),
        (
            "event",
            tm.seal(
                p.Apid.TM_EVENT,
                p.encode_event(p.Event(2, "entered SAFE mode by command")),
                met_us=met,
            ),
        ),
        ("event_empty", tm.seal(p.Apid.TM_EVENT, p.encode_event(p.Event(3, "")), met_us=met)),
        (
            "command_min",
            tc.seal(p.Apid.TC_COMMAND, p.encode_command(p.CommandPacket(0x0002)), met_us=met),
        ),
        (
            "command_max_args",
            tc.seal(
                p.Apid.TC_COMMAND,
                p.encode_command(
                    p.CommandPacket(0x0003, bytes(range(p.MAX_COMMAND_ARG_LEN)))
                ),
                met_us=met,
            ),
        ),
        ("min_frame", tm.seal(p.Apid.TM_EVENT, b"", met_us=met)),
        ("max_frame", tm.seal(p.Apid.TM_HOUSEKEEPING, bytes(p.MAX_USER_DATA), met_us=met)),
        ("unknown_apid", tm.seal(0x123, b"\x00\x00\x00\x00", met_us=met)),
    ]

    count = 0
    for name, frame in frames:
        # Unsigned: exercises the rejection path up to the MAC check.
        write(f"{name}_raw.bin", 0x00, 0x00, frame)
        # Signed: the fuzzer's mutations stay authenticated, so everything
        # behind the MAC check stays reachable.
        write(f"{name}_signed.bin", 0x03, 0x00, frame)
        count += 2

    # A few deliberately degenerate inputs so the fuzzer has the boundary
    # cases in hand from the start rather than having to rediscover them.
    write("empty.bin", 0x00, 0x00, b"")
    write("one_byte.bin", 0x00, 0x00, b"\x00")
    write("min_minus_one.bin", 0x00, 0x00, bytes(p.MIN_FRAME_SIZE - 1))
    write("all_zero_min.bin", 0x00, 0x00, bytes(p.MIN_FRAME_SIZE))
    write("all_ff.bin", 0x00, 0x00, b"\xff" * 64)
    write("oversized.bin", 0x00, 0x00, bytes(p.MAX_FRAME_SIZE + 10))
    count += 6

    print(f"wrote {count} corpus files to {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
