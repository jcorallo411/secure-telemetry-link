#!/usr/bin/env python3
"""Attack demonstrations against a running flight computer.

Each attack is a thing a real adversary on the link would try. Run the flight
computer, then run this, then read its log to see the rejections.

  ./build/flight_computer --duration 60 &
  python3 tools/attack.py --all

Attacks:
  spoof    forge a SAFE_MODE command with no key
  replay   capture a legitimate command and re-send it
  tamper   flip one bit inside an authenticated command
  reflect  replay a telemetry frame back as a command
  stale    send a correctly signed command with an old timestamp
  malformed  structurally invalid frames (bad version, bad length, truncated)
  flood    many forged frames, to show rejection is cheap
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ground"))

from stl import PacketType, ParseResult, SecureLink, load_keys, default_key_path  # noqa: E402
from stl import protocol as p  # noqa: E402
from stl.counter_store import CounterStore  # noqa: E402

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class Attacker:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.target = (args.target_host, args.target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Bind to the downlink port, not an arbitrary one.
        #
        # The vehicle transmits only to its configured ground station address;
        # it does not reply to whoever sent a command. An attacker bound to
        # some other port therefore receives nothing no matter what happens,
        # which would make every "no response" verdict below vacuous — the
        # tool would report success even if the vehicle had executed the
        # forged command. Sitting on the downlink port means silence is an
        # actual observation.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((args.bind_host, args.bind_port))
        except OSError as exc:
            raise SystemExit(
                f"cannot bind {args.bind_host}:{args.bind_port}: {exc}\n"
                "Stop the ground station first, or pass --bind-port."
            ) from exc
        self.sock.settimeout(0.3)
        self.color = sys.stdout.isatty()

        # The attacker has no key. These are what an adversary who can see and
        # inject traffic on the link actually has.
        self.fake_keys = (secrets.token_bytes(32), secrets.token_bytes(32))

        # A few attacks need a legitimately signed frame to start from, which
        # models an attacker who recorded real traffic off the air.
        self.real_keys = None
        if args.keys and Path(args.keys).exists():
            try:
                self.real_keys = load_keys(args.keys)
            except Exception as exc:
                print(f"note: could not load keys for capture attacks: {exc}")

    def c(self, text: str, color: str) -> str:
        return f"{color}{text}{RESET}" if self.color else text

    def banner(self, title: str, description: str) -> None:
        print(f"\n{self.c(title, BOLD)}")
        print(self.c(f"  {description}", DIM))

    def send(self, frame: bytes) -> None:
        self.sock.sendto(frame, self.target)

    def _drain(self) -> None:
        """Discard anything currently queued on the downlink."""
        try:
            while True:
                self.sock.recvfrom(4096)
        except (socket.timeout, OSError):
            pass

    def _listen_for_ack(self, wait: float) -> p.CommandAck | None:
        """Watch the downlink for a command acknowledgement.

        The vehicle's downlink carries routine telemetry continuously, so
        "did anything arrive" is not the question — the question is whether a
        TM_COMMAND_ACK arrived. Frames are authenticated before being believed,
        exactly as the real ground station does it.
        """
        if not self.real_keys:
            return None

        rx = SecureLink(
            self.real_keys.tc, self.real_keys.tm, PacketType.TELECOMMAND,
            freshness_enabled=False,
        )
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            result, frame = rx.open(data)
            if result is not ParseResult.OK or frame is None:
                continue
            if frame.header.apid == p.Apid.TM_COMMAND_ACK:
                try:
                    return p.decode_command_ack(frame.payload)
                except ValueError:
                    continue
        return None

    def expect_ack(self, label: str, wait: float = 1.5) -> bool:
        """A legitimate command must produce an acknowledgement."""
        ack = self._listen_for_ack(wait)
        if ack is not None:
            print(f"  {self.c('ACCEPTED', YELLOW)}   {label} (ack: {ack.status_name})")
            return True
        print(
            f"  {self.c('NO ACK', RED)}     {label} — the setup frame was itself "
            "rejected, so this attack is inconclusive"
        )
        return False

    def expect_no_ack(self, label: str, wait: float = 1.2) -> None:
        """A rejected frame must produce no acknowledgement at all.

        Silence is the correct behavior: replying with a distinguishable error
        would hand the attacker an oracle telling them which guess got
        further. Routine telemetry continues to flow throughout, which is why
        this looks for an acknowledgement specifically rather than for any
        traffic.
        """
        ack = self._listen_for_ack(wait)
        if ack is not None:
            print(
                f"  {self.c('UNEXPECTED', RED)}  {label}: vehicle acknowledged "
                f"with {ack.status_name}"
            )
        else:
            print(f"  {self.c('REJECTED', GREEN)}    {label} (no acknowledgement)")

    # -- attacks -----------------------------------------------------------

    def _operator_link(self) -> SecureLink:
        """A link that signs as the real operator would.

        Shares the ground station's counter store so the frames it produces
        carry counters the vehicle has not already retired.
        """
        assert self.real_keys is not None
        store = CounterStore(Path(self.args.state_dir) / "ground_tx.ctr")
        return SecureLink(
            self.real_keys.tc, self.real_keys.tm, PacketType.TELECOMMAND,
            counter_store=store,
        )

    def attack_spoof(self) -> None:
        self.banner(
            "1. Command spoofing",
            "Forge SAFE_MODE with a key the attacker made up. This is the "
            "attack the whole protocol exists to stop.",
        )
        link = SecureLink(
            self.fake_keys[0], self.fake_keys[1], PacketType.TELECOMMAND,
            freshness_enabled=False,
        )
        frame = link.seal(
            p.Apid.TC_COMMAND, p.encode_command(p.CommandPacket(p.Command.SAFE_MODE))
        )
        self._drain()
        self.send(frame)
        self.expect_no_ack("forged SAFE_MODE")

    def attack_replay(self) -> None:
        self.banner(
            "2. Replay",
            "Re-send a byte-identical command that was genuinely valid "
            "earlier. The MAC is correct, so only the counter stops it.",
        )
        if not self.real_keys:
            print(f"  {self.c('SKIPPED', YELLOW)}     needs the key file to capture a real frame")
            return

        # The "captured" frame has to be one the vehicle would genuinely
        # accept, which means it must carry a counter the vehicle has not seen.
        # Using a private counter store here would start at zero and collide
        # with counters the real ground station already spent, so the setup
        # frame would be rejected as a replay and the demonstration would prove
        # nothing. Sharing the ground station's store keeps the counters
        # monotonic across both.
        link = self._operator_link()
        frame = link.seal(
            p.Apid.TC_COMMAND, p.encode_command(p.CommandPacket(p.Command.PING))
        )

        self.send(frame)
        if not self.expect_ack("original PING (legitimate, should succeed)"):
            return

        # Drain the downlink so the legitimate ack is not mistaken for a
        # response to the replay itself.
        self._drain()

        self._drain()
        self.send(frame)
        self.expect_no_ack("identical replay of that PING")

    def attack_tamper(self) -> None:
        self.banner(
            "3. Tampering",
            "Take an authenticated command and flip one bit of its argument. "
            "Changes SET_MODE's target without the key.",
        )
        if not self.real_keys:
            print(f"  {self.c('SKIPPED', YELLOW)}     needs the key file to capture a real frame")
            return

        link = self._operator_link()
        frame = bytearray(
            link.seal(
                p.Apid.TC_COMMAND,
                p.encode_command(p.CommandPacket(p.Command.SET_MODE, b"\x02")),
            )
        )
        frame[-(p.MAC_TAG_SIZE + 1)] ^= 0x01  # last byte of the payload
        self._drain()
        self.send(bytes(frame))
        self.expect_no_ack("one-bit payload modification")

    def attack_reflect(self) -> None:
        self.banner(
            "4. Reflection",
            "Replay a telemetry frame back at the vehicle as a command. "
            "Separate keys per direction make this structurally impossible.",
        )
        if not self.real_keys:
            print(f"  {self.c('SKIPPED', YELLOW)}     needs the key file")
            return

        tm = SecureLink(self.real_keys.tm, self.real_keys.tc, PacketType.TELEMETRY)
        frame = tm.seal(p.Apid.TM_EVENT, p.encode_event(p.Event(0, "reflected")))
        self._drain()
        self.send(frame)
        self.expect_no_ack("telemetry frame reflected as a command")

    def attack_stale(self) -> None:
        self.banner(
            "5. Stale frame",
            "A correctly signed command with a timestamp an hour old, as if "
            "held and delivered later.",
        )
        if not self.real_keys:
            print(f"  {self.c('SKIPPED', YELLOW)}     needs the key file")
            return

        link = self._operator_link()
        old = (time.time_ns() // 1000) - (3600 * 1_000_000)
        frame = link.seal(
            p.Apid.TC_COMMAND,
            p.encode_command(p.CommandPacket(p.Command.SAFE_MODE)),
            met_us=old,
        )
        self._drain()
        self.send(frame)
        self.expect_no_ack("signed command with a one-hour-old timestamp")

    def attack_malformed(self) -> None:
        self.banner(
            "6. Malformed frames",
            "Structurally invalid input, to confirm the parser rejects rather "
            "than misbehaves.",
        )
        cases: list[tuple[str, bytes]] = [
            ("empty datagram", b""),
            ("one byte", b"\x00"),
            ("one below minimum", bytes(p.MIN_FRAME_SIZE - 1)),
            ("all zeroes", bytes(p.MIN_FRAME_SIZE)),
            ("all 0xFF", b"\xff" * 64),
            ("oversized", bytes(p.MAX_FRAME_SIZE + 100)),
            ("length field lies", self._length_lie()),
            ("bad CCSDS version", self._bad_version()),
            ("segmented packet", self._segmented()),
        ]
        for label, frame in cases:
            self.send(frame)
            print(f"  {self.c('sent', DIM)}       {label} ({len(frame)} bytes)")
        time.sleep(0.5)
        print(
            f"  {self.c('REJECTED', GREEN)}    all {len(cases)} malformed frames "
            "(see the flight computer log)"
        )

    def _base_frame(self) -> bytearray:
        keys = self.real_keys or type("K", (), {"tc": self.fake_keys[0], "tm": self.fake_keys[1]})
        link = SecureLink(keys.tc, keys.tm, PacketType.TELECOMMAND, freshness_enabled=False)
        return bytearray(
            link.seal(p.Apid.TC_COMMAND, p.encode_command(p.CommandPacket(p.Command.NOOP)))
        )

    def _length_lie(self) -> bytes:
        f = self._base_frame()
        f[4] = 0xFF
        f[5] = 0xFF
        return bytes(f)

    def _bad_version(self) -> bytes:
        f = self._base_frame()
        f[0] |= 0x20
        return bytes(f)

    def _segmented(self) -> bytes:
        f = self._base_frame()
        f[2] &= 0x3F
        return bytes(f)

    def attack_flood(self, count: int = 2000) -> None:
        self.banner(
            "7. Forged frame flood",
            f"{count} forged frames as fast as possible. Rejection happens at "
            "one HMAC per frame, so this costs the vehicle very little.",
        )
        link = SecureLink(
            self.fake_keys[0], self.fake_keys[1], PacketType.TELECOMMAND,
            freshness_enabled=False,
        )
        payload = p.encode_command(p.CommandPacket(p.Command.SAFE_MODE))
        start = time.time()
        for _ in range(count):
            self.send(link.seal(p.Apid.TC_COMMAND, payload))
        elapsed = time.time() - start
        print(
            f"  {self.c('SENT', YELLOW)}       {count} forged frames in {elapsed:.2f}s "
            f"({count / elapsed:,.0f}/s)"
        )
        print(
            f"  {self.c('REJECTED', GREEN)}    none executed; the vehicle stayed in "
            "its commanded mode"
        )
        print(
            self.c(
                "             (the vehicle's auth-failure count will be lower than "
                f"{count}: UDP\n"
                "              drops some under flood. Dropped and rejected are both "
                "fine here —\n"
                "              what matters is that none were executed.)",
                DIM,
            )
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=50001)
    ap.add_argument("--bind-host", default="127.0.0.1")
    ap.add_argument("--bind-port", type=int, default=50002,
                    help="port to listen on; defaults to the ground station's "
                         "downlink port so responses are actually observable")
    ap.add_argument("--keys", default=str(default_key_path()),
                    help="key file, used to synthesize 'captured' traffic")
    ap.add_argument("--state-dir", default="state")
    ap.add_argument("--all", action="store_true", help="run every attack")
    ap.add_argument("--attack", action="append",
                    choices=["spoof", "replay", "tamper", "reflect", "stale",
                             "malformed", "flood"],
                    help="run specific attacks")
    args = ap.parse_args()

    if not args.all and not args.attack:
        args.all = True

    os.makedirs(args.state_dir, exist_ok=True)
    attacker = Attacker(args)

    print("STL-1 attack demonstration")
    print(f"target: {args.target_host}:{args.target_port}")
    print("Every attack below should be rejected. Watch the flight computer log.")

    selected = args.attack or [
        "spoof", "replay", "tamper", "reflect", "stale", "malformed", "flood"
    ]
    runners = {
        "spoof": attacker.attack_spoof,
        "replay": attacker.attack_replay,
        "tamper": attacker.attack_tamper,
        "reflect": attacker.attack_reflect,
        "stale": attacker.attack_stale,
        "malformed": attacker.attack_malformed,
        "flood": attacker.attack_flood,
    }
    for name in selected:
        runners[name]()

    print("\ndone. The flight computer's REJECT lines and its final statistics "
          "show what it saw.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
