#!/usr/bin/env python3
"""STL-1 ground station.

Receives authenticated telemetry, logs it, displays it live, and uplinks
authenticated commands.

  python3 ground/station.py                      # live display
  python3 ground/station.py --no-display         # scrolling log only
  python3 ground/station.py --send PING          # one command, then exit
  python3 ground/station.py --send SET_TM_RATE:5
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stl import (  # noqa: E402
    Apid,
    Command,
    Mode,
    PacketType,
    ParseResult,
    SecureLink,
    load_keys,
    default_key_path,
)
from stl import protocol as p  # noqa: E402
from stl.counter_store import CounterStore  # noqa: E402

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def colorize(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


class GroundStation:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        keys = load_keys(args.keys)

        # The transmit counter has to survive a restart of this process, or the
        # flight computer's replay window will reject every command the second
        # time the station is run.
        counter_store = CounterStore(Path(args.state_dir) / "ground_tx.ctr")

        # Ground signs commands with K_TC and verifies telemetry with K_TM —
        # the mirror image of the flight computer's construction.
        self.link = SecureLink(
            tx_key=keys.tc,
            rx_key=keys.tm,
            tx_type=PacketType.TELECOMMAND,
            freshness_enabled=not args.no_freshness,
            counter_store=counter_store,
        )

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((args.bind_host, args.bind_port))
        self.sock.settimeout(0.2)
        self.peer = (args.peer_host, args.peer_port)

        self.color = sys.stdout.isatty() and not args.no_color
        self.running = True

        # Latest state for the display
        self.last_hk: p.Housekeeping | None = None
        self.last_att: p.Attitude | None = None
        self.last_hk_time: float = 0.0
        self.events: list[tuple[float, p.Event]] = []
        self.acks: list[tuple[float, p.CommandAck]] = []
        self.rejects: dict[str, int] = {}
        self.frames_rx = 0
        self.last_seq: dict[int, int] = {}
        self.gaps = 0
        self.started = time.time()

        self.tm_log = None
        self.event_log = None
        if args.log_dir:
            Path(args.log_dir).mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.tm_log = open(
                Path(args.log_dir) / f"telemetry_{stamp}.jsonl", "w", encoding="utf-8"
            )
            self.event_log = open(
                Path(args.log_dir) / f"events_{stamp}.log", "w", encoding="utf-8"
            )

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self.sock.close()
        for handle in (self.tm_log, self.event_log):
            if handle:
                handle.close()

    def stop(self, *_: object) -> None:
        self.running = False

    # -- uplink ------------------------------------------------------------

    def send_command(self, command_id: int, args: bytes = b"") -> int:
        cmd = p.CommandPacket(command_id=command_id, args=args)
        frame = self.link.seal(Apid.TC_COMMAND, p.encode_command(cmd))
        self.sock.sendto(frame, self.peer)
        return self.link.tx_frame_counter - 1

    # -- downlink ----------------------------------------------------------

    def poll(self) -> None:
        try:
            data, _addr = self.sock.recvfrom(4096)
        except socket.timeout:
            return
        except OSError:
            return

        result, frame = self.link.open(data)

        if result is not ParseResult.OK or frame is None:
            name = result.name
            self.rejects[name] = self.rejects.get(name, 0) + 1
            if not self.args.display:
                print(
                    colorize(f"  REJECT {name} ({len(data)} bytes)", RED, self.color)
                )
            return

        self.frames_rx += 1
        self._track_gaps(frame.header.apid, frame.header.sequence_count)

        try:
            self._dispatch(frame)
        except ValueError as exc:
            # An authenticated frame whose payload does not match its APID is
            # a version mismatch between the two ends, not an attack. It still
            # gets counted rather than swallowed.
            self.link.stats.bad_payload += 1
            self.rejects["BAD_PAYLOAD_LENGTH"] = (
                self.rejects.get("BAD_PAYLOAD_LENGTH", 0) + 1
            )
            if not self.args.display:
                print(colorize(f"  BAD PAYLOAD: {exc}", YELLOW, self.color))

    def _track_gaps(self, apid: int, seq: int) -> None:
        previous = self.last_seq.get(apid)
        if previous is not None:
            expected = (previous + 1) & 0x3FFF
            if seq != expected:
                # Expected on a lossy UDP link; counted so the operator can
                # tell "the link is lossy" from "the link is being jammed".
                self.gaps += 1
        self.last_seq[apid] = seq

    def _dispatch(self, frame) -> None:
        apid = frame.header.apid
        now = time.time()

        if apid == Apid.TM_HOUSEKEEPING:
            hk = p.decode_housekeeping(frame.payload)
            self.last_hk = hk
            self.last_hk_time = now
            self._log_tm("housekeeping", frame.header, hk.__dict__)

        elif apid == Apid.TM_ATTITUDE:
            att = p.decode_attitude(frame.payload)
            self.last_att = att
            self._log_tm(
                "attitude",
                frame.header,
                {"gyro": list(att.gyro), "accel": list(att.accel), "mag": list(att.mag)},
            )

        elif apid == Apid.TM_COMMAND_ACK:
            ack = p.decode_command_ack(frame.payload)
            self.acks.append((now, ack))
            self.acks = self.acks[-10:]
            self._log_tm(
                "command_ack",
                frame.header,
                {
                    "command_id": ack.command_id,
                    "frame_counter": ack.frame_counter,
                    "status": ack.status_name,
                },
            )
            if not self.args.display:
                color = GREEN if ack.status == 0 else YELLOW
                print(
                    colorize(
                        f"  ACK  cmd=0x{ack.command_id:04X} -> {ack.status_name}",
                        color,
                        self.color,
                    )
                )

        elif apid == Apid.TM_EVENT:
            ev = p.decode_event(frame.payload)
            self.events.append((now, ev))
            self.events = self.events[-10:]
            if self.event_log:
                stamp = datetime.now(timezone.utc).isoformat()
                self.event_log.write(f"{stamp} [{ev.severity_name}] {ev.message}\n")
                self.event_log.flush()
            if not self.args.display:
                color = {0: CYAN, 1: YELLOW, 2: RED, 3: RED}.get(ev.severity, RESET)
                print(
                    colorize(f"  EVENT [{ev.severity_name}] {ev.message}", color, self.color)
                )

    def _log_tm(self, kind: str, header, fields: dict) -> None:
        if not self.tm_log:
            return
        record = {
            "t": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "apid": header.apid,
            "seq": header.sequence_count,
            "frame_counter": header.frame_counter,
            "met_us": header.met_us,
            **fields,
        }
        self.tm_log.write(json.dumps(record) + "\n")
        self.tm_log.flush()

    # -- display -----------------------------------------------------------

    def render(self) -> None:
        rows: list[str] = []
        c = self.color

        age = time.time() - self.last_hk_time if self.last_hk_time else None
        link_up = age is not None and age < 3.0
        status = (
            colorize("● LINK UP", GREEN, c) if link_up else colorize("● NO DATA", RED, c)
        )

        rows.append(colorize("STL-1 GROUND STATION", BOLD, c) + f"    {status}")
        rows.append(colorize("─" * 62, DIM, c))

        if self.last_hk:
            hk = self.last_hk
            try:
                mode_name = Mode(hk.mode).name
            except ValueError:
                mode_name = f"UNKNOWN({hk.mode})"
            mode_color = RED if mode_name == "SAFE" else GREEN
            rows.append(
                f"  mode      {colorize(mode_name, mode_color, c):<22}"
                f"uptime   {hk.uptime_s:>6d} s"
            )
            rows.append(
                f"  bus       {hk.bus_voltage_v:6.2f} V  {hk.bus_current_a:5.2f} A"
                f"        rate     {hk.telemetry_rate_hz:>6d} Hz"
            )
            rows.append(
                f"  batt temp {hk.battery_temp_c:6.1f} C"
                f"               heater   {'ON' if hk.heater_on else 'OFF':>6}"
            )
            rows.append(f"  payld tmp {hk.payload_temp_c:6.1f} C")
        else:
            rows.append(colorize("  waiting for housekeeping telemetry…", DIM, c))

        if self.last_att:
            a = self.last_att
            rows.append("")
            rows.append(colorize("  ATTITUDE", BOLD, c))
            rows.append(
                f"    gyro   {a.gyro[0]:>8d} {a.gyro[1]:>8d} {a.gyro[2]:>8d}  urad/s"
            )
            rows.append(
                f"    accel  {a.accel[0]:>8d} {a.accel[1]:>8d} {a.accel[2]:>8d}  ug"
            )
            rows.append(
                f"    mag    {a.mag[0]:>8d} {a.mag[1]:>8d} {a.mag[2]:>8d}  nT"
            )

        rows.append("")
        rows.append(colorize("  LINK SECURITY", BOLD, c))
        s = self.link.stats
        rows.append(
            f"    accepted {s.accepted:<8d} auth fail {colorize(str(s.auth_failures), RED if s.auth_failures else RESET, c):<8}"
            f" replay {colorize(str(s.replay_rejects), RED if s.replay_rejects else RESET, c)}"
        )
        rows.append(
            f"    malformed {s.malformed:<7d} stale     {s.stale_rejects:<8d}"
            f" seq gaps {self.gaps}"
        )

        if self.acks:
            rows.append("")
            rows.append(colorize("  RECENT ACKS", BOLD, c))
            for _t, ack in self.acks[-3:]:
                color = GREEN if ack.status == 0 else YELLOW
                rows.append(
                    f"    0x{ack.command_id:04X}  {colorize(ack.status_name, color, c)}"
                )

        if self.events:
            rows.append("")
            rows.append(colorize("  EVENTS", BOLD, c))
            for _t, ev in self.events[-3:]:
                color = {0: CYAN, 1: YELLOW, 2: RED, 3: RED}.get(ev.severity, RESET)
                rows.append(f"    [{colorize(ev.severity_name, color, c)}] {ev.message}")

        rows.append("")
        rows.append(colorize("  Ctrl-C to exit", DIM, c))

        sys.stdout.write("\033[H\033[J" + "\n".join(rows) + "\n")
        sys.stdout.flush()

    # -- main loop ---------------------------------------------------------

    def run(self) -> int:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

        if self.args.display:
            sys.stdout.write("\033[?25l")  # hide cursor

        last_render = 0.0
        try:
            while self.running:
                self.poll()
                if self.args.display and (time.time() - last_render) > 0.25:
                    self.render()
                    last_render = time.time()
        finally:
            if self.args.display:
                sys.stdout.write("\033[?25h\n")  # restore cursor
            self.print_summary()
            self.close()
        return 0

    def print_summary(self) -> None:
        s = self.link.stats
        print("\nground station summary")
        print(f"  frames accepted  {s.accepted}")
        print(f"  auth failures    {s.auth_failures}")
        print(f"  replay rejects   {s.replay_rejects}")
        print(f"  stale rejects    {s.stale_rejects}")
        print(f"  malformed        {s.malformed}")
        print(f"  unknown apid     {s.unknown_apid}")
        print(f"  sequence gaps    {self.gaps}")
        if self.args.log_dir:
            print(f"  logs written to  {self.args.log_dir}/")


def parse_command_spec(spec: str) -> tuple[int, bytes]:
    """Parse a command like 'PING' or 'SET_TM_RATE:5' into (id, args)."""
    name, _, arg = spec.partition(":")
    name = name.strip().upper()

    try:
        command = Command[name]
    except KeyError:
        valid = ", ".join(cmd.name for cmd in Command)
        raise SystemExit(f"unknown command '{name}'. Valid: {valid}")

    if command in (Command.NOOP, Command.PING, Command.SAFE_MODE):
        if arg:
            raise SystemExit(f"{name} takes no argument")
        return int(command), b""

    if not arg:
        raise SystemExit(f"{name} requires an argument, e.g. {name}:1")

    if command == Command.SET_MODE:
        try:
            mode = Mode[arg.strip().upper()] if not arg.isdigit() else Mode(int(arg))
        except (KeyError, ValueError):
            valid = ", ".join(m.name for m in Mode)
            raise SystemExit(f"bad mode '{arg}'. Valid: {valid}")
        return int(command), bytes([int(mode)])

    if command == Command.SET_TM_RATE:
        hz = int(arg)
        if not (p.MIN_TM_RATE_HZ <= hz <= p.MAX_TM_RATE_HZ):
            raise SystemExit(
                f"rate must be {p.MIN_TM_RATE_HZ}..{p.MAX_TM_RATE_HZ} Hz"
            )
        return int(command), hz.to_bytes(2, "big")

    if command == Command.SET_HEATER:
        on = arg.strip().lower() in ("1", "on", "true", "yes")
        return int(command), bytes([1 if on else 0])

    raise SystemExit(f"no argument handler for {name}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys", default=str(default_key_path()), help="key file path")
    ap.add_argument("--bind-host", default="127.0.0.1")
    ap.add_argument("--bind-port", type=int, default=50002)
    ap.add_argument("--peer-host", default="127.0.0.1")
    ap.add_argument("--peer-port", type=int, default=50001)
    ap.add_argument("--log-dir", default="logs", help="directory for telemetry logs")
    ap.add_argument("--state-dir", default="state",
                    help="directory for the persistent transmit counter")
    ap.add_argument("--no-display", dest="display", action="store_false",
                    help="scrolling log instead of the live panel")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-freshness", action="store_true",
                    help="disable the timestamp freshness check")
    ap.add_argument("--send", metavar="CMD",
                    help="send one command and exit, e.g. PING or SET_TM_RATE:5")
    ap.add_argument("--wait", type=float, default=1.5,
                    help="seconds to wait for an ack after --send")
    ap.set_defaults(display=True)
    args = ap.parse_args()

    if args.send and os.environ.get("TERM") is None:
        args.display = False

    try:
        station = GroundStation(args)
    except Exception as exc:
        print(f"startup failed: {exc}", file=sys.stderr)
        return 1

    if args.send:
        command_id, cmd_args = parse_command_spec(args.send)
        counter = station.send_command(command_id, cmd_args)
        print(f"sent 0x{command_id:04X} (frame counter {counter}), waiting for ack…")

        deadline = time.time() + args.wait
        station.args.display = False
        while time.time() < deadline:
            station.poll()
            if any(a.frame_counter == counter for _t, a in station.acks):
                break
        matching = [a for _t, a in station.acks if a.frame_counter == counter]
        if matching:
            ack = matching[-1]
            print(f"ack: cmd=0x{ack.command_id:04X} status={ack.status_name}")
            station.close()
            return 0 if ack.status == 0 else 3
        print("no ack received within the timeout", file=sys.stderr)
        station.close()
        return 4

    return station.run()


if __name__ == "__main__":
    raise SystemExit(main())
