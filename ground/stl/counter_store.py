"""Persistent transmit-counter storage, ground side.

Mirrors flight/src/counter_store.cpp. See that file's header comment for why
this exists; in short, a sender whose counter restarts at zero looks exactly
like a replay attacker to a receiver that did not also restart, so the counter
has to survive a restart.

Counters are handed out from reserved blocks. The block is persisted *before*
any counter in it is used, so a crash skips counters rather than reusing them.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

BLOCK_SIZE = 1024
COUNTER_MAX = 0xFFFFFFFF


class CounterExhausted(Exception):
    """Raised when the 32-bit counter space is spent and the link needs rekeying."""


class CounterStateCorrupt(Exception):
    """Raised when the state file exists but does not hold a valid mark.

    Starting at zero instead would reuse counters the receiver has already
    accepted, locking this sender out of the replay window. Refusing to start
    makes the problem visible to an operator instead of silent.
    """


class CounterStore:
    __slots__ = ("_path", "_next", "_block_end")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._next = 0
        self._block_end = 0
        self._reserve(self._read_mark())

    def _read_mark(self) -> int:
        try:
            blob = self._path.read_bytes()
        except FileNotFoundError:
            return 0  # first run
        if len(blob) != 4:
            # Fail closed: only a missing file means "first run".
            raise CounterStateCorrupt(
                f"counter state file {self._path} is corrupt "
                f"({len(blob)} bytes, expected 4); refusing to start rather "
                "than reuse counters"
            )
        return struct.unpack(">I", blob)[0]

    def _write_mark(self, value: int) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")

        # Write to a temporary file, fsync it, then rename. Rename within a
        # directory is atomic, so a crash leaves either the old mark or the new
        # one, never four half-written bytes.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, struct.pack(">I", value))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)

        # Also fsync the directory, so the rename itself is durable.
        dir_fd = os.open(str(self._path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        except OSError:
            pass  # not supported on every filesystem; the rename still holds
        finally:
            os.close(dir_fd)

    def _reserve(self, start: int) -> None:
        if start > (COUNTER_MAX - BLOCK_SIZE):
            raise CounterExhausted(
                "transmit counter space exhausted; rekey the link"
            )
        end = start + BLOCK_SIZE
        self._write_mark(end)
        self._next = start
        self._block_end = end

    def next(self) -> int:
        if self._next >= self._block_end:
            self._reserve(self._block_end)
        value = self._next
        self._next += 1
        return value

    @property
    def peek(self) -> int:
        return self._next
