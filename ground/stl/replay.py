"""Sliding-window anti-replay, ground side.

Mirrors flight/src/replay.cpp. See docs/PROTOCOL.md section 5.1.
"""

from __future__ import annotations

from enum import Enum

WINDOW_SIZE = 64


class ReplayVerdict(Enum):
    ACCEPT = "accept"
    DUPLICATE = "duplicate"
    TOO_OLD = "too_old"


class ReplayWindow:
    """Accepts each frame counter at most once, tolerating reordering."""

    __slots__ = ("_highest", "_bitmap", "_started")

    def __init__(self) -> None:
        self._highest = 0
        self._bitmap = 0
        self._started = False

    def reset(self) -> None:
        self._highest = 0
        self._bitmap = 0
        self._started = False

    @property
    def highest(self) -> int:
        return self._highest

    @property
    def started(self) -> bool:
        return self._started

    def check_and_update(self, counter: int) -> ReplayVerdict:
        if not (0 <= counter <= 0xFFFFFFFF):
            raise ValueError("frame counter out of 32-bit range")

        if not self._started:
            self._started = True
            self._highest = counter
            self._bitmap = 1
            return ReplayVerdict.ACCEPT

        if counter > self._highest:
            advance = counter - self._highest
            if advance >= WINDOW_SIZE:
                self._bitmap = 1
            else:
                # Python ints are arbitrary precision, so the shift must be
                # masked back to the window width explicitly. The C++ side gets
                # this free from uint64_t; here it has to be written out, and
                # forgetting it would silently grow the window forever and
                # break the TOO_OLD check.
                self._bitmap = ((self._bitmap << advance) | 1) & ((1 << WINDOW_SIZE) - 1)
            self._highest = counter
            return ReplayVerdict.ACCEPT

        if counter == self._highest:
            return ReplayVerdict.DUPLICATE

        age = self._highest - counter
        if age >= WINDOW_SIZE:
            return ReplayVerdict.TOO_OLD

        mask = 1 << age
        if self._bitmap & mask:
            return ReplayVerdict.DUPLICATE

        self._bitmap |= mask
        return ReplayVerdict.ACCEPT
