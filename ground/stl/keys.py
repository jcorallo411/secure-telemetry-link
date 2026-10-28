"""Key file loading, ground side. Mirrors flight/src/keys.cpp."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"STLK"
VERSION = 1
KEY_SIZE = 32
KEYFILE_SIZE = 69


@dataclass(frozen=True)
class KeySet:
    tm: bytes  # vehicle -> ground
    tc: bytes  # ground -> vehicle


class KeyError_(Exception):
    """Raised when a key file cannot be loaded or fails validation."""


def load_keys(path: str | Path) -> KeySet:
    path = Path(path)
    if not path.exists():
        raise KeyError_(
            f"{path} does not exist; run `python3 tools/gen_keys.py` first"
        )

    st = path.stat()
    # A key readable by anyone else on the machine is not a secret. Failing
    # loudly here beats a system that appears secure and is not.
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise KeyError_(f"{path} is group/world accessible; run `chmod 600 {path}`")

    blob = path.read_bytes()
    if len(blob) != KEYFILE_SIZE:
        raise KeyError_(
            f"{path} is {len(blob)} bytes, expected {KEYFILE_SIZE}"
        )
    if blob[:4] != MAGIC:
        raise KeyError_(f"{path} has a bad magic number")
    if blob[4] != VERSION:
        raise KeyError_(f"{path} has unsupported version {blob[4]}")

    k_tm = blob[5 : 5 + KEY_SIZE]
    k_tc = blob[5 + KEY_SIZE : 5 + (2 * KEY_SIZE)]

    if not any(k_tm) or not any(k_tc):
        raise KeyError_(f"{path} contains an all-zero key; regenerate it")
    if k_tm == k_tc:
        raise KeyError_(f"{path} has identical TM and TC keys; regenerate it")

    return KeySet(tm=k_tm, tc=k_tc)


def default_key_path() -> Path:
    """keys/stl_keys.bin relative to the repository root."""
    return Path(__file__).resolve().parents[2] / "keys" / "stl_keys.bin"


__all__ = ["KeySet", "KeyError_", "load_keys", "default_key_path"]
