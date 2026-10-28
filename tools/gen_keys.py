#!/usr/bin/env python3
"""Generate the STL-1 pre-shared key file.

Two independent 32-byte keys, one per direction, from the OS CSPRNG.

Separate keys per direction mean a compromised ground receiver cannot be
turned around and used to forge commands to the vehicle, and they structurally
rule out reflection attacks where a captured telemetry frame is replayed back
as a command.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys

MAGIC = b"STLK"
VERSION = 1
KEY_SIZE = 32
KEYFILE_SIZE = 4 + 1 + KEY_SIZE + KEY_SIZE  # 69


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", "--output", default="keys/stl_keys.bin", help="output path"
    )
    parser.add_argument(
        "-f", "--force", action="store_true", help="overwrite an existing key file"
    )
    args = parser.parse_args()

    if os.path.exists(args.output) and not args.force:
        print(
            f"refusing to overwrite existing {args.output} (use --force)",
            file=sys.stderr,
        )
        return 1

    # secrets.token_bytes draws from the OS CSPRNG. Never use random.* for key
    # material: it is a Mersenne Twister, and observing a modest amount of its
    # output is enough to recover the internal state and predict every
    # subsequent byte.
    k_tm = secrets.token_bytes(KEY_SIZE)
    k_tc = secrets.token_bytes(KEY_SIZE)

    blob = MAGIC + bytes([VERSION]) + k_tm + k_tc
    assert len(blob) == KEYFILE_SIZE, "key blob size mismatch"

    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)

    # Create with 0600 from the outset rather than writing and then chmod-ing.
    # The chmod-after approach leaves a window in which the key file is
    # readable by other users on the machine.
    fd = os.open(
        args.output,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)

    os.chmod(args.output, stat.S_IRUSR | stat.S_IWUSR)

    print(f"wrote {args.output} ({KEYFILE_SIZE} bytes, mode 0600)")
    print(f"  K_TM (vehicle -> ground): {k_tm[:4].hex()}... ")
    print(f"  K_TC (ground -> vehicle): {k_tc[:4].hex()}... ")
    print("\nBoth ends must load the same file. Do not commit it to version control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
