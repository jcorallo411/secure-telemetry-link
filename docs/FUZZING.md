# Fuzzing the receive path

## What is being fuzzed, and why that target

`SecureLink::open` is the only code an unauthenticated attacker can reach.
Anything that arrives on the socket enters it before a single security check
has passed, so a memory-safety bug there is remote code execution against the
flight computer. Everything else in the system is behind either the MAC check
or the physical link.

The harness is `fuzz/fuzz_parser.cpp`. Run it with:

```sh
make fuzz-run FUZZ_SECONDS=120
```

The build needs a clang whose compiler-rt is installed (`libclang-rt-N-dev` on
Debian and Ubuntu). The Makefile probes the installed clangs for the fuzzer
runtime and picks one; override with `make fuzz FUZZ_CXX=clang++-18`.

## Two decisions that made the harness actually useful

**The fuzzer is given the real key.** This looks wrong at first glance. The
point of the MAC is to reject input from anyone without the key, so handing the
key to the fuzzer seems to test the wrong threat model.

It is the right call, for a specific reason. Without the key, every input is
rejected at step 5 of the validation pipeline, and the fuzzer can never reach
the replay window, the freshness check, APID dispatch, or any payload decoder.
It would explore roughly forty bytes of header parsing, report a healthy
execution rate, and find nothing — because there is nothing left to find in
that forty bytes. Giving the fuzzer the key lets it steer the authenticated
region directly, which is what exercises the code that actually parses
variable-length data.

The threat model this corresponds to is real, not hypothetical: an attacker who
has compromised the ground segment, or a key that leaked. Defense in depth
means the parser should not be exploitable even by someone holding the key.

The first four bytes of each input select the mode:

| Byte | Bit | Meaning |
|---|---|---|
| 0 | 0 | Recompute a valid MAC over the mutated frame |
| 0 | 1 | Rewrite the declared length so it matches the datagram |
| 1 | 0 | Enable the freshness check |

**The payload decoders are called on anything that validates.** Parsing does
not stop at `open`. `decode_command` and friends are the functions that copy
variable-length data into fixed buffers, which is where a bounds bug would
actually live. The harness calls all of them and reads back the results so that
an out-of-bounds access is a sanitizer report rather than a silent pass.

The harness also asserts invariants on every accepted frame: the payload
pointer stays inside the caller's buffer, the payload length stays within
`MAX_USER_DATA`, and the decoded data length agrees with the datagram. These
are the properties every downstream consumer assumes; if one is ever false, the
fuzzer traps immediately rather than waiting for a consumer to crash.

## Corpus

`tools/seed_corpus.py` writes 26 seeds: every APID in both signed and unsigned
form, the minimum and maximum legal frames, an unknown APID, and six degenerate
inputs (empty, one byte, one below the minimum, all zeroes, all `0xFF`,
oversized). Starting from valid structure means the fuzzer's mutations begin in
the interesting region instead of spending the budget failing the length check.

## Results

Run on 2026-10-28, 120 seconds, clang 17, ASan + UBSan:

```
Done 5532475 runs in 121 second(s)
stat::number_of_executed_units: 5532475
stat::average_exec_per_sec:     45722
stat::new_units_added:          146
stat::peak_rss_mb:              444
cov: 198 ft: 393 corp: 65
```

**5.5 million executions, no crashes, no leaks, no undefined behavior.**
Coverage plateaued at 198 edges early and stayed flat, which is the expected
shape for a parser this small with a well-seeded corpus.

## Validating the harness

A fuzzer that finds nothing is indistinguishable from a fuzzer that is not
reaching the code. So the harness was checked against a known bug.

The two-line bounds check in `decode_command` was removed:

```cpp
if (arg_len > MAX_COMMAND_ARG_LEN) {
    return false;
}
```

Without it, a frame may declare up to 65535 argument bytes, and `memcpy` writes
them into a fixed 64-byte array. The fuzzer found it in **under 90 seconds**:

```
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 255 at 0x7f0c39200114 thread T0
```

This confirms three things that the clean run alone does not: the fuzzer
reaches code behind the MAC check, it reaches the payload decoders, and the
sanitizers are correctly linked and reporting. The check was then restored and
the clean suite re-run.

This is also the honest answer to "did fuzzing find any bugs?" — it did not
find any in the shipped code, and the reason that statement is worth anything
is that the same setup finds a planted bug in 90 seconds.

## What this does not cover

- **The Python ground station.** `SecureLink.open` in Python is memory-safe by
  construction, so the class of bug this hunts for cannot occur there. The
  Python side is covered by unit tests and by the bit-flip test in
  `ground/tests/test_vectors.py`, which checks that every single-bit
  modification to a frame is rejected.
- **Logic bugs that are not memory-safety bugs.** A fuzzer with sanitizers
  finds crashes and undefined behavior. It would not notice if the replay
  window accepted a counter it should have rejected, because nothing crashes.
  Those properties are covered by the unit tests and the cross-implementation
  vectors instead.
- **Timing side channels.** Constant-time comparison is used for the MAC, but
  verifying constant-time behavior needs statistical timing analysis, not
  fuzzing.
- **Longer campaigns.** Two minutes is a smoke test. CI runs a 60-second
  fuzz smoke test on every push and pull request (`.github/workflows/ci.yml`),
  starting from the seed corpus each time. A real program would also run long
  campaigns with a corpus that accumulates between runs.
