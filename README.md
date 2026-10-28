# Secure Telemetry Link (STL-1)

An authenticated spacecraft telemetry and command link: a C++ flight computer,
a Python ground station, and a CCSDS-derived packet protocol with message
authentication and replay protection between them.

Every frame in both directions is authenticated with HMAC-SHA256 and protected
against replay by a sliding-window counter. The parser is fuzzed. The two
independent implementations are proven to agree byte-for-byte.

```
   ┌──────────────────┐                        ┌──────────────────┐
   │ Flight computer  │  ──── telemetry ────▶  │  Ground station  │
   │       C++17      │                        │     Python 3     │
   │                  │  ◀──── commands ─────  │                  │
   │ sensor model     │                        │ live display     │
   │ mode state m/c   │        UDP             │ JSONL logging    │
   │ zero deps        │                        │ command uplink   │
   └──────────────────┘                        └──────────────────┘
        signs with K_TM                             signs with K_TC
        verifies with K_TC                          verifies with K_TM
```

---

## Quick start

```sh
make                              # build flight computer + vector generator
python3 tools/gen_keys.py         # generate the pre-shared key file
mkdir -p state logs

./build/flight_computer &         # start the vehicle
python3 ground/station.py         # live ground station display
```

Send a command:

```sh
python3 ground/station.py --send PING
python3 ground/station.py --send SET_TM_RATE:5
python3 ground/station.py --send SAFE_MODE
python3 ground/station.py --send SET_HEATER:0   # rejected while in SAFE mode
```

Watch the defenses work:

```sh
python3 tools/attack.py --all     # 7 attack classes, all rejected
```

Run everything:

```sh
make check                        # C++ tests, sanitizers, vectors, Python tests
make fuzz-run FUZZ_SECONDS=120    # fuzz the parser
```

---

## What it does

**Flight side (C++17, no external dependencies).** Simulates a vehicle: a
sensor model with thermal lag, a load-dependent power bus and a slow spin,
driving housekeeping and attitude telemetry at a commandable rate. Accepts
authenticated commands, enforces a mode state machine, and acknowledges each
one. SHA-256 and HMAC are implemented from the specification so a flight build
depends on nothing but a compiler.

**Ground side (Python 3, standard library only).** Receives and validates
telemetry, renders a live terminal panel, writes JSONL telemetry logs and a
separate event log, and uplinks commands with argument validation.

**Between them, STL-1:** a real CCSDS Space Packet primary header, a 12-byte
secondary header carrying mission time and a monotonic frame counter, the
payload, and a 16-byte truncated HMAC-SHA256 tag. Full specification in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

---

## Design decisions worth explaining

**Authenticate before parsing anything variable-length.** The receive pipeline
is strictly ordered: datagram bounds, fixed-offset header fields, declared
length consistency, MAC verification, freshness, replay, then APID dispatch and
payload decode. Everything before the MAC check touches only fixed offsets in a
length-checked buffer. The surface an unauthenticated attacker can reach is
about forty bytes of header parsing, and that is the point.

**Separate keys per direction.** `K_TM` authenticates telemetry, `K_TC`
authenticates commands. A compromised ground receiver cannot be turned around
to forge commands, and reflection attacks — replaying a telemetry frame back as
a command — are structurally impossible rather than merely checked for.

**Silence on rejection.** The vehicle sends nothing in response to a frame that
fails authentication, replay, or freshness. A distinguishable error would be an
oracle telling an attacker which guess got further. Rejections are counted by
reason and reported in authenticated telemetry, so an operator can see an
attack without an attacker learning anything.

**Freshness is checked before replay.** The replay check mutates the window;
the freshness check does not. In the other order, an authenticated frame with a
far-future counter and a stale timestamp would advance the window before being
rejected, and legitimate traffic would then fail as `ReplayTooOld`. The
stateless check runs first so window state is only touched by frames the
receiver is otherwise willing to accept.

**Integers, not floats, on the wire.** Fixed-point integers serialize
identically across compilers and architectures. Scaling factors live in the
specification, not in the format. A protocol two independent implementations
must agree on is the wrong place for floating-point representation questions.

**UDP, not TCP.** Datagram-oriented, lossy, unordered, no handshake — the right
analogue for a space link. TCP would hide exactly the conditions the protocol
needs to handle and add head-of-line blocking a telemetry stream cannot
tolerate. Loss shows up as sequence gaps; reordering is absorbed by the replay
window.

**Two implementations, deliberately not a port.** The Python side was written
from the specification rather than translated from the C++. Two independent
implementations expose ambiguities in the spec that one implementation would
silently paper over, and `tools/vectors.cpp` plus
`ground/tests/test_vectors.py` prove they produce identical bytes.

---

## What went wrong during development

**The replay window locked out the legitimate sender.** Running the ground
station twice against one flight computer caused every command from the second
run to be rejected as `REPLAY_DUPLICATE`. Each `station.py` invocation is a
fresh process, so its frame counter restarted at zero — and a sender that
restarts its counter is, to the receiver, indistinguishable from an attacker
replaying old traffic.

The replay window was behaving correctly. The design was wrong. The fix is
counter block reservation, the same technique used for monotonic counters in
secure boot: persist `H + BLOCK` to durable storage *before* using any counter
from the block, so a crash skips counters rather than reusing them. Writing
after sending instead of before would reuse counters after a crash, which is
precisely the failure being prevented. Both implementations now do this
(`docs/PROTOCOL.md` §5.3), and
`test_link_rejects_zero_counter_restart` pins the original broken behavior so
it cannot quietly return.

**Zero-length datagrams were invisible.** The socket wrapper returned `0` for
both a timeout and a zero-length datagram, so empty UDP packets never reached
the parser and never appeared in the rejection counters — an attacker could
flood them and leave no trace in the statistics. Found by noticing that an
attack sending 9 malformed frames produced only 8 rejections. Timeout and error
are now negative, and a zero-length datagram is parsed and counted like
anything else.

---

## Verification

| | |
|---|---|
| C++ unit tests | 536 checks, 0 failures |
| Python unit tests | 38 tests, 0 failures |
| Cross-implementation vectors | 8 frames, byte-identical C++ vs Python |
| Bit-flip coverage | Every single-bit change to a frame is rejected |
| ASan + UBSan | Clean on the full suite |
| Fuzzing | 5.5M executions, 0 crashes |
| Fuzzer validated | Finds a planted bounds bug in under 90 seconds |
| Compiler | `-Wall -Wextra -Wpedantic -Wconversion -Werror`, clean |
| Attacks demonstrated | 7 classes, all rejected with the expected reason |

SHA-256 is checked against the FIPS 180-4 vectors including the one-million-byte
case, and HMAC against Python's `hmac` module.

**On the fuzzer.** The harness is given the real key. Without it, every input
is rejected at the MAC check and the fuzzer never reaches the replay window,
the freshness check, or any payload decoder — it would report a healthy
execution rate while exploring forty bytes of header. The corresponding threat
model is an attacker who has compromised the ground segment: the parser should
not be exploitable even by someone holding the key. And because a fuzzer that
finds nothing is indistinguishable from a fuzzer that is not reaching the code,
the harness was validated by deleting a bounds check and confirming it found
the resulting stack overflow in under 90 seconds. Details in
[`docs/FUZZING.md`](docs/FUZZING.md).

---

## Limitations

The full list is [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §6. The ones
that matter most:

- **No confidentiality.** Telemetry is authenticated, not encrypted. A passive
  observer reads every value. This is a scope choice, and §7 of the protocol
  spec describes what adding it should look like (an AEAD with the frame
  counter as nonce, not encryption bolted alongside the existing MAC).
- **Pre-shared keys in a file.** Fine for a testbed, wrong for a vehicle. No
  diversification, no rekeying, no hardware key storage.
- **The receiver's replay window is not persisted.** A receiver that restarts
  re-anchors on the first frame it accepts, which opens a narrow race described
  in threat model §4.3.
- **The cryptography is self-implemented.** Correct against the published
  vectors; not side-channel hardened. A real system uses an audited library.
- **Not flight-qualified.** The coding style borrows from MISRA C and NASA's
  Power of Ten. Borrowing a style is not meeting a standard.

---

## Layout

```
flight/          C++17 flight computer
  include/stl/   sha256, hmac, protocol, replay, secure_link,
                 counter_store, sensors, keys, udp
  src/           implementations + main
  tests/         536-check unit suite
ground/          Python 3 ground station
  stl/           protocol, replay, secure_link, counter_store, keys
  station.py     receiver, live display, command uplink
  tests/         unit tests + cross-implementation vectors
fuzz/            libFuzzer harness and seed corpus
tools/           gen_keys.py, vectors.cpp, seed_corpus.py, attack.py
docs/            PROTOCOL.md, THREAT_MODEL.md, FUZZING.md
```

## Make targets

| Target | Does |
|---|---|
| `make` | Build the flight computer and the vector generator |
| `make test` | C++ unit tests |
| `make asan` | The same tests under ASan + UBSan |
| `make vectors` | Print the cross-implementation test vectors |
| `make check` | Everything above plus the Python tests |
| `make fuzz-run` | Build and run the fuzzer (`FUZZ_SECONDS=N`) |
| `make clean` | Remove build artifacts |

## Requirements

- A C++17 compiler (tested with GCC 13)
- Python 3.9 or newer, standard library only; `pytest` for the tests
- For fuzzing: clang with compiler-rt (`libclang-rt-N-dev` on Debian/Ubuntu)
- Linux or macOS (uses POSIX sockets)

`keys/` and `state/` hold secrets and link state. Neither belongs in version
control.
