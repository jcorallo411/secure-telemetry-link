# STL-1 Threat Model

A threat model is only useful if it is honest about what the system does not
do. §6 is the list of properties this design does not provide, and it is the
most important section here.

---

## 1. System description

Two endpoints exchange UDP datagrams over an untrusted network:

```
   ┌──────────────────┐                      ┌──────────────────┐
   │ Flight computer  │  ── telemetry ───▶   │  Ground station  │
   │  (C++)           │                      │  (Python)        │
   │                  │  ◀── commands ────   │                  │
   │  sensors, mode   │                      │  display, log,   │
   │  state machine   │                      │  command entry   │
   └──────────────────┘                      └──────────────────┘
          K_TM signs ──┘                        └── K_TC signs
```

**Assets, in priority order:**

1. **Vehicle control.** The ability to command the vehicle. Compromise here
   can end a mission.
2. **Telemetry integrity.** Operators make decisions from telemetry. Falsified
   readings cause wrong decisions, which can be as damaging as a forged
   command.
3. **Key material.** Compromise of `K_TC` yields asset 1; compromise of
   `K_TM` yields asset 2.
4. **Availability.** Degraded, but not catastrophic on its own, since the link
   is expected to be intermittent anyway.

**Trust boundary.** Everything between the two endpoints is untrusted. Both
endpoints themselves are trusted; §5 covers what happens when that assumption
fails.

---

## 2. Adversaries

| # | Adversary | Capabilities | In scope |
|---|---|---|---|
| A1 | Passive eavesdropper | Observes all traffic | Yes |
| A2 | Active network attacker | Injects, modifies, drops, delays, reorders, replays | Yes — the primary adversary |
| A3 | Insider with key access | Holds a valid key | Partly — §5 |
| A4 | Supply chain | Compromises the build or a dependency | Partly — §6 |
| A5 | Physical access to the vehicle | Extracts keys from hardware | No |
| A6 | Signals-layer attacker | Jamming, RF spoofing, orbital interception | No |

A2 is the adversary the protocol is designed against: someone who can do
anything they like to packets in flight but does not hold a key.

---

## 3. STRIDE analysis

### Spoofing

| Threat | Mitigation | Verified by |
|---|---|---|
| Forged command to the vehicle | HMAC-SHA256 over the whole frame with `K_TC`; verification precedes any payload interpretation | `tools/attack.py --attack spoof`; `test_parser_rejections` |
| Forged telemetry to the ground | Same, with `K_TM` | `test_no_modification_survives_authentication` |
| Telemetry reflected back as a command | Separate keys per direction make this structurally impossible; the direction bit also mismatches and is rejected as `WRONG_DIRECTION` | `tools/attack.py --attack reflect` |

**Residual risk:** a valid key forges anything. §5.

### Tampering

| Threat | Mitigation | Verified by |
|---|---|---|
| Modifying any field in flight | The MAC covers the primary header, secondary header, and payload — not just the payload | Exhaustive single-bit-flip test over every bit of a frame |
| Truncating or extending a frame | The declared length must describe the datagram exactly; trailing bytes are rejected, not ignored | `test_trailing_bytes_rejected`, `test_truncation_rejected_at_every_length` |
| Exploiting the parser with malformed input | Ordered validation; no heap allocation in the parse path; every decoder checks exact length | 5.5M fuzz executions under ASan/UBSan |

### Repudiation

Out of scope in the usual sense (there is one vehicle and one operator), but
the ground station writes every accepted frame to a JSONL log with its frame
counter and MET, which gives a reconstructable record of what was commanded
and what came back.

**Residual risk:** logs are local and unsigned. An attacker who compromises the
ground host can rewrite history.

### Information disclosure

| Threat | Status |
|---|---|
| Reading telemetry contents | **Not mitigated.** STL-1 provides no confidentiality. A passive eavesdropper reads every value. This is a deliberate scope choice, not an oversight — see `docs/PROTOCOL.md` §1 and §7. |
| Key recovery via MAC timing | Mitigated: constant-time comparison on both sides (`constant_time_equal`, `hmac.compare_digest`) |
| Error messages as an oracle | Mitigated: the vehicle sends **no** response to a frame that fails authentication, replay, or freshness. Reasons are logged locally and surfaced only as aggregate counters in authenticated telemetry. |

### Denial of service

| Threat | Mitigation | Residual |
|---|---|---|
| Flooding with forged frames | Rejection costs one HMAC over at most 1058 bytes. Measured at 54,000 forged frames per second sent with no effect on vehicle behavior. | A sufficiently large flood still saturates the link. Not solvable at this layer. |
| Oversized datagrams | Bounded at `MAX_FRAME_SIZE`; larger ones truncate and fail the length check | — |
| Zero-length datagrams | Parsed and counted like any other frame. (This was initially swallowed by the socket layer, which conflated an empty datagram with a timeout; fixed so that it is rejected *and* appears in the counters.) | — |
| Replay flood | Window check is O(1) and happens after the MAC | — |
| Jamming | Out of scope (A6) | — |

### Elevation of privilege

| Threat | Mitigation |
|---|---|
| Commands invalid for the current mode | Mode state machine rejects them with `REJECTED_INVALID_IN_MODE`; verified end to end |
| Out-of-range arguments | Range-checked before application (`SET_TM_RATE` bounded 1–50 Hz, `SET_MODE` bounded to defined modes) |
| Memory corruption to hijack control flow | Bounded buffers, no dynamic allocation in the parse path, built with `-Werror -Wconversion`, stack protector, FORTIFY_SOURCE; fuzzed under ASan/UBSan |

---

## 4. Specific attacks and their handling

### 4.1 Replay

An attacker records a valid `SAFE_MODE` command and re-sends it later. The MAC
is correct, because it is a genuine frame.

Stopped by the 64-frame sliding window on the authenticated frame counter
(`docs/PROTOCOL.md` §5.1), backed by the freshness check on the authenticated
timestamp. Demonstrated by `tools/attack.py --attack replay`.

### 4.2 Delayed delivery

An attacker holds a valid frame and delivers it much later, within the replay
window's blind spot after a receiver restart.

Stopped by the freshness check: a frame whose MET differs from the receiver's
clock by more than 30 seconds is rejected. Demonstrated by
`tools/attack.py --attack stale`.

### 4.3 Receiver restart (known limitation)

**This is the weakest link in the replay defense and it deserves a plain
statement.**

The replay window is held in RAM. A receiver that restarts re-anchors on the
first frame it accepts. An attacker who can (a) predict or cause a receiver
restart and (b) deliver a captured frame before the legitimate sender does can
anchor the window at a counter of their choosing, and that captured frame is
accepted.

Three things limit it. The freshness check rejects anything more than 30
seconds old, so only recently captured frames are usable. The attacker must
win a race against the real sender. And the sender's counter persists
(§4.4), so after the attacker's frame the legitimate sender's higher counters
are still accepted — the window is anchored low, not poisoned.

Proper fixes, in increasing order of cost: persist the receiver's window
across restarts; add a session-establishment handshake with a fresh nonce on
each boot; require a time sync before enabling the command path.

### 4.4 Sender restart

A sender whose counter restarts at zero is indistinguishable from a replay
attacker, and the receiver correctly rejects it — locking out the legitimate
sender.

This was found during development rather than designed around: running the
ground station twice against one flight computer caused every command from the
second run to be rejected as `REPLAY_DUPLICATE`. Fixed with persistent counter
block reservation on both sides (`docs/PROTOCOL.md` §5.3). The regression is
pinned by `test_counter_store_persistence` and
`test_link_rejects_zero_counter_restart`, the latter of which documents the
original broken behavior so it cannot quietly return.

A later review found the fix could be undone by a crash mid-write: the C++
side truncated the state file before writing it, and both sides treated a
short file as a first run. The write is now atomic (temp file, fsync, rename,
directory fsync) and a corrupt state file stops startup instead of restarting
at zero. Pinned by `test_counter_store_fails_closed_on_corrupt_state` and
`test_counter_store_write_is_atomic`.

### 4.5 Key exhaustion

The frame counter is 32 bits and does not wrap. At 50 Hz, exhaustion takes
roughly 2.7 years of continuous transmission. On exhaustion the sender stops
and reports that the link must be rekeyed, rather than wrapping into counters
the receiver has already retired.

---

## 5. Primary residual risk: key management

**Pre-shared symmetric keys in a file on disk.** This is appropriate for a
ground testbed and inappropriate for a vehicle.

What is actually done: 32-byte keys from the OS CSPRNG, separate per direction,
stored `0600`, with both implementations refusing to load a key file that is
group- or world-accessible, that is all zeroes, or whose two keys are
identical.

What is missing, and would be required for anything real:

- **Per-vehicle key diversification.** One key compromise currently
  compromises every vehicle sharing the file.
- **Rekeying.** There is no way to roll a key without manual redistribution.
- **Hardware key storage.** Keys live in process memory and can be read from a
  core dump or by any process with debug privileges.
- **A key ladder.** A single key for the lifetime of a mission violates
  everything known about key lifetime management.
- **Authenticated key establishment.** There is no handshake, so there is no
  forward secrecy and no session binding.

An insider holding `K_TC` can issue any command the protocol allows. Nothing in
this design mitigates that, and it would be dishonest to claim otherwise.

---

## 6. What this system does NOT provide

Stated plainly, because a security document that only lists mitigations is
marketing.

1. **No confidentiality.** All telemetry is readable by anyone on the path.
2. **No protection against a key holder.** Key compromise is total compromise
   for that direction.
3. **No protection against endpoint compromise.** An attacker with code
   execution on either host has already won.
4. **No forward secrecy.** A key recovered later decrypts — or rather,
   authenticates — everything ever recorded.
5. **No availability guarantee.** Jamming and link saturation are out of scope.
6. **No supply-chain assurance.** The build is not reproducible and
   dependencies are not pinned by hash.
7. **No formal verification.** Fuzzing and tests raise confidence; they do not
   prove absence of bugs.
8. **Not flight-qualified.** No radiation tolerance, no single-event-upset
   handling, no redundancy, no DO-178C or NASA software-assurance process, no
   independent V&V. The coding style borrows from MISRA C and NASA's Power of
   Ten; borrowing a style is not the same as meeting a standard.
9. **The cryptography is self-implemented.** SHA-256 and HMAC are written from
   the specification here, which is appropriate for a dependency-free flight
   build and for demonstrating understanding. It is not what should ship: a
   real system uses an audited, constant-time, side-channel-hardened library.
   The implementation is checked against FIPS 180-4 vectors and against
   Python's `hashlib`/`hmac`, which establishes functional correctness and
   nothing about side-channel resistance.
10. **No protection of logs or stored state.** The counter state file and the
    telemetry logs are unsigned and world-readable. The counter file is
    written atomically and a corrupt one is refused, but nothing stops an
    attacker with write access to it from rolling it back.

---

## 7. Assurance summary

| Activity | Result |
|---|---|
| Unit tests (C++) | 563 checks, 0 failures |
| Unit tests (Python) | 42 tests, 0 failures |
| Cross-implementation vectors | 8 frames, byte-identical between C++ and Python |
| Exhaustive bit-flip test | Every single-bit modification of a frame rejected |
| ASan + UBSan on the full suite | Clean |
| Fuzzing | 5.5M executions, 0 crashes |
| Fuzzer validated against a planted bug | Stack overflow found in under 90 seconds |
| Compiler warnings | `-Wall -Wextra -Wpedantic -Wconversion -Werror`, clean |
| Attack demonstrations | 7 attack classes, all rejected with the expected reason |

## 8. If this were going further

In priority order:

1. Replace the hand-written crypto with an audited library (libsodium or
   mbedTLS) behind the same interface.
2. Add an authenticated session handshake, which fixes §4.3 and gives forward
   secrecy.
3. Move to an AEAD (ChaCha20-Poly1305 or AES-GCM) with the frame counter as
   the nonce, adding confidentiality without hand-composing two primitives.
4. Persist the receiver's replay window.
5. Run the fuzzer continuously in CI with an accumulating corpus.
6. Add key diversification and a rekeying path.
