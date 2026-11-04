# STL-1 Protocol Specification

**Secure Telemetry Link, version 1.** A CCSDS-derived space packet format with
origin authentication and replay protection, carried over UDP.

This document is normative. The C++ flight implementation and the Python ground
implementation are both written against it, and `tools/vectors` plus
`ground/tests/test_vectors.py` prove the two agree byte-for-byte.

---

## 1. Design goals and non-goals

| Goal | Rationale |
|---|---|
| Authenticate every frame in both directions | A spoofed command is the highest-severity failure in a space link. Telemetry is authenticated too, because operators make decisions from it. |
| Reject replayed frames | An attacker who records a valid `SAFE_MODE` command must not be able to re-send it an hour later. |
| Parse only what is authenticated | The MAC is verified before any field in the packet data field is interpreted. This shrinks the attack surface reachable by an unauthenticated attacker to the fixed-size header parse. |
| Bounded memory, bounded work | No heap allocation and no unbounded loops in the receive path. |
| Stay recognizably CCSDS | The primary header is a real CCSDS Space Packet primary header, so the format is legible to anyone who has worked with flight software. |

**Non-goals.** STL-1 does not provide confidentiality. Telemetry content is not
encrypted. This is a deliberate scope choice: authentication and replay defense
are the properties that protect vehicle control, and leaving out encryption
keeps the frame inspectable in ground test equipment. Section 7 describes what
would change if confidentiality were added.

STL-1 is also not a flight-qualified protocol. It is a teaching and research
implementation. See `docs/THREAT_MODEL.md` §6 for the explicit list of
properties it does *not* give you.

---

## 2. Frame layout

All multi-byte integers are **big-endian** (network order), consistent with
CCSDS practice.

```
0        6                  18                        N-16        N
+--------+------------------+-------------------------+-----------+
| Primary| Secondary header |      User data field    |  MAC tag  |
| header |    (12 bytes)    |      (0..1024 bytes)    | (16 bytes)|
|(6 bytes)|                 |                         |           |
+--------+------------------+-------------------------+-----------+
|<------------------ MAC input (N-16 bytes) ---------->|
```

Minimum frame: 34 bytes (6 + 12 + 0 + 16).
Maximum frame: 1058 bytes (6 + 12 + 1024 + 16), chosen to stay inside a
1500-byte Ethernet MTU with room for IP/UDP headers and any tunnel overhead.

### 2.1 Primary header (6 bytes, CCSDS 133.0-B Space Packet)

```
 Byte 0            Byte 1            Byte 2            Byte 3
+-----------------+-----------------+-----------------+-----------------+
|Ver|T|S|   APID (11 bits)          |SeqF |  Sequence count (14 bits)   |
|3b |1|1|                           | 2b  |                             |
+-----------------+-----------------+-----------------+-----------------+
 Byte 4            Byte 5
+-----------------+-----------------+
|   Packet data length (16 bits)    |
+-----------------+-----------------+
```

| Field | Bits | Value in STL-1 |
|---|---|---|
| Version number | 3 | `000` — CCSDS version 1. Any other value is rejected. |
| Packet type (T) | 1 | `0` = telemetry (vehicle to ground), `1` = telecommand (ground to vehicle). Must match the direction the receiver expects. |
| Secondary header flag (S) | 1 | Always `1`. STL-1 always carries a secondary header. A frame with `S=0` is rejected. |
| APID | 11 | Application process ID. See §3. |
| Sequence flags | 2 | Always `11` (unsegmented). STL-1 does not segment packets; a segmented frame is rejected rather than reassembled, because reassembly buffers are a classic memory-safety sink. |
| Sequence count | 14 | Per-APID counter, wraps at 16384. Used for gap detection and operator diagnostics only — **not** for replay defense. |
| Packet data length | 16 | CCSDS convention: `(octets in packet data field) - 1`. The packet data field is everything after byte 5, including the MAC tag. |

**Note on the length field.** CCSDS defines this as length-minus-one, which
means a declared value of `0` is a 1-byte data field, and the field cannot
express an empty data field. STL-1's minimum data field is 28 bytes
(secondary header + MAC), so the smallest legal declared value is 27. The
parser checks this explicitly; off-by-one handling of this field is the single
most likely place for a length bug, so it has dedicated unit tests.

### 2.2 Secondary header (12 bytes)

```
+----------------------------------+---------------------+
| Mission elapsed time (8 bytes)   | Frame counter (4B)  |
|  microseconds since epoch, u64   |   monotonic, u32    |
+----------------------------------+---------------------+
```

- **Mission elapsed time (MET).** Microseconds since mission epoch, as an
  unsigned 64-bit integer. Used for telemetry timestamping and for the
  freshness check in §5.2. Authenticated, so it cannot be altered in flight.
  This implementation uses the Unix epoch as the mission epoch, so that both
  ends share a time base without a separate time-sync protocol. A real mission
  defines its own epoch and distributes time over the link; that changes the
  value in this field and nothing else about the format.
- **Frame counter.** A monotonically increasing per-direction counter. This is
  the replay-defense primitive (§5.1). It is independent of the CCSDS sequence
  count: the sequence count is per-APID and wraps, the frame counter is
  per-direction and does not wrap within a session.

### 2.3 MAC tag (16 bytes)

`HMAC-SHA256(key, primary_header || secondary_header || user_data)`, truncated
to the leftmost 16 bytes.

Truncation to 128 bits is standard practice (RFC 2104 §5 permits it) and halves
the per-frame overhead. At 128 bits the forgery probability is negligible
against any realistic attacker.

Two **separate keys** are used, one per direction:

- `K_TM` authenticates vehicle-to-ground telemetry.
- `K_TC` authenticates ground-to-vehicle commands.

Using distinct keys means a compromised ground receiver cannot be used to forge
commands, and it structurally prevents reflection attacks where a captured
telemetry frame is replayed back as a command.

---

## 3. APID map

| APID | Direction | Name | Payload |
|---|---|---|---|
| `0x001` | TM | `TM_HOUSEKEEPING` | §4.1 |
| `0x002` | TM | `TM_ATTITUDE` | §4.2 |
| `0x003` | TM | `TM_COMMAND_ACK` | §4.3 |
| `0x004` | TM | `TM_EVENT` | §4.4 |
| `0x010` | TC | `TC_COMMAND` | §4.5 |

APIDs outside this set are rejected after MAC verification. An unknown APID is
an authenticated-but-unrecognized frame, which is logged as an anomaly rather
than silently dropped: it usually means a version mismatch between the two
ends, and silently dropping it would make that very hard to debug.

---

## 4. Payload formats

### 4.1 TM_HOUSEKEEPING (24 bytes)

| Offset | Type | Field | Units |
|---|---|---|---|
| 0 | u8 | mode | see §6 |
| 1 | u8 | heater_on | 0 or 1 |
| 2 | u16 | telemetry_rate_hz | Hz |
| 4 | i32 | bus_voltage_mv | millivolts |
| 8 | i32 | bus_current_ma | milliamps |
| 12 | i32 | battery_temp_mc | millidegrees C |
| 16 | i32 | payload_temp_mc | millidegrees C |
| 20 | u32 | uptime_s | seconds |

Fixed-point integers are used throughout rather than floats. Integer
serialization is bit-exact across compilers and architectures, which matters
for a protocol that two independent implementations must agree on. The scaling
factor lives in this spec, not in the wire format.

### 4.2 TM_ATTITUDE (36 bytes)

| Offset | Type | Field | Units |
|---|---|---|---|
| 0 | i32 ×3 | gyro_x/y/z | microradians per second |
| 12 | i32 ×3 | accel_x/y/z | micro-g |
| 24 | i32 ×3 | mag_x/y/z | nanotesla |

### 4.3 TM_COMMAND_ACK (8 bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | u16 | command_id being acknowledged |
| 2 | u32 | frame_counter of the command being acknowledged |
| 6 | u8 | status (§4.6) |
| 7 | u8 | reserved, must be 0 |

Acknowledging by frame counter rather than by sequence count means the ack is
unambiguous even if two identical commands are sent.

### 4.4 TM_EVENT (variable, up to 72 bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | u8 | severity: 0=info, 1=warning, 2=error, 3=critical |
| 1 | u8 | message length, 0..70 |
| 2 | bytes | ASCII message, not NUL-terminated |

The length is explicit and bounded; the message is never treated as a
C string on either side.

### 4.5 TC_COMMAND (4 + argument bytes)

| Offset | Type | Field |
|---|---|---|
| 0 | u16 | command_id (§6) |
| 2 | u16 | argument length, 0..64 |
| 4 | bytes | arguments |

### 4.6 Acknowledgement status codes

| Code | Meaning |
|---|---|
| 0 | `ACCEPTED` |
| 1 | `REJECTED_UNKNOWN_COMMAND` |
| 2 | `REJECTED_BAD_ARGUMENT` |
| 3 | `REJECTED_INVALID_IN_MODE` |

Note that authentication and replay failures produce **no** acknowledgement.
Returning a distinguishable error for a bad MAC would give an attacker an
oracle. Unauthenticated frames are counted and logged locally, and the counters
are reported in telemetry, but nothing is transmitted in response to the
sender.

---

## 5. Receive-path validation

A receiver MUST perform these steps in this order. The ordering is the security
argument: everything before step 6 operates only on fixed-offset fields in a
length-checked buffer, and nothing in the variable-length region is interpreted
until the MAC has been verified.

1. **Datagram length bounds.** Reject if `len < 34` or `len > 1058`.
2. **Primary header decode.** Fixed 6-byte read. Reject on: version ≠ 0,
   secondary header flag ≠ 1, sequence flags ≠ 3, packet type not matching the
   expected direction.
3. **Declared length consistency.** Reject unless
   `declared_length + 1 + 6 == len`. The declared length must describe the
   datagram exactly. A frame with trailing bytes is rejected rather than
   truncated, because accepting it would let an attacker append data that one
   implementation ignores and another parses.
4. **Minimum data field.** Reject if `declared_length + 1 < 28`.
5. **MAC verification.** Compute HMAC-SHA256 over the first `len - 16` bytes
   with the direction's key. Compare against the trailing 16 bytes in
   **constant time**. Reject on mismatch.
6. **Freshness check.** Apply §5.2. Reject on failure.
7. **Replay check.** Apply §5.1. Reject on failure.
8. **APID dispatch and payload decode.** Only now is the payload interpreted,
   and the decoder checks the payload length against the exact expected length
   for that APID before reading any field.

**Why freshness precedes replay.** The replay check mutates receiver state and
the freshness check does not. If replay ran first, an authenticated frame
carrying a far-future counter and a stale timestamp would advance the window
before being rejected, and subsequent legitimate frames would fail as
`ReplayTooOld`. Running the stateless check first means window state is only
ever touched by frames the receiver is otherwise willing to accept. Both checks
sit behind MAC verification, so reaching either one already requires the key;
the ordering is about not letting a rejected frame leave state behind.

### 5.1 Anti-replay window

A sliding window, modeled on the IPsec anti-replay scheme (RFC 4303 §3.4.3),
sized at 64 frames and held in a single `uint64_t` bitmap.

Let `H` be the highest frame counter accepted so far, `W = 64`, and `C` the
counter of the frame under test.

- If `C > H`: accept. Shift the bitmap left by `C - H`, set bit 0, set `H = C`.
  A shift of 64 or more clears the window entirely.
- If `C == H`: reject as a duplicate.
- If `H - C >= W`: reject as too old. The frame is outside the window and the
  receiver cannot prove it has not already been seen.
- Otherwise the frame is inside the window. Reject if bit `H - C` is already
  set (duplicate), else accept and set that bit.

The window tolerates reordering, which a UDP link will produce naturally, while
guaranteeing that no counter is accepted twice. A window of 64 is comfortable
for a link running at tens of hertz; it is a `constexpr` and can be widened to
any multiple of 64 by changing the bitmap type.

The window state is **not** persisted across a receiver restart. For a flight
system that matters, and the mitigation is in `docs/THREAT_MODEL.md` §4.3.

### 5.3 Transmit counter persistence

A sender MUST NOT restart its frame counter at zero. The replay window has no
way to distinguish a restarted sender from an attacker replaying captured
traffic, so a volatile counter makes a legitimate sender lock itself out after
any restart. This was not a theoretical concern during development: running the
ground station twice against one flight computer caused every command from the
second run to be rejected as `REPLAY_DUPLICATE`.

Both implementations therefore reserve counters in blocks:

1. At startup, read the persisted high-water mark `H`.
2. Write `H + BLOCK` back to durable storage, **before** using any counter
   from the block. The write must be atomic: write a temporary file, fsync
   it, rename it over the state file, and fsync the directory, so a crash
   never leaves a truncated mark.
3. Hand out `H … H+BLOCK-1` from memory.
4. On exhaustion, reserve the next block.

A state file that exists but does not hold a valid mark MUST cause the
sender to refuse to start. Only an absent file means first run; treating a
corrupt file as zero would reuse counters, which is the failure this section
exists to prevent.

Persisting before use is the essential ordering. If the process dies mid-block,
storage already claims the whole block as spent, so the next run starts above
every counter that could have been transmitted. The cost is skipped counters
after a crash, which the window absorbs as an ordinary forward jump. Persisting
*after* sending would reuse counters after a crash, which is precisely the
failure being prevented.

The counter is 32 bits and does not wrap. On exhaustion the sender stops and
reports that the link must be rekeyed, rather than wrapping into counter values
the receiver has already retired.

A receiver that restarts re-anchors its window on the first frame it accepts.
That is a real and deliberate limitation, covered in `docs/THREAT_MODEL.md`
§4.3.

### 5.2 Freshness

A frame whose MET differs from the receiver's clock by more than
`FRESHNESS_WINDOW_US` (default 30 seconds) is rejected.

This is a defense-in-depth layer, not the primary replay defense. It bounds the
damage if an attacker finds a way to desynchronize the counter state, and it
catches grossly stale frames held by an attacker for later delivery. It assumes
loosely synchronized clocks, which is a weaker assumption than it sounds —
30 seconds is generous, and real spacecraft links have far better time sync
than that. Receivers with no trustworthy clock may disable the check; the
flight implementation disables it until it has received its first time sync.

---

## 6. Command set and mode state machine

| ID | Command | Argument | Valid in modes |
|---|---|---|---|
| `0x0001` | `NOOP` | none | all |
| `0x0002` | `PING` | none | all |
| `0x0003` | `SET_MODE` | u8 mode | all |
| `0x0004` | `SET_TM_RATE` | u16 Hz, 1..50 | IDLE, NOMINAL |
| `0x0005` | `SET_HEATER` | u8 0/1 | IDLE, NOMINAL |
| `0x0006` | `SAFE_MODE` | none | all |

Modes: `0 = BOOT`, `1 = IDLE`, `2 = NOMINAL`, `3 = SAFE`.

In `SAFE` mode the vehicle accepts only `NOOP`, `PING`, `SET_MODE`, and
`SAFE_MODE`. Rate and heater commands are rejected with
`REJECTED_INVALID_IN_MODE`. The telemetry rate is forced to 1 Hz and the heater
is forced on, which is the usual shape of a safe-mode policy: minimize power
and keep the vehicle thermally alive while an operator works out what happened.

---

## 7. Key management

Keys are 32 bytes each, generated by `tools/gen_keys.py` from the OS CSPRNG and
written to `keys/stl_keys.bin` with mode `0600`. Both ends load the same file.

This is the weakest part of the design and the spec says so plainly. A
pre-shared symmetric key in a file is appropriate for a ground testbed and
inappropriate for a vehicle. A real system needs key diversification per
vehicle, a rekeying mechanism, keys held in hardware that cannot export them,
and a key ladder so that a compromise of one key does not compromise the
mission. `docs/THREAT_MODEL.md` §5 treats this as the primary residual risk.

If confidentiality were added, the right move would be to replace the
HMAC trailer with an AEAD construction (AES-GCM or ChaCha20-Poly1305) using the
frame counter as the nonce, rather than bolting encryption alongside the
existing MAC. Encrypt-then-MAC composed by hand is a well-known source of
error, and the counter is already a unique, authenticated, never-repeating
value, which is exactly what an AEAD nonce requires.

---

## 8. Transport

UDP. The vehicle listens on port 50001, the ground station on 50002, both on
localhost by default.

UDP is the right analogue for a space link: datagram-oriented, lossy,
unordered, no handshake. Using TCP would paper over exactly the conditions the
protocol needs to handle, and would add head-of-line blocking that a real
telemetry stream cannot tolerate. Loss and reordering are handled by the
sequence count (gap detection) and the replay window (reorder tolerance).
