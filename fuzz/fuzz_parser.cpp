// libFuzzer harness for the STL-1 receive path.
//
// The target is SecureLink::open, which is the only code an unauthenticated
// attacker can reach: anything arriving on the socket lands here before a
// single security check has passed. A memory-safety bug in this function is
// remote code execution against the flight computer, so it is the right thing
// to point a fuzzer at.
//
// Two things make this harness actually find bugs rather than just burn CPU.
//
// First, the fuzzer is given the *real key*. A fuzzer with no key gets
// rejected at the MAC check every time and can never reach the replay,
// freshness, APID-dispatch or payload-decode code at all — it would explore
// about forty bytes of a parser and report full coverage of nothing. The first
// four bytes of input select a mutation mode; in "sign" mode the harness
// computes a correct MAC over whatever the fuzzer produced, so the fuzzer can
// steer the authenticated region directly.
//
// Second, the payload decoders are called on anything that validates. Parsing
// does not end at `open`; the decoders are part of the attack surface for a
// key holder and for anyone exploiting a bug upstream of them.
//
// Build and run:
//   make fuzz-run FUZZ_SECONDS=120

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "stl/protocol.h"
#include "stl/secure_link.h"

namespace {

constexpr std::size_t MODE_PREFIX = 4U;

void fill_key(std::uint8_t key[stl::HMAC_KEY_SIZE], std::uint8_t base) {
    for (std::size_t i = 0U; i < stl::HMAC_KEY_SIZE; ++i) {
        key[i] = static_cast<std::uint8_t>(base + (i * 7U));
    }
}

// Exercises every decoder the dispatcher could legitimately reach. Results are
// deliberately ignored; the point is that none of these may read out of
// bounds, and the sanitizers decide whether that held.
void exercise_decoders(const stl::ReceivedFrame& frame) {
    stl::Housekeeping hk;
    (void)stl::decode_housekeeping(frame.payload, frame.payload_len, hk);

    stl::Attitude att;
    (void)stl::decode_attitude(frame.payload, frame.payload_len, att);

    stl::CommandAck ack;
    (void)stl::decode_command_ack(frame.payload, frame.payload_len, ack);

    stl::Command cmd;
    if (stl::decode_command(frame.payload, frame.payload_len, cmd)) {
        // Touch the decoded arguments so a bad length is caught by ASan
        // rather than passing silently.
        volatile std::uint8_t sink = 0U;
        for (std::size_t i = 0U; i < cmd.arg_len; ++i) {
            sink = static_cast<std::uint8_t>(sink ^ cmd.args[i]);
        }
        (void)sink;
    }

    // The event payload is length-prefixed and must never be treated as a C
    // string; this mirrors what the ground station does with it.
    if (frame.payload_len >= stl::EVENT_HEADER_SIZE) {
        const std::uint8_t msg_len = frame.payload[1];
        if (static_cast<std::size_t>(msg_len) <= stl::MAX_EVENT_MESSAGE &&
            (frame.payload_len == (stl::EVENT_HEADER_SIZE + msg_len))) {
            volatile std::uint8_t sink = 0U;
            for (std::size_t i = 0U; i < msg_len; ++i) {
                sink = static_cast<std::uint8_t>(
                    sink ^ frame.payload[stl::EVENT_HEADER_SIZE + i]);
            }
            (void)sink;
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < MODE_PREFIX) {
        return 0;
    }

    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    const std::uint8_t mode = data[0];
    const std::uint8_t flags = data[1];

    const std::uint8_t* body = data + MODE_PREFIX;
    std::size_t body_len = size - MODE_PREFIX;
    if (body_len > stl::MAX_FRAME_SIZE) {
        body_len = stl::MAX_FRAME_SIZE;
    }

    // A fresh receiver per input keeps runs independent and reproducible: with
    // shared state a crash would depend on everything the fuzzer happened to
    // send beforehand, and the saved artifact would not reproduce it.
    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);
    rx.enable_freshness_check((flags & 0x01U) != 0U);

    std::uint8_t frame[stl::MAX_FRAME_SIZE];
    std::size_t frame_len = body_len;
    std::memcpy(frame, body, body_len);

    if ((mode & 0x01U) != 0U) {
        // "Sign" mode: recompute a valid MAC so the fuzzer reaches everything
        // behind the authentication check.
        if (frame_len >= stl::MIN_FRAME_SIZE) {
            stl::mac_tag(k_tm, frame, frame_len - stl::MAC_TAG_SIZE,
                         frame + frame_len - stl::MAC_TAG_SIZE);
        }
    }

    if ((mode & 0x02U) != 0U) {
        // "Fix length" mode: make the declared length consistent with the
        // datagram, so the fuzzer is not stuck failing the length check while
        // trying to explore the fields beyond it.
        if (frame_len >= stl::PRIMARY_HEADER_SIZE) {
            const std::size_t data_field = frame_len - stl::PRIMARY_HEADER_SIZE;
            if ((data_field >= 1U) && (data_field <= 0x10000U)) {
                stl::store_be16(frame + 4,
                                static_cast<std::uint16_t>(data_field - 1U));
            }
            // Re-sign, since the length field is inside the MAC's input.
            if (((mode & 0x01U) != 0U) && (frame_len >= stl::MIN_FRAME_SIZE)) {
                stl::mac_tag(k_tm, frame, frame_len - stl::MAC_TAG_SIZE,
                             frame + frame_len - stl::MAC_TAG_SIZE);
            }
        }
    }

    stl::ReceivedFrame received;
    const stl::ParseResult result = rx.open(frame, frame_len, 1700000000000000ULL,
                                            received);

    if (result == stl::ParseResult::Ok) {
        // Invariants that must hold for anything the parser accepts. If any of
        // these is false, a later consumer is about to read out of bounds.
        if (received.payload_len > stl::MAX_USER_DATA) {
            __builtin_trap();
        }
        if ((received.payload < frame) ||
            ((received.payload + received.payload_len) >
             (frame + frame_len - stl::MAC_TAG_SIZE))) {
            __builtin_trap();
        }
        if (received.header.data_length !=
            (frame_len - stl::PRIMARY_HEADER_SIZE)) {
            __builtin_trap();
        }
        exercise_decoders(received);
    }

    return 0;
}
