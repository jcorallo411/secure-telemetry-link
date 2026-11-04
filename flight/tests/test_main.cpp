// Flight-side unit tests.
//
// A deliberately tiny harness rather than a framework: the flight library has
// no external dependencies, and the tests should not introduce one.

#include <cstdio>
#include <cstring>
#include <string>

#include "stl/counter_store.h"
#include "stl/hmac.h"
#include "stl/protocol.h"
#include "stl/replay.h"
#include "stl/secure_link.h"
#include "stl/sha256.h"

namespace {

int g_checks = 0;
int g_failures = 0;
const char* g_current_test = "";

void check(bool condition, const char* expr, int line) {
    g_checks += 1;
    if (!condition) {
        g_failures += 1;
        std::printf("  FAIL  %s:%d  %s\n", g_current_test, line, expr);
    }
}

#define CHECK(expr) check((expr), #expr, __LINE__)
#define TEST(name)                     \
    g_current_test = name;             \
    std::printf("  %s\n", name);

void fill_key(std::uint8_t key[stl::HMAC_KEY_SIZE], std::uint8_t base) {
    for (std::size_t i = 0U; i < stl::HMAC_KEY_SIZE; ++i) {
        key[i] = static_cast<std::uint8_t>(base + (i * 7U));
    }
}

std::string to_hex(const std::uint8_t* d, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2U);
    for (std::size_t i = 0U; i < n; ++i) {
        s.push_back(digits[d[i] >> 4]);
        s.push_back(digits[d[i] & 0x0FU]);
    }
    return s;
}

// ---------------------------------------------------------------------------

void test_sha256_known_vectors() {
    TEST("sha256 known vectors (FIPS 180-4)");
    std::uint8_t out[stl::SHA256_DIGEST_SIZE];

    stl::Sha256::hash(nullptr, 0U, out);
    CHECK(to_hex(out, sizeof(out)) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const char* abc = "abc";
    stl::Sha256::hash(reinterpret_cast<const std::uint8_t*>(abc), 3U, out);
    CHECK(to_hex(out, sizeof(out)) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // 56 bytes: exercises the padding path where the length does not fit in
    // the final block and a second block is required.
    const char* two_block =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    stl::Sha256::hash(reinterpret_cast<const std::uint8_t*>(two_block),
                      std::strlen(two_block), out);
    CHECK(to_hex(out, sizeof(out)) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // One million 'a': exercises multi-block streaming and the 64-bit length.
    {
        stl::Sha256 ctx;
        std::uint8_t chunk[1000];
        std::memset(chunk, 'a', sizeof(chunk));
        for (int i = 0; i < 1000; ++i) {
            ctx.update(chunk, sizeof(chunk));
        }
        ctx.finish(out);
        CHECK(to_hex(out, sizeof(out)) ==
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }
}

void test_sha256_streaming_equals_oneshot() {
    TEST("sha256 streaming matches one-shot at every split point");
    std::uint8_t data[200];
    for (std::size_t i = 0U; i < sizeof(data); ++i) {
        data[i] = static_cast<std::uint8_t>(i * 3U);
    }

    std::uint8_t reference[stl::SHA256_DIGEST_SIZE];
    stl::Sha256::hash(data, sizeof(data), reference);

    // Splitting the input anywhere must not change the digest. This is where
    // buffering bugs live.
    for (std::size_t split = 0U; split <= sizeof(data); ++split) {
        std::uint8_t out[stl::SHA256_DIGEST_SIZE];
        stl::Sha256 ctx;
        ctx.update(data, split);
        ctx.update(data + split, sizeof(data) - split);
        ctx.finish(out);
        CHECK(std::memcmp(out, reference, sizeof(out)) == 0);
    }
}

void test_constant_time_equal() {
    TEST("constant-time comparison");
    std::uint8_t a[16];
    std::uint8_t b[16];
    std::memset(a, 0x5A, sizeof(a));
    std::memcpy(b, a, sizeof(b));

    CHECK(stl::constant_time_equal(a, b, sizeof(a)));

    for (std::size_t i = 0U; i < sizeof(a); ++i) {
        b[i] ^= 0x01U;
        CHECK(!stl::constant_time_equal(a, b, sizeof(a)));
        b[i] ^= 0x01U;
    }
    CHECK(stl::constant_time_equal(a, b, sizeof(a)));
}

void test_replay_window() {
    TEST("replay window");
    {
        stl::ReplayWindow w;
        CHECK(w.check_and_update(0U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(0U) == stl::ReplayVerdict::Duplicate);
        CHECK(w.check_and_update(1U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(1U) == stl::ReplayVerdict::Duplicate);
    }
    {
        // Reordering within the window is tolerated, each counter once.
        stl::ReplayWindow w;
        CHECK(w.check_and_update(10U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(13U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(11U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(12U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(11U) == stl::ReplayVerdict::Duplicate);
        CHECK(w.check_and_update(13U) == stl::ReplayVerdict::Duplicate);
        CHECK(w.highest() == 13U);
    }
    {
        // Exactly at the window edge, and one step beyond it.
        stl::ReplayWindow w;
        CHECK(w.check_and_update(100U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(100U + stl::REPLAY_WINDOW_SIZE - 1U) ==
              stl::ReplayVerdict::Accept);
        // 100 is now exactly WINDOW_SIZE-1 behind the highest: still inside.
        CHECK(w.check_and_update(100U) == stl::ReplayVerdict::Duplicate);
        // Push one further so 100 falls out of the window entirely.
        CHECK(w.check_and_update(100U + stl::REPLAY_WINDOW_SIZE) ==
              stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(100U) == stl::ReplayVerdict::TooOld);
    }
    {
        // A jump clear past the window must not leave stale bits set, which
        // would wrongly reject a fresh counter as a duplicate.
        stl::ReplayWindow w;
        CHECK(w.check_and_update(5U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(5000U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(4999U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(4999U) == stl::ReplayVerdict::Duplicate);
        CHECK(w.check_and_update(5U) == stl::ReplayVerdict::TooOld);
    }
    {
        // Counter near the 32-bit maximum: no overflow in the age arithmetic.
        stl::ReplayWindow w;
        CHECK(w.check_and_update(0xFFFFFFF0U) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(0xFFFFFFFFU) == stl::ReplayVerdict::Accept);
        CHECK(w.check_and_update(0xFFFFFFF0U) == stl::ReplayVerdict::Duplicate);
    }
}

void test_seal_open_round_trip() {
    TEST("seal/open round trip");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);
    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);

    std::uint8_t payload[stl::HOUSEKEEPING_PAYLOAD_SIZE];
    stl::Housekeeping hk;
    hk.mode = 2U;
    hk.heater_on = 1U;
    hk.telemetry_rate_hz = 4U;
    hk.bus_voltage_mv = 27850;
    hk.bus_current_ma = 1432;
    hk.battery_temp_mc = -4250;
    hk.payload_temp_mc = 12750;
    hk.uptime_s = 86399U;
    stl::encode_housekeeping(hk, payload);

    std::uint8_t frame[stl::MAX_FRAME_SIZE];
    const std::size_t n = tx.seal(stl::APID_TM_HOUSEKEEPING, payload,
                                  sizeof(payload), 1700000000000000ULL, frame,
                                  sizeof(frame));
    CHECK(n == (stl::HEADER_SIZE + sizeof(payload) + stl::MAC_TAG_SIZE));

    stl::ReceivedFrame got;
    CHECK(rx.open(frame, n, 1700000000000000ULL, got) == stl::ParseResult::Ok);
    CHECK(got.header.apid == stl::APID_TM_HOUSEKEEPING);
    CHECK(got.payload_len == sizeof(payload));

    stl::Housekeeping decoded;
    CHECK(stl::decode_housekeeping(got.payload, got.payload_len, decoded));
    CHECK(decoded.bus_voltage_mv == hk.bus_voltage_mv);
    CHECK(decoded.battery_temp_mc == hk.battery_temp_mc);  // negative survives
    CHECK(decoded.uptime_s == hk.uptime_s);
}

void test_parser_rejections() {
    TEST("parser rejects malformed frames");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);
    std::uint8_t good[stl::MAX_FRAME_SIZE];
    std::uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::size_t good_len =
        tx.seal(stl::APID_TM_EVENT, payload, sizeof(payload), 1000ULL, good,
                sizeof(good));
    CHECK(good_len > 0U);

    auto fresh_rx = [&]() {
        return stl::SecureLink(k_tc, k_tm, stl::PacketType::Telecommand);
    };

    stl::ReceivedFrame frame;

    // Null and undersized inputs.
    {
        auto rx = fresh_rx();
        CHECK(rx.open(nullptr, 100U, 1000ULL, frame) == stl::ParseResult::TooShort);
    }
    for (std::size_t len = 0U; len < stl::MIN_FRAME_SIZE; ++len) {
        auto rx = fresh_rx();
        CHECK(rx.open(good, len, 1000ULL, frame) == stl::ParseResult::TooShort);
    }

    // Oversized.
    {
        auto rx = fresh_rx();
        std::uint8_t big[stl::MAX_FRAME_SIZE + 1U];
        std::memset(big, 0, sizeof(big));
        CHECK(rx.open(big, sizeof(big), 1000ULL, frame) == stl::ParseResult::TooLong);
    }

    // Bad CCSDS version (top 3 bits of byte 0).
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[0] = static_cast<std::uint8_t>(bad[0] | 0x20U);
        CHECK(rx.open(bad, good_len, 1000ULL, frame) == stl::ParseResult::BadVersion);
    }

    // Secondary header flag cleared.
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[0] = static_cast<std::uint8_t>(bad[0] & ~0x08U);
        CHECK(rx.open(bad, good_len, 1000ULL, frame) ==
              stl::ParseResult::NoSecondaryHeader);
    }

    // Segmented (sequence flags other than 11).
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[2] = static_cast<std::uint8_t>(bad[2] & 0x3FU);
        CHECK(rx.open(bad, good_len, 1000ULL, frame) == stl::ParseResult::Segmented);
    }

    // Wrong direction: a telemetry receiver handed telemetry.
    {
        stl::SecureLink tm_rx(k_tm, k_tc, stl::PacketType::Telemetry);
        CHECK(tm_rx.open(good, good_len, 1000ULL, frame) ==
              stl::ParseResult::WrongDirection);
    }

    // Declared length disagreeing with the datagram, in both directions.
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[5] = static_cast<std::uint8_t>(bad[5] + 1U);
        CHECK(rx.open(bad, good_len, 1000ULL, frame) ==
              stl::ParseResult::LengthMismatch);
    }
    {
        // Trailing bytes appended: the declared length no longer describes the
        // datagram, so this must be rejected rather than quietly truncated.
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[good_len] = 0xFFU;
        CHECK(rx.open(bad, good_len + 1U, 1000ULL, frame) ==
              stl::ParseResult::LengthMismatch);
    }

    // A declared data field smaller than the secondary header plus MAC.
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MIN_FRAME_SIZE];
        std::memcpy(bad, good, stl::MIN_FRAME_SIZE);
        // Declare 27 octets (value 26) in a 34-byte datagram: too small, and
        // the length check must fire before anything reads the data field.
        stl::store_be16(bad + 4, 26U);
        const stl::ParseResult r = rx.open(bad, 33U, 1000ULL, frame);
        CHECK((r == stl::ParseResult::DataFieldTooSmall) ||
              (r == stl::ParseResult::TooShort));
    }

    // Corrupted MAC.
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[good_len - 1U] ^= 0x01U;
        CHECK(rx.open(bad, good_len, 1000ULL, frame) == stl::ParseResult::AuthFailure);
    }

    // Corrupted payload: the MAC must catch it.
    {
        auto rx = fresh_rx();
        std::uint8_t bad[stl::MAX_FRAME_SIZE];
        std::memcpy(bad, good, good_len);
        bad[stl::HEADER_SIZE] ^= 0x01U;
        CHECK(rx.open(bad, good_len, 1000ULL, frame) == stl::ParseResult::AuthFailure);
    }

    // Wrong key.
    {
        std::uint8_t other[stl::HMAC_KEY_SIZE];
        fill_key(other, 0x99U);
        stl::SecureLink rx(k_tc, other, stl::PacketType::Telecommand);
        CHECK(rx.open(good, good_len, 1000ULL, frame) == stl::ParseResult::AuthFailure);
    }
}

void test_unknown_apid_after_auth() {
    TEST("unknown APID rejected, but only after authentication");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);
    std::uint8_t frame_buf[stl::MAX_FRAME_SIZE];
    std::uint8_t payload[4] = {0, 0, 0, 0};

    const std::size_t n = tx.seal(0x123U, payload, sizeof(payload), 1000ULL,
                                  frame_buf, sizeof(frame_buf));
    CHECK(n > 0U);

    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);
    stl::ReceivedFrame frame;
    CHECK(rx.open(frame_buf, n, 1000ULL, frame) == stl::ParseResult::UnknownApid);
    // Authentication succeeded, so this counts as an unknown APID rather than
    // an auth failure. The distinction is what makes the counters useful.
    CHECK(rx.stats().auth_failures == 0U);
    CHECK(rx.stats().unknown_apid == 1U);
}

void test_replay_through_link() {
    TEST("replayed frame rejected end to end");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);
    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);

    std::uint8_t payload[2] = {0, 0};
    std::uint8_t f1[stl::MAX_FRAME_SIZE];
    std::uint8_t f2[stl::MAX_FRAME_SIZE];
    const std::size_t n1 =
        tx.seal(stl::APID_TM_EVENT, payload, sizeof(payload), 1000ULL, f1, sizeof(f1));
    const std::size_t n2 =
        tx.seal(stl::APID_TM_EVENT, payload, sizeof(payload), 1000ULL, f2, sizeof(f2));

    stl::ReceivedFrame frame;
    CHECK(rx.open(f1, n1, 1000ULL, frame) == stl::ParseResult::Ok);
    CHECK(rx.open(f2, n2, 1000ULL, frame) == stl::ParseResult::Ok);
    // Byte-identical replay of a frame that already verified.
    CHECK(rx.open(f1, n1, 1000ULL, frame) == stl::ParseResult::ReplayDuplicate);
    CHECK(rx.open(f2, n2, 1000ULL, frame) == stl::ParseResult::ReplayDuplicate);
    CHECK(rx.stats().replay_rejects == 2U);
}

void test_freshness() {
    TEST("stale timestamp rejected, and does not disturb the replay window");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);
    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);
    rx.enable_freshness_check(true);

    const std::uint64_t now = 2000ULL * 1000000ULL;
    std::uint8_t payload[2] = {0, 0};
    std::uint8_t stale[stl::MAX_FRAME_SIZE];
    const std::size_t n = tx.seal(stl::APID_TM_EVENT, payload, sizeof(payload),
                                  now - (60ULL * 1000000ULL), stale, sizeof(stale));

    stl::ReceivedFrame frame;
    CHECK(rx.open(stale, n, now, frame) == stl::ParseResult::StaleTimestamp);
    // Freshness is checked before replay, so the window must be untouched.
    CHECK(!rx.replay_window().started());

    std::uint8_t fresh[stl::MAX_FRAME_SIZE];
    const std::size_t m =
        tx.seal(stl::APID_TM_EVENT, payload, sizeof(payload), now, fresh, sizeof(fresh));
    CHECK(rx.open(fresh, m, now, frame) == stl::ParseResult::Ok);
}

void test_command_decode_bounds() {
    TEST("command decoder rejects inconsistent lengths");
    stl::Command cmd;

    // Declared argument length larger than the buffer that follows.
    {
        std::uint8_t data[6];
        stl::store_be16(data, stl::CMD_SET_MODE);
        stl::store_be16(data + 2, 100U);  // claims 100 bytes of arguments
        CHECK(!stl::decode_command(data, sizeof(data), cmd));
    }
    // Declared argument length above the hard maximum.
    {
        std::uint8_t data[stl::COMMAND_HEADER_SIZE + stl::MAX_COMMAND_ARG_LEN + 1U];
        std::memset(data, 0, sizeof(data));
        stl::store_be16(data, stl::CMD_SET_MODE);
        stl::store_be16(data + 2,
                        static_cast<std::uint16_t>(stl::MAX_COMMAND_ARG_LEN + 1U));
        CHECK(!stl::decode_command(data, sizeof(data), cmd));
    }
    // Declared shorter than what arrived: trailing bytes are not ignored.
    {
        std::uint8_t data[10];
        std::memset(data, 0, sizeof(data));
        stl::store_be16(data, stl::CMD_SET_MODE);
        stl::store_be16(data + 2, 1U);
        CHECK(!stl::decode_command(data, sizeof(data), cmd));
    }
    // Truncated header.
    {
        std::uint8_t data[3] = {0, 1, 0};
        CHECK(!stl::decode_command(data, sizeof(data), cmd));
    }
    // Exactly right.
    {
        std::uint8_t data[5];
        stl::store_be16(data, stl::CMD_SET_MODE);
        stl::store_be16(data + 2, 1U);
        data[4] = 3U;
        CHECK(stl::decode_command(data, sizeof(data), cmd));
        CHECK(cmd.command_id == stl::CMD_SET_MODE);
        CHECK(cmd.arg_len == 1U);
        CHECK(cmd.args[0] == 3U);
    }
}

void test_payload_decoders_reject_wrong_size() {
    TEST("payload decoders reject any length but the exact one");
    std::uint8_t buf[64];
    std::memset(buf, 0, sizeof(buf));

    for (std::size_t len = 0U; len < sizeof(buf); ++len) {
        stl::Housekeeping hk;
        const bool ok = stl::decode_housekeeping(buf, len, hk);
        CHECK(ok == (len == stl::HOUSEKEEPING_PAYLOAD_SIZE));

        stl::Attitude att;
        const bool ok2 = stl::decode_attitude(buf, len, att);
        CHECK(ok2 == (len == stl::ATTITUDE_PAYLOAD_SIZE));

        stl::CommandAck ack;
        const bool ok3 = stl::decode_command_ack(buf, len, ack);
        CHECK(ok3 == (len == stl::COMMAND_ACK_PAYLOAD_SIZE));
    }
}

void test_seal_bounds() {
    TEST("seal refuses to overflow its output buffer");
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);
    stl::SecureLink tx(k_tm, k_tc, stl::PacketType::Telemetry);

    std::uint8_t payload[stl::MAX_USER_DATA + 1U];
    std::memset(payload, 0xAB, sizeof(payload));
    std::uint8_t out[stl::MAX_FRAME_SIZE];

    // Payload above the protocol maximum.
    CHECK(tx.seal(stl::APID_TM_EVENT, payload, stl::MAX_USER_DATA + 1U, 0ULL, out,
                  sizeof(out)) == 0U);
    // Output buffer one byte too small.
    CHECK(tx.seal(stl::APID_TM_EVENT, payload, 8U, 0ULL, out,
                  stl::HEADER_SIZE + 8U + stl::MAC_TAG_SIZE - 1U) == 0U);
    // APID that does not fit in 11 bits.
    CHECK(tx.seal(0x800U, payload, 8U, 0ULL, out, sizeof(out)) == 0U);
    // Exactly the maximum payload fits.
    CHECK(tx.seal(stl::APID_TM_EVENT, payload, stl::MAX_USER_DATA, 0ULL, out,
                  sizeof(out)) == stl::MAX_FRAME_SIZE);
}

void test_counter_store_persistence() {
    TEST("counter store never reuses a counter across restarts");
    const char* path = "build/.test_counter.ctr";
    std::remove(path);

    std::uint32_t first_run_last = 0U;
    {
        stl::CounterStore cs;
        const char* err = nullptr;
        CHECK(cs.open(path, &err));
        std::uint32_t c = 0U;
        for (int i = 0; i < 10; ++i) {
            CHECK(cs.next(c));
            first_run_last = c;
        }
        CHECK(first_run_last == 9U);
    }
    {
        // A "restart": the new run must start strictly above anything the
        // previous run could have sent, even though it only used 10 counters.
        stl::CounterStore cs;
        const char* err = nullptr;
        CHECK(cs.open(path, &err));
        std::uint32_t c = 0U;
        CHECK(cs.next(c));
        CHECK(c > first_run_last);
        CHECK(c == stl::COUNTER_BLOCK_SIZE);
    }
    std::remove(path);
}

namespace {

bool write_raw(const char* path, const std::uint8_t* data, std::size_t len) {
    std::FILE* f = std::fopen(path, "wb");
    if (f == nullptr) {
        return false;
    }
    const bool ok = (std::fwrite(data, 1U, len, f) == len);
    return (std::fclose(f) == 0) && ok;
}

std::size_t file_size(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return static_cast<std::size_t>(-1);
    }
    std::uint8_t buf[16];
    const std::size_t n = std::fread(buf, 1U, sizeof(buf), f);
    std::fclose(f);
    return n;
}

}  // namespace

void test_counter_store_fails_closed_on_corrupt_state() {
    TEST("a torn or garbled counter file stops startup instead of restarting at zero");
    // Regression for a crash mid-write. The original in-place write truncated
    // the file before writing, so a crash could leave it empty, and an empty
    // file was treated as a first run: counters restarted at zero, which is
    // the replay-window lockout counter persistence was built to prevent.
    const char* path = "build/.test_counter_corrupt.ctr";
    const std::uint8_t five[5] = {0U, 0U, 4U, 0U, 0U};
    const std::size_t lengths[3] = {0U, 2U, 5U};
    for (std::size_t i = 0; i < 3U; ++i) {
        std::remove(path);
        CHECK(write_raw(path, five, lengths[i]));
        stl::CounterStore cs;
        const char* err = nullptr;
        CHECK(!cs.open(path, &err));
        CHECK(!cs.ok());
        std::uint32_t c = 0U;
        CHECK(!cs.next(c));
        CHECK(err != nullptr && std::strstr(err, "corrupt") != nullptr);
        CHECK(file_size(path) == lengths[i]);  // evidence left untouched
    }
    std::remove(path);
}

void test_counter_store_write_is_atomic() {
    TEST("counter reservations go through a temp file and leave a 4-byte mark");
    const char* path = "build/.test_counter_atomic.ctr";
    const char* tmp = "build/.test_counter_atomic.ctr.tmp";
    std::remove(path);
    std::remove(tmp);
    {
        stl::CounterStore cs;
        const char* err = nullptr;
        CHECK(cs.open(path, &err));
        std::uint32_t c = 0U;
        bool all_issued = true;
        for (std::uint32_t i = 0U; i <= stl::COUNTER_BLOCK_SIZE; ++i) {
            all_issued = cs.next(c) && all_issued;  // crosses one block boundary
        }
        CHECK(all_issued);
        CHECK(c == stl::COUNTER_BLOCK_SIZE);
    }
    CHECK(file_size(path) == 4U);
    CHECK(file_size(tmp) == static_cast<std::size_t>(-1));  // no temp left
    {
        // A stale temp file from an earlier crash must not affect startup.
        const std::uint8_t junk[2] = {0xFFU, 0xFFU};
        CHECK(write_raw(tmp, junk, 2U));
        stl::CounterStore cs;
        const char* err = nullptr;
        CHECK(cs.open(path, &err));
        std::uint32_t c = 0U;
        CHECK(cs.next(c));
        CHECK(c == 2U * stl::COUNTER_BLOCK_SIZE);
    }
    std::remove(path);
    std::remove(tmp);
}

void test_link_rejects_zero_counter_restart() {
    TEST("a restarted sender without a counter store is correctly rejected");
    // Documents the failure that motivated counter persistence: two senders
    // that both start at zero look like a replay to the receiver.
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    stl::SecureLink rx(k_tc, k_tm, stl::PacketType::Telecommand);
    std::uint8_t payload[2] = {0, 0};
    stl::ReceivedFrame frame;

    {
        stl::SecureLink tx1(k_tm, k_tc, stl::PacketType::Telemetry);
        std::uint8_t f[stl::MAX_FRAME_SIZE];
        const std::size_t n =
            tx1.seal(stl::APID_TM_EVENT, payload, sizeof(payload), 1000ULL, f, sizeof(f));
        CHECK(rx.open(f, n, 1000ULL, frame) == stl::ParseResult::Ok);
    }
    {
        stl::SecureLink tx2(k_tm, k_tc, stl::PacketType::Telemetry);  // "restarted"
        std::uint8_t f[stl::MAX_FRAME_SIZE];
        const std::size_t n =
            tx2.seal(stl::APID_TM_EVENT, payload, sizeof(payload), 1000ULL, f, sizeof(f));
        CHECK(rx.open(f, n, 1000ULL, frame) == stl::ParseResult::ReplayDuplicate);
    }
}

}  // namespace

int main() {
    std::printf("STL-1 flight-side tests\n\n");

    test_sha256_known_vectors();
    test_sha256_streaming_equals_oneshot();
    test_constant_time_equal();
    test_replay_window();
    test_seal_open_round_trip();
    test_parser_rejections();
    test_unknown_apid_after_auth();
    test_replay_through_link();
    test_freshness();
    test_command_decode_bounds();
    test_payload_decoders_reject_wrong_size();
    test_seal_bounds();
    test_counter_store_persistence();
    test_counter_store_fails_closed_on_corrupt_state();
    test_counter_store_write_is_atomic();
    test_link_rejects_zero_counter_restart();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
