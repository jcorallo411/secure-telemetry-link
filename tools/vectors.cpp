// Emits STL-1 test vectors as JSON on stdout.
//
// ground/tests/test_vectors.py reads this output and checks that the Python
// implementation produces identical bytes and reaches identical verdicts.
//
// This is the test that matters most in a two-implementation system. Both
// sides can be internally consistent, pass all their own unit tests, and still
// disagree about the wire format — and a protocol where the two ends disagree
// is a protocol where "it worked on my machine" is the only spec. Fixed keys
// and fixed timestamps keep the output byte-reproducible.

#include <cstdio>
#include <cstring>

#include "stl/protocol.h"
#include "stl/secure_link.h"

namespace {

void print_hex(const std::uint8_t* d, std::size_t n) {
    for (std::size_t i = 0U; i < n; ++i) {
        std::printf("%02x", d[i]);
    }
}

// Deterministic non-trivial keys. Never used for anything real; the key file
// generator draws from the OS CSPRNG.
void fill_key(std::uint8_t key[stl::HMAC_KEY_SIZE], std::uint8_t base) {
    for (std::size_t i = 0U; i < stl::HMAC_KEY_SIZE; ++i) {
        key[i] = static_cast<std::uint8_t>(base + (i * 7U));
    }
}

bool first_item = true;

void begin_item() {
    if (!first_item) {
        std::printf(",\n");
    }
    first_item = false;
}

}  // namespace

int main() {
    std::uint8_t k_tm[stl::HMAC_KEY_SIZE];
    std::uint8_t k_tc[stl::HMAC_KEY_SIZE];
    fill_key(k_tm, 0x11U);
    fill_key(k_tc, 0x42U);

    std::printf("{\n");
    std::printf("  \"k_tm\": \"");
    print_hex(k_tm, sizeof(k_tm));
    std::printf("\",\n  \"k_tc\": \"");
    print_hex(k_tc, sizeof(k_tc));
    std::printf("\",\n  \"frames\": [\n");

    std::uint8_t buf[stl::MAX_FRAME_SIZE];
    std::uint8_t payload[stl::MAX_USER_DATA];

    const std::uint64_t base_met = 1700000000000000ULL;

    // ---- housekeeping -----------------------------------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
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

        const std::size_t n = tm_link.seal(stl::APID_TM_HOUSEKEEPING, payload,
                                           stl::HOUSEKEEPING_PAYLOAD_SIZE,
                                           base_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"housekeeping\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_HOUSEKEEPING,
                    static_cast<unsigned long long>(base_met));
        print_hex(payload, stl::HOUSEKEEPING_PAYLOAD_SIZE);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- attitude, with negative values on every axis ---------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        stl::Attitude att;
        att.gyro[0] = -123456;
        att.gyro[1] = 0;
        att.gyro[2] = 2147483647;  // INT32_MAX
        att.accel[0] = -2147483647 - 1;  // INT32_MIN, written without UB
        att.accel[1] = 9810;
        att.accel[2] = -1;
        att.mag[0] = 25000;
        att.mag[1] = -25000;
        att.mag[2] = -42000;
        stl::encode_attitude(att, payload);

        const std::size_t n =
            tm_link.seal(stl::APID_TM_ATTITUDE, payload, stl::ATTITUDE_PAYLOAD_SIZE,
                         base_met + 1000ULL, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"attitude_extremes\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_ATTITUDE,
                    static_cast<unsigned long long>(base_met + 1000ULL));
        print_hex(payload, stl::ATTITUDE_PAYLOAD_SIZE);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- command ack ------------------------------------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        stl::CommandAck ack;
        ack.command_id = stl::CMD_SET_TM_RATE;
        ack.frame_counter = 4294967295U;  // UINT32_MAX
        ack.status = static_cast<std::uint8_t>(stl::AckStatus::RejectedInvalidInMode);
        stl::encode_command_ack(ack, payload);

        const std::size_t n =
            tm_link.seal(stl::APID_TM_COMMAND_ACK, payload,
                         stl::COMMAND_ACK_PAYLOAD_SIZE, base_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"command_ack\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_COMMAND_ACK,
                    static_cast<unsigned long long>(base_met));
        print_hex(payload, stl::COMMAND_ACK_PAYLOAD_SIZE);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- event, minimum-length payload ------------------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        payload[0] = 3U;  // critical
        payload[1] = 0U;  // empty message: exercises the zero-length edge
        const std::size_t n =
            tm_link.seal(stl::APID_TM_EVENT, payload, stl::EVENT_HEADER_SIZE,
                         base_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"event_empty\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_EVENT, static_cast<unsigned long long>(base_met));
        print_hex(payload, stl::EVENT_HEADER_SIZE);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- command, maximum argument length ---------------------------------
    {
        stl::SecureLink tc_link(k_tc, k_tm, stl::PacketType::Telecommand);
        stl::Command cmd;
        cmd.command_id = stl::CMD_SET_MODE;
        cmd.arg_len = static_cast<std::uint16_t>(stl::MAX_COMMAND_ARG_LEN);
        for (std::size_t i = 0U; i < stl::MAX_COMMAND_ARG_LEN; ++i) {
            cmd.args[i] = static_cast<std::uint8_t>(0xA0U + i);
        }
        const std::size_t plen = stl::encode_command(cmd, payload, sizeof(payload));
        const std::size_t n = tc_link.seal(stl::APID_TC_COMMAND, payload, plen,
                                           base_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"command_max_args\", \"apid\": %u, \"dir\": \"tc\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TC_COMMAND, static_cast<unsigned long long>(base_met));
        print_hex(payload, plen);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- empty user data: smallest legal frame ----------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        const std::size_t n = tm_link.seal(stl::APID_TM_EVENT, nullptr, 0U,
                                           base_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"min_frame\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"\", \"frame\": \"",
                    stl::APID_TM_EVENT, static_cast<unsigned long long>(base_met));
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- maximum user data: largest legal frame ---------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        for (std::size_t i = 0U; i < stl::MAX_USER_DATA; ++i) {
            payload[i] = static_cast<std::uint8_t>(i & 0xFFU);
        }
        const std::size_t n = tm_link.seal(stl::APID_TM_HOUSEKEEPING, payload,
                                           stl::MAX_USER_DATA, base_met, buf,
                                           sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"max_frame\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_HOUSEKEEPING,
                    static_cast<unsigned long long>(base_met));
        print_hex(payload, stl::MAX_USER_DATA);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    // ---- MET at the 64-bit maximum ----------------------------------------
    {
        stl::SecureLink tm_link(k_tm, k_tc, stl::PacketType::Telemetry);
        payload[0] = 0U;
        payload[1] = 0U;
        const std::uint64_t huge_met = 0xFFFFFFFFFFFFFFFFULL;
        const std::size_t n =
            tm_link.seal(stl::APID_TM_EVENT, payload, stl::EVENT_HEADER_SIZE,
                         huge_met, buf, sizeof(buf));
        begin_item();
        std::printf("    {\"name\": \"met_max\", \"apid\": %u, \"dir\": \"tm\", "
                    "\"met\": %llu, \"counter\": 0, \"payload\": \"",
                    stl::APID_TM_EVENT, static_cast<unsigned long long>(huge_met));
        print_hex(payload, stl::EVENT_HEADER_SIZE);
        std::printf("\", \"frame\": \"");
        print_hex(buf, n);
        std::printf("\"}");
    }

    std::printf("\n  ]\n}\n");
    return 0;
}
