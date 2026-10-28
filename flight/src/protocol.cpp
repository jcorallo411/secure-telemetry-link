#include "stl/protocol.h"

#include <cstring>

namespace stl {

// ---------------------------------------------------------------------------
// Byte order
// ---------------------------------------------------------------------------

void store_be16(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

void store_be64(std::uint8_t* p, std::uint64_t v) noexcept {
    for (std::size_t i = 0U; i < 8U; ++i) {
        p[i] = static_cast<std::uint8_t>(v >> (56U - (8U * i)));
    }
}

std::uint16_t load_be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) |
                                      static_cast<std::uint16_t>(p[1]));
}

std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint64_t load_be64(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
        v = (v << 8) | static_cast<std::uint64_t>(p[i]);
    }
    return v;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

const char* parse_result_name(ParseResult r) noexcept {
    switch (r) {
        case ParseResult::Ok:                return "OK";
        case ParseResult::TooShort:          return "TOO_SHORT";
        case ParseResult::TooLong:           return "TOO_LONG";
        case ParseResult::BadVersion:        return "BAD_VERSION";
        case ParseResult::NoSecondaryHeader: return "NO_SECONDARY_HEADER";
        case ParseResult::Segmented:         return "SEGMENTED";
        case ParseResult::WrongDirection:    return "WRONG_DIRECTION";
        case ParseResult::LengthMismatch:    return "LENGTH_MISMATCH";
        case ParseResult::DataFieldTooSmall: return "DATA_FIELD_TOO_SMALL";
        case ParseResult::AuthFailure:       return "AUTH_FAILURE";
        case ParseResult::ReplayDuplicate:   return "REPLAY_DUPLICATE";
        case ParseResult::ReplayTooOld:      return "REPLAY_TOO_OLD";
        case ParseResult::StaleTimestamp:    return "STALE_TIMESTAMP";
        case ParseResult::UnknownApid:       return "UNKNOWN_APID";
        case ParseResult::BadPayloadLength:  return "BAD_PAYLOAD_LENGTH";
        default:                             return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// Payload codecs
//
// Every decoder takes an explicit length and checks it against the exact
// expected size before touching a single field. These run only on frames whose
// MAC already verified, but they are written as if they did not: a decoder
// that is only safe because of what runs before it becomes unsafe the moment
// someone reuses it somewhere else.
// ---------------------------------------------------------------------------

void encode_housekeeping(const Housekeeping& hk,
                         std::uint8_t out[HOUSEKEEPING_PAYLOAD_SIZE]) noexcept {
    out[0] = hk.mode;
    out[1] = hk.heater_on;
    store_be16(out + 2, hk.telemetry_rate_hz);
    store_be_i32(out + 4, hk.bus_voltage_mv);
    store_be_i32(out + 8, hk.bus_current_ma);
    store_be_i32(out + 12, hk.battery_temp_mc);
    store_be_i32(out + 16, hk.payload_temp_mc);
    store_be32(out + 20, hk.uptime_s);
}

bool decode_housekeeping(const std::uint8_t* data, std::size_t len,
                         Housekeeping& out) noexcept {
    if ((data == nullptr) || (len != HOUSEKEEPING_PAYLOAD_SIZE)) {
        return false;
    }
    out.mode = data[0];
    out.heater_on = data[1];
    out.telemetry_rate_hz = load_be16(data + 2);
    out.bus_voltage_mv = load_be_i32(data + 4);
    out.bus_current_ma = load_be_i32(data + 8);
    out.battery_temp_mc = load_be_i32(data + 12);
    out.payload_temp_mc = load_be_i32(data + 16);
    out.uptime_s = load_be32(data + 20);
    return true;
}

void encode_attitude(const Attitude& att,
                     std::uint8_t out[ATTITUDE_PAYLOAD_SIZE]) noexcept {
    for (std::size_t i = 0U; i < 3U; ++i) {
        store_be_i32(out + (i * 4U), att.gyro[i]);
        store_be_i32(out + 12U + (i * 4U), att.accel[i]);
        store_be_i32(out + 24U + (i * 4U), att.mag[i]);
    }
}

bool decode_attitude(const std::uint8_t* data, std::size_t len,
                     Attitude& out) noexcept {
    if ((data == nullptr) || (len != ATTITUDE_PAYLOAD_SIZE)) {
        return false;
    }
    for (std::size_t i = 0U; i < 3U; ++i) {
        out.gyro[i] = load_be_i32(data + (i * 4U));
        out.accel[i] = load_be_i32(data + 12U + (i * 4U));
        out.mag[i] = load_be_i32(data + 24U + (i * 4U));
    }
    return true;
}

void encode_command_ack(const CommandAck& ack,
                        std::uint8_t out[COMMAND_ACK_PAYLOAD_SIZE]) noexcept {
    store_be16(out, ack.command_id);
    store_be32(out + 2, ack.frame_counter);
    out[6] = ack.status;
    out[7] = 0U;  // reserved
}

bool decode_command_ack(const std::uint8_t* data, std::size_t len,
                        CommandAck& out) noexcept {
    if ((data == nullptr) || (len != COMMAND_ACK_PAYLOAD_SIZE)) {
        return false;
    }
    out.command_id = load_be16(data);
    out.frame_counter = load_be32(data + 2);
    out.status = data[6];
    return true;
}

std::size_t encode_command(const Command& cmd, std::uint8_t* out,
                           std::size_t out_cap) noexcept {
    if (cmd.arg_len > MAX_COMMAND_ARG_LEN) {
        return 0U;
    }
    const std::size_t need = COMMAND_HEADER_SIZE + cmd.arg_len;
    if ((out == nullptr) || (out_cap < need)) {
        return 0U;
    }
    store_be16(out, cmd.command_id);
    store_be16(out + 2, cmd.arg_len);
    if (cmd.arg_len > 0U) {
        std::memcpy(out + COMMAND_HEADER_SIZE, cmd.args, cmd.arg_len);
    }
    return need;
}

bool decode_command(const std::uint8_t* data, std::size_t len,
                    Command& out) noexcept {
    if ((data == nullptr) || (len < COMMAND_HEADER_SIZE)) {
        return false;
    }
    const std::uint16_t arg_len = load_be16(data + 2);

    // Two independent checks. The declared argument length must fit in our
    // fixed buffer, and it must match what actually arrived. Checking only the
    // first would let a short frame with a large declared length read past the
    // end of the datagram; checking only the second would let a well-formed
    // but oversized frame overflow the destination array.
    if (arg_len > MAX_COMMAND_ARG_LEN) {
        return false;
    }
    if (len != (COMMAND_HEADER_SIZE + static_cast<std::size_t>(arg_len))) {
        return false;
    }

    out.command_id = load_be16(data);
    out.arg_len = arg_len;
    std::memset(out.args, 0, sizeof(out.args));
    if (arg_len > 0U) {
        std::memcpy(out.args, data + COMMAND_HEADER_SIZE, arg_len);
    }
    return true;
}

}  // namespace stl
