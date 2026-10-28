// STL-1 wire protocol: CCSDS-style packet structure, constants, payloads.
// See docs/PROTOCOL.md, which this file implements.

#ifndef STL_PROTOCOL_H
#define STL_PROTOCOL_H

#include <cstddef>
#include <cstdint>

#include "stl/hmac.h"

namespace stl {

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

constexpr std::size_t PRIMARY_HEADER_SIZE = 6U;
constexpr std::size_t SECONDARY_HEADER_SIZE = 12U;
constexpr std::size_t HEADER_SIZE = PRIMARY_HEADER_SIZE + SECONDARY_HEADER_SIZE;

constexpr std::size_t MAX_USER_DATA = 1024U;
constexpr std::size_t MIN_FRAME_SIZE = HEADER_SIZE + MAC_TAG_SIZE;          // 34
constexpr std::size_t MAX_FRAME_SIZE = HEADER_SIZE + MAX_USER_DATA + MAC_TAG_SIZE;  // 1058

// Smallest legal packet data field: secondary header + MAC tag.
constexpr std::size_t MIN_DATA_FIELD = SECONDARY_HEADER_SIZE + MAC_TAG_SIZE;  // 28

// ---------------------------------------------------------------------------
// Header field values
// ---------------------------------------------------------------------------

constexpr std::uint8_t CCSDS_VERSION = 0U;
constexpr std::uint8_t SEQ_FLAGS_UNSEGMENTED = 3U;

enum class PacketType : std::uint8_t { Telemetry = 0U, Telecommand = 1U };

// ---------------------------------------------------------------------------
// APIDs
// ---------------------------------------------------------------------------

constexpr std::uint16_t APID_TM_HOUSEKEEPING = 0x001U;
constexpr std::uint16_t APID_TM_ATTITUDE = 0x002U;
constexpr std::uint16_t APID_TM_COMMAND_ACK = 0x003U;
constexpr std::uint16_t APID_TM_EVENT = 0x004U;
constexpr std::uint16_t APID_TC_COMMAND = 0x010U;

// ---------------------------------------------------------------------------
// Commands and modes
// ---------------------------------------------------------------------------

constexpr std::uint16_t CMD_NOOP = 0x0001U;
constexpr std::uint16_t CMD_PING = 0x0002U;
constexpr std::uint16_t CMD_SET_MODE = 0x0003U;
constexpr std::uint16_t CMD_SET_TM_RATE = 0x0004U;
constexpr std::uint16_t CMD_SET_HEATER = 0x0005U;
constexpr std::uint16_t CMD_SAFE_MODE = 0x0006U;

constexpr std::size_t MAX_COMMAND_ARG_LEN = 64U;

enum class Mode : std::uint8_t { Boot = 0U, Idle = 1U, Nominal = 2U, Safe = 3U };

enum class AckStatus : std::uint8_t {
    Accepted = 0U,
    RejectedUnknownCommand = 1U,
    RejectedBadArgument = 2U,
    RejectedInvalidInMode = 3U
};

constexpr std::uint16_t MIN_TM_RATE_HZ = 1U;
constexpr std::uint16_t MAX_TM_RATE_HZ = 50U;

// ---------------------------------------------------------------------------
// Parse results
// ---------------------------------------------------------------------------

// Every way a frame can be rejected gets its own code. This matters more than
// it looks: a single "invalid" return makes it impossible to tell a benign
// bug from an attack in the logs, and the per-reason counters are what turn
// this into something an operator can actually act on.
enum class ParseResult : std::uint8_t {
    Ok = 0U,
    TooShort,
    TooLong,
    BadVersion,
    NoSecondaryHeader,
    Segmented,
    WrongDirection,
    LengthMismatch,
    DataFieldTooSmall,
    AuthFailure,
    ReplayDuplicate,
    ReplayTooOld,
    StaleTimestamp,
    UnknownApid,
    BadPayloadLength
};

const char* parse_result_name(ParseResult r) noexcept;

// ---------------------------------------------------------------------------
// Decoded header
// ---------------------------------------------------------------------------

struct PacketHeader {
    PacketType type;
    std::uint16_t apid;
    std::uint16_t sequence_count;
    std::uint16_t data_length;  // declared value + 1, i.e. true octet count
    std::uint64_t met_us;
    std::uint32_t frame_counter;
};

// ---------------------------------------------------------------------------
// Byte-order helpers (explicit, so the wire format never depends on the host)
// ---------------------------------------------------------------------------

void store_be16(std::uint8_t* p, std::uint16_t v) noexcept;
void store_be32(std::uint8_t* p, std::uint32_t v) noexcept;
void store_be64(std::uint8_t* p, std::uint64_t v) noexcept;
std::uint16_t load_be16(const std::uint8_t* p) noexcept;
std::uint32_t load_be32(const std::uint8_t* p) noexcept;
std::uint64_t load_be64(const std::uint8_t* p) noexcept;

inline void store_be_i32(std::uint8_t* p, std::int32_t v) noexcept {
    store_be32(p, static_cast<std::uint32_t>(v));
}
inline std::int32_t load_be_i32(const std::uint8_t* p) noexcept {
    return static_cast<std::int32_t>(load_be32(p));
}

// ---------------------------------------------------------------------------
// Payload structures
// ---------------------------------------------------------------------------

constexpr std::size_t HOUSEKEEPING_PAYLOAD_SIZE = 24U;
constexpr std::size_t ATTITUDE_PAYLOAD_SIZE = 36U;
constexpr std::size_t COMMAND_ACK_PAYLOAD_SIZE = 8U;
constexpr std::size_t EVENT_HEADER_SIZE = 2U;
constexpr std::size_t MAX_EVENT_MESSAGE = 70U;
constexpr std::size_t COMMAND_HEADER_SIZE = 4U;

struct Housekeeping {
    std::uint8_t mode;
    std::uint8_t heater_on;
    std::uint16_t telemetry_rate_hz;
    std::int32_t bus_voltage_mv;
    std::int32_t bus_current_ma;
    std::int32_t battery_temp_mc;
    std::int32_t payload_temp_mc;
    std::uint32_t uptime_s;
};

struct Attitude {
    std::int32_t gyro[3];   // microrad/s
    std::int32_t accel[3];  // micro-g
    std::int32_t mag[3];    // nT
};

struct CommandAck {
    std::uint16_t command_id;
    std::uint32_t frame_counter;
    std::uint8_t status;
};

struct Command {
    std::uint16_t command_id;
    std::uint16_t arg_len;
    std::uint8_t args[MAX_COMMAND_ARG_LEN];
};

void encode_housekeeping(const Housekeeping& hk, std::uint8_t out[HOUSEKEEPING_PAYLOAD_SIZE]) noexcept;
bool decode_housekeeping(const std::uint8_t* data, std::size_t len, Housekeeping& out) noexcept;

void encode_attitude(const Attitude& att, std::uint8_t out[ATTITUDE_PAYLOAD_SIZE]) noexcept;
bool decode_attitude(const std::uint8_t* data, std::size_t len, Attitude& out) noexcept;

void encode_command_ack(const CommandAck& ack, std::uint8_t out[COMMAND_ACK_PAYLOAD_SIZE]) noexcept;
bool decode_command_ack(const std::uint8_t* data, std::size_t len, CommandAck& out) noexcept;

// Returns bytes written, or 0 if the command does not fit.
std::size_t encode_command(const Command& cmd, std::uint8_t* out, std::size_t out_cap) noexcept;
bool decode_command(const std::uint8_t* data, std::size_t len, Command& out) noexcept;

}  // namespace stl

#endif  // STL_PROTOCOL_H
