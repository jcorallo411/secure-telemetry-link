#include "stl/secure_link.h"

#include <cstring>

namespace stl {

namespace {

bool apid_is_known(std::uint16_t apid) noexcept {
    return (apid == APID_TM_HOUSEKEEPING) || (apid == APID_TM_ATTITUDE) ||
           (apid == APID_TM_COMMAND_ACK) || (apid == APID_TM_EVENT) ||
           (apid == APID_TC_COMMAND);
}

std::uint64_t abs_diff_u64(std::uint64_t a, std::uint64_t b) noexcept {
    return (a > b) ? (a - b) : (b - a);
}

}  // namespace

SecureLink::SecureLink(const std::uint8_t tx_key[HMAC_KEY_SIZE],
                       const std::uint8_t rx_key[HMAC_KEY_SIZE],
                       PacketType tx_type) noexcept
    : tx_type_(tx_type),
      expected_rx_type_((tx_type == PacketType::Telemetry)
                            ? PacketType::Telecommand
                            : PacketType::Telemetry),
      tx_counter_(0U),
      counter_store_(nullptr),
      freshness_enabled_(false),
      freshness_window_us_(DEFAULT_FRESHNESS_WINDOW_US) {
    std::memcpy(tx_key_, tx_key, HMAC_KEY_SIZE);
    std::memcpy(rx_key_, rx_key, HMAC_KEY_SIZE);
    std::memset(seq_counts_, 0, sizeof(seq_counts_));
    stats_.clear();
}

std::uint16_t SecureLink::next_sequence(std::uint16_t apid) noexcept {
    const std::size_t slot = static_cast<std::size_t>(apid) % SEQ_SLOTS;
    const std::uint16_t value = seq_counts_[slot];
    seq_counts_[slot] = static_cast<std::uint16_t>((value + 1U) & 0x3FFFU);
    return value;
}

std::size_t SecureLink::seal(std::uint16_t apid, const std::uint8_t* payload,
                             std::size_t payload_len, std::uint64_t met_us,
                             std::uint8_t* out, std::size_t out_cap) noexcept {
    if (payload_len > MAX_USER_DATA) {
        return 0U;
    }
    if ((payload == nullptr) && (payload_len > 0U)) {
        return 0U;
    }
    if (apid > 0x7FFU) {
        return 0U;  // APID is 11 bits
    }

    const std::size_t frame_len = HEADER_SIZE + payload_len + MAC_TAG_SIZE;
    if ((out == nullptr) || (out_cap < frame_len)) {
        return 0U;
    }

    const std::size_t data_field_len =
        SECONDARY_HEADER_SIZE + payload_len + MAC_TAG_SIZE;

    // --- primary header -----------------------------------------------------
    std::uint16_t word0 = apid;  // bits 10..0
    word0 = static_cast<std::uint16_t>(word0 | (1U << 11));  // sec hdr flag
    if (tx_type_ == PacketType::Telecommand) {
        word0 = static_cast<std::uint16_t>(word0 | (1U << 12));
    }
    // version bits 15..13 stay 0
    store_be16(out, word0);

    const std::uint16_t seq = next_sequence(apid);
    const std::uint16_t word1 = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(SEQ_FLAGS_UNSEGMENTED) << 14) | seq);
    store_be16(out + 2, word1);

    // CCSDS length field is octets-minus-one.
    store_be16(out + 4, static_cast<std::uint16_t>(data_field_len - 1U));

    // --- secondary header ---------------------------------------------------
    std::uint32_t counter = 0U;
    if (counter_store_ != nullptr) {
        if (!counter_store_->next(counter)) {
            // Refuse to transmit rather than fall back to a volatile counter.
            // A frame sent with a counter that might be reused is worse than
            // no frame: it teaches the receiver's window to reject the real
            // traffic that follows.
            return 0U;
        }
        tx_counter_ = counter + 1U;
    } else {
        counter = tx_counter_;
        tx_counter_ += 1U;
    }

    store_be64(out + 6, met_us);
    store_be32(out + 14, counter);

    // --- user data ----------------------------------------------------------
    if (payload_len > 0U) {
        std::memcpy(out + HEADER_SIZE, payload, payload_len);
    }

    // --- authentication tag over everything that precedes it ----------------
    mac_tag(tx_key_, out, HEADER_SIZE + payload_len, out + HEADER_SIZE + payload_len);

    return frame_len;
}

ParseResult SecureLink::open(const std::uint8_t* data, std::size_t len,
                             std::uint64_t now_us, ReceivedFrame& frame) noexcept {
    // Step 1: datagram bounds. Everything below indexes fixed offsets inside
    // a buffer already proven to be at least MIN_FRAME_SIZE bytes.
    if (data == nullptr) {
        stats_.malformed += 1U;
        return ParseResult::TooShort;
    }
    if (len < MIN_FRAME_SIZE) {
        stats_.malformed += 1U;
        return ParseResult::TooShort;
    }
    if (len > MAX_FRAME_SIZE) {
        stats_.malformed += 1U;
        return ParseResult::TooLong;
    }

    // Step 2: primary header.
    const std::uint16_t word0 = load_be16(data);
    const std::uint8_t version = static_cast<std::uint8_t>((word0 >> 13) & 0x07U);
    const std::uint8_t type_bit = static_cast<std::uint8_t>((word0 >> 12) & 0x01U);
    const std::uint8_t sec_hdr_flag = static_cast<std::uint8_t>((word0 >> 11) & 0x01U);
    const std::uint16_t apid = static_cast<std::uint16_t>(word0 & 0x07FFU);

    if (version != CCSDS_VERSION) {
        stats_.malformed += 1U;
        return ParseResult::BadVersion;
    }
    if (sec_hdr_flag != 1U) {
        stats_.malformed += 1U;
        return ParseResult::NoSecondaryHeader;
    }

    const std::uint16_t word1 = load_be16(data + 2);
    const std::uint8_t seq_flags = static_cast<std::uint8_t>((word1 >> 14) & 0x03U);
    const std::uint16_t seq_count = static_cast<std::uint16_t>(word1 & 0x3FFFU);

    if (seq_flags != SEQ_FLAGS_UNSEGMENTED) {
        stats_.malformed += 1U;
        return ParseResult::Segmented;
    }

    const PacketType ptype =
        (type_bit == 1U) ? PacketType::Telecommand : PacketType::Telemetry;
    if (ptype != expected_rx_type_) {
        // A telemetry frame arriving where a command belongs is either a
        // misconfiguration or a reflection attempt. Separate keys per
        // direction already make the latter infeasible; this catches it one
        // step earlier and names it in the logs.
        stats_.malformed += 1U;
        return ParseResult::WrongDirection;
    }

    // Step 3: the declared length must describe this datagram exactly.
    // Computed in std::size_t so the +1 cannot wrap a 16-bit value.
    const std::size_t declared = static_cast<std::size_t>(load_be16(data + 4)) + 1U;
    if ((PRIMARY_HEADER_SIZE + declared) != len) {
        stats_.malformed += 1U;
        return ParseResult::LengthMismatch;
    }

    // Step 4: the data field must be big enough to hold what we are about to
    // read out of it.
    if (declared < MIN_DATA_FIELD) {
        stats_.malformed += 1U;
        return ParseResult::DataFieldTooSmall;
    }

    // Step 5: authenticate before interpreting anything variable-length.
    const std::size_t mac_offset = len - MAC_TAG_SIZE;
    std::uint8_t expected[MAC_TAG_SIZE];
    mac_tag(rx_key_, data, mac_offset, expected);
    if (!constant_time_equal(expected, data + mac_offset, MAC_TAG_SIZE)) {
        stats_.auth_failures += 1U;
        return ParseResult::AuthFailure;
    }

    // From here on every byte in the frame is known to come from a holder of
    // the receive key.
    const std::uint64_t met_us = load_be64(data + 6);
    const std::uint32_t counter = load_be32(data + 14);

    // Step 6: freshness.
    //
    // This runs before the replay check, and the ordering is deliberate.
    // check_and_update() mutates the window, so if replay ran first a frame
    // that then failed freshness would still have advanced the window — an
    // authenticated frame with a far-future counter and a stale timestamp
    // could push the window forward and cause legitimate traffic to be
    // rejected as TooOld. Running the stateless check first means the window
    // is only ever touched by frames we are otherwise prepared to accept.
    if (freshness_enabled_ && (abs_diff_u64(met_us, now_us) > freshness_window_us_)) {
        stats_.stale_rejects += 1U;
        return ParseResult::StaleTimestamp;
    }

    // Step 7: replay.
    const ReplayVerdict verdict = replay_.check_and_update(counter);
    if (verdict == ReplayVerdict::Duplicate) {
        stats_.replay_rejects += 1U;
        return ParseResult::ReplayDuplicate;
    }
    if (verdict == ReplayVerdict::TooOld) {
        stats_.replay_rejects += 1U;
        return ParseResult::ReplayTooOld;
    }

    // Step 8: APID.
    if (!apid_is_known(apid)) {
        stats_.unknown_apid += 1U;
        return ParseResult::UnknownApid;
    }

    frame.header.type = ptype;
    frame.header.apid = apid;
    frame.header.sequence_count = seq_count;
    frame.header.data_length = static_cast<std::uint16_t>(declared);
    frame.header.met_us = met_us;
    frame.header.frame_counter = counter;
    frame.payload = data + HEADER_SIZE;
    frame.payload_len = len - HEADER_SIZE - MAC_TAG_SIZE;

    stats_.accepted += 1U;
    return ParseResult::Ok;
}

}  // namespace stl
