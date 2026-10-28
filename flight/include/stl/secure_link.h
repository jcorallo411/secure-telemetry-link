// The secure link layer: frame construction on transmit, and the ordered
// validation pipeline on receive (docs/PROTOCOL.md section 5).

#ifndef STL_SECURE_LINK_H
#define STL_SECURE_LINK_H

#include <cstddef>
#include <cstdint>

#include "stl/counter_store.h"
#include "stl/protocol.h"
#include "stl/replay.h"

namespace stl {

constexpr std::uint64_t DEFAULT_FRESHNESS_WINDOW_US = 30ULL * 1000ULL * 1000ULL;

// Per-rejection-reason counters. Reported in telemetry so that an operator can
// see an attack in progress rather than just noticing that frames stopped
// arriving.
struct LinkStats {
    std::uint64_t accepted;
    std::uint64_t malformed;       // header-level rejects
    std::uint64_t auth_failures;
    std::uint64_t replay_rejects;
    std::uint64_t stale_rejects;
    std::uint64_t unknown_apid;
    std::uint64_t bad_payload;

    void clear() noexcept {
        accepted = 0U;
        malformed = 0U;
        auth_failures = 0U;
        replay_rejects = 0U;
        stale_rejects = 0U;
        unknown_apid = 0U;
        bad_payload = 0U;
    }
};

// A received frame after successful validation. `payload` points into the
// caller's receive buffer; it is valid only while that buffer is unmodified.
// Nothing is copied, because copying a variable-length payload into a second
// fixed buffer is where length bugs breed.
struct ReceivedFrame {
    PacketHeader header;
    const std::uint8_t* payload;
    std::size_t payload_len;
};

class SecureLink {
public:
    // tx_key authenticates what this end sends; rx_key authenticates what it
    // receives. The two ends of a link pass these in opposite order.
    SecureLink(const std::uint8_t tx_key[HMAC_KEY_SIZE],
               const std::uint8_t rx_key[HMAC_KEY_SIZE],
               PacketType tx_type) noexcept;

    // Builds an authenticated frame into `out`.
    // Returns bytes written, or 0 on any failure (payload too large, buffer
    // too small). A zero return is never a partially written buffer.
    std::size_t seal(std::uint16_t apid, const std::uint8_t* payload,
                     std::size_t payload_len, std::uint64_t met_us,
                     std::uint8_t* out, std::size_t out_cap) noexcept;

    // Validates a received datagram. On ParseResult::Ok, `frame` describes it.
    // On anything else `frame` is untouched and the relevant counter has been
    // incremented.
    ParseResult open(const std::uint8_t* data, std::size_t len,
                     std::uint64_t now_us, ReceivedFrame& frame) noexcept;

    // Attaches a persistent counter source. Without one the transmit counter
    // starts at zero each run, which a receiver that did not also restart will
    // correctly reject as a replay. The store must outlive this link.
    void attach_counter_store(CounterStore* store) noexcept { counter_store_ = store; }

    // Freshness checking stays off until the receiver has a clock it trusts.
    void enable_freshness_check(bool enabled) noexcept { freshness_enabled_ = enabled; }
    void set_freshness_window_us(std::uint64_t w) noexcept { freshness_window_us_ = w; }

    const LinkStats& stats() const noexcept { return stats_; }
    std::uint32_t tx_frame_counter() const noexcept { return tx_counter_; }
    const ReplayWindow& replay_window() const noexcept { return replay_; }

private:
    std::uint16_t next_sequence(std::uint16_t apid) noexcept;

    std::uint8_t tx_key_[HMAC_KEY_SIZE];
    std::uint8_t rx_key_[HMAC_KEY_SIZE];
    PacketType tx_type_;
    PacketType expected_rx_type_;

    std::uint32_t tx_counter_;
    CounterStore* counter_store_;

    // CCSDS sequence counts are per-APID. A small fixed table covers the APIDs
    // in use; an unlisted APID shares slot 0, which only affects gap-detection
    // cosmetics, never security.
    static constexpr std::size_t SEQ_SLOTS = 8U;
    std::uint16_t seq_counts_[SEQ_SLOTS];

    ReplayWindow replay_;
    bool freshness_enabled_;
    std::uint64_t freshness_window_us_;
    LinkStats stats_;
};

}  // namespace stl

#endif  // STL_SECURE_LINK_H
