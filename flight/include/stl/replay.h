// Sliding-window anti-replay, modeled on IPsec (RFC 4303 section 3.4.3).
//
// The window tolerates the reordering a UDP link produces while guaranteeing
// that no frame counter is ever accepted twice.

#ifndef STL_REPLAY_H
#define STL_REPLAY_H

#include <cstdint>

namespace stl {

constexpr std::uint32_t REPLAY_WINDOW_SIZE = 64U;  // bits in the bitmap

enum class ReplayVerdict : std::uint8_t {
    Accept = 0U,
    Duplicate = 1U,
    TooOld = 2U
};

class ReplayWindow {
public:
    ReplayWindow() noexcept : highest_(0U), bitmap_(0U), started_(false) {}

    void reset() noexcept {
        highest_ = 0U;
        bitmap_ = 0U;
        started_ = false;
    }

    // Tests `counter` and, on Accept, records it. Not idempotent: a second
    // call with the same counter returns Duplicate.
    ReplayVerdict check_and_update(std::uint32_t counter) noexcept;

    std::uint32_t highest() const noexcept { return highest_; }
    bool started() const noexcept { return started_; }

private:
    std::uint32_t highest_;
    std::uint64_t bitmap_;  // bit n set means (highest_ - n) has been seen
    bool started_;
};

}  // namespace stl

#endif  // STL_REPLAY_H
