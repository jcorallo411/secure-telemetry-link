#include "stl/replay.h"

namespace stl {

ReplayVerdict ReplayWindow::check_and_update(std::uint32_t counter) noexcept {
    // First frame of the session anchors the window. Note this accepts any
    // starting counter, including a large one. That is deliberate: a receiver
    // joining a link already in progress must be able to synchronize. It is
    // also a real limitation, since an attacker who gets a captured frame in
    // before the legitimate sender can anchor the window at a value of their
    // choosing. The freshness check in protocol section 5.2 is what bounds
    // that, and docs/THREAT_MODEL.md section 4.3 covers it in full.
    if (!started_) {
        started_ = true;
        highest_ = counter;
        bitmap_ = 1U;
        return ReplayVerdict::Accept;
    }

    if (counter > highest_) {
        const std::uint32_t advance = counter - highest_;
        if (advance >= REPLAY_WINDOW_SIZE) {
            // Jumped clear past the window; every old slot is now unprovable,
            // so start fresh with only this frame recorded.
            bitmap_ = 1U;
        } else {
            bitmap_ = (bitmap_ << advance) | 1ULL;
        }
        highest_ = counter;
        return ReplayVerdict::Accept;
    }

    if (counter == highest_) {
        return ReplayVerdict::Duplicate;
    }

    const std::uint32_t age = highest_ - counter;
    if (age >= REPLAY_WINDOW_SIZE) {
        return ReplayVerdict::TooOld;
    }

    const std::uint64_t mask = 1ULL << age;
    if ((bitmap_ & mask) != 0ULL) {
        return ReplayVerdict::Duplicate;
    }

    bitmap_ |= mask;
    return ReplayVerdict::Accept;
}

}  // namespace stl
