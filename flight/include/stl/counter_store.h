// Persistent transmit-counter storage.
//
// Why this exists
// ---------------
// The anti-replay window rejects any frame counter it has already seen. That
// is correct, and it means a sender whose counter restarts at zero after a
// reboot is indistinguishable from an attacker replaying old traffic — the
// receiver rejects the legitimate sender, and the link is dead until the
// receiver is also restarted. This was found by running the ground station
// twice against one flight computer; the second run's commands were all
// rejected as REPLAY_DUPLICATE.
//
// The fix is counter block reservation, the same technique used for monotonic
// counters in secure boot and HSM designs:
//
//   1. At startup, read the persisted high-water mark H.
//   2. Immediately write H + BLOCK back to the file and flush it.
//   3. Hand out counters H, H+1, ... H+BLOCK-1 from memory.
//   4. When the block is exhausted, reserve the next one.
//
// Persisting before use, rather than after, is the whole point. If the process
// dies mid-block, the file already claims the entire block as spent, so the
// next run starts above every counter that could possibly have been
// transmitted. The cost is skipped counters after a crash, which the replay
// window handles as an ordinary forward jump. The opposite order — write after
// send — would reuse counters after a crash, which is the exact failure this
// is meant to prevent.

#ifndef STL_COUNTER_STORE_H
#define STL_COUNTER_STORE_H

#include <cstdint>

namespace stl {

constexpr std::uint32_t COUNTER_BLOCK_SIZE = 1024U;

class CounterStore {
public:
    CounterStore() noexcept : path_(nullptr), next_(0U), block_end_(0U), ok_(false) {}

    // Opens (creating if absent) the state file and reserves the first block.
    bool open(const char* path, const char** err) noexcept;

    // Returns the next counter to use, reserving a new block if needed.
    // Returns false only if a required reservation write failed.
    bool next(std::uint32_t& out) noexcept;

    std::uint32_t peek() const noexcept { return next_; }
    bool ok() const noexcept { return ok_; }

private:
    bool reserve(std::uint32_t from, const char** err) noexcept;

    const char* path_;
    std::uint32_t next_;
    std::uint32_t block_end_;
    bool ok_;
};

}  // namespace stl

#endif  // STL_COUNTER_STORE_H
