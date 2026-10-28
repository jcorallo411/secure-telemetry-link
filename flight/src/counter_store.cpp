#include "stl/counter_store.h"

#include <unistd.h>

#include <cstdio>
#include <cstring>

namespace stl {

namespace {

// Writes the high-water mark and forces it to disk before returning. fflush
// alone only pushes the bytes into the kernel; without fsync a power loss can
// lose the reservation and hand the next run a counter it has already used.
bool write_mark(const char* path, std::uint32_t value) noexcept {
    std::FILE* f = std::fopen(path, "wb");
    if (f == nullptr) {
        return false;
    }
    std::uint8_t buf[4];
    buf[0] = static_cast<std::uint8_t>(value >> 24);
    buf[1] = static_cast<std::uint8_t>(value >> 16);
    buf[2] = static_cast<std::uint8_t>(value >> 8);
    buf[3] = static_cast<std::uint8_t>(value);

    const bool written = (std::fwrite(buf, 1U, 4U, f) == 4U);
    const bool flushed = (std::fflush(f) == 0);
    const bool synced = (::fsync(fileno(f)) == 0);
    const bool closed = (std::fclose(f) == 0);

    return written && flushed && synced && closed;
}

bool read_mark(const char* path, std::uint32_t& out) noexcept {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return false;  // absent is not an error; caller starts at zero
    }
    std::uint8_t buf[4];
    const std::size_t got = std::fread(buf, 1U, 4U, f);
    std::fclose(f);
    if (got != 4U) {
        return false;
    }
    out = (static_cast<std::uint32_t>(buf[0]) << 24) |
          (static_cast<std::uint32_t>(buf[1]) << 16) |
          (static_cast<std::uint32_t>(buf[2]) << 8) |
          static_cast<std::uint32_t>(buf[3]);
    return true;
}

}  // namespace

bool CounterStore::reserve(std::uint32_t from, const char** err) noexcept {
    // Saturate rather than wrap. A wrapped counter would be accepted by the
    // replay window as a huge backward jump and rejected forever after; worse,
    // it would silently reuse counter values. Exhausting a 32-bit counter
    // means the link must be rekeyed, and the honest thing is to stop.
    if (from > (0xFFFFFFFFU - COUNTER_BLOCK_SIZE)) {
        *err = "transmit counter space exhausted; rekey the link";
        return false;
    }

    const std::uint32_t end = from + COUNTER_BLOCK_SIZE;
    if (!write_mark(path_, end)) {
        *err = "cannot persist counter reservation";
        return false;
    }
    next_ = from;
    block_end_ = end;
    return true;
}

bool CounterStore::open(const char* path, const char** err) noexcept {
    const char* dummy = nullptr;
    if (err == nullptr) {
        err = &dummy;
    }
    if (path == nullptr) {
        *err = "null counter store path";
        return false;
    }

    path_ = path;

    std::uint32_t mark = 0U;
    if (!read_mark(path_, mark)) {
        mark = 0U;  // first run
    }

    if (!reserve(mark, err)) {
        ok_ = false;
        return false;
    }

    ok_ = true;
    *err = "";
    return true;
}

bool CounterStore::next(std::uint32_t& out) noexcept {
    if (!ok_) {
        return false;
    }
    if (next_ >= block_end_) {
        const char* err = nullptr;
        if (!reserve(block_end_, &err)) {
            ok_ = false;
            return false;
        }
    }
    out = next_;
    next_ += 1U;
    return true;
}

}  // namespace stl
