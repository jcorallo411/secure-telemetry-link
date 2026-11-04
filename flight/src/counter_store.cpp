#include "stl/counter_store.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>

#include <cstdio>
#include <cstring>

namespace stl {

namespace {

// Longest state-file path accepted. Fixed buffers keep the path handling free
// of heap allocation, like the rest of the flight code.
constexpr std::size_t MAX_PATH_LEN = 1024U;

enum class ReadStatus { Ok, Absent, Corrupt, IoError };

// Forces a directory entry to disk, so a rename into it survives power loss.
// Not every filesystem supports fsync on a directory; the rename itself is
// still atomic, so failure here is not treated as fatal.
void sync_parent_dir(const char* path) noexcept {
    char dir[MAX_PATH_LEN];
    const std::size_t len = std::strlen(path);
    if (len >= sizeof(dir)) {
        return;
    }
    std::memcpy(dir, path, len + 1U);
    char* slash = std::strrchr(dir, '/');
    if (slash == nullptr) {
        dir[0] = '.';
        dir[1] = '\0';
    } else if (slash == dir) {
        dir[1] = '\0';  // file directly under "/"
    } else {
        *slash = '\0';
    }
    const int fd = ::open(dir, O_RDONLY);
    if (fd >= 0) {
        (void)::fsync(fd);
        (void)::close(fd);
    }
}

// Writes the high-water mark atomically and durably.
//
// The mark goes to "<path>.tmp" first, is fsynced, and is then renamed over
// the real file. rename() within one directory is atomic, so a crash at any
// point leaves either the old mark or the new one on disk, never a truncated
// file. Writing the real file in place (fopen "wb") would truncate it first,
// and a crash between the truncate and the write would leave it empty; the
// next run would then have no mark to start from, which is the restart-at-zero
// failure this class exists to prevent.
bool write_mark(const char* path, std::uint32_t value) noexcept {
    char tmp[MAX_PATH_LEN];
    const int n = std::snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || static_cast<std::size_t>(n) >= sizeof(tmp)) {
        return false;
    }

    std::FILE* f = std::fopen(tmp, "wb");
    if (f == nullptr) {
        return false;
    }
    std::uint8_t buf[4];
    buf[0] = static_cast<std::uint8_t>(value >> 24);
    buf[1] = static_cast<std::uint8_t>(value >> 16);
    buf[2] = static_cast<std::uint8_t>(value >> 8);
    buf[3] = static_cast<std::uint8_t>(value);

    // fflush alone only pushes the bytes into the kernel; without fsync a
    // power loss can lose the reservation and hand the next run a counter it
    // has already used.
    const bool written = (std::fwrite(buf, 1U, 4U, f) == 4U);
    const bool flushed = (std::fflush(f) == 0);
    const bool synced = (::fsync(fileno(f)) == 0);
    const bool closed = (std::fclose(f) == 0);
    if (!(written && flushed && synced && closed)) {
        (void)std::remove(tmp);
        return false;
    }

    if (std::rename(tmp, path) != 0) {
        (void)std::remove(tmp);
        return false;
    }
    sync_parent_dir(path);
    return true;
}

// Only a file that does not exist means "first run". A file that exists but
// cannot be read, or does not hold exactly four bytes, is reported as such so
// the caller can refuse to start: guessing zero would reuse counters the
// receiver has already seen.
ReadStatus read_mark(const char* path, std::uint32_t& out) noexcept {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return (errno == ENOENT) ? ReadStatus::Absent : ReadStatus::IoError;
    }
    std::uint8_t buf[5];
    const std::size_t got = std::fread(buf, 1U, sizeof(buf), f);
    const bool read_error = (std::ferror(f) != 0);
    std::fclose(f);
    if (read_error) {
        return ReadStatus::IoError;
    }
    if (got != 4U) {
        return ReadStatus::Corrupt;  // short, empty, or longer than a mark
    }
    out = (static_cast<std::uint32_t>(buf[0]) << 24) |
          (static_cast<std::uint32_t>(buf[1]) << 16) |
          (static_cast<std::uint32_t>(buf[2]) << 8) |
          static_cast<std::uint32_t>(buf[3]);
    return ReadStatus::Ok;
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
    switch (read_mark(path_, mark)) {
        case ReadStatus::Ok:
            break;
        case ReadStatus::Absent:
            mark = 0U;  // first run
            break;
        case ReadStatus::Corrupt:
            // Fail closed. Restarting at zero would reuse counters and lock
            // this sender out of the receiver's replay window.
            *err = "counter state file is corrupt (not 4 bytes); refusing to "
                   "start rather than reuse counters";
            ok_ = false;
            return false;
        case ReadStatus::IoError:
        default:
            *err = "cannot read counter state file";
            ok_ = false;
            return false;
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
