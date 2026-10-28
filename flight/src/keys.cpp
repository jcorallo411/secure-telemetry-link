#include "stl/keys.h"

#include <sys/stat.h>

#include <cstdio>
#include <cstring>

namespace stl {

bool load_keys(const char* path, KeySet& out, const char** err) noexcept {
    const char* dummy = nullptr;
    if (err == nullptr) {
        err = &dummy;
    }

    if (path == nullptr) {
        *err = "null key path";
        return false;
    }

    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        *err = "cannot open key file (run tools/gen_keys.py first)";
        return false;
    }

    // Refuse group- or world-readable key files. A key that anyone on the box
    // can read is not a secret, and silently accepting it would hide the
    // single most consequential misconfiguration in the system.
    struct stat st;
    if (fstat(fileno(f), &st) == 0) {
        if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            std::fclose(f);
            *err = "key file is group/world accessible; chmod 600 it";
            return false;
        }
    }

    std::uint8_t buf[KEYFILE_SIZE];
    const std::size_t got = std::fread(buf, 1U, sizeof(buf), f);

    // Read one extra byte to detect a file that is longer than expected.
    std::uint8_t extra = 0U;
    const std::size_t trailing = std::fread(&extra, 1U, 1U, f);
    std::fclose(f);

    if (got != KEYFILE_SIZE) {
        *err = "key file is the wrong size";
        return false;
    }
    if (trailing != 0U) {
        *err = "key file has trailing data";
        return false;
    }
    if (std::memcmp(buf, "STLK", 4U) != 0) {
        *err = "key file magic mismatch";
        return false;
    }
    if (buf[4] != KEYFILE_VERSION) {
        *err = "unsupported key file version";
        return false;
    }

    std::memcpy(out.tm, buf + 5, HMAC_KEY_SIZE);
    std::memcpy(out.tc, buf + 37, HMAC_KEY_SIZE);

    // Reject the all-zero key outright. It is what you get from a truncated
    // write or a failed RNG, and it would otherwise "work" end to end while
    // providing no security at all.
    std::uint8_t tm_or = 0U;
    std::uint8_t tc_or = 0U;
    for (std::size_t i = 0U; i < HMAC_KEY_SIZE; ++i) {
        tm_or = static_cast<std::uint8_t>(tm_or | out.tm[i]);
        tc_or = static_cast<std::uint8_t>(tc_or | out.tc[i]);
    }
    if ((tm_or == 0U) || (tc_or == 0U)) {
        *err = "key file contains an all-zero key";
        return false;
    }
    if (std::memcmp(out.tm, out.tc, HMAC_KEY_SIZE) == 0) {
        *err = "TM and TC keys are identical; regenerate";
        return false;
    }

    std::memset(buf, 0, sizeof(buf));
    *err = "";
    return true;
}

}  // namespace stl
