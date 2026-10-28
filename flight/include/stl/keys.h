// Key file loading.
//
// Format of keys/stl_keys.bin:
//   offset 0 : magic "STLK" (4 bytes)
//   offset 4 : format version, currently 1 (1 byte)
//   offset 5 : K_TM, 32 bytes  (authenticates vehicle -> ground)
//   offset 37: K_TC, 32 bytes  (authenticates ground -> vehicle)
//   total    : 69 bytes
//
// A pre-shared key file is the right level of ceremony for a testbed and the
// wrong one for a vehicle. docs/THREAT_MODEL.md section 5 treats this as the
// primary residual risk and describes what a real system needs instead.

#ifndef STL_KEYS_H
#define STL_KEYS_H

#include <cstdint>

#include "stl/hmac.h"

namespace stl {

constexpr std::uint8_t KEYFILE_VERSION = 1U;
constexpr std::size_t KEYFILE_SIZE = 69U;

struct KeySet {
    std::uint8_t tm[HMAC_KEY_SIZE];  // vehicle -> ground
    std::uint8_t tc[HMAC_KEY_SIZE];  // ground -> vehicle
};

// Returns true on success. On failure `err` (if non-null) receives a short
// human-readable reason.
bool load_keys(const char* path, KeySet& out, const char** err) noexcept;

}  // namespace stl

#endif  // STL_KEYS_H
