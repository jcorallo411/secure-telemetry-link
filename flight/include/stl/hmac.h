// HMAC-SHA256 (RFC 2104) and a constant-time comparison.

#ifndef STL_HMAC_H
#define STL_HMAC_H

#include <cstddef>
#include <cstdint>

#include "stl/sha256.h"

namespace stl {

constexpr std::size_t HMAC_KEY_SIZE = 32U;  // keys are exactly 32 bytes here
constexpr std::size_t MAC_TAG_SIZE = 16U;   // HMAC output truncated to 128 bits

// Full 32-byte HMAC-SHA256.
void hmac_sha256(const std::uint8_t key[HMAC_KEY_SIZE],
                 const std::uint8_t* data, std::size_t len,
                 std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept;

// HMAC-SHA256 truncated to the leftmost MAC_TAG_SIZE bytes, which is what
// goes on the wire.
void mac_tag(const std::uint8_t key[HMAC_KEY_SIZE], const std::uint8_t* data,
             std::size_t len, std::uint8_t out[MAC_TAG_SIZE]) noexcept;

// Constant-time comparison. Returns true when equal.
//
// A byte-at-a-time comparison that returns early leaks, through timing, how
// many leading bytes of a forged tag were correct. That turns tag forgery from
// a 2^128 problem into a 16-step search. This accumulates differences with OR
// and branches exactly once, at the end.
bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                         std::size_t len) noexcept;

}  // namespace stl

#endif  // STL_HMAC_H
