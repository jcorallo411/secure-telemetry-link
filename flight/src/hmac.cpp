#include "stl/hmac.h"

#include <cstring>

namespace stl {

void hmac_sha256(const std::uint8_t key[HMAC_KEY_SIZE], const std::uint8_t* data,
                 std::size_t len, std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept {
    // Keys here are fixed at 32 bytes, which is shorter than the 64-byte block
    // size, so the RFC 2104 "hash the key if it is too long" branch cannot be
    // reached. Keeping the key length fixed removes that branch entirely.
    static_assert(HMAC_KEY_SIZE <= SHA256_BLOCK_SIZE,
                  "key must fit in one block");

    std::uint8_t k_ipad[SHA256_BLOCK_SIZE];
    std::uint8_t k_opad[SHA256_BLOCK_SIZE];

    std::memset(k_ipad, 0x36, sizeof(k_ipad));
    std::memset(k_opad, 0x5c, sizeof(k_opad));

    for (std::size_t i = 0U; i < HMAC_KEY_SIZE; ++i) {
        k_ipad[i] = static_cast<std::uint8_t>(k_ipad[i] ^ key[i]);
        k_opad[i] = static_cast<std::uint8_t>(k_opad[i] ^ key[i]);
    }

    std::uint8_t inner[SHA256_DIGEST_SIZE];
    Sha256 ctx;
    ctx.update(k_ipad, sizeof(k_ipad));
    ctx.update(data, len);
    ctx.finish(inner);

    ctx.reset();
    ctx.update(k_opad, sizeof(k_opad));
    ctx.update(inner, sizeof(inner));
    ctx.finish(out);

    // Scrub the padded key material. Not a complete defense (the compiler may
    // still elide it, and the key is in memory anyway), but cheap, and it
    // shrinks the window in which a core dump exposes derived key state.
    std::memset(k_ipad, 0, sizeof(k_ipad));
    std::memset(k_opad, 0, sizeof(k_opad));
    std::memset(inner, 0, sizeof(inner));
}

void mac_tag(const std::uint8_t key[HMAC_KEY_SIZE], const std::uint8_t* data,
             std::size_t len, std::uint8_t out[MAC_TAG_SIZE]) noexcept {
    std::uint8_t full[SHA256_DIGEST_SIZE];
    hmac_sha256(key, data, len, full);
    std::memcpy(out, full, MAC_TAG_SIZE);
    std::memset(full, 0, sizeof(full));
}

bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                         std::size_t len) noexcept {
    std::uint8_t diff = 0U;
    for (std::size_t i = 0U; i < len; ++i) {
        diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0U;
}

}  // namespace stl
