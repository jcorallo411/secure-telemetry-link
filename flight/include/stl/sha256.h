// SHA-256 (FIPS 180-4).
//
// Written from the standard rather than pulled from OpenSSL so that the flight
// side has no external dependencies: a flight build should be auditable in its
// entirety and buildable for a bare-metal target with nothing but a compiler.
//
// No heap allocation, no recursion, fixed loop bounds.

#ifndef STL_SHA256_H
#define STL_SHA256_H

#include <cstddef>
#include <cstdint>

namespace stl {

constexpr std::size_t SHA256_DIGEST_SIZE = 32U;
constexpr std::size_t SHA256_BLOCK_SIZE = 64U;

class Sha256 {
public:
    Sha256() noexcept { reset(); }

    void reset() noexcept;
    void update(const std::uint8_t* data, std::size_t len) noexcept;

    // Writes SHA256_DIGEST_SIZE bytes to `out`. The object is left finalized;
    // call reset() before reusing it.
    void finish(std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept;

    // One-shot convenience wrapper.
    static void hash(const std::uint8_t* data, std::size_t len,
                     std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept;

private:
    void compress(const std::uint8_t block[SHA256_BLOCK_SIZE]) noexcept;

    std::uint32_t state_[8];
    std::uint64_t bit_len_;
    std::uint8_t buffer_[SHA256_BLOCK_SIZE];
    std::size_t buffer_len_;
};

}  // namespace stl

#endif  // STL_SHA256_H
