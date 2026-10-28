#include "stl/sha256.h"

#include <cstring>

namespace stl {
namespace {

constexpr std::uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32U - n));
}

inline std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

}  // namespace

void Sha256::reset() noexcept {
    state_[0] = 0x6a09e667U;
    state_[1] = 0xbb67ae85U;
    state_[2] = 0x3c6ef372U;
    state_[3] = 0xa54ff53aU;
    state_[4] = 0x510e527fU;
    state_[5] = 0x9b05688cU;
    state_[6] = 0x1f83d9abU;
    state_[7] = 0x5be0cd19U;
    bit_len_ = 0U;
    buffer_len_ = 0U;
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t block[SHA256_BLOCK_SIZE]) noexcept {
    std::uint32_t w[64];

    for (std::size_t i = 0U; i < 16U; ++i) {
        w[i] = load_be32(block + (i * 4U));
    }
    for (std::size_t i = 16U; i < 64U; ++i) {
        const std::uint32_t s0 =
            rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 =
            rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0U; i < 64U; ++i) {
        const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t len) noexcept {
    if ((data == nullptr) || (len == 0U)) {
        return;
    }

    bit_len_ += static_cast<std::uint64_t>(len) * 8U;

    std::size_t offset = 0U;

    // Top up a partially filled buffer first.
    if (buffer_len_ > 0U) {
        const std::size_t space = SHA256_BLOCK_SIZE - buffer_len_;
        const std::size_t take = (len < space) ? len : space;
        std::memcpy(buffer_ + buffer_len_, data, take);
        buffer_len_ += take;
        offset += take;
        if (buffer_len_ == SHA256_BLOCK_SIZE) {
            compress(buffer_);
            buffer_len_ = 0U;
        }
    }

    // Consume whole blocks straight from the input.
    while ((len - offset) >= SHA256_BLOCK_SIZE) {
        compress(data + offset);
        offset += SHA256_BLOCK_SIZE;
    }

    // Stash the remainder.
    const std::size_t rest = len - offset;
    if (rest > 0U) {
        std::memcpy(buffer_ + buffer_len_, data + offset, rest);
        buffer_len_ += rest;
    }
}

void Sha256::finish(std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept {
    const std::uint64_t total_bits = bit_len_;

    // Append 0x80, then zeroes, then the 64-bit big-endian length.
    std::uint8_t pad = 0x80U;
    update(&pad, 1U);
    bit_len_ = total_bits;  // update() must not count the padding

    pad = 0x00U;
    while (buffer_len_ != 56U) {
        update(&pad, 1U);
        bit_len_ = total_bits;
    }

    std::uint8_t len_be[8];
    for (std::size_t i = 0U; i < 8U; ++i) {
        len_be[i] = static_cast<std::uint8_t>(total_bits >> (56U - (8U * i)));
    }
    update(len_be, 8U);
    bit_len_ = total_bits;

    for (std::size_t i = 0U; i < 8U; ++i) {
        store_be32(out + (i * 4U), state_[i]);
    }
}

void Sha256::hash(const std::uint8_t* data, std::size_t len,
                  std::uint8_t out[SHA256_DIGEST_SIZE]) noexcept {
    Sha256 ctx;
    ctx.update(data, len);
    ctx.finish(out);
}

}  // namespace stl
