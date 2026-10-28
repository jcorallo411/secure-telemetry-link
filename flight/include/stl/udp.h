// Minimal blocking-with-timeout UDP socket wrapper.

#ifndef STL_UDP_H
#define STL_UDP_H

#include <cstddef>
#include <cstdint>

namespace stl {

class UdpSocket {
public:
    UdpSocket() noexcept : fd_(-1) {}
    ~UdpSocket() noexcept;

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // Binds to host:port. Returns false and sets `err` on failure.
    bool bind(const char* host, std::uint16_t port, const char** err) noexcept;

    // Sets the default destination for send().
    bool set_peer(const char* host, std::uint16_t port, const char** err) noexcept;

    bool send(const std::uint8_t* data, std::size_t len) noexcept;

    // Timeout and error are negative, so that a zero-length datagram is
    // reported as the datagram it is rather than being confused with "nothing
    // arrived". A zero-length UDP datagram is a real thing an attacker can
    // send, and conflating it with a timeout means it never reaches the
    // parser and never appears in the rejection counters.
    static constexpr long RECV_TIMEOUT = -1;
    static constexpr long RECV_ERROR = -2;

    // Returns the datagram size (>= 0), RECV_TIMEOUT, or RECV_ERROR.
    // A datagram larger than `cap` is truncated and reported as `cap` bytes;
    // the length checks in SecureLink::open then reject it, which is the
    // correct outcome for an oversized frame.
    long recv_timeout(std::uint8_t* buf, std::size_t cap, int timeout_ms) noexcept;

    bool valid() const noexcept { return fd_ >= 0; }
    void close() noexcept;

private:
    int fd_;
    // sockaddr_in kept as raw storage so the header does not drag in
    // <netinet/in.h> for every translation unit that includes it.
    unsigned char peer_[16];
    bool has_peer_ = false;
};

}  // namespace stl

#endif  // STL_UDP_H
