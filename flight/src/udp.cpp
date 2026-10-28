#include "stl/udp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace stl {

static_assert(sizeof(sockaddr_in) <= 16U, "peer_ storage too small");

UdpSocket::~UdpSocket() noexcept { close(); }

void UdpSocket::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool UdpSocket::bind(const char* host, std::uint16_t port, const char** err) noexcept {
    const char* dummy = nullptr;
    if (err == nullptr) {
        err = &dummy;
    }

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        *err = "socket() failed";
        return false;
    }

    int one = 1;
    (void)::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close();
        *err = "invalid bind address";
        return false;
    }

    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close();
        *err = "bind() failed (port already in use?)";
        return false;
    }

    *err = "";
    return true;
}

bool UdpSocket::set_peer(const char* host, std::uint16_t port, const char** err) noexcept {
    const char* dummy = nullptr;
    if (err == nullptr) {
        err = &dummy;
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        *err = "invalid peer address";
        return false;
    }

    std::memcpy(peer_, &addr, sizeof(addr));
    has_peer_ = true;
    *err = "";
    return true;
}

bool UdpSocket::send(const std::uint8_t* data, std::size_t len) noexcept {
    if ((fd_ < 0) || !has_peer_ || (data == nullptr)) {
        return false;
    }
    sockaddr_in addr;
    std::memcpy(&addr, peer_, sizeof(addr));
    const ssize_t n = ::sendto(fd_, data, len, 0,
                               reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return (n == static_cast<ssize_t>(len));
}

long UdpSocket::recv_timeout(std::uint8_t* buf, std::size_t cap, int timeout_ms) noexcept {
    if ((fd_ < 0) || (buf == nullptr) || (cap == 0U)) {
        return RECV_ERROR;
    }

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd_, &rfds);

    const int ready = ::select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
    if (ready == 0) {
        return RECV_TIMEOUT;
    }
    if (ready < 0) {
        // EINTR is an interrupted wait, not a failure; report it as a timeout
        // so the caller simply loops.
        return (errno == EINTR) ? RECV_TIMEOUT : RECV_ERROR;
    }

    const ssize_t n = ::recvfrom(fd_, buf, cap, 0, nullptr, nullptr);
    if (n < 0) {
        return RECV_ERROR;
    }
    return static_cast<long>(n);  // may legitimately be 0
}

}  // namespace stl
