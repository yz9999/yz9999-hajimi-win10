#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOCRYPT
#define NOCRYPT
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <windows.h>
#ifdef interface
#undef interface
#endif
#ifdef small
#undef small
#endif
#ifdef ERROR
#undef ERROR
#endif
#if defined(_MSC_VER)
#include <BaseTsd.h>
#include <intrin.h>
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
using ssize_t = SSIZE_T;
#endif
#endif
#else
#if defined(__APPLE__) && !defined(__APPLE_USE_RFC_3542)
#define __APPLE_USE_RFC_3542 1
#endif
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#ifndef IP_DONTFRAG
#define IP_DONTFRAG 28
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif
#endif
#endif

#if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define HAJIMI_PROTO_LITTLE_ENDIAN 1
#else
#define HAJIMI_PROTO_LITTLE_ENDIAN 0
#endif

namespace hajimi::platform {

// Signed socket handle type so `< 0` / `>= 0` invariants hold identically on
// 64-bit Windows (`INVALID_SOCKET == ~0 == -1`) and POSIX (`int`).
#if defined(_WIN32)
using NativeSocket = intptr_t;
constexpr NativeSocket kInvalidSocket = -1;

inline void ensureWinsock() {
    static std::once_flag once;
    static int initErr = 0;
    std::call_once(once, [] {
        WSADATA wsa{};
        initErr = ::WSAStartup(MAKEWORD(2, 2), &wsa);
    });
    if (initErr != 0) {
        throw std::runtime_error("WSAStartup(2.2) failed");
    }
}

inline SOCKET toOsSocket(NativeSocket s) noexcept {
    return s < 0 ? INVALID_SOCKET : static_cast<SOCKET>(s);
}

inline NativeSocket toNativeSocket(SOCKET s) noexcept {
    if (s == INVALID_SOCKET) return kInvalidSocket;
    const auto signedVal = static_cast<intptr_t>(s);
    return signedVal < 0 ? kInvalidSocket : signedVal;
}

inline void closeNativeSocket(NativeSocket &s) noexcept {
    if (s >= 0) {
        ::closesocket(toOsSocket(s));
        s = kInvalidSocket;
    }
}

inline int lastSocketError() noexcept {
    return ::WSAGetLastError();
}

inline bool isSocketWouldBlock(int err) noexcept {
    return err == WSAEWOULDBLOCK || err == EAGAIN || err == EWOULDBLOCK;
}

inline bool isSocketInterruptedOrTransient(int err) noexcept {
    return err == WSAEINTR || err == WSAENOBUFS || err == WSAECONNREFUSED || err == WSAECONNRESET;
}

inline bool isSocketMsgSize(int err) noexcept {
    return err == WSAEMSGSIZE;
}

inline bool isSocketPathError(int err) noexcept {
    return err == WSAEADDRNOTAVAIL || err == WSAENETDOWN ||
           err == WSAENETUNREACH || err == WSAEHOSTUNREACH || err == WSAENOTCONN;
}

inline bool setNonBlockingAndCloexec(NativeSocket s) noexcept {
    if (s < 0) return false;
    u_long nonBlocking = 1;
    if (::ioctlsocket(toOsSocket(s), FIONBIO, &nonBlocking) != 0) return false;
    (void)::SetHandleInformation(reinterpret_cast<HANDLE>(toOsSocket(s)), HANDLE_FLAG_INHERIT, 0);
    return true;
}

inline void disableUdpConnReset(NativeSocket s) noexcept {
    if (s < 0) return;
    BOOL newBehavior = FALSE;
    DWORD bytesReturned = 0;
    (void)::WSAIoctl(toOsSocket(s), SIO_UDP_CONNRESET,
                     &newBehavior, sizeof(newBehavior),
                     nullptr, 0, &bytesReturned, nullptr, nullptr);
}

inline bool bindSocketToInterface(NativeSocket s, int family, unsigned int ifIndex, const std::string &) noexcept {
    if (s < 0 || ifIndex == 0) return false;
    if (family == AF_INET) {
        // Winsock2 IP_UNICAST_IF requires network byte order for 32-bit interface index.
        DWORD netIfIndex = ::htonl(static_cast<u_long>(ifIndex));
        return ::setsockopt(toOsSocket(s), IPPROTO_IP, IP_UNICAST_IF,
                            reinterpret_cast<const char *>(&netIfIndex), sizeof(netIfIndex)) == 0;
    }
    if (family == AF_INET6) {
        // Winsock2 IPV6_UNICAST_IF requires host byte order.
        DWORD hostIfIndex = static_cast<DWORD>(ifIndex);
        return ::setsockopt(toOsSocket(s), IPPROTO_IPV6, IPV6_UNICAST_IF,
                            reinterpret_cast<const char *>(&hostIfIndex), sizeof(hostIfIndex)) == 0;
    }
    return false;
}

inline void enableSocketDontFragment(NativeSocket s, int family) noexcept {
    if (s < 0) return;
    if (family == AF_INET) {
#ifndef IP_DONTFRAGMENT
#define IP_DONTFRAGMENT 14
#endif
        DWORD df = 1;
        (void)::setsockopt(toOsSocket(s), IPPROTO_IP, IP_DONTFRAGMENT,
                           reinterpret_cast<const char *>(&df), sizeof(df));
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
        DWORD pmtu = IP_PMTUDISC_DO;
        (void)::setsockopt(toOsSocket(s), IPPROTO_IP, IP_MTU_DISCOVER,
                           reinterpret_cast<const char *>(&pmtu), sizeof(pmtu));
#endif
    } else if (family == AF_INET6) {
#if defined(IPV6_DONTFRAG)
        DWORD df = 1;
        (void)::setsockopt(toOsSocket(s), IPPROTO_IPV6, IPV6_DONTFRAG,
                           reinterpret_cast<const char *>(&df), sizeof(df));
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
        DWORD pmtu = IPV6_PMTUDISC_DO;
        (void)::setsockopt(toOsSocket(s), IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                           reinterpret_cast<const char *>(&pmtu), sizeof(pmtu));
#endif
    }
}

inline bool createWakePair(NativeSocket wake[2]) noexcept {
    wake[0] = kInvalidSocket;
    wake[1] = kInvalidSocket;
    try { ensureWinsock(); } catch (...) { return false; }

    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return false;
    BOOL exclusive = TRUE;
    (void)::setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char *>(&exclusive), sizeof(exclusive));

    sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    bindAddr.sin_port = 0;
    int addrLen = sizeof(bindAddr);
    if (::bind(listener, reinterpret_cast<sockaddr *>(&bindAddr), addrLen) != 0 ||
        ::getsockname(listener, reinterpret_cast<sockaddr *>(&bindAddr), &addrLen) != 0 ||
        ::listen(listener, 1) != 0) {
        ::closesocket(listener);
        return false;
    }

    SOCKET writer = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (writer == INVALID_SOCKET) {
        ::closesocket(listener);
        return false;
    }
    if (::connect(writer, reinterpret_cast<sockaddr *>(&bindAddr), addrLen) != 0) {
        ::closesocket(writer);
        ::closesocket(listener);
        return false;
    }

    sockaddr_in peerAddr{}, writerLocalAddr{};
    int peerLen = sizeof(peerAddr), writerLocalLen = sizeof(writerLocalAddr);
    SOCKET reader = ::accept(listener, reinterpret_cast<sockaddr *>(&peerAddr), &peerLen);
    ::closesocket(listener);
    if (reader == INVALID_SOCKET) {
        ::closesocket(writer);
        return false;
    }
    if (::getsockname(writer, reinterpret_cast<sockaddr *>(&writerLocalAddr), &writerLocalLen) != 0 ||
        peerAddr.sin_addr.s_addr != writerLocalAddr.sin_addr.s_addr ||
        peerAddr.sin_port != writerLocalAddr.sin_port) {
        ::closesocket(reader);
        ::closesocket(writer);
        return false;
    }

    BOOL noDelay = TRUE;
    (void)::setsockopt(reader, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&noDelay), sizeof(noDelay));
    (void)::setsockopt(writer, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&noDelay), sizeof(noDelay));

    NativeSocket r = toNativeSocket(reader);
    NativeSocket w = toNativeSocket(writer);
    if (r < 0 || w < 0 || !setNonBlockingAndCloexec(r) || !setNonBlockingAndCloexec(w)) {
        if (r >= 0) closeNativeSocket(r); else ::closesocket(reader);
        if (w >= 0) closeNativeSocket(w); else ::closesocket(writer);
        return false;
    }
    wake[0] = r;
    wake[1] = w;
    return true;
}

inline void writeWakeSignal(NativeSocket writer) noexcept {
    if (writer >= 0) {
        const char value = 1;
        (void)::send(toOsSocket(writer), &value, 1, 0);
    }
}

inline void drainWakeSignal(NativeSocket reader) noexcept {
    if (reader >= 0) {
        char buf[256];
        while (::recv(toOsSocket(reader), buf, sizeof(buf), 0) > 0) {}
    }
}

inline bool utf8ToWide(const std::string &utf8, std::wstring &out) {
    out.clear();
    if (utf8.empty()) return true;
    if (utf8.find('\0') != std::string::npos) return false;
    int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       utf8.data(), static_cast<int>(utf8.size()),
                                       nullptr, 0);
    if (needed <= 0) return false;
    out.resize(static_cast<size_t>(needed));
    int written = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                        utf8.data(), static_cast<int>(utf8.size()),
                                        out.data(), needed);
    return written == needed;
}

inline std::string readBoundedRegularFileUTF8(const std::string &utf8Path,
                                              size_t maxBytes,
                                              const char *readErrMsg,
                                              const char *notRegularMsg,
                                              const char *boundsMsg) {
    std::wstring wpath;
    if (!utf8ToWide(utf8Path, wpath) || wpath.empty()) {
        throw std::runtime_error(readErrMsg);
    }
    DWORD attrs = ::GetFileAttributesW(wpath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) != 0) {
        throw std::runtime_error(notRegularMsg);
    }
    struct HandleGuard {
        HANDLE h = INVALID_HANDLE_VALUE;
        ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
    } file{::CreateFileW(wpath.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (file.h == INVALID_HANDLE_VALUE) {
        throw std::runtime_error(readErrMsg);
    }
    if (::GetFileType(file.h) != FILE_TYPE_DISK) {
        throw std::runtime_error(notRegularMsg);
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!::GetFileInformationByHandle(file.h, &info)) {
        throw std::runtime_error(readErrMsg);
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) != 0) {
        throw std::runtime_error(notRegularMsg);
    }
    LARGE_INTEGER fileSize{};
    if (!::GetFileSizeEx(file.h, &fileSize) || fileSize.QuadPart <= 0 ||
        static_cast<uint64_t>(fileSize.QuadPart) > maxBytes) {
        throw std::runtime_error(boundsMsg);
    }
    std::string loaded;
    loaded.reserve(static_cast<size_t>(fileSize.QuadPart));
    char block[16 * 1024];
    while (loaded.size() <= maxBytes) {
        DWORD toRead = static_cast<DWORD>((std::min)(sizeof(block), maxBytes + 1 - loaded.size()));
        DWORD got = 0;
        if (!::ReadFile(file.h, block, toRead, &got, nullptr)) {
            throw std::runtime_error(readErrMsg);
        }
        if (got == 0) break;
        loaded.append(block, static_cast<size_t>(got));
    }
    if (loaded.empty() || loaded.size() > maxBytes) {
        throw std::runtime_error(boundsMsg);
    }
    return loaded;
}

#else // POSIX (macOS / Linux)

using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;

inline void ensureWinsock() noexcept {}

inline int toOsSocket(NativeSocket s) noexcept { return s; }
inline NativeSocket toNativeSocket(int s) noexcept { return s < 0 ? kInvalidSocket : s; }

inline void closeNativeSocket(NativeSocket &s) noexcept {
    if (s >= 0) {
        ::close(s);
        s = kInvalidSocket;
    }
}

inline int lastSocketError() noexcept { return errno; }

inline bool isSocketWouldBlock(int err) noexcept {
    return err == EAGAIN || err == EWOULDBLOCK;
}

inline bool isSocketInterruptedOrTransient(int err) noexcept {
    return err == EINTR || err == ENOBUFS || err == ECONNREFUSED;
}

inline bool isSocketMsgSize(int err) noexcept {
    return err == EMSGSIZE;
}

inline bool isSocketPathError(int err) noexcept {
    return err == EADDRNOTAVAIL || err == ENETDOWN ||
           err == ENETUNREACH || err == EHOSTUNREACH || err == ENOTCONN;
}

inline bool setNonBlockingAndCloexec(NativeSocket s) noexcept {
    if (s < 0) return false;
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0 || ::fcntl(s, F_SETFL, flags | O_NONBLOCK) != 0) return false;
    (void)::fcntl(s, F_SETFD, FD_CLOEXEC);
    return true;
}

inline void disableUdpConnReset(NativeSocket) noexcept {}

inline bool bindSocketToInterface(NativeSocket s, int family, unsigned int ifIndex, const std::string &ifName) noexcept {
    if (s < 0 || ifIndex == 0) return false;
#if defined(__APPLE__)
    (void)ifName;
    int level = family == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IP;
    int option = family == AF_INET6 ? IPV6_BOUND_IF : IP_BOUND_IF;
    return ::setsockopt(s, level, option, &ifIndex, sizeof(ifIndex)) == 0;
#elif defined(SO_BINDTODEVICE)
    (void)family;
    return ::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifName.c_str(),
                        static_cast<socklen_t>(ifName.size() + 1)) == 0;
#else
    (void)family; (void)ifName;
    return false;
#endif
}

inline void enableSocketDontFragment(NativeSocket s, int family) noexcept {
    if (s < 0) return;
#if defined(__APPLE__)
    if (family == AF_INET) {
        int df = 1;
        (void)::setsockopt(s, IPPROTO_IP, IP_DONTFRAG, &df, sizeof(df));
    } else if (family == AF_INET6) {
        int df = 1;
        (void)::setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &df, sizeof(df));
    }
#elif defined(__linux__)
    if (family == AF_INET) {
        int df = IP_PMTUDISC_DO;
        (void)::setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &df, sizeof(df));
    } else if (family == AF_INET6) {
        int df = IPV6_PMTUDISC_DO;
        (void)::setsockopt(s, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &df, sizeof(df));
    }
#else
    (void)family;
#endif
}

inline bool createWakePair(NativeSocket wake[2]) noexcept {
    wake[0] = kInvalidSocket;
    wake[1] = kInvalidSocket;
    int fds[2]{-1, -1};
    if (::pipe(fds) != 0) return false;
    if (!setNonBlockingAndCloexec(fds[0]) || !setNonBlockingAndCloexec(fds[1])) {
        ::close(fds[0]);
        ::close(fds[1]);
        return false;
    }
    wake[0] = fds[0];
    wake[1] = fds[1];
    return true;
}

inline void writeWakeSignal(NativeSocket writer) noexcept {
    if (writer >= 0) {
        uint8_t value = 1;
        (void)::write(writer, &value, 1);
    }
}

inline void drainWakeSignal(NativeSocket reader) noexcept {
    if (reader >= 0) {
        uint8_t values[256];
        while (::read(reader, values, sizeof(values)) > 0) {}
    }
}

inline std::string readBoundedRegularFileUTF8(const std::string &utf8Path,
                                              size_t maxBytes,
                                              const char *readErrMsg,
                                              const char *notRegularMsg,
                                              const char *boundsMsg) {
    struct stat status{};
    if (::stat(utf8Path.c_str(), &status) != 0) {
        throw std::runtime_error(readErrMsg);
    }
    if (!S_ISREG(status.st_mode)) {
        throw std::runtime_error(notRegularMsg);
    }
    struct Descriptor {
        int value;
        ~Descriptor() { if (value >= 0) ::close(value); }
    } input{::open(utf8Path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC)};
    if (input.value < 0 || ::fstat(input.value, &status) != 0) {
        throw std::runtime_error(readErrMsg);
    }
    if (!S_ISREG(status.st_mode)) {
        throw std::runtime_error(notRegularMsg);
    }
    if (status.st_size <= 0 || static_cast<uint64_t>(status.st_size) > maxBytes) {
        throw std::runtime_error(boundsMsg);
    }
    std::string loaded;
    loaded.reserve(static_cast<size_t>(status.st_size));
    char block[16 * 1024];
    while (loaded.size() <= maxBytes) {
        auto maximum = (std::min)(sizeof(block), maxBytes + 1 - loaded.size());
        auto count = ::read(input.value, block, maximum);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(readErrMsg);
        }
        if (!count) break;
        loaded.append(block, static_cast<size_t>(count));
    }
    if (loaded.empty() || loaded.size() > maxBytes) {
        throw std::runtime_error(boundsMsg);
    }
    return loaded;
}

#endif // _WIN32

// Portable bit & 128-bit arithmetic intrinsics
inline int popcount32(uint32_t x) noexcept {
#if defined(_MSC_VER) && !defined(__clang__)
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    return static_cast<int>((((x + (x >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24);
#else
    return __builtin_popcount(x);
#endif
}

inline int popcount64(uint64_t x) noexcept {
#if defined(_MSC_VER) && !defined(__clang__)
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    return static_cast<int>((((x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL) * 0x0101010101010101ULL) >> 56);
#else
    return __builtin_popcountll(x);
#endif
}

inline int ctz64(uint64_t x) noexcept {
    if (x == 0) return 64;
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long idx = 0;
    _BitScanForward64(&idx, x);
    return static_cast<int>(idx);
#else
    return __builtin_ctzll(x);
#endif
}

inline int clz64(uint64_t x) noexcept {
    if (x == 0) return 64;
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long idx = 0;
    _BitScanReverse64(&idx, x);
    return 63 - static_cast<int>(idx);
#else
    return __builtin_clzll(x);
#endif
}

inline uint64_t umul128(uint64_t a, uint64_t b, uint64_t &hiOut) noexcept {
#if defined(__SIZEOF_INT128__)
    __uint128_t r = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
    hiOut = static_cast<uint64_t>(r >> 64);
    return static_cast<uint64_t>(r);
#elif defined(_MSC_VER) && defined(_M_X64)
    return _umul128(a, b, &hiOut);
#elif defined(_MSC_VER) && defined(_M_ARM64)
    hiOut = __umulh(a, b);
    return a * b;
#else
    uint64_t aLo = static_cast<uint32_t>(a), aHi = a >> 32;
    uint64_t bLo = static_cast<uint32_t>(b), bHi = b >> 32;
    uint64_t p0 = aLo * bLo;
    uint64_t p1 = aLo * bHi;
    uint64_t p2 = aHi * bLo;
    uint64_t p3 = aHi * bHi;
    uint64_t cy = ((p0 >> 32) + static_cast<uint32_t>(p1) + static_cast<uint32_t>(p2)) >> 32;
    hiOut = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    return p0 + (p1 << 32) + (p2 << 32);
#endif
}

} // namespace hajimi::platform
