#ifndef HAJIMI_WIN_TRANSPORT_CXX_H
#define HAJIMI_WIN_TRANSPORT_CXX_H


#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "../../HajimiProtocolsCXX/Runtime.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace hajimi::win_transport {

struct RuntimeConfig {
    size_t maxQueuedStreamBytes = 2 * 1024 * 1024; // 2 MiB per stream/datagram
    size_t maxCoalescedSendBytes = 131072;          // 128 KiB scatter-gather batch
    double tcpHandshakeTimeoutSeconds = 10.0;
};

/// Native C++17 asynchronous transport runtime for Windows (Winsock2 non-blocking
/// reactor, 128 KiB WSASend scatter-gather batching, SIO_UDP_CONNRESET protection,
/// IP_UNICAST_IF / IPV6_UNICAST_IF physical interface pinning, OpenSSL 3.5+ TLS 1.2/1.3
/// with X25519MLKEM768 hybrid PQC and offline Windows Crypt32 root-store verification).
class WinTransportRuntime final : public std::enable_shared_from_this<WinTransportRuntime> {
public:
    static std::shared_ptr<WinTransportRuntime> create(const RuntimeConfig &config = {});
    ~WinTransportRuntime();

    WinTransportRuntime(const WinTransportRuntime &) = delete;
    WinTransportRuntime &operator=(const WinTransportRuntime &) = delete;

    /// Creates a TransportFactory bound to this runtime's serialized application
    /// strand, timer wheel, and TCP/TLS/UDP reactor.
    std::shared_ptr<hajimi::TransportFactory> makeFactory(
        double setupDeadlineSeconds = hajimi::ProtocolTimeouts::protocolSetupSeconds);

    /// Signals fail-closed cancellation to active dials/streams while continuing
    /// to drain queued cleanup callbacks on the serialized strand.
    void cancelAll();

    /// Stops reactor and strand threads cleanly and releases all OS sockets.
    void shutdown();

    /// Flushes cached interface name/alias -> NET_IFINDEX mappings after network changes.
    void flushInterfaceCache();

    /// Resolves a Windows interface name, GUID, or friendly alias (UTF-8) to its
    /// current non-zero interface index, or 0 if not found.
    unsigned int resolveInterfaceIndex(const std::string &interfaceName);

    struct Impl;
private:
    explicit WinTransportRuntime(const RuntimeConfig &config);
    std::unique_ptr<Impl> impl_;
};

} // namespace hajimi::win_transport
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif

/// Executes offline loopback self-tests for WinTransportRuntime (strand ordering,
/// post-cancel cleanup delivery, 128 KiB TCP scatter-gather & half-close, TLS 1.3
/// handshake/ALPN/trust validation, and UDP SIO_UDP_CONNRESET resilience).
/// Returns 0 on success, or a positive step code on failure.
int hajimi_win_transport_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* HAJIMI_WIN_TRANSPORT_CXX_H */
