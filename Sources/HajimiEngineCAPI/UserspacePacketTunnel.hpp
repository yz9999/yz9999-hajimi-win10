#pragma once

#include "EncryptedDnsAndFakeIp.hpp"
#include "../HajimiDataPlaneC/include/hajimi_dataplane.h"
#include "../HajimiFlowCXX/include/HajimiFlowCXX.h"
#include "../HajimiPlatformC/include/HajimiShmRing.h"
#include "../HajimiPlatformC/include/HajimiPacketSlabPool.h"
#include "../HajimiPlatformC/include/HajimiAsyncPoller.h" 
#include "../HajimiProtocolsCXX/Runtime.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace hajimi::engine {

struct TunnelFlowKey {
    uint8_t version = 4;
    uint8_t srcIp[16]{};
    uint8_t dstIp[16]{};
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    bool operator==(const TunnelFlowKey &o) const noexcept;
};

struct TunnelFlowKeyHash {
    size_t operator()(const TunnelFlowKey &k) const noexcept;
};

/// Endpoint-Independent (Full-Cone) UDP NAT key scoped per `(version, clientIp, clientPort, outboundPolicy)`
/// so STUN / WebRTC / P2P games & QUIC reuse a single outbound `Datagram` association per client socket.
struct UdpNatKey {
    uint8_t version = 4;
    uint8_t srcIp[16]{};
    uint16_t srcPort = 0;
    std::string policyLeaf;

    bool operator==(const UdpNatKey &o) const noexcept;
};

struct UdpNatKeyHash {
    size_t operator()(const UdpNatKey &k) const noexcept;
};

struct TunnelTelemetry {
    uint64_t rxPackets = 0;
    uint64_t txPackets = 0;
    uint64_t uploadedBytes = 0;
    uint64_t downloadedBytes = 0;
    uint32_t activeTcpFlows = 0;
    uint64_t totalTcpFlows = 0;
    uint32_t activeUdpSessions = 0;
    uint64_t totalUdpSessions = 0;
};

struct TunnelFlowTrackerHooks {
    std::function<uint64_t(const char *proto,
                           const std::string &clientIp,
                           uint16_t clientPort,
                           const std::string &targetHost,
                           uint16_t targetPort,
                           const std::string &policy,
                           std::function<void()> cancelFn)> onOpen;
    std::function<void(uint64_t connId, uint64_t addUp, uint64_t addDown)> onBytes;
    std::function<void(uint64_t connId)> onClose;
};

/// Userspace L3 Packet Tunnel Data-Plane (`HajimiNativeCore` C++17 counterpart)
/// Supports both `framePrefixLength = 0` (Windows Wintun pure Layer-3 IPv4/IPv6)
/// and `framePrefixLength = 4` (macOS `utun` 4-byte AF header) with zero extra copies.
class UserspacePacketTunnel {
public:
    using StreamConnector = std::function<void(
        const std::string &clientIp, uint16_t clientPort, const Target &target, StreamCallback cb)>;

    using DatagramPolicySelector = std::function<std::string(
        const std::string &clientIp, uint16_t clientPort, const Target &target)>;

    using DatagramConnector = std::function<void(
        const std::string &policyLeaf, const Target &initialTarget, DatagramCallback cb)>;

    static constexpr size_t kMaxTcpSessions = 4096;
    static constexpr int64_t kTcpSynTimeoutMs = 15 * 1000;
    static constexpr int64_t kTcpEstablishedIdleMs = 300 * 1000;
    static constexpr int64_t kTcpFinWaitTimeoutMs = 15 * 1000;

    static constexpr size_t kMaxUdpNatSessions = 2048;
    static constexpr size_t kMaxPendingUdpPackets = 128;
    static constexpr size_t kMaxPendingUdpBytes = 512 * 1024;
    static constexpr int64_t kUdpSessionIdleTimeoutMs = 90 * 1000;

    explicit UserspacePacketTunnel(EncryptedDnsEngine &dnsEngine);
    ~UserspacePacketTunnel();

    void setStreamConnector(StreamConnector connector);
    void setDatagramHooks(DatagramPolicySelector policySelector, DatagramConnector connector);
    void setFlowTrackerHooks(TunnelFlowTrackerHooks hooks);

    /// Attaches to the 16 MiB `DuplexHeader` shared-memory ring created by `HajimiHelperService.exe`
    /// and starts the unprivileged packet worker thread.
    bool attachSharedMemory(void *shmBaseAddress,
                            uintptr_t rxEventHandle,
                            uintptr_t txEventHandle,
                            uint32_t framePrefixLen = 0);

    void detachSharedMemory();

    /// Attaches a non-blocking BSD `utun` (macOS, `framePrefixLen = 4`) or POSIX TUN
    /// file descriptor and runs a high-speed 64-packet batched `kqueue`/`epoll` worker.
    bool attachUtunFd(int utunFd, uint32_t framePrefixLen = 4);
    void detachUtunFd();

    /// Ingests one inbound frame (`framePrefixLen` = 0 for Wintun raw L3, 4 for utun).
    bool ingestPacket(const uint8_t *frame, size_t frameLen, uint32_t framePrefixLen = 0);

    /// Pops one outbound L3 frame queued when running in direct/test mode without SHM ring.
    size_t popOutboundPacket(uint8_t *outBuf, size_t outCap);

    /// Closes and evicts UDP NAT sessions idle longer than `idleTimeoutMs`. Returns evicted count.
    size_t reapIdleUdpSessions(int64_t idleTimeoutMs = kUdpSessionIdleTimeoutMs);

    /// Closes and evicts half-open, FIN-WAIT, or long-idle TCP flows. Returns evicted count.
    size_t reapIdleTcpSessions(int64_t synTimeoutMs = kTcpSynTimeoutMs,
                               int64_t establishedIdleMs = kTcpEstablishedIdleMs,
                               int64_t finWaitTimeoutMs = kTcpFinWaitTimeoutMs);

    TunnelTelemetry telemetry() const;

private:
    enum class TcpState : uint8_t {
        SynReceived = 0,
        Established = 1,
        FinWait = 2,
        Closed = 3
    };

    struct TcpSession : public std::enable_shared_from_this<TcpSession> {
        TunnelFlowKey key{};
        TcpState state = TcpState::SynReceived;
        uint32_t serverSeq = 0;
        uint32_t clientNextSeq = 0;
        uint16_t peerWindow = 65535;
        hajimi_tcp_reassembly *reassembly = nullptr;
        hajimi_rto rto{};
        hajimi_bdp_estimator bdp{};
        std::shared_ptr<Stream> upstream;
        std::vector<uint8_t> pendingUpstreamWrite;
        bool upstreamConnected = false;
        bool finSent = false;
        int64_t lastActivityMs = 0;
        uint64_t trackerConnId = 0;

        ~TcpSession() {
            if (reassembly) {
                hajimi_tcp_reassembly_destroy(reassembly);
                reassembly = nullptr;
            }
            if (upstream) {
                upstream->close();
                upstream.reset();
            }
        }
    };

    struct TunOrigEndpoint {
        uint8_t ip[16]{};
        uint16_t port = 0;
        bool wasFakeIp = false;
    };

    struct PendingOutboundDatagram {
        Target target;
        Buffer payload;
    };

    struct UdpNatSession : public std::enable_shared_from_this<UdpNatSession> {
        UdpNatKey key{};
        std::shared_ptr<Datagram> upstream;
        std::deque<PendingOutboundDatagram> pendingQueue;
        size_t pendingBytes = 0;
        bool ready = false;
        bool closed = false;
        int64_t lastActivityMs = 0;
        uint64_t trackerConnId = 0;

        std::unordered_map<std::string, TunOrigEndpoint> targetToOrigDst;
        TunOrigEndpoint lastOrigDst{};

        ~UdpNatSession() {
            if (upstream) {
                upstream->close();
                upstream.reset();
            }
        }
    };

    void emitEgressL3(const uint8_t *l3Bytes, size_t l3Len, uint8_t ipVersion);
    void handleIcmpEcho(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip);
    void handleUdpDatagram(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip);
    void deliverDownstreamUdpReply(const std::shared_ptr<UdpNatSession> &sess,
                                   const Target &remoteFrom,
                                   const Buffer &payload);
    void reapIdleUdpSessionsLocked(int64_t nowMs, int64_t idleTimeoutMs,
                                   std::vector<uint64_t> &closedIds,
                                   std::vector<std::shared_ptr<Datagram>> &toClose);
    void reapIdleTcpSessionsLocked(int64_t nowMs,
                                   int64_t synTimeoutMs,
                                   int64_t establishedIdleMs,
                                   int64_t finWaitTimeoutMs,
                                   std::vector<uint64_t> &closedIds,
                                   std::vector<std::shared_ptr<Stream>> &toClose);

    void handleTcpSegment(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip);
    void sendTcpPacket(TcpSession &sess, uint8_t flags, const uint8_t *payload, size_t payloadLen);
    void startUpstreamPump(const std::shared_ptr<TcpSession> &sess);
    void shmWorkerLoop();
    void utunWorkerLoop();
    void startAsyncPool();
    void stopAsyncPool();
    void postAsync(std::function<void()> fn);

    EncryptedDnsEngine &dns_;
    mutable std::mutex mu_;
    StreamConnector streamConnector_;
    DatagramPolicySelector datagramPolicySelector_;
    DatagramConnector datagramConnector_;
    TunnelFlowTrackerHooks trackerHooks_{};

    std::unordered_map<TunnelFlowKey, std::shared_ptr<TcpSession>, TunnelFlowKeyHash> tcpFlows_;
    std::unordered_map<UdpNatKey, std::shared_ptr<UdpNatSession>, UdpNatKeyHash> udpNatSessions_;
    struct CachedUdpPolicy {
        std::string policy;
        int64_t expiresAtMs = 0;
    };
    std::unordered_map<TunnelFlowKey, CachedUdpPolicy, TunnelFlowKeyHash> udpPolicyCache_;
    std::deque<std::vector<uint8_t>> directEgressQueue_;
    uint16_t ipIdCounter_ = 1;
    uint64_t rxPackets_ = 0;
    uint64_t txPackets_ = 0;
    uint64_t uploadedBytes_ = 0;
    uint64_t downloadedBytes_ = 0;
    uint64_t totalTcpFlows_ = 0;
    uint64_t totalUdpSessions_ = 0;
    int64_t lastUdpGcMs_ = 0;
    int64_t lastTcpGcMs_ = 0;

    std::atomic<bool> shmRunning_{false};
    void *shmBase_ = nullptr;
    uintptr_t rxEvent_ = 0;
    uintptr_t txEvent_ = 0;
    uint32_t shmFramePrefixLen_ = 0;
    std::thread shmThread_;

    std::atomic<bool> utunRunning_{false};
    int utunFd_ = -1;
    uint32_t utunFramePrefixLen_ = 4;
    platform_io::AsyncPoller utunPoller_;
    std::thread utunThread_;

    std::mutex asyncMu_;
    std::condition_variable asyncCv_;
    std::deque<std::function<void()>> asyncQueue_;
    std::vector<std::thread> asyncWorkers_;
    bool asyncStop_ = false;
    std::atomic<bool> asyncPoolActive_{false};
};

} // namespace hajimi::engine
