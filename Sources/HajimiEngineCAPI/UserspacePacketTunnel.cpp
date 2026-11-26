#include "UserspacePacketTunnel.hpp"
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>

namespace hajimi::engine {
namespace {

int64_t steadyNowMillis() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string normalizeEndpointMapKey(const std::string &host, uint16_t port) {
    std::string h = host;
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') {
        h = h.substr(1, h.size() - 2);
    }
    for (char &c : h) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return h + ":" + std::to_string(port);
}

std::string formatRawIpBytes(uint8_t version, const uint8_t ip[16]) {
    if (version == 4) {
        char buf[20]{};
        size_t n = hajimi_format_ipv4_literal(ip, buf, sizeof(buf));
        return std::string(buf, n);
    }
    char v6Buf[INET6_ADDRSTRLEN + 4]{};
    if (inet_ntop(AF_INET6, ip, v6Buf, sizeof(v6Buf))) {
        return v6Buf;
    }
    return {};
}

bool parseHostLiteralBytes(uint8_t version, const std::string &host, uint8_t outIp[16]) noexcept {
    std::string clean = host;
    if (clean.size() >= 2 && clean.front() == '[' && clean.back() == ']') {
        clean = clean.substr(1, clean.size() - 2);
    }
    if (version == 4) {
        return hajimi_parse_ipv4_literal(clean.data(), clean.size(), outIp) == 1;
    }
    return inet_pton(AF_INET6, clean.c_str(), outIp) == 1;
}

} // namespace

bool TunnelFlowKey::operator==(const TunnelFlowKey &o) const noexcept {
    const size_t addrLen = (version == 6) ? 16u : 4u;
    return version == o.version &&
           srcPort == o.srcPort &&
           dstPort == o.dstPort &&
           std::memcmp(srcIp, o.srcIp, addrLen) == 0 &&
           std::memcmp(dstIp, o.dstIp, addrLen) == 0;
}

size_t TunnelFlowKeyHash::operator()(const TunnelFlowKey &k) const noexcept {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&](uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    mix(k.version);
    const size_t addrLen = (k.version == 6) ? 16u : 4u;
    for (size_t i = 0; i < addrLen; ++i) mix(k.srcIp[i]);
    for (size_t i = 0; i < addrLen; ++i) mix(k.dstIp[i]);
    mix(static_cast<uint8_t>(k.srcPort >> 8));
    mix(static_cast<uint8_t>(k.srcPort & 0xFFu));
    mix(static_cast<uint8_t>(k.dstPort >> 8));
    mix(static_cast<uint8_t>(k.dstPort & 0xFFu));
    return static_cast<size_t>(h);
}

bool UdpNatKey::operator==(const UdpNatKey &o) const noexcept {
    const size_t addrLen = (version == 6) ? 16u : 4u;
    return version == o.version &&
           srcPort == o.srcPort &&
           std::memcmp(srcIp, o.srcIp, addrLen) == 0 &&
           policyLeaf == o.policyLeaf;
}

size_t UdpNatKeyHash::operator()(const UdpNatKey &k) const noexcept {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&](uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    mix(k.version);
    const size_t addrLen = (k.version == 6) ? 16u : 4u;
    for (size_t i = 0; i < addrLen; ++i) mix(k.srcIp[i]);
    mix(static_cast<uint8_t>(k.srcPort >> 8));
    mix(static_cast<uint8_t>(k.srcPort & 0xFFu));
    for (unsigned char c : k.policyLeaf) mix(c);
    return static_cast<size_t>(h);
}

UserspacePacketTunnel::UserspacePacketTunnel(EncryptedDnsEngine &dnsEngine)
    : dns_(dnsEngine) {}

UserspacePacketTunnel::~UserspacePacketTunnel() {
    detachSharedMemory();
    detachUtunFd();
    std::vector<std::shared_ptr<Stream>> closingTcp;
    std::vector<std::shared_ptr<Datagram>> closingUdp;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto &kv : tcpFlows_) {
            kv.second->state = TcpState::Closed;
            if (kv.second->upstream) closingTcp.push_back(std::move(kv.second->upstream));
        }
        tcpFlows_.clear();
        for (auto &kv : udpNatSessions_) {
            kv.second->closed = true;
            if (kv.second->upstream) closingUdp.push_back(std::move(kv.second->upstream));
        }
        udpNatSessions_.clear();
    }
    for (auto &s : closingTcp) s->close();
    for (auto &d : closingUdp) d->close();
}

void UserspacePacketTunnel::setStreamConnector(StreamConnector connector) {
    std::lock_guard<std::mutex> lk(mu_);
    streamConnector_ = std::move(connector);
}

void UserspacePacketTunnel::setDatagramHooks(DatagramPolicySelector policySelector,
                                             DatagramConnector connector) {
    std::lock_guard<std::mutex> lk(mu_);
    datagramPolicySelector_ = std::move(policySelector);
    datagramConnector_ = std::move(connector);
}

void UserspacePacketTunnel::setFlowTrackerHooks(TunnelFlowTrackerHooks hooks) {
    std::lock_guard<std::mutex> lk(mu_);
    trackerHooks_ = std::move(hooks);
}

bool UserspacePacketTunnel::attachSharedMemory(void *shmBaseAddress,
                                               uintptr_t rxEventHandle,
                                               uintptr_t txEventHandle,
                                               uint32_t framePrefixLen) {
    detachSharedMemory();
    if (!shm::validateDuplexRegion(shmBaseAddress)) {
        return false;
    }
    if (framePrefixLen != 0 && framePrefixLen != HAJIMI_FRAME_PREFIX_LENGTH) {
        return false;
    }
    shmBase_ = shmBaseAddress;
    rxEvent_ = rxEventHandle;
    txEvent_ = txEventHandle;
    shmFramePrefixLen_ = framePrefixLen;
    shmRunning_.store(true, std::memory_order_release);
    shmThread_ = std::thread([this] { shmWorkerLoop(); });
    return true;
}

void UserspacePacketTunnel::detachSharedMemory() {
    bool expected = true;
    if (shmRunning_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
#if defined(_WIN32)
        if (rxEvent_ != 0) {
            (void)::SetEvent(reinterpret_cast<HANDLE>(rxEvent_));
        }
#endif
        if (shmThread_.joinable()) {
            shmThread_.join();
        }
    }
    std::vector<std::shared_ptr<Stream>> closingTcp;
    std::vector<std::shared_ptr<Datagram>> closingUdp;
    std::vector<uint64_t> closedConnIds;
    std::function<void(uint64_t)> closeHook;
    {
        std::lock_guard<std::mutex> lk(mu_);
        shmBase_ = nullptr;
        rxEvent_ = 0;
        txEvent_ = 0;
        closeHook = trackerHooks_.onClose;
        for (auto &kv : tcpFlows_) {
            kv.second->state = TcpState::Closed;
            if (kv.second->trackerConnId != 0) closedConnIds.push_back(kv.second->trackerConnId);
            if (kv.second->upstream) closingTcp.push_back(std::move(kv.second->upstream));
        }
        tcpFlows_.clear();
        for (auto &kv : udpNatSessions_) {
            kv.second->closed = true;
            if (kv.second->trackerConnId != 0) closedConnIds.push_back(kv.second->trackerConnId);
            if (kv.second->upstream) closingUdp.push_back(std::move(kv.second->upstream));
        }
        udpNatSessions_.clear();
    }
    for (auto &s : closingTcp) s->close();
    for (auto &d : closingUdp) d->close();
    if (closeHook) {
        for (uint64_t id : closedConnIds) closeHook(id);
    }
}

bool UserspacePacketTunnel::attachUtunFd(int utunFd, uint32_t framePrefixLen) {
#if defined(_WIN32)
    (void)utunFd;
    (void)framePrefixLen;
    return false;
#else
    if (utunFd < 0) return false;
    detachUtunFd();
    int flags = ::fcntl(utunFd, F_GETFL, 0);
    if (flags >= 0) {
        (void)::fcntl(utunFd, F_SETFL, flags | O_NONBLOCK);
    }
    utunFd_ = utunFd;
    utunFramePrefixLen_ = framePrefixLen;
    utunPoller_.updateInterest(utunFd_, platform_io::kEventRead, 1u);
    utunRunning_.store(true, std::memory_order_release);
    utunThread_ = std::thread([this] { utunWorkerLoop(); });
    return true;
#endif
}

void UserspacePacketTunnel::detachUtunFd() {
    bool expected = true;
    if (utunRunning_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        utunPoller_.wake();
        if (utunThread_.joinable()) {
            utunThread_.join();
        }
    }
#if !defined(_WIN32)
    if (utunFd_ >= 0) {
        utunPoller_.removeInterest(utunFd_);
        utunFd_ = -1;
    }
#endif
}

void UserspacePacketTunnel::utunWorkerLoop() {
#if !defined(_WIN32)
    alignas(64) uint8_t rxBuf[HAJIMI_SHM_MAX_PACKET_BYTES + 16u];
    platform_io::ReadySocketEvent evs[8];
    uint32_t idleLoops = 0;

    while (utunRunning_.load(std::memory_order_acquire)) {
        uint32_t batchCount = 0;
        while (batchCount < HAJIMI_SHM_MAX_BATCH && utunRunning_.load(std::memory_order_relaxed)) {
            ssize_t n = ::read(utunFd_, rxBuf, sizeof(rxBuf));
            if (n <= 0) break;
            ingestPacket(rxBuf, static_cast<size_t>(n), utunFramePrefixLen_);
            ++batchCount;
        }
        if (batchCount == HAJIMI_SHM_MAX_BATCH) {
            continue;
        }
        (void)utunPoller_.wait(evs, 8u, 15);
        if ((++idleLoops & 0x7Fu) == 0u) {
            (void)reapIdleUdpSessions(kUdpSessionIdleTimeoutMs);
            (void)reapIdleTcpSessions();
        }
    }
#endif
}

void UserspacePacketTunnel::shmWorkerLoop() {
    auto *hdr = static_cast<shm::DuplexHeader *>(shmBase_);
    const uint8_t *rxRing = shm::rxRingStorage(shmBase_);
    shm::PacketSpan batch[HAJIMI_SHM_MAX_BATCH];
    uint32_t idleLoops = 0;

    while (shmRunning_.load(std::memory_order_acquire)) {
        if (hdr->closed.load(std::memory_order_acquire) != 0u) {
            break;
        }
        uint32_t drained = 0;
        while (drained < 1024u && shmRunning_.load(std::memory_order_relaxed)) {
            uint32_t nextTail = 0;
            uint32_t nSpans = shm::spscPeekBatch(
                hdr->rxProducer, hdr->rxConsumer, rxRing, hdr->ringCapacity,
                batch, HAJIMI_SHM_MAX_BATCH, nextTail);
            if (nSpans == 0u) {
                if (nextTail != hdr->rxConsumer.tail.load(std::memory_order_relaxed)) {
                    shm::spscCommitPopBatch(hdr->rxConsumer, nextTail);
                }
                break;
            }
            for (uint32_t i = 0; i < nSpans; ++i) {
                ingestPacket(batch[i].data, batch[i].len, shmFramePrefixLen_);
            }
            shm::spscCommitPopBatch(hdr->rxConsumer, nextTail);
            drained += nSpans;
        }
        if (drained > 0) continue;

        hdr->rxProducer.consumerSleeping.store(1u, std::memory_order_seq_cst);
        uint32_t retryTail = 0;
        uint32_t retrySpans = shm::spscPeekBatch(
            hdr->rxProducer, hdr->rxConsumer, rxRing, hdr->ringCapacity,
            batch, HAJIMI_SHM_MAX_BATCH, retryTail);
        if (retrySpans > 0u) {
            hdr->rxProducer.consumerSleeping.store(0u, std::memory_order_release);
            for (uint32_t i = 0; i < retrySpans; ++i) {
                ingestPacket(batch[i].data, batch[i].len, shmFramePrefixLen_);
            }
            shm::spscCommitPopBatch(hdr->rxConsumer, retryTail);
            continue;
        }

#if defined(_WIN32)
        if (rxEvent_ != 0) {
            (void)::WaitForSingleObject(reinterpret_cast<HANDLE>(rxEvent_), 15);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#else
        std::this_thread::sleep_for(std::chrono::microseconds(500));
#endif
        hdr->rxProducer.consumerSleeping.store(0u, std::memory_order_release);
        if ((++idleLoops & 0xFFu) == 0u) {
            (void)reapIdleUdpSessions(kUdpSessionIdleTimeoutMs);
            (void)reapIdleTcpSessions();
        }
    }
}

void UserspacePacketTunnel::emitEgressL3(const uint8_t *l3Bytes, size_t l3Len, uint8_t ipVersion) {
    if (!l3Bytes || l3Len == 0 || l3Len > HAJIMI_SHM_MAX_PACKET_BYTES) return;

    void *shmPtr = shmBase_;
    if (shmPtr && shmRunning_.load(std::memory_order_acquire)) {
        auto *hdr = static_cast<shm::DuplexHeader *>(shmPtr);
        uint8_t *txRing = shm::txRingStorage(shmPtr);
        bool wakePeer = false;
        const uint32_t prefixLen = shmFramePrefixLen_;
        if (prefixLen == HAJIMI_FRAME_PREFIX_LENGTH) {
            uint8_t afHdr[HAJIMI_FRAME_PREFIX_LENGTH]{};
            hajimi_write_frame_prefix(afHdr, ipVersion);
            (void)shm::spscTryPushFramed(hdr->txProducer, hdr->txConsumer, txRing, hdr->ringCapacity,
                                         afHdr, HAJIMI_FRAME_PREFIX_LENGTH,
                                         l3Bytes, static_cast<uint32_t>(l3Len), wakePeer);
        } else {
            (void)shm::spscTryPush(hdr->txProducer, hdr->txConsumer, txRing, hdr->ringCapacity,
                                   l3Bytes, static_cast<uint32_t>(l3Len), wakePeer);
        }
#if defined(_WIN32)
        if (wakePeer && txEvent_ != 0) {
            (void)::SetEvent(reinterpret_cast<HANDLE>(txEvent_));
        }
#else
        (void)wakePeer;
#endif
        ++txPackets_;
        return;
    }

#if !defined(_WIN32)
    const int activeUtun = utunFd_;
    if (activeUtun >= 0 && utunRunning_.load(std::memory_order_acquire)) {
        if (utunFramePrefixLen_ == HAJIMI_FRAME_PREFIX_LENGTH) {
            uint8_t afHdr[HAJIMI_FRAME_PREFIX_LENGTH]{};
            hajimi_write_frame_prefix(afHdr, ipVersion);
            dataplane::PooledPacketBuffer slabPkt;
            slabPkt.assignFramed(afHdr, HAJIMI_FRAME_PREFIX_LENGTH, l3Bytes, l3Len);
            const ssize_t w = ::write(activeUtun, slabPkt.data(), slabPkt.size());
            (void)w;
        } else {
            const ssize_t w = ::write(activeUtun, l3Bytes, l3Len);
            (void)w;
        }
        ++txPackets_;
        return;
    }
#endif

    const uint32_t prefixLen = shmFramePrefixLen_;
    if (directEgressQueue_.size() < 4096) {
        if (prefixLen == HAJIMI_FRAME_PREFIX_LENGTH) {
            std::vector<uint8_t> framed(HAJIMI_FRAME_PREFIX_LENGTH + l3Len);
            hajimi_write_frame_prefix(framed.data(), ipVersion);
            std::memcpy(framed.data() + HAJIMI_FRAME_PREFIX_LENGTH, l3Bytes, l3Len);
            directEgressQueue_.push_back(std::move(framed));
        } else {
            directEgressQueue_.emplace_back(l3Bytes, l3Bytes + l3Len);
        }
        ++txPackets_;
    }
}

size_t UserspacePacketTunnel::popOutboundPacket(uint8_t *outBuf, size_t outCap) {
    std::lock_guard<std::mutex> lk(mu_);
    if (directEgressQueue_.empty() || !outBuf) return 0;
    const auto &front = directEgressQueue_.front();
    if (front.size() > outCap) return 0;
    const size_t n = front.size();
    std::memcpy(outBuf, front.data(), n);
    directEgressQueue_.pop_front();
    return n;
}

bool UserspacePacketTunnel::ingestPacket(const uint8_t *frame, size_t frameLen, uint32_t framePrefixLen) {
    if (!frame || frameLen <= framePrefixLen) return false;
    const uint8_t *l3 = frame + framePrefixLen;
    const size_t l3Len = frameLen - framePrefixLen;

    hajimi_ip_packet ip{};
    if (hajimi_parse_ip(l3, l3Len, &ip) != HAJIMI_PARSE_OK) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        ++rxPackets_;
    }

    if ((ip.version == 4 && ip.protocol == 1) || (ip.version == 6 && ip.protocol == 58)) {
        handleIcmpEcho(l3, l3Len, ip);
        return true;
    }
    if (ip.protocol == 17) {
        handleUdpDatagram(l3, l3Len, ip);
        return true;
    }
    if (ip.protocol == 6) {
        handleTcpSegment(l3, l3Len, ip);
        return true;
    }
    return true;
}

void UserspacePacketTunnel::handleIcmpEcho(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip) {
    if (ip.payload_offset + ip.payload_length > l3Len || ip.payload_length < 8) return;
    const uint8_t *icmp = l3 + ip.payload_offset;

    if (ip.version == 4 && icmp[0] == 8 && icmp[1] == 0) {
        std::vector<uint8_t> reply(20 + ip.payload_length, 0);
        reply[0] = 0x45u;
        const uint16_t totalLen = static_cast<uint16_t>(reply.size());
        reply[2] = static_cast<uint8_t>(totalLen >> 8);
        reply[3] = static_cast<uint8_t>(totalLen & 0xFFu);
        reply[8] = 64;
        reply[9] = 1;
        std::memcpy(reply.data() + 12, ip.destination, 4);
        std::memcpy(reply.data() + 16, ip.source, 4);
        const uint16_t ipCsum = hajimi_ipv4_header_checksum(reply.data(), 20);
        reply[10] = static_cast<uint8_t>(ipCsum >> 8);
        reply[11] = static_cast<uint8_t>(ipCsum & 0xFFu);

        uint8_t *icmpOut = reply.data() + 20;
        std::memcpy(icmpOut, icmp, ip.payload_length);
        icmpOut[0] = 0;
        icmpOut[2] = 0;
        icmpOut[3] = 0;
        const uint16_t csum = hajimi_checksum(icmpOut, ip.payload_length);
        icmpOut[2] = static_cast<uint8_t>(csum >> 8);
        icmpOut[3] = static_cast<uint8_t>(csum & 0xFFu);

        std::lock_guard<std::mutex> lk(mu_);
        emitEgressL3(reply.data(), reply.size(), 4);
    } else if (ip.version == 6 && icmp[0] == 128 && icmp[1] == 0) {
        std::vector<uint8_t> reply(40 + ip.payload_length, 0);
        reply[0] = 0x60u;
        const uint16_t plen = static_cast<uint16_t>(ip.payload_length);
        reply[4] = static_cast<uint8_t>(plen >> 8);
        reply[5] = static_cast<uint8_t>(plen & 0xFFu);
        reply[6] = 58;
        reply[7] = 64;
        std::memcpy(reply.data() + 8, ip.destination, 16);
        std::memcpy(reply.data() + 24, ip.source, 16);

        uint8_t *icmpOut = reply.data() + 40;
        std::memcpy(icmpOut, icmp, ip.payload_length);
        icmpOut[0] = 129;
        icmpOut[2] = 0;
        icmpOut[3] = 0;
        const uint16_t csum = hajimi_transport_checksum(
            reply.data() + 8, reply.data() + 24, 16, 58, icmpOut, ip.payload_length);
        icmpOut[2] = static_cast<uint8_t>(csum >> 8);
        icmpOut[3] = static_cast<uint8_t>(csum & 0xFFu);

        std::lock_guard<std::mutex> lk(mu_);
        emitEgressL3(reply.data(), reply.size(), 6);
    }
}

void UserspacePacketTunnel::reapIdleUdpSessionsLocked(
    int64_t nowMs, int64_t idleTimeoutMs,
    std::vector<uint64_t> &closedIds,
    std::vector<std::shared_ptr<Datagram>> &toClose) {
    for (auto it = udpNatSessions_.begin(); it != udpNatSessions_.end();) {
        if (it->second->closed || (nowMs - it->second->lastActivityMs > idleTimeoutMs)) {
            it->second->closed = true;
            if (it->second->trackerConnId != 0) closedIds.push_back(it->second->trackerConnId);
            if (it->second->upstream) {
                toClose.push_back(std::move(it->second->upstream));
            }
            it = udpNatSessions_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t UserspacePacketTunnel::reapIdleUdpSessions(int64_t idleTimeoutMs) {
    std::vector<std::shared_ptr<Datagram>> toClose;
    std::vector<uint64_t> closedIds;
    std::function<void(uint64_t)> closeHook;
    const int64_t nowMs = steadyNowMillis();
    {
        std::lock_guard<std::mutex> lk(mu_);
        closeHook = trackerHooks_.onClose;
        reapIdleUdpSessionsLocked(nowMs, idleTimeoutMs, closedIds, toClose);
    }
    for (auto &dg : toClose) dg->close();
    if (closeHook) {
        for (uint64_t id : closedIds) closeHook(id);
    }
    return toClose.size() + (closedIds.size() > toClose.size() ? (closedIds.size() - toClose.size()) : 0);
}

void UserspacePacketTunnel::reapIdleTcpSessionsLocked(
    int64_t nowMs,
    int64_t synTimeoutMs,
    int64_t establishedIdleMs,
    int64_t finWaitTimeoutMs,
    std::vector<uint64_t> &closedIds,
    std::vector<std::shared_ptr<Stream>> &toClose) {
    for (auto it = tcpFlows_.begin(); it != tcpFlows_.end();) {
        auto &sess = *it->second;
        int64_t limit = establishedIdleMs;
        if (sess.state == TcpState::SynReceived) limit = synTimeoutMs;
        else if (sess.state == TcpState::FinWait) limit = finWaitTimeoutMs;

        if (sess.state == TcpState::Closed || (nowMs - sess.lastActivityMs > limit)) {
            if (sess.state != TcpState::Closed) {
                sendTcpPacket(sess, HAJIMI_TCP_RST | HAJIMI_TCP_ACK, nullptr, 0);
                sess.state = TcpState::Closed;
            }
            if (sess.trackerConnId != 0) closedIds.push_back(sess.trackerConnId);
            if (sess.upstream) {
                toClose.push_back(std::move(sess.upstream));
            }
            it = tcpFlows_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t UserspacePacketTunnel::reapIdleTcpSessions(int64_t synTimeoutMs,
                                                  int64_t establishedIdleMs,
                                                  int64_t finWaitTimeoutMs) {
    std::vector<std::shared_ptr<Stream>> toClose;
    std::vector<uint64_t> closedIds;
    std::function<void(uint64_t)> closeHook;
    const int64_t nowMs = steadyNowMillis();
    {
        std::lock_guard<std::mutex> lk(mu_);
        closeHook = trackerHooks_.onClose;
        reapIdleTcpSessionsLocked(nowMs, synTimeoutMs, establishedIdleMs, finWaitTimeoutMs, closedIds, toClose);
    }
    for (auto &st : toClose) st->close();
    if (closeHook) {
        for (uint64_t id : closedIds) closeHook(id);
    }
    return toClose.size();
}

void UserspacePacketTunnel::deliverDownstreamUdpReply(const std::shared_ptr<UdpNatSession> &sess,
                                                      const Target &remoteFrom,
                                                      const Buffer &payload) {
    if (!sess || payload.empty() || payload.size() > 65507u) return;

    uint64_t cid = 0;
    std::function<void(uint64_t, uint64_t, uint64_t)> bytesHook;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (sess->closed) return;
        sess->lastActivityMs = steadyNowMillis();
        downloadedBytes_ += payload.size();
        cid = sess->trackerConnId;
        bytesHook = trackerHooks_.onBytes;

        uint8_t replySrcIp[16]{};
        uint16_t replySrcPort = remoteFrom.port ? remoteFrom.port : sess->lastOrigDst.port;
        bool resolvedSrc = false;

        if (!remoteFrom.host.empty() && replySrcPort != 0) {
            auto it = sess->targetToOrigDst.find(normalizeEndpointMapKey(remoteFrom.host, replySrcPort));
            if (it != sess->targetToOrigDst.end()) {
                std::memcpy(replySrcIp, it->second.ip, 16);
                replySrcPort = it->second.port;
                resolvedSrc = true;
            }
        }

        if (!resolvedSrc && sess->lastOrigDst.wasFakeIp && sess->targetToOrigDst.size() == 1) {
            std::memcpy(replySrcIp, sess->lastOrigDst.ip, 16);
            if (replySrcPort == 0) replySrcPort = sess->lastOrigDst.port;
            resolvedSrc = true;
        }

        if (!resolvedSrc && !remoteFrom.host.empty()) {
            if (parseHostLiteralBytes(sess->key.version, remoteFrom.host, replySrcIp)) {
                resolvedSrc = true;
            }
        }

        if (!resolvedSrc) {
            std::memcpy(replySrcIp, sess->lastOrigDst.ip, 16);
            if (replySrcPort == 0) replySrcPort = sess->lastOrigDst.port;
        }

        if (replySrcPort != 0) {
            if (sess->key.version == 4 && 28u + payload.size() <= HAJIMI_SHM_MAX_PACKET_BYTES) {
                std::vector<uint8_t> pkt(28u + payload.size());
                size_t built = hajimi_build_ipv4_udp(
                    pkt.data(), pkt.size(),
                    replySrcIp, replySrcPort,
                    sess->key.srcIp, sess->key.srcPort,
                    payload.data(), payload.size(),
                    ++ipIdCounter_);
                if (built > 0) emitEgressL3(pkt.data(), built, 4);
            } else if (sess->key.version == 6 && 48u + payload.size() <= HAJIMI_SHM_MAX_PACKET_BYTES) {
                std::vector<uint8_t> pkt(48u + payload.size());
                size_t built = hajimi_build_ipv6_udp(
                    pkt.data(), pkt.size(),
                    replySrcIp, replySrcPort,
                    sess->key.srcIp, sess->key.srcPort,
                    payload.data(), payload.size());
                if (built > 0) emitEgressL3(pkt.data(), built, 6);
            }
        }
    }
    if (cid != 0 && bytesHook) bytesHook(cid, 0, payload.size());
}

void UserspacePacketTunnel::handleUdpDatagram(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip) {
    if (ip.payload_offset + ip.payload_length > l3Len) return;
    hajimi_udp_datagram udp{};
    const uint8_t *udpStart = l3 + ip.payload_offset;
    if (hajimi_parse_udp(udpStart, ip.payload_length, &udp) != HAJIMI_PARSE_OK) {
        return;
    }

    const uint8_t *payload = udpStart + udp.payload_offset;
    const size_t payloadLen = udp.payload_length;

    if (udp.destination_port == 53 && payloadLen >= 12) {
        std::vector<uint8_t> dnsReply = dns_.resolveWireQuery(payload, payloadLen);
        if (!dnsReply.empty()) {
            std::lock_guard<std::mutex> lk(mu_);
            uploadedBytes_ += payloadLen;
            downloadedBytes_ += dnsReply.size();
            if (ip.version == 4) {
                std::vector<uint8_t> pkt(28 + dnsReply.size());
                size_t built = hajimi_build_ipv4_udp(
                    pkt.data(), pkt.size(),
                    ip.destination, udp.destination_port,
                    ip.source, udp.source_port,
                    dnsReply.data(), dnsReply.size(),
                    ++ipIdCounter_);
                if (built > 0) emitEgressL3(pkt.data(), built, 4);
            } else {
                std::vector<uint8_t> pkt(48 + dnsReply.size());
                size_t built = hajimi_build_ipv6_udp(
                    pkt.data(), pkt.size(),
                    ip.destination, udp.destination_port,
                    ip.source, udp.source_port,
                    dnsReply.data(), dnsReply.size());
                if (built > 0) emitEgressL3(pkt.data(), built, 6);
            }
        }
        return;
    }

    if (payloadLen == 0 || udp.destination_port == 0) return;

    Target target{};
    target.port = udp.destination_port;
    target.udp = true;
    bool wasFakeIp = false;

    if (ip.version == 4) {
        const uint32_t dstHostOrder =
            (static_cast<uint32_t>(ip.destination[0]) << 24) |
            (static_cast<uint32_t>(ip.destination[1]) << 16) |
            (static_cast<uint32_t>(ip.destination[2]) << 8) |
            static_cast<uint32_t>(ip.destination[3]);
        std::string mappedDomain;
        if (dns_.fakeIpPool().lookupDomainByHostOrder(dstHostOrder, mappedDomain)) {
            target.host = std::move(mappedDomain);
            wasFakeIp = true;
        } else {
            target.host = FakeIpPool::formatIpv4HostOrder(dstHostOrder);
        }
    } else {
        target.host = formatRawIpBytes(6, ip.destination);
    }
    if (target.host.empty()) return;

    const std::string clientIpStr = formatRawIpBytes(ip.version, ip.source);

    DatagramPolicySelector policySel;
    DatagramConnector dgConnector;
    TunnelFlowTrackerHooks hooks;
    {
        std::lock_guard<std::mutex> lk(mu_);
        policySel = datagramPolicySelector_;
        dgConnector = datagramConnector_;
        hooks = trackerHooks_;
    }
    if (!dgConnector) return;

    const std::string leafPolicy = policySel
        ? policySel(clientIpStr, udp.source_port, target)
        : std::string("DIRECT");

    if (leafPolicy == "REJECT" || leafPolicy == "REJECT-TINYGIF") {
        return;
    }

    UdpNatKey natKey{};
    natKey.version = ip.version;
    std::memcpy(natKey.srcIp, ip.source, ip.address_length);
    natKey.srcPort = udp.source_port;
    natKey.policyLeaf = leafPolicy;

    std::shared_ptr<Datagram> readyUpstream;
    std::shared_ptr<UdpNatSession> sessionToConnect;
    std::vector<std::shared_ptr<Datagram>> gcClosing;
    std::vector<uint64_t> gcClosedIds;
    uint64_t existingConnId = 0;
    Buffer dataCopy(payload, payload + payloadLen);
    const int64_t nowMs = steadyNowMillis();

    {
        std::lock_guard<std::mutex> lk(mu_);
        uploadedBytes_ += payloadLen;

        if (nowMs - lastUdpGcMs_ > 15000) {
            lastUdpGcMs_ = nowMs;
            reapIdleUdpSessionsLocked(nowMs, kUdpSessionIdleTimeoutMs, gcClosedIds, gcClosing);
        }

        auto it = udpNatSessions_.find(natKey);
        if (it == udpNatSessions_.end()) {
            if (udpNatSessions_.size() >= kMaxUdpNatSessions) {
                auto oldestIt = udpNatSessions_.begin();
                for (auto scan = udpNatSessions_.begin(); scan != udpNatSessions_.end(); ++scan) {
                    if (scan->second->lastActivityMs < oldestIt->second->lastActivityMs) {
                        oldestIt = scan;
                    }
                }
                if (oldestIt != udpNatSessions_.end()) {
                    oldestIt->second->closed = true;
                    if (oldestIt->second->trackerConnId != 0) gcClosedIds.push_back(oldestIt->second->trackerConnId);
                    if (oldestIt->second->upstream) {
                        gcClosing.push_back(std::move(oldestIt->second->upstream));
                    }
                    udpNatSessions_.erase(oldestIt);
                }
            }

            auto sess = std::make_shared<UdpNatSession>();
            sess->key = natKey;
            sess->lastActivityMs = nowMs;
            TunOrigEndpoint orig{};
            std::memcpy(orig.ip, ip.destination, ip.address_length);
            orig.port = udp.destination_port;
            orig.wasFakeIp = wasFakeIp;
            sess->lastOrigDst = orig;
            sess->targetToOrigDst[normalizeEndpointMapKey(target.host, target.port)] = orig;

            if (payloadLen <= kMaxPendingUdpBytes) {
                sess->pendingBytes = payloadLen;
                sess->pendingQueue.push_back({target, std::move(dataCopy)});
            }

            udpNatSessions_[natKey] = sess;
            ++totalUdpSessions_;
            sessionToConnect = sess;
        } else {
            auto &sess = *it->second;
            sess.lastActivityMs = nowMs;
            existingConnId = sess.trackerConnId;
            TunOrigEndpoint orig{};
            std::memcpy(orig.ip, ip.destination, ip.address_length);
            orig.port = udp.destination_port;
            orig.wasFakeIp = wasFakeIp;
            sess.lastOrigDst = orig;
            if (sess.targetToOrigDst.size() < 256) {
                sess.targetToOrigDst[normalizeEndpointMapKey(target.host, target.port)] = orig;
            }

            if (sess.ready && sess.upstream) {
                readyUpstream = sess.upstream;
            } else if (!sess.closed &&
                       sess.pendingQueue.size() < kMaxPendingUdpPackets &&
                       sess.pendingBytes + payloadLen <= kMaxPendingUdpBytes) {
                sess.pendingBytes += payloadLen;
                sess.pendingQueue.push_back({target, std::move(dataCopy)});
            }
        }
    }

    for (auto &dg : gcClosing) dg->close();
    if (hooks.onClose) {
        for (uint64_t cid : gcClosedIds) hooks.onClose(cid);
    }

    if (existingConnId != 0 && hooks.onBytes) {
        hooks.onBytes(existingConnId, payloadLen, 0);
    }

    if (readyUpstream) {
        readyUpstream->send(std::move(target), std::move(dataCopy), [](Error) {});
        return;
    }

    if (sessionToConnect) {
        std::weak_ptr<UdpNatSession> weakSess = sessionToConnect;
        if (hooks.onOpen) {
            uint64_t cid = hooks.onOpen(
                "TUN-UDP", clientIpStr, udp.source_port, target.host, target.port, leafPolicy,
                [this, weakSess]() {
                    if (auto locked = weakSess.lock()) {
                        std::shared_ptr<Datagram> closing;
                        {
                            std::lock_guard<std::mutex> lk(mu_);
                            if (!locked->closed) {
                                locked->closed = true;
                                closing = std::move(locked->upstream);
                                udpNatSessions_.erase(locked->key);
                            }
                        }
                        if (closing) closing->close();
                    }
                });
            {
                std::lock_guard<std::mutex> lk(mu_);
                sessionToConnect->trackerConnId = cid;
            }
            if (cid != 0 && hooks.onBytes) hooks.onBytes(cid, payloadLen, 0);
        }

        dgConnector(leafPolicy, target, [this, weakSess](std::shared_ptr<Datagram> dg, Error err) {
            auto s = weakSess.lock();
            if (!s) {
                if (dg) dg->close();
                return;
            }

            std::deque<PendingOutboundDatagram> buffered;
            uint64_t failCid = 0;
            std::function<void(uint64_t)> closeHook;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (s->closed || !err.empty() || !dg) {
                    s->closed = true;
                    failCid = s->trackerConnId;
                    closeHook = trackerHooks_.onClose;
                    udpNatSessions_.erase(s->key);
                    if (dg) dg->close();
                } else {
                    s->upstream = dg;
                    s->ready = true;
                    s->lastActivityMs = steadyNowMillis();
                    buffered.swap(s->pendingQueue);
                    s->pendingBytes = 0;
                }
            }
            if (failCid != 0 && closeHook) {
                closeHook(failCid);
                return;
            }
            if (!dg || s->closed) return;

            dg->start(
                [this, weakSess](Target remoteFrom, Buffer rxData) {
                    if (auto locked = weakSess.lock()) {
                        deliverDownstreamUdpReply(locked, remoteFrom, rxData);
                    }
                },
                [this, weakSess](Error) {
                    if (auto locked = weakSess.lock()) {
                        std::shared_ptr<Datagram> closing;
                        uint64_t cid = 0;
                        std::function<void(uint64_t)> cHook;
                        {
                            std::lock_guard<std::mutex> lk(mu_);
                            if (!locked->closed) {
                                locked->closed = true;
                                cid = locked->trackerConnId;
                                cHook = trackerHooks_.onClose;
                                closing = std::move(locked->upstream);
                                udpNatSessions_.erase(locked->key);
                            }
                        }
                        if (closing) closing->close();
                        if (cid != 0 && cHook) cHook(cid);
                    }
                });

            for (auto &pkt : buffered) {
                dg->send(std::move(pkt.target), std::move(pkt.payload), [](Error) {});
            }
        });
    }
}

void UserspacePacketTunnel::sendTcpPacket(TcpSession &sess,
                                          uint8_t flags,
                                          const uint8_t *payload,
                                          size_t payloadLen) {
    const uint32_t ackNum = sess.reassembly
        ? hajimi_tcp_reassembly_expected(sess.reassembly)
        : sess.clientNextSeq;

    if (sess.key.version == 4) {
        dataplane::PooledPacketBuffer pkt(40 + payloadLen);
        size_t built = hajimi_build_ipv4_tcp(
            pkt.data(), pkt.capacity(),
            sess.key.dstIp, sess.key.dstPort,
            sess.key.srcIp, sess.key.srcPort,
            sess.serverSeq, ackNum,
            flags, 65535,
            payload, payloadLen,
            ++ipIdCounter_);
        if (built > 0) emitEgressL3(pkt.data(), built, 4);
    } else {
        dataplane::PooledPacketBuffer pkt(60 + payloadLen);
        size_t built = hajimi_build_ipv6_tcp(
            pkt.data(), pkt.capacity(),
            sess.key.dstIp, sess.key.dstPort,
            sess.key.srcIp, sess.key.srcPort,
            sess.serverSeq, ackNum,
            flags, 65535,
            payload, payloadLen);
        if (built > 0) emitEgressL3(pkt.data(), built, 6);
    }

    uint32_t seqAdvance = static_cast<uint32_t>(payloadLen);
    if ((flags & HAJIMI_TCP_SYN) != 0) ++seqAdvance;
    if ((flags & HAJIMI_TCP_FIN) != 0) ++seqAdvance;
    sess.serverSeq += seqAdvance;
    downloadedBytes_ += payloadLen;
}

void UserspacePacketTunnel::startUpstreamPump(const std::shared_ptr<TcpSession> &sess) {
    std::shared_ptr<Stream> up;
    {
        std::lock_guard<std::mutex> lk(mu_);
        up = sess->upstream;
    }
    if (!up) return;

    std::weak_ptr<TcpSession> weakSess = sess;
    up->read(32768, [this, weakSess](Buffer chunk, bool eof, Error err) {
        auto s = weakSess.lock();
        if (!s) return;
        bool keepReading = false;
        uint64_t cid = 0;
        std::function<void(uint64_t, uint64_t, uint64_t)> bytesHook;
        std::function<void(uint64_t)> closeHook;
        bool notifyClosed = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (s->state == TcpState::Closed) return;
            s->lastActivityMs = steadyNowMillis();
            cid = s->trackerConnId;
            bytesHook = trackerHooks_.onBytes;
            closeHook = trackerHooks_.onClose;

            if (!err.empty()) {
                sendTcpPacket(*s, HAJIMI_TCP_RST | HAJIMI_TCP_ACK, nullptr, 0);
                s->state = TcpState::Closed;
                tcpFlows_.erase(s->key);
                notifyClosed = true;
            } else {
                if (!chunk.empty()) {
                    size_t offset = 0;
                    while (offset < chunk.size()) {
                        const size_t step = (std::min)(static_cast<size_t>(1360), chunk.size() - offset);
                        sendTcpPacket(*s, HAJIMI_TCP_ACK | HAJIMI_TCP_PSH, chunk.data() + offset, step);
                        offset += step;
                    }
                }
                if (eof) {
                    if (!s->finSent) {
                        s->finSent = true;
                        sendTcpPacket(*s, HAJIMI_TCP_FIN | HAJIMI_TCP_ACK, nullptr, 0);
                        s->state = TcpState::FinWait;
                    }
                } else {
                    keepReading = true;
                }
            }
        }
        if (!chunk.empty() && cid != 0 && bytesHook) {
            bytesHook(cid, 0, chunk.size());
        }
        if (notifyClosed && cid != 0 && closeHook) {
            closeHook(cid);
        }
        if (keepReading) {
            startUpstreamPump(s);
        }
    });
}

void UserspacePacketTunnel::handleTcpSegment(const uint8_t *l3, size_t l3Len, const hajimi_ip_packet &ip) {
    if (ip.payload_offset + ip.payload_length > l3Len) return;
    hajimi_tcp_segment tcp{};
    const uint8_t *tcpStart = l3 + ip.payload_offset;
    if (hajimi_parse_tcp(tcpStart, ip.payload_length, &tcp) != HAJIMI_PARSE_OK) {
        return;
    }

    TunnelFlowKey key{};
    key.version = ip.version;
    std::memcpy(key.srcIp, ip.source, ip.address_length);
    std::memcpy(key.dstIp, ip.destination, ip.address_length);
    key.srcPort = tcp.source_port;
    key.dstPort = tcp.destination_port;

    StreamConnector connectorToLaunch;
    TunnelFlowTrackerHooks hooks;
    std::string clientIpStr;
    Target dialTarget{};
    std::shared_ptr<TcpSession> newSession;
    std::shared_ptr<Stream> streamToWrite;
    std::vector<std::shared_ptr<Stream>> gcClosing;
    std::vector<uint64_t> closedIds;
    uint64_t activeCid = 0;
    size_t uploadedPayloadBytes = 0;
    Buffer bytesToForward;
    bool closeUpstreamFin = false;
    const int64_t nowMs = steadyNowMillis();

    {
        std::lock_guard<std::mutex> lk(mu_);
        hooks = trackerHooks_;

        if (nowMs - lastTcpGcMs_ > 15000) {
            lastTcpGcMs_ = nowMs;
            reapIdleTcpSessionsLocked(nowMs, kTcpSynTimeoutMs, kTcpEstablishedIdleMs,
                                      kTcpFinWaitTimeoutMs, closedIds, gcClosing);
        }

        auto it = tcpFlows_.find(key);

        if ((tcp.flags & HAJIMI_TCP_RST) != 0) {
            if (it != tcpFlows_.end()) {
                it->second->state = TcpState::Closed;
                if (it->second->trackerConnId != 0) closedIds.push_back(it->second->trackerConnId);
                if (it->second->upstream) gcClosing.push_back(std::move(it->second->upstream));
                tcpFlows_.erase(it);
            }
        } else if ((tcp.flags & HAJIMI_TCP_SYN) != 0 && (tcp.flags & HAJIMI_TCP_ACK) == 0) {
            if (tcpFlows_.size() >= kMaxTcpSessions) {
                auto oldestIt = tcpFlows_.begin();
                for (auto scan = tcpFlows_.begin(); scan != tcpFlows_.end(); ++scan) {
                    if (scan->second->lastActivityMs < oldestIt->second->lastActivityMs) {
                        oldestIt = scan;
                    }
                }
                if (oldestIt != tcpFlows_.end()) {
                    oldestIt->second->state = TcpState::Closed;
                    if (oldestIt->second->trackerConnId != 0) closedIds.push_back(oldestIt->second->trackerConnId);
                    if (oldestIt->second->upstream) gcClosing.push_back(std::move(oldestIt->second->upstream));
                    tcpFlows_.erase(oldestIt);
                }
            }

            auto sess = std::make_shared<TcpSession>();
            sess->key = key;
            sess->state = TcpState::SynReceived;
            sess->lastActivityMs = nowMs;
            sess->serverSeq = 0x484A0000u ^ (static_cast<uint32_t>(key.srcPort) << 16) ^ tcp.sequence;
            sess->clientNextSeq = tcp.sequence + 1u;
            sess->reassembly = hajimi_tcp_reassembly_create(sess->clientNextSeq, 512 * 1024, 256);
            hajimi_rto_init(&sess->rto);
            hajimi_bdp_init(&sess->bdp, 10.0);

            tcpFlows_[key] = sess;
            ++totalTcpFlows_;
            sendTcpPacket(*sess, HAJIMI_TCP_SYN | HAJIMI_TCP_ACK, nullptr, 0);

            if (streamConnector_) {
                connectorToLaunch = streamConnector_;
                newSession = sess;
                clientIpStr = formatRawIpBytes(key.version, key.srcIp);
                dialTarget.port = key.dstPort;
                dialTarget.udp = false;
                if (key.version == 4) {
                    const uint32_t dstHostOrder =
                        (static_cast<uint32_t>(key.dstIp[0]) << 24) |
                        (static_cast<uint32_t>(key.dstIp[1]) << 16) |
                        (static_cast<uint32_t>(key.dstIp[2]) << 8) |
                        static_cast<uint32_t>(key.dstIp[3]);
                    std::string mappedDomain;
                    if (dns_.fakeIpPool().lookupDomainByHostOrder(dstHostOrder, mappedDomain)) {
                        dialTarget.host = std::move(mappedDomain);
                    } else {
                        dialTarget.host = FakeIpPool::formatIpv4HostOrder(dstHostOrder);
                    }
                } else {
                    dialTarget.host = formatRawIpBytes(6, key.dstIp);
                }
            }
        } else if (it != tcpFlows_.end()) {
            auto &sess = *it->second;
            sess.lastActivityMs = nowMs;
            activeCid = sess.trackerConnId;
            if (sess.state == TcpState::SynReceived && (tcp.flags & HAJIMI_TCP_ACK) != 0) {
                sess.state = TcpState::Established;
            }

            if (tcp.payload_length > 0 && sess.reassembly) {
                const uint8_t *payload = tcpStart + tcp.payload_offset;
                uploadedBytes_ += tcp.payload_length;
                uploadedPayloadBytes = tcp.payload_length;
                hajimi_tcp_reassembly_ingest(
                    sess.reassembly, tcp.sequence, payload, tcp.payload_length, &bytesToForward,
                    [](void *ctx, const uint8_t *data, size_t len) -> int {
                        auto *out = static_cast<Buffer *>(ctx);
                        out->insert(out->end(), data, data + len);
                        return 1;
                    });
                sendTcpPacket(sess, HAJIMI_TCP_ACK, nullptr, 0);

                if (!bytesToForward.empty()) {
                    if (sess.upstreamConnected && sess.upstream) {
                        streamToWrite = sess.upstream;
                    } else {
                        sess.pendingUpstreamWrite.insert(
                            sess.pendingUpstreamWrite.end(),
                            bytesToForward.begin(), bytesToForward.end());
                        bytesToForward.clear();
                    }
                }
            }

            if ((tcp.flags & HAJIMI_TCP_FIN) != 0) {
                if (sess.reassembly) {
                    hajimi_tcp_reassembly_fin(sess.reassembly, tcp.sequence + tcp.payload_length);
                } else {
                    sess.clientNextSeq = tcp.sequence + tcp.payload_length + 1u;
                }
                if (!sess.finSent) {
                    sess.finSent = true;
                    sendTcpPacket(sess, HAJIMI_TCP_FIN | HAJIMI_TCP_ACK, nullptr, 0);
                } else {
                    sendTcpPacket(sess, HAJIMI_TCP_ACK, nullptr, 0);
                }
                closeUpstreamFin = true;
                streamToWrite = sess.upstream;
                if (sess.trackerConnId != 0) closedIds.push_back(sess.trackerConnId);
                sess.state = TcpState::Closed;
                tcpFlows_.erase(it);
            } else if (sess.state == TcpState::FinWait && (tcp.flags & HAJIMI_TCP_ACK) != 0) {
                if (sess.trackerConnId != 0) closedIds.push_back(sess.trackerConnId);
                if (sess.upstream) gcClosing.push_back(std::move(sess.upstream));
                sess.state = TcpState::Closed;
                tcpFlows_.erase(it);
            }
        }
    }

    for (auto &st : gcClosing) st->close();
    if (activeCid != 0 && uploadedPayloadBytes > 0 && hooks.onBytes) {
        hooks.onBytes(activeCid, uploadedPayloadBytes, 0);
    }
    if (hooks.onClose) {
        for (uint64_t cid : closedIds) hooks.onClose(cid);
    }

    if (connectorToLaunch && newSession) {
        std::weak_ptr<TcpSession> weakSess = newSession;
        if (hooks.onOpen) {
            uint64_t cid = hooks.onOpen(
                "TUN-TCP", clientIpStr, key.srcPort, dialTarget.host, dialTarget.port, "AUTO",
                [this, weakSess]() {
                    if (auto locked = weakSess.lock()) {
                        std::shared_ptr<Stream> closing;
                        {
                            std::lock_guard<std::mutex> lk(mu_);
                            if (locked->state != TcpState::Closed) {
                                sendTcpPacket(*locked, HAJIMI_TCP_RST | HAJIMI_TCP_ACK, nullptr, 0);
                                locked->state = TcpState::Closed;
                                closing = std::move(locked->upstream);
                                tcpFlows_.erase(locked->key);
                            }
                        }
                        if (closing) closing->close();
                    }
                });
            std::lock_guard<std::mutex> lk(mu_);
            newSession->trackerConnId = cid;
        }

        connectorToLaunch(clientIpStr, key.srcPort, dialTarget,
                          [this, weakSess](std::shared_ptr<Stream> stream, Error err) {
            auto s = weakSess.lock();
            if (!s) {
                if (stream) stream->close();
                return;
            }
            Buffer buffered;
            uint64_t failCid = 0;
            std::function<void(uint64_t)> closeHook;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (s->state == TcpState::Closed) {
                    if (stream) stream->close();
                    return;
                }
                if (!err.empty() || !stream) {
                    sendTcpPacket(*s, HAJIMI_TCP_RST | HAJIMI_TCP_ACK, nullptr, 0);
                    s->state = TcpState::Closed;
                    failCid = s->trackerConnId;
                    closeHook = trackerHooks_.onClose;
                    tcpFlows_.erase(s->key);
                    if (stream) stream->close();
                } else {
                    s->upstream = stream;
                    s->upstreamConnected = true;
                    s->lastActivityMs = steadyNowMillis();
                    buffered.swap(s->pendingUpstreamWrite);
                }
            }
            if (failCid != 0 && closeHook) {
                closeHook(failCid);
                return;
            }
            if (!stream || s->state == TcpState::Closed) return;

            if (!buffered.empty()) {
                stream->write(std::move(buffered), [](Error) {});
            }
            startUpstreamPump(s);
        });
    }

    if (streamToWrite && !bytesToForward.empty()) {
        streamToWrite->write(std::move(bytesToForward), [](Error) {});
    }
    if (closeUpstreamFin && streamToWrite) {
        if (streamToWrite->supportsHalfClose()) {
            streamToWrite->shutdownWrite([](Error) {});
        } else {
            streamToWrite->close();
        }
    }
}

TunnelTelemetry UserspacePacketTunnel::telemetry() const {
    std::lock_guard<std::mutex> lk(mu_);
    TunnelTelemetry t{};
    t.rxPackets = rxPackets_;
    t.txPackets = txPackets_;
    t.uploadedBytes = uploadedBytes_;
    t.downloadedBytes = downloadedBytes_;
    t.activeTcpFlows = static_cast<uint32_t>(tcpFlows_.size());
    t.totalTcpFlows = totalTcpFlows_;
    t.activeUdpSessions = static_cast<uint32_t>(udpNatSessions_.size());
    t.totalUdpSessions = totalUdpSessions_;
    return t;
}

} // namespace hajimi::engine
