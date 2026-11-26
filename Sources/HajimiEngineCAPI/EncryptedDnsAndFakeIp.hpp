#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace hajimi::engine {

/// RFC 2544 Fake-IP pool (`198.19.0.0/16`), matching `Sources/HajimiCore/FakeIP.swift`
/// so tunnel gateway `198.18.16.1/16` never collides with synthetic DNS answers.
class FakeIpPool {
public:
    static constexpr uint32_t kBaseHostOrder = 0xC6130000u; // 198.19.0.0
    static constexpr uint32_t kPoolCount     = 0xFFFFu;

    FakeIpPool() = default;

    static bool isFakeIpv4HostOrder(uint32_t hostOrderIp) noexcept {
        return hostOrderIp >= (kBaseHostOrder + 2u) && hostOrderIp < (kBaseHostOrder + kPoolCount);
    }

    static bool isFakeIpv4String(const std::string &ipStr) noexcept;
    static std::string formatIpv4HostOrder(uint32_t hostOrderIp);
    static bool parseIpv4HostOrder(const std::string &ipStr, uint32_t &outHostOrder) noexcept;

    std::string allocateForDomain(const std::string &domain);
    uint32_t allocateHostOrder(const std::string &domain);
    bool lookupDomain(const std::string &ipStr, std::string &outDomain) const;
    bool lookupDomainByHostOrder(uint32_t hostOrderIp, std::string &outDomain) const;
    void clear();
    size_t size() const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, uint32_t> domainToIp_;
    std::unordered_map<uint32_t, std::string> ipToDomain_;
    std::deque<uint32_t> fifoOrder_;
    uint32_t nextOffset_ = 2u;
};

struct DnsParsedQuestion {
    uint16_t txId = 0;
    uint16_t flags = 0;
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    size_t questionEndOffset = 0;
    bool recursionDesired = true;
};

class EncryptedDnsEngine {
public:
    EncryptedDnsEngine();

    void configure(const std::vector<std::string> &plainNameservers,
                   const std::vector<std::string> &encryptedUpstreams,
                   const std::unordered_map<std::string, std::string> &staticHosts,
                   bool fakeIpEnabled,
                   bool ipv6Enabled);

    /// Binds upstream DoH / DoT / UDP sockets to the physical NIC so DNS queries
    /// never loop back into Wintun (`0.0.0.0/1`) during Enhanced Mode.
    void setOutboundInterface(const std::string &interfaceName);

    /// Returns numeric IP literals extracted from configured DNS upstreams for split-route bypass.
    std::vector<std::string> upstreamBypassIps() const;

    void setProxiedDomainPredicate(std::function<bool(const std::string &)> pred);

    FakeIpPool &fakeIpPool() noexcept { return fakeIp_; }
    const FakeIpPool &fakeIpPool() const noexcept { return fakeIp_; }

    static bool parseWireQuery(const uint8_t *wire, size_t len, DnsParsedQuestion &outQ) noexcept;

    static std::vector<uint8_t> buildIpv4Answer(const uint8_t *queryWire,
                                                size_t queryLen,
                                                const DnsParsedQuestion &q,
                                                uint32_t ipv4HostOrder,
                                                uint32_t ttlSeconds);

    static std::vector<uint8_t> buildEmptyResponse(const uint8_t *queryWire,
                                                   size_t queryLen,
                                                   const DnsParsedQuestion &q,
                                                   uint8_t rcode);

    std::vector<uint8_t> resolveWireQuery(const uint8_t *queryWire, size_t queryLen);

    void flushCache();

    struct Stats {
        uint64_t totalQueries = 0;
        uint64_t fakeIpHits = 0;
        uint64_t cacheHits = 0;
        uint64_t upstreamSuccess = 0;
        uint64_t upstreamFailures = 0;
    };
    Stats snapshotStats() const;

private:
    struct CacheEntry {
        std::vector<uint8_t> wireTemplate;
        int64_t expiresAtSteadyMs = 0;
    };

    std::vector<uint8_t> forwardUpstreamDoT(const std::string &host, uint16_t port,
                                            const std::string &sni,
                                            const std::string &ifName,
                                            const uint8_t *queryWire, size_t queryLen);
    std::vector<uint8_t> forwardUpstreamDoH(const std::string &httpsUrl,
                                            const std::string &ifName,
                                            const uint8_t *queryWire, size_t queryLen);
    std::vector<uint8_t> forwardUpstreamUDP(const std::string &ip, uint16_t port,
                                            const std::string &ifName,
                                            const uint8_t *queryWire, size_t queryLen);

    mutable std::mutex mu_;
    std::vector<std::string> plainNameservers_{"1.1.1.1", "8.8.8.8"};
    std::vector<std::string> encryptedUpstreams_{"tls://1.1.1.1:853"};
    std::unordered_map<std::string, std::string> staticHosts_;
    std::string outboundIfName_;
    bool fakeIpEnabled_ = true;
    bool ipv6Enabled_ = false;
    std::function<bool(const std::string &)> isProxied_;

    FakeIpPool fakeIp_;
    std::unordered_map<std::string, CacheEntry> cache_;
    Stats stats_{};
};

} // namespace hajimi::engine
