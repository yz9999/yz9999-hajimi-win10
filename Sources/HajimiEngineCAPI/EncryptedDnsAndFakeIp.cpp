#include "EncryptedDnsAndFakeIp.hpp"
#include "../HajimiDataPlaneC/include/hajimi_dataplane.h"
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <net/if.h>
#elif !defined(_WIN32)
#include <net/if.h>
#endif

#if defined(_WIN32)
#include <iphlpapi.h>
#include <netioapi.h>
#undef NOCRYPT
#include <wincrypt.h>
#ifdef X509_NAME
#undef X509_NAME
#endif
#ifdef X509_EXTENSIONS
#undef X509_EXTENSIONS
#endif
#ifdef PKCS7_SIGNER_INFO
#undef PKCS7_SIGNER_INFO
#endif
#ifdef OCSP_REQUEST
#undef OCSP_REQUEST
#endif
#ifdef OCSP_RESPONSE
#undef OCSP_RESPONSE
#endif
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace hajimi::engine {
namespace {

int64_t nowSteadyMs() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string lowerDomain(std::string d) {
    while (!d.empty() && d.back() == '.') d.pop_back();
    for (char &c : d) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return d;
}

std::string stripBrackets(const std::string &h) {
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') {
        return h.substr(1, h.size() - 2);
    }
    return h;
}

bool isNumericIpLiteral(const std::string &host) noexcept {
    std::string clean = stripBrackets(host);
    uint8_t buf[16]{};
    return inet_pton(AF_INET, clean.c_str(), buf) == 1 ||
           inet_pton(AF_INET6, clean.c_str(), buf) == 1;
}

void bindSocketToPhysicalInterface(platform::NativeSocket sock, int family, const std::string &ifName) noexcept {
    if (sock < 0 || ifName.empty()) return;
#if defined(_WIN32)
    std::wstring wideAlias;
    if (!platform::utf8ToWide(ifName, wideAlias) || wideAlias.empty()) return;
    NET_LUID luid{};
    NET_IFINDEX ifIdx = 0;
    if (::ConvertInterfaceAliasToLuid(wideAlias.c_str(), &luid) != NO_ERROR ||
        ::ConvertInterfaceLuidToIndex(&luid, &ifIdx) != NO_ERROR || ifIdx == 0) {
        return;
    }
    if (family == AF_INET) {
        DWORD netOrderIdx = htonl(static_cast<u_long>(ifIdx));
        (void)::setsockopt(platform::toOsSocket(sock), IPPROTO_IP, IP_UNICAST_IF,
                           reinterpret_cast<const char *>(&netOrderIdx), sizeof(netOrderIdx));
    } else if (family == AF_INET6) {
        DWORD hostIdx = static_cast<DWORD>(ifIdx);
        (void)::setsockopt(platform::toOsSocket(sock), IPPROTO_IPV6, IPV6_UNICAST_IF,
                           reinterpret_cast<const char *>(&hostIdx), sizeof(hostIdx));
    }
#elif defined(__APPLE__)
    unsigned int ifIdx = ::if_nametoindex(ifName.c_str());
    if (ifIdx == 0) return;
    if (family == AF_INET) {
        (void)::setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &ifIdx, sizeof(ifIdx));
    } else if (family == AF_INET6) {
        (void)::setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &ifIdx, sizeof(ifIdx));
    }
#elif defined(__linux__) && defined(SO_BINDTODEVICE)
    (void)family;
    (void)::setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifName.c_str(),
                       static_cast<socklen_t>(ifName.size()));
#else
    (void)sock; (void)family; (void)ifName;
#endif
}

SSL_CTX *sharedDnsClientSslCtx() noexcept {
    static std::mutex ctxMu;
    static SSL_CTX *cached = nullptr;
    std::lock_guard<std::mutex> lk(ctxMu);
    if (cached) return cached;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return nullptr;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#if defined(_WIN32)
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (store) {
        HCERTSTORE hSys = ::CertOpenSystemStoreW(0, L"ROOT");
        if (hSys) {
            PCCERT_CONTEXT pCert = nullptr;
            while ((pCert = ::CertEnumCertificatesInStore(hSys, pCert)) != nullptr) {
                const unsigned char *der = pCert->pbCertEncoded;
                X509 *x = d2i_X509(nullptr, &der, static_cast<long>(pCert->cbCertEncoded));
                if (x) {
                    (void)X509_STORE_add_cert(store, x);
                    X509_free(x);
                }
            }
            ::CertCloseStore(hSys, 0);
        }
    }
    ERR_clear_error();
#elif defined(__APPLE__)
    (void)SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", nullptr);
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (store) {
        CFArrayRef anchors = nullptr;
        if (SecTrustCopyAnchorCertificates(&anchors) == errSecSuccess && anchors != nullptr) {
            CFIndex n = CFArrayGetCount(anchors);
            for (CFIndex i = 0; i < n; ++i) {
                auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, i);
                if (!cert) continue;
                CFDataRef der = SecCertificateCopyData(cert);
                if (!der) continue;
                const unsigned char *ptr = CFDataGetBytePtr(der);
                X509 *x = d2i_X509(nullptr, &ptr, static_cast<long>(CFDataGetLength(der)));
                if (x) {
                    (void)X509_STORE_add_cert(store, x);
                    X509_free(x);
                }
                CFRelease(der);
            }
            CFRelease(anchors);
        }
    }
    ERR_clear_error();
#else
    (void)SSL_CTX_set_default_verify_paths(ctx);
#endif
    cached = ctx;
    return cached;
}

void configureTlsPeerVerify(SSL *ssl, const std::string &verifyHost) noexcept {
    if (!ssl) return;
    std::string clean = stripBrackets(verifyHost);
    if (clean.empty()) return;
    SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
    if (isNumericIpLiteral(clean)) {
        // RFC 6066 §3: Never send numeric IP literals in TLS SNI; verify IP SAN instead!
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
        if (param) (void)X509_VERIFY_PARAM_set1_ip_asc(param, clean.c_str());
    } else {
        (void)SSL_set_tlsext_host_name(ssl, clean.c_str());
        (void)SSL_set1_host(ssl, clean.c_str());
    }
}

std::vector<uint8_t> buildWireDnsQuery(const std::string &domain, uint16_t qtype, uint16_t txId) {
    std::vector<uint8_t> out;
    out.reserve(64);
    out.push_back(static_cast<uint8_t>(txId >> 8));
    out.push_back(static_cast<uint8_t>(txId & 0xFFu));
    out.push_back(0x01); out.push_back(0x00); // RD=1
    out.push_back(0x00); out.push_back(0x01); // QDCOUNT=1
    out.push_back(0x00); out.push_back(0x00);
    out.push_back(0x00); out.push_back(0x00);
    out.push_back(0x00); out.push_back(0x00);

    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == std::string::npos) dot = domain.size();
        size_t len = dot - pos;
        if (len == 0 || len > 63) return {};
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = pos; i < dot; ++i) out.push_back(static_cast<uint8_t>(domain[i]));
        pos = (dot < domain.size()) ? (dot + 1) : domain.size();
    }
    out.push_back(0x00);
    out.push_back(static_cast<uint8_t>(qtype >> 8));
    out.push_back(static_cast<uint8_t>(qtype & 0xFFu));
    out.push_back(0x00); out.push_back(0x01); // IN
    return out;
}

bool skipDnsWireName(const uint8_t *wire, size_t len, size_t &pos) noexcept {
    int jumps = 0;
    while (pos < len) {
        uint8_t tag = wire[pos];
        if (tag == 0) {
            ++pos;
            return true;
        }
        if ((tag & 0xC0u) == 0xC0u) {
            if (pos + 2 > len || ++jumps > 16) return false;
            pos += 2;
            return true;
        }
        if ((tag & 0xC0u) != 0 || pos + 1 + tag > len) return false;
        pos += 1 + tag;
    }
    return false;
}

std::string extractFirstIpFromDnsWireReply(const std::vector<uint8_t> &reply, uint16_t wantQtype) {
    if (reply.size() < 12) return {};
    const uint8_t rcode = reply[3] & 0x0Fu;
    if (rcode != 0) return {};
    const uint16_t qdcount = static_cast<uint16_t>((reply[4] << 8) | reply[5]);
    const uint16_t ancount = static_cast<uint16_t>((reply[6] << 8) | reply[7]);
    if (ancount == 0) return {};

    size_t pos = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        if (!skipDnsWireName(reply.data(), reply.size(), pos)) return {};
        if (pos + 4 > reply.size()) return {};
        pos += 4;
    }
    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skipDnsWireName(reply.data(), reply.size(), pos)) return {};
        if (pos + 10 > reply.size()) return {};
        const uint16_t rtype = static_cast<uint16_t>((reply[pos] << 8) | reply[pos + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((reply[pos + 8] << 8) | reply[pos + 9]);
        pos += 10;
        if (pos + rdlen > reply.size()) return {};
        if (rtype == wantQtype) {
            if (wantQtype == 1 && rdlen == 4) {
                char buf[INET_ADDRSTRLEN + 4]{};
                if (inet_ntop(AF_INET, reply.data() + pos, buf, sizeof(buf))) {
                    std::string ip(buf);
                    if (!FakeIpPool::isFakeIpv4String(ip)) return ip;
                }
            } else if (wantQtype == 28 && rdlen == 16) {
                char buf[INET6_ADDRSTRLEN + 4]{};
                if (inet_ntop(AF_INET6, reply.data() + pos, buf, sizeof(buf))) {
                    return std::string(buf);
                }
            }
        }
        pos += rdlen;
    }
    return {};
}

std::string decodeHttpChunkedBody(const std::string &rawBody) {
    std::string out;
    size_t pos = 0;
    while (pos < rawBody.size()) {
        auto crlf = rawBody.find("\r\n", pos);
        if (crlf == std::string::npos) break;
        std::string hexLen = rawBody.substr(pos, crlf - pos);
        auto semi = hexLen.find(';');
        if (semi != std::string::npos) hexLen.resize(semi);
        char *endp = nullptr;
        unsigned long chunkLen = std::strtoul(hexLen.c_str(), &endp, 16);
        if (endp == hexLen.c_str()) break;
        pos = crlf + 2;
        if (chunkLen == 0) break;
        if (pos + chunkLen > rawBody.size()) break;
        out.append(rawBody, pos, chunkLen);
        pos += chunkLen;
        if (pos + 2 <= rawBody.size() && rawBody[pos] == '\r' && rawBody[pos + 1] == '\n') {
            pos += 2;
        }
    }
    return out;
}

bool waitSocketIo(platform::NativeSocket sock, bool wantWrite, int timeoutMs) noexcept {
    if (sock < 0) return false;
#if defined(_WIN32)
    WSAPOLLFD pfd{};
    pfd.fd = platform::toOsSocket(sock);
    pfd.events = wantWrite ? POLLWRNORM : POLLRDNORM;
    int rc = ::WSAPoll(&pfd, 1, timeoutMs);
    if (rc <= 0) return false;
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && !wantWrite && (pfd.revents & POLLRDNORM) == 0) {
        return false;
    }
    if (wantWrite && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return false;
    return true;
#else
    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = wantWrite ? POLLOUT : POLLIN;
    int rc = ::poll(&pfd, 1, timeoutMs);
    if (rc <= 0) return false;
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && !wantWrite && (pfd.revents & POLLIN) == 0) {
        return false;
    }
    if (wantWrite && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return false;
    return true;
#endif
}

platform::NativeSocket connectTcpWithTimeout(const std::string &hostOrIp,
                                             uint16_t port,
                                             const std::string &ifName,
                                             int timeoutMs) noexcept {
    try { platform::ensureWinsock(); } catch (...) { return platform::kInvalidSocket; }
    std::string cleanHost = stripBrackets(hostOrIp);
    sockaddr_storage ss{};
    socklen_t slen = 0;
    int family = AF_UNSPEC;

    sockaddr_in v4{};
    sockaddr_in6 v6{};
    if (inet_pton(AF_INET, cleanHost.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        slen = sizeof(v4);
        family = AF_INET;
        std::memcpy(&ss, &v4, sizeof(v4));
    } else if (inet_pton(AF_INET6, cleanHost.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        slen = sizeof(v6);
        family = AF_INET6;
        std::memcpy(&ss, &v6, sizeof(v6));
    } else {
        // Never invoke ::getaddrinfo() when bound to a physical interface during TUN mode:
        // system DNS may point back into our own utun listener, causing a deadlock or Fake-IP loop.
        if (!ifName.empty()) {
            return platform::kInvalidSocket;
        }
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_NUMERICSERV;
        const std::string portStr = std::to_string(port);
        if (::getaddrinfo(cleanHost.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
            if (res) ::freeaddrinfo(res);
            return platform::kInvalidSocket;
        }
        slen = static_cast<socklen_t>(res->ai_addrlen);
        std::memcpy(&ss, res->ai_addr, res->ai_addrlen);
        family = res->ai_family;
        ::freeaddrinfo(res);
    }

    auto raw = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    platform::NativeSocket s = platform::toNativeSocket(raw);
    if (s < 0) return platform::kInvalidSocket;
    if (!platform::setNonBlockingAndCloexec(s)) {
        platform::closeNativeSocket(s);
        return platform::kInvalidSocket;
    }
    bindSocketToPhysicalInterface(s, family, ifName);
    int one = 1;
    (void)::setsockopt(platform::toOsSocket(s), IPPROTO_TCP, TCP_NODELAY,
                       reinterpret_cast<const char *>(&one), sizeof(one));

    int rc = ::connect(platform::toOsSocket(s), reinterpret_cast<const sockaddr *>(&ss), slen);
    if (rc != 0) {
        int err = platform::lastSocketError();
#if defined(_WIN32)
        const bool inProg = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
        const bool inProg = (err == EINPROGRESS || err == EWOULDBLOCK);
#endif
        if (!inProg || !waitSocketIo(s, true, timeoutMs)) {
            platform::closeNativeSocket(s);
            return platform::kInvalidSocket;
        }
        int soErr = 0;
        socklen_t optLen = sizeof(soErr);
        if (::getsockopt(platform::toOsSocket(s), SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char *>(&soErr), &optLen) != 0 || soErr != 0) {
            platform::closeNativeSocket(s);
            return platform::kInvalidSocket;
        }
    }
    return s;
}

} // namespace

// ============================================================================
// FakeIpPool
// ============================================================================
bool FakeIpPool::parseIpv4HostOrder(const std::string &ipStr, uint32_t &outHostOrder) noexcept {
    uint8_t raw[4]{};
    if (hajimi_parse_ipv4_literal(ipStr.data(), ipStr.size(), raw) != 1) {
        return false;
    }
    outHostOrder = (static_cast<uint32_t>(raw[0]) << 24) |
                   (static_cast<uint32_t>(raw[1]) << 16) |
                   (static_cast<uint32_t>(raw[2]) << 8) |
                   static_cast<uint32_t>(raw[3]);
    return true;
}

std::string FakeIpPool::formatIpv4HostOrder(uint32_t hostOrderIp) {
    uint8_t raw[4] = {
        static_cast<uint8_t>((hostOrderIp >> 24) & 0xFFu),
        static_cast<uint8_t>((hostOrderIp >> 16) & 0xFFu),
        static_cast<uint8_t>((hostOrderIp >> 8) & 0xFFu),
        static_cast<uint8_t>(hostOrderIp & 0xFFu)
    };
    char buf[20]{};
    size_t n = hajimi_format_ipv4_literal(raw, buf, sizeof(buf));
    return std::string(buf, n);
}

bool FakeIpPool::isFakeIpv4String(const std::string &ipStr) noexcept {
    uint32_t h = 0;
    return parseIpv4HostOrder(ipStr, h) && isFakeIpv4HostOrder(h);
}

uint32_t FakeIpPool::allocateHostOrder(const std::string &domain) {
    const std::string key = lowerDomain(domain);
    if (key.empty()) return 0;

    std::lock_guard<std::mutex> lk(mu_);
    auto found = domainToIp_.find(key);
    if (found != domainToIp_.end()) {
        return found->second;
    }

    if (fifoOrder_.size() >= (kPoolCount - 16u) && !fifoOrder_.empty()) {
        uint32_t oldest = fifoOrder_.front();
        fifoOrder_.pop_front();
        auto oldIt = ipToDomain_.find(oldest);
        if (oldIt != ipToDomain_.end()) {
            domainToIp_.erase(oldIt->second);
            ipToDomain_.erase(oldIt);
        }
    }

    uint32_t candidate = kBaseHostOrder + nextOffset_;
    uint32_t probes = 0;
    while (ipToDomain_.find(candidate) != ipToDomain_.end() && probes < kPoolCount) {
        nextOffset_ = (nextOffset_ + 1u) % kPoolCount;
        if (nextOffset_ < 2u) nextOffset_ = 2u;
        candidate = kBaseHostOrder + nextOffset_;
        ++probes;
    }
    nextOffset_ = (nextOffset_ + 1u) % kPoolCount;
    if (nextOffset_ < 2u) nextOffset_ = 2u;

    domainToIp_[key] = candidate;
    ipToDomain_[candidate] = key;
    fifoOrder_.push_back(candidate);
    return candidate;
}

std::string FakeIpPool::allocateForDomain(const std::string &domain) {
    uint32_t ip = allocateHostOrder(domain);
    return ip == 0 ? std::string{} : formatIpv4HostOrder(ip);
}

bool FakeIpPool::lookupDomainByHostOrder(uint32_t hostOrderIp, std::string &outDomain) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = ipToDomain_.find(hostOrderIp);
    if (it == ipToDomain_.end()) return false;
    outDomain = it->second;
    return true;
}

bool FakeIpPool::lookupDomain(const std::string &ipStr, std::string &outDomain) const {
    uint32_t h = 0;
    if (!parseIpv4HostOrder(ipStr, h)) return false;
    return lookupDomainByHostOrder(h, outDomain);
}

void FakeIpPool::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    domainToIp_.clear();
    ipToDomain_.clear();
    fifoOrder_.clear();
    nextOffset_ = 2u;
}

size_t FakeIpPool::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return domainToIp_.size();
}

// ============================================================================
// EncryptedDnsEngine
// ============================================================================
EncryptedDnsEngine::EncryptedDnsEngine() {
    isProxied_ = [](const std::string &) { return true; };
}

void EncryptedDnsEngine::configure(const std::vector<std::string> &plainNameservers,
                                   const std::vector<std::string> &encryptedUpstreams,
                                   const std::unordered_map<std::string, std::string> &staticHosts,
                                   bool fakeIpEnabled,
                                   bool ipv6Enabled) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!plainNameservers.empty()) {
        plainNameservers_ = plainNameservers;
    } else if (encryptedUpstreams.empty()) {
        plainNameservers_ = {"223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"};
    }
    encryptedUpstreams_ = encryptedUpstreams;
    staticHosts_ = staticHosts;
    fakeIpEnabled_ = fakeIpEnabled;
    ipv6Enabled_ = ipv6Enabled;
    cache_.clear();
    directHostCache_.clear();
}

void EncryptedDnsEngine::setOutboundInterface(const std::string &interfaceName) {
    std::lock_guard<std::mutex> lk(mu_);
    outboundIfName_ = interfaceName;
}

std::vector<std::string> EncryptedDnsEngine::upstreamBypassIps() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::string> out;
    auto pushIfIp = [&](const std::string &candidate) {
        if (isNumericIpLiteral(candidate) && std::find(out.begin(), out.end(), candidate) == out.end()) {
            out.push_back(candidate);
        }
    };
    auto collectHost = [&](std::string spec) {
        auto hashPos = spec.find('#');
        if (hashPos != std::string::npos) {
            std::string pinned = stripBrackets(spec.substr(hashPos + 1));
            pushIfIp(pinned);
            spec.resize(hashPos);
        }
        if (spec.rfind("tls://", 0) == 0) spec = spec.substr(6);
        else if (spec.rfind("https://", 0) == 0) spec = spec.substr(8);
        auto slash = spec.find('/');
        if (slash != std::string::npos) spec.resize(slash);
        if (!spec.empty() && spec.front() != '[') {
            auto colon = spec.rfind(':');
            if (colon != std::string::npos && spec.find(':') == colon) spec.resize(colon);
        } else if (!spec.empty() && spec.front() == '[') {
            auto closeB = spec.find(']');
            if (closeB != std::string::npos) spec = spec.substr(1, closeB - 1);
        }
        pushIfIp(spec);
    };
    for (const auto &ns : plainNameservers_) collectHost(ns);
    for (const auto &up : encryptedUpstreams_) collectHost(up);
    return out;
}

void EncryptedDnsEngine::setProxiedDomainPredicate(std::function<bool(const std::string &)> pred) {
    std::lock_guard<std::mutex> lk(mu_);
    isProxied_ = std::move(pred);
}

bool EncryptedDnsEngine::parseWireQuery(const uint8_t *wire, size_t len, DnsParsedQuestion &outQ) noexcept {
    if (!wire || len < 17 || len > 4096) return false;
    uint16_t flags = static_cast<uint16_t>((wire[2] << 8) | wire[3]);
    if ((flags & 0x8000u) != 0) return false;
    uint16_t qdcount = static_cast<uint16_t>((wire[4] << 8) | wire[5]);
    if (qdcount == 0) return false;

    outQ = DnsParsedQuestion{};
    outQ.txId = static_cast<uint16_t>((wire[0] << 8) | wire[1]);
    outQ.flags = flags;
    outQ.recursionDesired = ((flags & 0x0100u) != 0);

    size_t pos = 12;
    size_t jumpedEnd = 0;
    int jumps = 0;
    std::string labels;
    labels.reserve(64);

    while (true) {
        if (pos >= len) return false;
        uint8_t tag = wire[pos];
        if (tag == 0) {
            ++pos;
            if (jumpedEnd == 0) jumpedEnd = pos;
            break;
        }
        if ((tag & 0xC0u) == 0xC0u) {
            if (pos + 1 >= len || ++jumps > 16) return false;
            uint16_t ptr = static_cast<uint16_t>(((tag & 0x3Fu) << 8) | wire[pos + 1]);
            if (jumpedEnd == 0) jumpedEnd = pos + 2;
            if (ptr < 12 || ptr >= len) return false;
            pos = ptr;
            continue;
        }
        if ((tag & 0xC0u) != 0 || tag > 63 || pos + 1 + tag > len) {
            return false;
        }
        if (!labels.empty()) labels.push_back('.');
        for (size_t i = 0; i < tag; ++i) {
            char c = static_cast<char>(wire[pos + 1 + i]);
            labels.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        pos += 1 + tag;
        if (labels.size() > 253) return false;
    }

    if (jumpedEnd + 4 > len) return false;
    outQ.qname = std::move(labels);
    outQ.qtype = static_cast<uint16_t>((wire[jumpedEnd] << 8) | wire[jumpedEnd + 1]);
    outQ.qclass = static_cast<uint16_t>((wire[jumpedEnd + 2] << 8) | wire[jumpedEnd + 3]);
    outQ.questionEndOffset = jumpedEnd + 4;
    return true;
}

std::vector<uint8_t> EncryptedDnsEngine::buildIpv4Answer(const uint8_t *queryWire,
                                                         size_t queryLen,
                                                         const DnsParsedQuestion &q,
                                                         uint32_t ipv4HostOrder,
                                                         uint32_t ttlSeconds) {
    if (!queryWire || q.questionEndOffset < 16 || q.questionEndOffset > queryLen) return {};
    const size_t qSectionLen = q.questionEndOffset - 12;
    std::vector<uint8_t> out;
    out.reserve(12 + qSectionLen + 16);

    uint16_t respFlags = 0x8080u | (q.recursionDesired ? 0x0100u : 0u);
    out.push_back(static_cast<uint8_t>(q.txId >> 8));
    out.push_back(static_cast<uint8_t>(q.txId & 0xFFu));
    out.push_back(static_cast<uint8_t>(respFlags >> 8));
    out.push_back(static_cast<uint8_t>(respFlags & 0xFFu));
    out.push_back(0); out.push_back(1);
    out.push_back(0); out.push_back(1);
    out.push_back(0); out.push_back(0);
    out.push_back(0); out.push_back(0);

    out.insert(out.end(), queryWire + 12, queryWire + q.questionEndOffset);

    out.push_back(0xC0u); out.push_back(0x0Cu);
    out.push_back(0x00u); out.push_back(0x01u);
    out.push_back(0x00u); out.push_back(0x01u);
    out.push_back(static_cast<uint8_t>((ttlSeconds >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((ttlSeconds >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((ttlSeconds >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(ttlSeconds & 0xFFu));
    out.push_back(0x00u); out.push_back(0x04u);
    out.push_back(static_cast<uint8_t>((ipv4HostOrder >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((ipv4HostOrder >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((ipv4HostOrder >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(ipv4HostOrder & 0xFFu));
    return out;
}

std::vector<uint8_t> EncryptedDnsEngine::buildEmptyResponse(const uint8_t *queryWire,
                                                            size_t queryLen,
                                                            const DnsParsedQuestion &q,
                                                            uint8_t rcode) {
    if (!queryWire || q.questionEndOffset < 16 || q.questionEndOffset > queryLen) return {};
    const size_t qSectionLen = q.questionEndOffset - 12;
    std::vector<uint8_t> out;
    out.reserve(12 + qSectionLen);
    uint16_t respFlags = 0x8080u | (q.recursionDesired ? 0x0100u : 0u) | (rcode & 0x0Fu);
    out.push_back(static_cast<uint8_t>(q.txId >> 8));
    out.push_back(static_cast<uint8_t>(q.txId & 0xFFu));
    out.push_back(static_cast<uint8_t>(respFlags >> 8));
    out.push_back(static_cast<uint8_t>(respFlags & 0xFFu));
    out.push_back(0); out.push_back(1);
    out.push_back(0); out.push_back(0);
    out.push_back(0); out.push_back(0);
    out.push_back(0); out.push_back(0);
    out.insert(out.end(), queryWire + 12, queryWire + q.questionEndOffset);
    return out;
}

std::vector<uint8_t> EncryptedDnsEngine::forwardUpstreamUDP(const std::string &ip,
                                                            uint16_t port,
                                                            const std::string &ifName,
                                                            const uint8_t *queryWire,
                                                            size_t queryLen) {
    try { platform::ensureWinsock(); } catch (...) { return {}; }
    sockaddr_storage ss{};
    socklen_t slen = 0;
    sockaddr_in v4{};
    sockaddr_in6 v6{};
    std::string cleanIp = stripBrackets(ip);
    if (inet_pton(AF_INET, cleanIp.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        slen = sizeof(v4);
        std::memcpy(&ss, &v4, sizeof(v4));
    } else if (inet_pton(AF_INET6, cleanIp.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        slen = sizeof(v6);
        std::memcpy(&ss, &v6, sizeof(v6));
    } else {
        return {};
    }

    auto raw = ::socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    platform::NativeSocket sock = platform::toNativeSocket(raw);
    if (sock < 0) return {};
    platform::disableUdpConnReset(sock);
    if (!platform::setNonBlockingAndCloexec(sock)) {
        platform::closeNativeSocket(sock);
        return {};
    }
    bindSocketToPhysicalInterface(sock, ss.ss_family, ifName);

    auto sent = ::sendto(platform::toOsSocket(sock),
                         reinterpret_cast<const char *>(queryWire),
                         static_cast<int>(queryLen), 0,
                         reinterpret_cast<const sockaddr *>(&ss), slen);
    if (sent != static_cast<int>(queryLen) || !waitSocketIo(sock, false, 1500)) {
        platform::closeNativeSocket(sock);
        return {};
    }

    uint8_t rx[4096];
    sockaddr_storage from{};
    socklen_t fromLen = sizeof(from);
    auto got = ::recvfrom(platform::toOsSocket(sock), reinterpret_cast<char *>(rx), sizeof(rx), 0,
                          reinterpret_cast<sockaddr *>(&from), &fromLen);
    platform::closeNativeSocket(sock);
    if (got < 12 || rx[0] != queryWire[0] || rx[1] != queryWire[1]) {
        return {};
    }
    return std::vector<uint8_t>(rx, rx + got);
}

std::vector<uint8_t> EncryptedDnsEngine::forwardUpstreamDoT(const std::string &host,
                                                            uint16_t port,
                                                            const std::string &sni,
                                                            const std::string &ifName,
                                                            const uint8_t *queryWire,
                                                            size_t queryLen) {
    if (queryLen < 12 || queryLen > 4096) return {};
    std::string connectHost = host;
    if (!isNumericIpLiteral(connectHost) && !ifName.empty()) {
        std::vector<std::string> plainSnap;
        {
            std::lock_guard<std::mutex> lk(mu_);
            plainSnap = plainNameservers_;
        }
        connectHost = resolveDirectHostViaPlain(lowerDomain(connectHost), 4, plainSnap, ifName);
        if (connectHost.empty()) return {};
    }
    platform::NativeSocket sock = connectTcpWithTimeout(connectHost, port, ifName, 1800);
    if (sock < 0) return {};

    SSL_CTX *ctx = sharedDnsClientSslCtx();
    if (!ctx) {
        platform::closeNativeSocket(sock);
        return {};
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        platform::closeNativeSocket(sock);
        return {};
    }
    BIO *bio = BIO_new_socket(static_cast<int>(platform::toOsSocket(sock)), BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    configureTlsPeerVerify(ssl, sni.empty() ? host : sni);

    auto doSslStep = [&](auto fn) -> bool {
        auto deadline = nowSteadyMs() + 2000;
        while (nowSteadyMs() < deadline) {
            ERR_clear_error();
            int r = fn();
            if (r > 0) return true;
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ) {
                if (!waitSocketIo(sock, false, 250)) continue;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (!waitSocketIo(sock, true, 250)) continue;
            } else {
                return false;
            }
        }
        return false;
    };

    if (!doSslStep([&]() { return SSL_connect(ssl); })) {
        SSL_free(ssl);
        platform::closeNativeSocket(sock);
        return {};
    }

    std::vector<uint8_t> framed(2 + queryLen);
    framed[0] = static_cast<uint8_t>((queryLen >> 8) & 0xFFu);
    framed[1] = static_cast<uint8_t>(queryLen & 0xFFu);
    std::memcpy(framed.data() + 2, queryWire, queryLen);

    size_t written = 0;
    while (written < framed.size()) {
        int step = 0;
        if (!doSslStep([&]() {
                step = SSL_write(ssl, framed.data() + written, static_cast<int>(framed.size() - written));
                return step;
            })) {
            SSL_free(ssl);
            platform::closeNativeSocket(sock);
            return {};
        }
        written += static_cast<size_t>(step);
    }

    uint8_t lenHdr[2]{};
    size_t hdrGot = 0;
    while (hdrGot < 2) {
        int step = 0;
        if (!doSslStep([&]() {
                step = SSL_read(ssl, lenHdr + hdrGot, static_cast<int>(2 - hdrGot));
                return step;
            })) {
            SSL_free(ssl);
            platform::closeNativeSocket(sock);
            return {};
        }
        hdrGot += static_cast<size_t>(step);
    }

    const size_t respLen = (static_cast<size_t>(lenHdr[0]) << 8) | lenHdr[1];
    if (respLen < 12 || respLen > 4096) {
        SSL_free(ssl);
        platform::closeNativeSocket(sock);
        return {};
    }

    std::vector<uint8_t> resp(respLen);
    size_t bodyGot = 0;
    while (bodyGot < respLen) {
        int step = 0;
        if (!doSslStep([&]() {
                step = SSL_read(ssl, resp.data() + bodyGot, static_cast<int>(respLen - bodyGot));
                return step;
            })) {
            SSL_free(ssl);
            platform::closeNativeSocket(sock);
            return {};
        }
        bodyGot += static_cast<size_t>(step);
    }

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    platform::closeNativeSocket(sock);
    resp[0] = queryWire[0];
    resp[1] = queryWire[1];
    return resp;
}

std::vector<uint8_t> EncryptedDnsEngine::forwardUpstreamDoH(const std::string &httpsUrl,
                                                            const std::string &ifName,
                                                            const uint8_t *queryWire,
                                                            size_t queryLen) {
    if (queryLen < 12 || queryLen > 4096 || httpsUrl.rfind("https://", 0) != 0) return {};
    std::string rem = httpsUrl.substr(8);
    std::string pinnedIp;
    auto hashPos = rem.find('#');
    if (hashPos != std::string::npos) {
        pinnedIp = stripBrackets(rem.substr(hashPos + 1));
        rem.resize(hashPos);
    }
    std::string path = "/dns-query";
    auto slash = rem.find('/');
    if (slash != std::string::npos) {
        path = rem.substr(slash);
        rem = rem.substr(0, slash);
    }
    std::string host = rem;
    uint16_t port = 443;
    auto colon = rem.rfind(':');
    if (colon != std::string::npos && rem.find(']') == std::string::npos) {
        host = rem.substr(0, colon);
        unsigned long p = std::strtoul(rem.substr(colon + 1).c_str(), nullptr, 10);
        if (p > 0 && p <= 65535) port = static_cast<uint16_t>(p);
    }

    std::string connectHost = !pinnedIp.empty() ? pinnedIp : host;
    if (!isNumericIpLiteral(connectHost) && !ifName.empty()) {
        std::vector<std::string> plainSnap;
        {
            std::lock_guard<std::mutex> lk(mu_);
            plainSnap = plainNameservers_;
        }
        connectHost = resolveDirectHostViaPlain(lowerDomain(connectHost), 4, plainSnap, ifName);
        if (connectHost.empty()) return {};
    }

    platform::NativeSocket sock = connectTcpWithTimeout(connectHost, port, ifName, 1800);
    if (sock < 0) return {};

    SSL_CTX *ctx = sharedDnsClientSslCtx();
    if (!ctx) {
        platform::closeNativeSocket(sock);
        return {};
    }
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        platform::closeNativeSocket(sock);
        return {};
    }
    BIO *bio = BIO_new_socket(static_cast<int>(platform::toOsSocket(sock)), BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    configureTlsPeerVerify(ssl, host);

    auto doSslStep = [&](auto fn) -> bool {
        auto deadline = nowSteadyMs() + 2000;
        while (nowSteadyMs() < deadline) {
            ERR_clear_error();
            int r = fn();
            if (r > 0) return true;
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_WANT_READ) {
                if (!waitSocketIo(sock, false, 250)) continue;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (!waitSocketIo(sock, true, 250)) continue;
            } else {
                return false;
            }
        }
        return false;
    };

    if (!doSslStep([&]() { return SSL_connect(ssl); })) {
        SSL_free(ssl);
        platform::closeNativeSocket(sock);
        return {};
    }

    // RFC 8484 §4.1: Normalize DoH wire DNS Message ID to 0x0000 for HTTP cacheability
    std::vector<uint8_t> normQuery(queryWire, queryWire + queryLen);
    normQuery[0] = 0;
    normQuery[1] = 0;

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "Accept: application/dns-message\r\n"
        << "Content-Type: application/dns-message\r\n"
        << "Content-Length: " << normQuery.size() << "\r\n"
        << "Connection: close\r\n\r\n";
    std::string hdr = req.str();
    std::vector<uint8_t> tx(hdr.begin(), hdr.end());
    tx.insert(tx.end(), normQuery.begin(), normQuery.end());

    size_t sent = 0;
    while (sent < tx.size()) {
        int step = 0;
        if (!doSslStep([&]() {
                step = SSL_write(ssl, tx.data() + sent, static_cast<int>(tx.size() - sent));
                return step;
            })) {
            SSL_free(ssl);
            platform::closeNativeSocket(sock);
            return {};
        }
        sent += static_cast<size_t>(step);
    }

    std::string rawResp;
    char buf[4096];
    while (rawResp.size() < 16384) {
        int step = SSL_read(ssl, buf, sizeof(buf));
        if (step > 0) {
            rawResp.append(buf, static_cast<size_t>(step));
            continue;
        }
        int err = SSL_get_error(ssl, step);
        if (err == SSL_ERROR_WANT_READ && waitSocketIo(sock, false, 400)) continue;
        break;
    }
    SSL_free(ssl);
    platform::closeNativeSocket(sock);

    auto hdrEnd = rawResp.find("\r\n\r\n");
    if (hdrEnd == std::string::npos || rawResp.rfind("HTTP/1.", 0) != 0 ||
        rawResp.find(" 200") == std::string::npos) {
        return {};
    }
    std::string lowerHdr = rawResp.substr(0, hdrEnd);
    for (char &c : lowerHdr) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string body = rawResp.substr(hdrEnd + 4);
    if (lowerHdr.find("transfer-encoding: chunked") != std::string::npos) {
        body = decodeHttpChunkedBody(body);
    }
    if (body.size() < 12) return {};

    std::vector<uint8_t> wireOut(
        reinterpret_cast<const uint8_t *>(body.data()),
        reinterpret_cast<const uint8_t *>(body.data() + body.size()));
    wireOut[0] = queryWire[0];
    wireOut[1] = queryWire[1];
    return wireOut;
}

bool EncryptedDnsEngine::tryResolveFastPath(const uint8_t *queryWire,
                                            size_t queryLen,
                                            std::vector<uint8_t> &outReply) {
    outReply.clear();
    DnsParsedQuestion q;
    if (!parseWireQuery(queryWire, queryLen, q)) {
        return true; // malformed query -> no reply needed
    }

    std::unordered_map<std::string, std::string> hostsCopy;
    bool fakeIpOn = true;
    bool ipv6On = false;
    std::function<bool(const std::string &)> predCopy;
    {
        std::lock_guard<std::mutex> lk(mu_);
        hostsCopy = staticHosts_;
        fakeIpOn = fakeIpEnabled_;
        ipv6On = ipv6Enabled_;
        predCopy = isProxied_;
    }

    if (q.qname == "localhost") {
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.totalQueries;
        }
        outReply = (q.qtype == 1)
            ? buildIpv4Answer(queryWire, queryLen, q, 0x7F000001u, 300)
            : buildEmptyResponse(queryWire, queryLen, q, 0);
        return true;
    }
    auto hostIt = hostsCopy.find(q.qname);
    if (hostIt != hostsCopy.end()) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.totalQueries;
        }
        uint32_t staticV4 = 0;
        if (q.qtype == 1 && FakeIpPool::parseIpv4HostOrder(hostIt->second, staticV4)) {
            outReply = buildIpv4Answer(queryWire, queryLen, q, staticV4, 60);
        } else {
            outReply = buildEmptyResponse(queryWire, queryLen, q, 0);
        }
        return true;
    }

    const bool proxied = predCopy ? predCopy(q.qname) : false;
    if (fakeIpOn && proxied) {
        if (q.qtype == 1) {
            uint32_t fakeV4 = fakeIp_.allocateHostOrder(q.qname);
            if (fakeV4 != 0) {
                std::lock_guard<std::mutex> lk(mu_);
                ++stats_.totalQueries;
                ++stats_.fakeIpHits;
                outReply = buildIpv4Answer(queryWire, queryLen, q, fakeV4, 5);
                return true;
            }
        } else if (q.qtype == 28 || q.qtype == 65) {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.totalQueries;
            ++stats_.fakeIpHits;
            outReply = buildEmptyResponse(queryWire, queryLen, q, 0);
            return true;
        }
    }

    if (!ipv6On && q.qtype == 28) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++stats_.totalQueries;
        }
        outReply = buildEmptyResponse(queryWire, queryLen, q, 0);
        return true;
    }

    const std::string cacheKey = q.qname + "#" + std::to_string(q.qtype) + "#" + std::to_string(q.qclass);
    const int64_t nowMs = nowSteadyMs();
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto cit = cache_.find(cacheKey);
        if (cit != cache_.end()) {
            if (cit->second.expiresAtSteadyMs > nowMs && cit->second.wireTemplate.size() >= 12) {
                ++stats_.totalQueries;
                ++stats_.cacheHits;
                outReply = cit->second.wireTemplate;
                outReply[0] = static_cast<uint8_t>(q.txId >> 8);
                outReply[1] = static_cast<uint8_t>(q.txId & 0xFFu);
                return true;
            }
            cache_.erase(cit);
        }
    }
    return false;
}

std::string EncryptedDnsEngine::resolveDirectHostViaPlain(const std::string &lowerHost,
                                                          int preferFamily,
                                                          const std::vector<std::string> &plainServers,
                                                          const std::string &ifName) {
    std::vector<std::string> servers = plainServers;
    if (servers.empty()) {
        servers = {"223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"};
    }
    const uint16_t firstType = (preferFamily == 6) ? 28u : 1u;
    const uint16_t secondType = (preferFamily == 0) ? 28u : 0u;
    uint16_t qtypes[2] = {firstType, secondType};

    for (uint16_t qtype : qtypes) {
        if (qtype == 0) continue;
        auto qwire = buildWireDnsQuery(lowerHost, qtype, static_cast<uint16_t>(nowSteadyMs() & 0xFFFFu));
        if (qwire.empty()) continue;
        for (const auto &ns : servers) {
            std::string ip = ns;
            uint16_t port = 53;
            auto colon = ns.rfind(':');
            if (colon != std::string::npos && ns.find(':') == colon) {
                ip = ns.substr(0, colon);
                unsigned long p = std::strtoul(ns.substr(colon + 1).c_str(), nullptr, 10);
                if (p > 0 && p <= 65535) port = static_cast<uint16_t>(p);
            }
            auto resp = forwardUpstreamUDP(ip, port, ifName, qwire.data(), qwire.size());
            std::string resolved = extractFirstIpFromDnsWireReply(resp, qtype);
            if (!resolved.empty()) return resolved;
        }
    }
    return {};
}

std::string EncryptedDnsEngine::resolveDirectHost(const std::string &host, int preferFamily) {
    std::string clean = stripBrackets(host);
    if (clean.empty()) return {};
    if (isNumericIpLiteral(clean)) return clean;
    const std::string lowerH = lowerDomain(clean);
    if (lowerH == "localhost") return (preferFamily == 6) ? "::1" : "127.0.0.1";

    std::vector<std::string> plainCopy, encCopy;
    std::string ifNameCopy;
    const std::string cacheKey = lowerH + "#" + std::to_string(preferFamily);
    const int64_t nowMs = nowSteadyMs();
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto sit = staticHosts_.find(lowerH);
        if (sit != staticHosts_.end() && !sit->second.empty()) return sit->second;
        auto dit = directHostCache_.find(cacheKey);
        if (dit != directHostCache_.end()) {
            if (dit->second.expiresAtSteadyMs > nowMs && !dit->second.ip.empty()) {
                return dit->second.ip;
            }
            directHostCache_.erase(dit);
        }
        plainCopy = plainNameservers_;
        encCopy = encryptedUpstreams_;
        ifNameCopy = outboundIfName_;
    }

    // Prefer plain UDP nameservers first for direct bootstrap/egress resolution:
    // fast single-RTT UDP over IP_BOUND_IF without TLS handshake overhead.
    std::string resolved = resolveDirectHostViaPlain(lowerH, preferFamily, plainCopy, ifNameCopy);

    // Fallback to configured encrypted DNS if plain DNS failed.
    if (resolved.empty() && !encCopy.empty()) {
        const uint16_t qtype = (preferFamily == 6) ? 28u : 1u;
        auto qwire = buildWireDnsQuery(lowerH, qtype, static_cast<uint16_t>(nowSteadyMs() & 0xFFFFu));
        if (!qwire.empty()) {
            for (const auto &up : encCopy) {
                std::vector<uint8_t> resp;
                if (up.rfind("tls://", 0) == 0) {
                    std::string body = up.substr(6);
                    std::string pinned;
                    auto hp = body.find('#');
                    if (hp != std::string::npos) {
                        pinned = stripBrackets(body.substr(hp + 1));
                        body.resize(hp);
                    }
                    std::string h = body;
                    uint16_t port = 853;
                    auto colon = body.rfind(':');
                    if (colon != std::string::npos) {
                        h = body.substr(0, colon);
                        unsigned long p = std::strtoul(body.substr(colon + 1).c_str(), nullptr, 10);
                        if (p > 0 && p <= 65535) port = static_cast<uint16_t>(p);
                    }
                    resp = forwardUpstreamDoT(!pinned.empty() ? pinned : h, port, h, ifNameCopy,
                                              qwire.data(), qwire.size());
                } else if (up.rfind("https://", 0) == 0) {
                    resp = forwardUpstreamDoH(up, ifNameCopy, qwire.data(), qwire.size());
                }
                resolved = extractFirstIpFromDnsWireReply(resp, qtype);
                if (!resolved.empty()) break;
            }
        }
    }

    // Last-resort universal fallback UDP resolvers over physical interface if configured servers failed.
    if (resolved.empty()) {
        resolved = resolveDirectHostViaPlain(lowerH, preferFamily,
                                             {"223.5.5.5", "119.29.29.29", "8.8.8.8", "1.1.1.1"},
                                             ifNameCopy);
    }

    if (!resolved.empty()) {
        std::lock_guard<std::mutex> lk(mu_);
        if (directHostCache_.size() > 2048) directHostCache_.clear();
        directHostCache_[cacheKey] = DirectHostEntry{resolved, nowMs + 60000};
    }
    return resolved;
}

std::vector<uint8_t> EncryptedDnsEngine::resolveWireQuery(const uint8_t *queryWire, size_t queryLen) {
    DnsParsedQuestion q;
    if (!parseWireQuery(queryWire, queryLen, q)) {
        return {};
    }

    std::vector<uint8_t> fastReply;
    if (tryResolveFastPath(queryWire, queryLen, fastReply)) {
        return fastReply;
    }

    std::vector<std::string> encCopy, plainCopy;
    std::string ifNameCopy;
    {
        std::lock_guard<std::mutex> lk(mu_);
        ++stats_.totalQueries;
        encCopy = encryptedUpstreams_;
        plainCopy = plainNameservers_;
        ifNameCopy = outboundIfName_;
    }

    const std::string cacheKey = q.qname + "#" + std::to_string(q.qtype) + "#" + std::to_string(q.qclass);
    const int64_t nowMs = nowSteadyMs();

    std::vector<uint8_t> resp;
    for (const auto &up : encCopy) {
        if (up.rfind("tls://", 0) == 0) {
            std::string body = up.substr(6);
            std::string pinned;
            auto hp = body.find('#');
            if (hp != std::string::npos) {
                pinned = stripBrackets(body.substr(hp + 1));
                body.resize(hp);
            }
            std::string host = body;
            uint16_t port = 853;
            auto colon = body.rfind(':');
            if (colon != std::string::npos) {
                host = body.substr(0, colon);
                unsigned long p = std::strtoul(body.substr(colon + 1).c_str(), nullptr, 10);
                if (p > 0 && p <= 65535) port = static_cast<uint16_t>(p);
            }
            resp = forwardUpstreamDoT(!pinned.empty() ? pinned : host, port, host, ifNameCopy, queryWire, queryLen);
        } else if (up.rfind("https://", 0) == 0) {
            resp = forwardUpstreamDoH(up, ifNameCopy, queryWire, queryLen);
        }
        if (resp.size() >= 12) break;
    }

    if (resp.size() < 12) {
        for (const auto &ns : plainCopy) {
            std::string ip = ns;
            uint16_t port = 53;
            auto colon = ns.rfind(':');
            if (colon != std::string::npos && ns.find(':') == colon) {
                ip = ns.substr(0, colon);
                unsigned long p = std::strtoul(ns.substr(colon + 1).c_str(), nullptr, 10);
                if (p > 0 && p <= 65535) port = static_cast<uint16_t>(p);
            }
            resp = forwardUpstreamUDP(ip, port, ifNameCopy, queryWire, queryLen);
            if (resp.size() >= 12) break;
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (resp.size() >= 12) {
            ++stats_.upstreamSuccess;
            if (cache_.size() > 4096) cache_.clear();
            const uint8_t rcode = resp[3] & 0x0Fu;
            const int64_t ttlMs = (rcode == 0) ? 60000 : 10000;
            cache_[cacheKey] = CacheEntry{resp, nowMs + ttlMs};
            return resp;
        }
        ++stats_.upstreamFailures;
    }
    return buildEmptyResponse(queryWire, queryLen, q, 2);
}

void EncryptedDnsEngine::flushCache() {
    std::lock_guard<std::mutex> lk(mu_);
    cache_.clear();
    directHostCache_.clear();
}

EncryptedDnsEngine::Stats EncryptedDnsEngine::snapshotStats() const {
    std::lock_guard<std::mutex> lk(mu_);
    return stats_;
}

} // namespace hajimi::engine
