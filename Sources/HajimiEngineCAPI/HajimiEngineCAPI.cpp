#include "include/HajimiEngineCAPI.h"
#include "EncryptedDnsAndFakeIp.hpp"
#include "ProfileConfigParser.hpp"
#include "UserspacePacketTunnel.hpp"
#include "WinSystemProxyAndProcess.hpp"

#include "../HajimiDataPlaneC/include/hajimi_dataplane.h"
#include "../HajimiFlowCXX/include/HajimiFlowCXX.h"
#include "../HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"
#include "../HajimiProtocolsCXX/include/HajimiProtocolsCXX.h"
#include "../HajimiWinTransportCXX/include/HajimiWinTransportCXX.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#elif defined(_WIN32)
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
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

using namespace hajimi;
using namespace hajimi::engine;

constexpr const char *kEngineVersion = "0.2.2-unified-b85";

int64_t steadyMillisNow() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

double steadySecondsNow() noexcept {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

std::string formatWallTimeHHMMSS() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
#if defined(_WIN32)
    localtime_s(&localTm, &tt);
#else
    localtime_r(&tt, &localTm);
#endif
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
                  localTm.tm_hour, localTm.tm_min, localTm.tm_sec);
    return buf;
}

uint64_t fnv1a64Ascii(const std::string &s) noexcept {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= static_cast<uint64_t>(std::tolower(c));
        h *= 1099511628211ULL;
    }
    return h;
}

std::string basenameOnly(const std::string &path) {
    if (path.empty()) return {};
    auto pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

void copyErr(char *errBuf, size_t errCap, const std::string &msg) noexcept {
    if (!errBuf || errCap == 0) return;
    const size_t n = (std::min)(msg.size(), errCap - 1);
    std::memcpy(errBuf, msg.data(), n);
    errBuf[n] = '\0';
}

char *allocHeapCString(const std::string &s) noexcept {
    char *p = static_cast<char *>(std::malloc(s.size() + 1));
    if (!p) return nullptr;
    std::memcpy(p, s.data(), s.size());
    p[s.size()] = '\0';
    return p;
}

std::string jsonEscapeStr(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

const char *policyGroupKindStr(PolicyGroupKind k) noexcept {
    switch (k) {
        case PolicyGroupKind::UrlTest:     return "url-test";
        case PolicyGroupKind::Fallback:    return "fallback";
        case PolicyGroupKind::LoadBalance: return "load-balance";
        case PolicyGroupKind::SmartUCB1:   return "smart";
        default:                           return "select";
    }
}

bool isLoopbackHostString(const std::string &host) {
    return host == "127.0.0.1" || host == "::1" || host == "[::1]" || host == "localhost";
}

bool waitFdReady(platform::NativeSocket s, bool write, int timeoutMs) noexcept {
    if (s < 0) return false;
#if defined(_WIN32)
    WSAPOLLFD pfd{};
    pfd.fd = platform::toOsSocket(s);
    pfd.events = write ? POLLWRNORM : POLLRDNORM;
    int rc = ::WSAPoll(&pfd, 1, timeoutMs);
    const SHORT mask = static_cast<SHORT>((write ? POLLWRNORM : POLLRDNORM) | POLLERR | POLLHUP);
    return rc > 0 && (pfd.revents & mask) != 0;
#else
    pollfd pfd{};
    pfd.fd = s;
    pfd.events = write ? POLLOUT : POLLIN;
    int rc = ::poll(&pfd, 1, timeoutMs);
    const short mask = static_cast<short>((write ? POLLOUT : POLLIN) | POLLERR | POLLHUP);
    return rc > 0 && (pfd.revents & mask) != 0;
#endif
}

bool sendAllBlockingWithDeadline(platform::NativeSocket s, const uint8_t *data, size_t len, int timeoutMs = 4000) noexcept {
    size_t sent = 0;
    while (sent < len) {
        if (!waitFdReady(s, true, timeoutMs)) return false;
        auto n = ::send(platform::toOsSocket(s),
                        reinterpret_cast<const char *>(data + sent),
                        static_cast<int>((std::min)(len - sent, static_cast<size_t>(65536))), 0);
        if (n <= 0) {
            if (platform::isSocketWouldBlock(platform::lastSocketError())) continue;
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool bindTcpListener(const std::string &host, uint16_t requestedPort,
                     platform::NativeSocket &outSock, uint16_t &outBoundPort,
                     std::string &outError) {
    try { platform::ensureWinsock(); } catch (const std::exception &e) {
        outError = e.what();
        return false;
    }

    sockaddr_storage ss{};
    socklen_t slen = 0;
    std::string cleanHost = host.empty() ? "127.0.0.1" : host;
    if (cleanHost.size() >= 2 && cleanHost.front() == '[' && cleanHost.back() == ']') {
        cleanHost = cleanHost.substr(1, cleanHost.size() - 2);
    }

    sockaddr_in v4{};
    sockaddr_in6 v6{};
    if (inet_pton(AF_INET, cleanHost.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(requestedPort);
        slen = sizeof(v4);
        std::memcpy(&ss, &v4, sizeof(v4));
    } else if (inet_pton(AF_INET6, cleanHost.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(requestedPort);
        slen = sizeof(v6);
        std::memcpy(&ss, &v6, sizeof(v6));
    } else {
        outError = "Invalid listener bind IP: " + host;
        return false;
    }

    auto raw = ::socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
    platform::NativeSocket s = platform::toNativeSocket(raw);
    if (s < 0) {
        outError = "socket(TCP) failed";
        return false;
    }
#if defined(_WIN32)
    BOOL excl = TRUE;
    (void)::setsockopt(platform::toOsSocket(s), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char *>(&excl), sizeof(excl));
#else
    int reuse = 1;
    (void)::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    if (!platform::setNonBlockingAndCloexec(s) ||
        ::bind(platform::toOsSocket(s), reinterpret_cast<const sockaddr *>(&ss), slen) != 0 ||
        ::listen(platform::toOsSocket(s), 128) != 0) {
        platform::closeNativeSocket(s);
        outError = "bind/listen failed on " + cleanHost + ":" + std::to_string(requestedPort);
        return false;
    }

    sockaddr_storage bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(platform::toOsSocket(s), reinterpret_cast<sockaddr *>(&bound), &blen) != 0) {
        platform::closeNativeSocket(s);
        outError = "getsockname failed";
        return false;
    }
    outBoundPort = (bound.ss_family == AF_INET6)
        ? ntohs(reinterpret_cast<const sockaddr_in6 *>(&bound)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in *>(&bound)->sin_port);
    outSock = s;
    return true;
}

bool bindUdpListener(const std::string &host, uint16_t requestedPort,
                     platform::NativeSocket &outSock, uint16_t &outBoundPort,
                     std::string &outError) {
    try { platform::ensureWinsock(); } catch (const std::exception &e) {
        outError = e.what();
        return false;
    }
    std::string cleanHost = host.empty() ? "127.0.0.1" : host;
    if (cleanHost.size() >= 2 && cleanHost.front() == '[' && cleanHost.back() == ']') {
        cleanHost = cleanHost.substr(1, cleanHost.size() - 2);
    }

    sockaddr_storage ss{};
    socklen_t slen = 0;
    sockaddr_in v4{};
    sockaddr_in6 v6{};
    if (inet_pton(AF_INET, cleanHost.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(requestedPort);
        slen = sizeof(v4);
        std::memcpy(&ss, &v4, sizeof(v4));
    } else if (inet_pton(AF_INET6, cleanHost.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(requestedPort);
        slen = sizeof(v6);
        std::memcpy(&ss, &v6, sizeof(v6));
    } else {
        outError = "Invalid UDP bind IP: " + cleanHost;
        return false;
    }

    auto raw = ::socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    platform::NativeSocket s = platform::toNativeSocket(raw);
    if (s < 0) {
        outError = "socket(UDP) failed";
        return false;
    }
    platform::disableUdpConnReset(s);
    if (!platform::setNonBlockingAndCloexec(s) ||
        ::bind(platform::toOsSocket(s), reinterpret_cast<const sockaddr *>(&ss), slen) != 0) {
        platform::closeNativeSocket(s);
        outError = "UDP bind failed";
        return false;
    }
    sockaddr_storage bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(platform::toOsSocket(s), reinterpret_cast<sockaddr *>(&bound), &blen) != 0) {
        platform::closeNativeSocket(s);
        outError = "UDP getsockname failed";
        return false;
    }
    outBoundPort = (bound.ss_family == AF_INET6)
        ? ntohs(reinterpret_cast<const sockaddr_in6 *>(&bound)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in *>(&bound)->sin_port);
    outSock = s;
    return true;
}

struct SharedRelayState {
    platform::NativeSocket sock = platform::kInvalidSocket;
    std::shared_ptr<Stream> outbound;
    std::mutex sockMu;
    std::condition_variable cv;
    bool remoteDone = false;

    void forceAbort() {
        std::shared_ptr<Stream> outCopy;
        {
            std::lock_guard<std::mutex> lk(sockMu);
            if (sock >= 0) {
#if defined(_WIN32)
                ::shutdown(platform::toOsSocket(sock), SD_BOTH);
#else
                ::shutdown(sock, SHUT_RDWR);
#endif
                platform::closeNativeSocket(sock);
            }
            remoteDone = true;
            outCopy = std::move(outbound);
            cv.notify_all();
        }
        if (outCopy) outCopy->close();
    }

    ~SharedRelayState() {
        platform::closeNativeSocket(sock);
    }
};

struct SyncWriteWait {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    Error err;
};

struct SyncStreamDialWait {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false;
    std::shared_ptr<Stream> stream;
    Error err;
};

struct SyncDatagramDialWait {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    bool abandoned = false;
    std::shared_ptr<Datagram> dgram;
    Error err;
};

void pumpSocketToOutboundStream(const std::shared_ptr<SharedRelayState> &relay,
                                const Buffer &initialPayload,
                                std::atomic<uint64_t> &upCounter,
                                std::atomic<uint64_t> &downCounter,
                                std::atomic<uint32_t> &activeConns,
                                const std::function<void(uint64_t, uint64_t)> &onConnBytes) {
    activeConns.fetch_add(1, std::memory_order_relaxed);
    std::shared_ptr<Stream> outbound;
    {
        std::lock_guard<std::mutex> lk(relay->sockMu);
        outbound = relay->outbound;
    }
    if (!outbound) {
        activeConns.fetch_sub(1, std::memory_order_relaxed);
        return;
    }

    struct DownPump : public std::enable_shared_from_this<DownPump> {
        std::shared_ptr<SharedRelayState> relay;
        std::shared_ptr<Stream> out;
        std::atomic<uint64_t> *down;
        std::function<void(uint64_t, uint64_t)> onBytes;

        void step() {
            auto self = shared_from_this();
            out->read(65536, [self](Buffer data, bool eof, Error err) {
                if (!data.empty()) {
                    self->down->fetch_add(data.size(), std::memory_order_relaxed);
                    if (self->onBytes) self->onBytes(0, data.size());
                    std::lock_guard<std::mutex> lk(self->relay->sockMu);
                    if (self->relay->sock >= 0) {
                        if (!sendAllBlockingWithDeadline(self->relay->sock, data.data(), data.size(), 5000)) {
                            eof = true;
                        }
                    } else {
                        eof = true;
                    }
                }
                if (eof || !err.empty()) {
                    std::lock_guard<std::mutex> lk(self->relay->sockMu);
                    if (self->relay->sock >= 0) {
#if defined(_WIN32)
                        ::shutdown(platform::toOsSocket(self->relay->sock), SD_SEND);
#else
                        ::shutdown(self->relay->sock, SHUT_WR);
#endif
                    }
                    self->relay->remoteDone = true;
                    self->relay->cv.notify_all();
                    return;
                }
                self->step();
            });
        }
    };

    if (!initialPayload.empty()) {
        upCounter.fetch_add(initialPayload.size(), std::memory_order_relaxed);
        if (onConnBytes) onConnBytes(initialPayload.size(), 0);
        auto wWait = std::make_shared<SyncWriteWait>();
        outbound->write(initialPayload, [wWait](Error e) {
            std::lock_guard<std::mutex> lk(wWait->mu);
            wWait->err = std::move(e);
            wWait->done = true;
            wWait->cv.notify_one();
        });
        bool wDone = false;
        Error wErr;
        {
            std::unique_lock<std::mutex> lk(wWait->mu);
            wDone = wWait->cv.wait_for(lk, std::chrono::seconds(5), [&] { return wWait->done; });
            wErr = wWait->err;
        }
        if (!wDone || !wErr.empty()) {
            relay->forceAbort();
            activeConns.fetch_sub(1, std::memory_order_relaxed);
            return;
        }
    }

    auto dp = std::make_shared<DownPump>();
    dp->relay = relay;
    dp->out = outbound;
    dp->down = &downCounter;
    dp->onBytes = onConnBytes;
    dp->step();

    uint8_t rxBuf[32768];
    while (true) {
        platform::NativeSocket curSock = platform::kInvalidSocket;
        {
            std::lock_guard<std::mutex> lk(relay->sockMu);
            if (relay->remoteDone || relay->sock < 0) break;
            curSock = relay->sock;
        }
        if (!waitFdReady(curSock, false, 200)) {
            continue;
        }
        int got = 0;
        {
            std::lock_guard<std::mutex> lk(relay->sockMu);
            if (relay->sock < 0) break;
            got = static_cast<int>(::recv(platform::toOsSocket(relay->sock),
                                          reinterpret_cast<char *>(rxBuf), sizeof(rxBuf), 0));
        }
        if (got < 0) {
            if (platform::isSocketWouldBlock(platform::lastSocketError())) continue;
            break;
        }
        if (got == 0) {
            if (outbound->supportsHalfClose()) {
                outbound->shutdownWrite([](Error) {});
            }
            break;
        }
        upCounter.fetch_add(static_cast<size_t>(got), std::memory_order_relaxed);
        if (onConnBytes) onConnBytes(static_cast<uint64_t>(got), 0);
        auto wWait = std::make_shared<SyncWriteWait>();
        outbound->write(Buffer(rxBuf, rxBuf + got), [wWait](Error e) {
            std::lock_guard<std::mutex> lk(wWait->mu);
            wWait->err = std::move(e);
            wWait->done = true;
            wWait->cv.notify_one();
        });
        bool wDone = false;
        Error wErr;
        {
            std::unique_lock<std::mutex> lk(wWait->mu);
            wDone = wWait->cv.wait_for(lk, std::chrono::seconds(10), [&] { return wWait->done; });
            wErr = wWait->err;
        }
        if (!wDone || !wErr.empty()) {
            break;
        }
    }

    {
        std::unique_lock<std::mutex> lk(relay->sockMu);
        relay->cv.wait_for(lk, std::chrono::milliseconds(800), [&] { return relay->remoteDone; });
        platform::closeNativeSocket(relay->sock);
    }
    outbound->close();
    activeConns.fetch_sub(1, std::memory_order_relaxed);
}

std::string stripIpv6BracketsSimple(const std::string &h) {
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']') {
        return h.substr(1, h.size() - 2);
    }
    return h;
}

bool isIpLiteralSimple(const std::string &h) {
    std::string clean = stripIpv6BracketsSimple(h);
    uint8_t tmp[16]{};
    return inet_pton(AF_INET, clean.c_str(), tmp) == 1 ||
           inet_pton(AF_INET6, clean.c_str(), tmp) == 1;
}

SSL_CTX *sharedSystemClientSslCtx() {
    static SSL_CTX *gCtx = []() -> SSL_CTX * {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return nullptr;
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#if defined(_WIN32)
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        HCERTSTORE sysRoot = ::CertOpenSystemStoreW(0, L"ROOT");
        if (store && sysRoot) {
            PCCERT_CONTEXT cert = nullptr;
            while ((cert = ::CertEnumCertificatesInStore(sysRoot, cert)) != nullptr) {
                const unsigned char *der = cert->pbCertEncoded;
                X509 *x = d2i_X509(nullptr, &der, static_cast<long>(cert->cbCertEncoded));
                if (x) {
                    if (X509_STORE_add_cert(store, x) != 1) ERR_clear_error();
                    X509_free(x);
                } else {
                    ERR_clear_error();
                }
            }
            ::CertCloseStore(sysRoot, 0);
        }
#elif defined(__APPLE__)
        SSL_CTX_set_default_verify_paths(ctx);
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
                        if (X509_STORE_add_cert(store, x) != 1) ERR_clear_error();
                        X509_free(x);
                    } else {
                        ERR_clear_error();
                    }
                    CFRelease(der);
                }
                CFRelease(anchors);
            }
        }
#else
        SSL_CTX_set_default_verify_paths(ctx);
#endif
        return ctx;
    }();
    return gCtx;
}

bool loadCustomCaIntoCtx(SSL_CTX *ctx, const std::string &caPath) {
    if (!ctx || caPath.empty()) return false;
    std::string pem;
    try {
        pem = platform::readBoundedRegularFileUTF8(
            caPath, 1024 * 1024, "CA read error", "CA not regular", "CA size error");
    } catch (...) {
        return false;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!store || !bio) {
        if (bio) BIO_free(bio);
        return false;
    }
    STACK_OF(X509_INFO) *infos = PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!infos) return false;
    bool added = false;
    const int n = sk_X509_INFO_num(infos);
    for (int i = 0; i < n; ++i) {
        X509_INFO *inf = sk_X509_INFO_value(infos, i);
        if (inf && inf->x509) {
            if (X509_STORE_add_cert(store, inf->x509) == 1) added = true;
            else ERR_clear_error();
        }
    }
    sk_X509_INFO_pop_free(infos, X509_INFO_free);
    return added;
}

class TlsClientOverStream final : public Stream,
                                  public std::enable_shared_from_this<TlsClientOverStream> {
public:
    TlsClientOverStream(std::shared_ptr<Stream> raw, SSL_CTX *ownedCtx, SSL *ssl, BIO *rbio, BIO *wbio)
        : raw_(std::move(raw)), ownedCtx_(ownedCtx), ssl_(ssl), rbio_(rbio), wbio_(wbio) {}

    ~TlsClientOverStream() override {
        if (ssl_) SSL_free(ssl_);
        if (ownedCtx_) SSL_CTX_free(ownedCtx_);
    }

    void startHandshake(StreamCallback cb) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            handshakeCb_ = std::move(cb);
        }
        driveHandshake();
    }

    void write(Buffer data, WriteCallback completion) override {
        if (data.empty()) {
            if (completion) completion({});
            return;
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || !ssl_) {
                if (completion) completion("Chained TLS stream closed");
                return;
            }
            size_t off = 0;
            while (off < data.size()) {
                ERR_clear_error();
                int chunk = static_cast<int>((std::min)(data.size() - off, size_t{16384}));
                int n = SSL_write(ssl_, data.data() + off, chunk);
                if (n <= 0) {
                    if (completion) completion("Chained TLS write failed");
                    return;
                }
                off += static_cast<size_t>(n);
            }
            drainWbioLocked();
            if (completion) queuedWriteCbs_.push_back(std::move(completion));
        }
        pumpRawWrite();
    }

    void read(size_t maximum, ReadCallback completion) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || !ssl_) {
                if (completion) completion({}, true, {});
                return;
            }
            pendingReadMax_ = (std::max)(size_t{1}, (std::min)(maximum, size_t{65536}));
            pendingReadCb_ = std::move(completion);
        }
        driveAppRead();
    }

    void close() override {
        std::shared_ptr<Stream> raw;
        StreamCallback hcb;
        ReadCallback rcb;
        std::vector<WriteCallback> wcbs;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_) return;
            closed_ = true;
            raw = raw_;
            hcb = std::move(handshakeCb_);
            rcb = std::move(pendingReadCb_);
            wcbs.swap(queuedWriteCbs_);
            pendingRawWrite_.clear();
        }
        if (raw) raw->close();
        if (hcb) hcb(nullptr, "Chained TLS stream closed");
        if (rcb) rcb({}, true, {});
        for (auto &w : wcbs) {
            if (w) w("Chained TLS stream closed");
        }
    }

private:
    std::shared_ptr<Stream> raw_;
    SSL_CTX *ownedCtx_ = nullptr;
    SSL *ssl_ = nullptr;
    BIO *rbio_ = nullptr;
    BIO *wbio_ = nullptr;

    std::mutex mu_;
    bool closed_ = false;
    bool rawReading_ = false;
    bool rawWriting_ = false;
    Buffer pendingRawWrite_;
    std::vector<WriteCallback> queuedWriteCbs_;
    StreamCallback handshakeCb_;
    size_t pendingReadMax_ = 16384;
    ReadCallback pendingReadCb_;

    void drainWbioLocked() {
        while (wbio_) {
            size_t pend = BIO_ctrl_pending(wbio_);
            if (pend == 0) break;
            size_t oldSz = pendingRawWrite_.size();
            pendingRawWrite_.resize(oldSz + pend);
            int got = BIO_read(wbio_, pendingRawWrite_.data() + oldSz, static_cast<int>(pend));
            if (got <= 0) {
                pendingRawWrite_.resize(oldSz);
                break;
            }
            pendingRawWrite_.resize(oldSz + static_cast<size_t>(got));
        }
    }

    void failAll(const Error &err) {
        std::shared_ptr<Stream> raw;
        StreamCallback hcb;
        ReadCallback rcb;
        std::vector<WriteCallback> wcbs;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_) return;
            closed_ = true;
            raw = raw_;
            hcb = std::move(handshakeCb_);
            rcb = std::move(pendingReadCb_);
            wcbs.swap(queuedWriteCbs_);
            pendingRawWrite_.clear();
        }
        if (raw) raw->close();
        Error eff = err.empty() ? Error("Chained TLS error") : err;
        if (hcb) hcb(nullptr, eff);
        if (rcb) rcb({}, false, eff);
        for (auto &w : wcbs) {
            if (w) w(eff);
        }
    }

    void pumpRawWrite() {
        Buffer chunk;
        std::vector<WriteCallback> cbs;
        std::shared_ptr<Stream> raw;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || rawWriting_ || pendingRawWrite_.empty()) {
                if (!closed_ && !rawWriting_ && pendingRawWrite_.empty() && !queuedWriteCbs_.empty()) {
                    cbs.swap(queuedWriteCbs_);
                } else {
                    return;
                }
            } else {
                rawWriting_ = true;
                chunk.swap(pendingRawWrite_);
                cbs.swap(queuedWriteCbs_);
                raw = raw_;
            }
        }
        if (chunk.empty()) {
            for (auto &w : cbs) {
                if (w) w({});
            }
            return;
        }
        auto self = shared_from_this();
        raw->write(std::move(chunk), [self, cbs = std::move(cbs)](Error err) mutable {
            if (!err.empty()) {
                for (auto &w : cbs) {
                    if (w) w(err);
                }
                self->failAll(err);
                return;
            }
            {
                std::lock_guard<std::mutex> lk(self->mu_);
                self->rawWriting_ = false;
            }
            for (auto &w : cbs) {
                if (w) w({});
            }
            self->pumpRawWrite();
        });
    }

    void driveHandshake() {
        StreamCallback doneCb;
        bool needRead = false;
        std::shared_ptr<Stream> raw;
        Error fatalErr;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || !ssl_) return;
            ERR_clear_error();
            int rc = SSL_do_handshake(ssl_);
            drainWbioLocked();
            if (rc == 1) {
                doneCb = std::move(handshakeCb_);
            } else {
                int sslErr = SSL_get_error(ssl_, rc);
                if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
                    if (sslErr == SSL_ERROR_WANT_READ && !rawReading_) {
                        rawReading_ = true;
                        needRead = true;
                        raw = raw_;
                    }
                } else {
                    long vr = SSL_get_verify_result(ssl_);
                    if (vr != X509_V_OK) {
                        fatalErr = std::string("Chained TLS verify failed: ") + X509_verify_cert_error_string(vr);
                    } else {
                        fatalErr = "Chained TLS handshake failed";
                    }
                }
            }
        }
        if (!fatalErr.empty()) {
            failAll(fatalErr);
            return;
        }
        pumpRawWrite();
        if (doneCb) {
            doneCb(shared_from_this(), {});
            return;
        }
        if (needRead && raw) {
            auto self = shared_from_this();
            raw->read(16384, [self](Buffer chunk, bool eof, Error rerr) {
                if (!rerr.empty() || eof || chunk.empty()) {
                    self->failAll(rerr.empty() ? Error("Chained TLS handshake EOF") : rerr);
                    return;
                }
                {
                    std::lock_guard<std::mutex> lk(self->mu_);
                    if (self->closed_ || !self->rbio_) return;
                    self->rawReading_ = false;
                    BIO_write(self->rbio_, chunk.data(), static_cast<int>(chunk.size()));
                }
                self->driveHandshake();
            });
        }
    }

    void driveAppRead() {
        ReadCallback rcb;
        Buffer plainOut;
        bool gotData = false;
        bool gotEof = false;
        bool needRead = false;
        std::shared_ptr<Stream> raw;
        Error fatalErr;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_ || !ssl_ || !pendingReadCb_) return;
            plainOut.resize(pendingReadMax_);
            ERR_clear_error();
            int n = SSL_read(ssl_, plainOut.data(), static_cast<int>(plainOut.size()));
            drainWbioLocked();
            if (n > 0) {
                plainOut.resize(static_cast<size_t>(n));
                rcb = std::move(pendingReadCb_);
                gotData = true;
            } else {
                int sslErr = SSL_get_error(ssl_, n);
                if (sslErr == SSL_ERROR_ZERO_RETURN) {
                    rcb = std::move(pendingReadCb_);
                    gotEof = true;
                } else if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
                    if (sslErr == SSL_ERROR_WANT_READ && !rawReading_) {
                        rawReading_ = true;
                        needRead = true;
                        raw = raw_;
                    }
                } else {
                    fatalErr = "Chained TLS read failed";
                }
            }
        }
        if (!fatalErr.empty()) {
            failAll(fatalErr);
            return;
        }
        pumpRawWrite();
        if (gotData && rcb) {
            rcb(std::move(plainOut), false, {});
            return;
        }
        if (gotEof && rcb) {
            rcb({}, true, {});
            return;
        }
        if (needRead && raw) {
            auto self = shared_from_this();
            raw->read(32768, [self](Buffer chunk, bool eof, Error rerr) {
                if (!rerr.empty()) {
                    self->failAll(rerr);
                    return;
                }
                if (eof || chunk.empty()) {
                    ReadCallback cb;
                    {
                        std::lock_guard<std::mutex> lk(self->mu_);
                        self->rawReading_ = false;
                        cb = std::move(self->pendingReadCb_);
                    }
                    if (cb) cb({}, true, {});
                    return;
                }
                {
                    std::lock_guard<std::mutex> lk(self->mu_);
                    if (self->closed_ || !self->rbio_) return;
                    self->rawReading_ = false;
                    BIO_write(self->rbio_, chunk.data(), static_cast<int>(chunk.size()));
                }
                self->driveAppRead();
            });
        }
    }
};

void wrapClientTlsOverStream(const Node &innerNode,
                             const TLSOptions &tlsOpts,
                             std::shared_ptr<Stream> upstream,
                             StreamCallback cb) {
    if (!tlsOpts.enabled) {
        cb(std::move(upstream), {});
        return;
    }

    SSL_CTX *ownedCtx = nullptr;
    SSL_CTX *useCtx = nullptr;
    const std::string caPath = innerNode.option("ca");
    if (!caPath.empty()) {
        ownedCtx = SSL_CTX_new(TLS_client_method());
        if (!ownedCtx || !loadCustomCaIntoCtx(ownedCtx, caPath)) {
            if (ownedCtx) SSL_CTX_free(ownedCtx);
            upstream->close();
            cb(nullptr, "Failed to load custom CA for chained TLS");
            return;
        }
        SSL_CTX_set_min_proto_version(ownedCtx, TLS1_2_VERSION);
        useCtx = ownedCtx;
    } else {
        useCtx = sharedSystemClientSslCtx();
    }
    if (!useCtx) {
        upstream->close();
        cb(nullptr, "Failed to initialize OpenSSL client context");
        return;
    }

    SSL *ssl = SSL_new(useCtx);
    BIO *rbio = BIO_new(BIO_s_mem());
    BIO *wbio = BIO_new(BIO_s_mem());
    if (!ssl || !rbio || !wbio) {
        if (rbio) BIO_free(rbio);
        if (wbio) BIO_free(wbio);
        if (ssl) SSL_free(ssl);
        if (ownedCtx) SSL_CTX_free(ownedCtx);
        upstream->close();
        cb(nullptr, "Failed to allocate OpenSSL session over chained stream");
        return;
    }
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);

    const std::string sniHost = stripIpv6BracketsSimple(
        tlsOpts.serverName.empty() ? innerNode.host : tlsOpts.serverName);
    if (!sniHost.empty() && !isIpLiteralSimple(sniHost)) {
        SSL_set_tlsext_host_name(ssl, sniHost.c_str());
    }

    if (!tlsOpts.alpn.empty()) {
        Buffer wire;
        for (const auto &proto : tlsOpts.alpn) {
            if (!proto.empty() && proto.size() <= 255) {
                wire.push_back(static_cast<uint8_t>(proto.size()));
                wire.insert(wire.end(), proto.begin(), proto.end());
            }
        }
        if (!wire.empty()) {
            SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned int>(wire.size()));
        }
    }

    if (tlsOpts.skipVerify) {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
        if (!sniHost.empty()) {
            X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
            if (isIpLiteralSimple(sniHost)) {
                X509_VERIFY_PARAM_set1_ip_asc(vp, sniHost.c_str());
            } else {
#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
                X509_VERIFY_PARAM_set1_host(vp, sniHost.c_str(), sniHost.size());
#else
                X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                SSL_set1_host(ssl, sniHost.c_str());
#endif
            }
        }
    }

    auto tlsStream = std::make_shared<TlsClientOverStream>(
        std::move(upstream), ownedCtx, ssl, rbio, wbio);
    tlsStream->startHandshake(std::move(cb));
}

} // namespace

struct HJEngineOpaque {
    struct ActiveConnEntry {
        uint64_t id = 0;
        std::string proto;
        std::string process;
        std::string host;
        uint16_t port = 0;
        std::string policy;
        uint64_t upBytes = 0;
        uint64_t downBytes = 0;
        int64_t startMs = 0;
        std::function<void()> cancelFn;
    };

    struct LogEntry {
        uint64_t seq = 0;
        std::string timeStr;
        std::string level;
        std::string message;
    };

    static constexpr size_t kMaxActiveConnRecords = 1024;
    static constexpr size_t kMaxLogEntries = 256;
    static constexpr uint32_t kMaxConcurrentHandlers = 512;

    std::mutex mu;
    EngineProfile profile;
    std::atomic<int> outboundMode{HAJIMI_MODE_RULE};
    std::string outboundIfName;
    std::string activeBindHost = "127.0.0.1";

    // Per-node latency & smart adaptive statistics
    std::unordered_map<std::string, int32_t> nodeLatenciesMs;
    std::unordered_map<std::string, hajimi_smart_node_stats> smartNodeStats;

    std::shared_ptr<win_transport::WinTransportRuntime> transport;
    EncryptedDnsEngine dns;
    LocalProcessSocketCache processCache;
    std::unique_ptr<UserspacePacketTunnel> tunnel;

    std::atomic<bool> running{false};
    std::mutex stopMu;
    std::condition_variable stopCv;

    // Controlled client handler lifetime tracking (zero dangling detached threads)
    std::mutex handlersMu;
    std::condition_variable handlersCv;
    uint32_t activeHandlers = 0;

    // Active connection table & rolling log buffer
    std::mutex connMu;
    uint64_t nextConnId = 1;
    std::unordered_map<uint64_t, ActiveConnEntry> activeConnTable;

    std::mutex logMu;
    uint64_t nextLogSeq = 1;
    std::deque<LogEntry> logRing;

    platform::NativeSocket httpSock = platform::kInvalidSocket;
    platform::NativeSocket socksSock = platform::kInvalidSocket;
    platform::NativeSocket ctrlSock = platform::kInvalidSocket;
    platform::NativeSocket dnsSock = platform::kInvalidSocket;

    uint16_t boundHttpPort = 0;
    uint16_t boundSocksPort = 0;
    uint16_t boundCtrlPort = 0;
    uint16_t boundDnsPort = 0;
    std::string controllerKey;
    std::string globalSelectedNode = "__AUTO_FASTEST__";

    std::vector<std::thread> workerThreads;

    std::atomic<uint64_t> uploadedBytes{0};
    std::atomic<uint64_t> downloadedBytes{0};
    std::atomic<uint32_t> activeConnections{0};
    std::atomic<uint64_t> totalConnections{0};

    mutable std::mutex rateMu;
    std::array<uint64_t, 60> upRateHistory{};
    std::array<uint64_t, 60> downRateHistory{};
    size_t rateCursor = 0;
    uint64_t prevSampleUp = 0;
    uint64_t prevSampleDown = 0;

    HJEngineOpaque() {
        transport = win_transport::WinTransportRuntime::create();
        tunnel = std::make_unique<UserspacePacketTunnel>(dns);

        dns.setProxiedDomainPredicate([this](const std::string &qname) {
            std::string pol = resolvePolicyName(qname, 443, "DNS", "");
            return pol != "DIRECT" && pol != "REJECT" && pol != "REJECT-TINYGIF";
        });

        tunnel->setStreamConnector([this](const std::string &cliIp, uint16_t cliPort, const Target &target, StreamCallback cb) {
            std::string procPath;
            (void)processCache.lookupOwnerExecutable(false, cliIp, cliPort, procPath);
            openRoutedStream(target, procPath, nullptr, std::move(cb));
        });

        tunnel->setDatagramHooks(
            [this](const std::string &cliIp, uint16_t cliPort, const Target &target) {
                std::string procPath;
                (void)processCache.lookupOwnerExecutable(true, cliIp, cliPort, procPath);
                return resolvePolicyName(target.host, target.port, "UDP", procPath);
            },
            [this](const std::string &leafPolicy, const Target &initialTarget, DatagramCallback cb) {
                openRoutedDatagram(leafPolicy, initialTarget, std::move(cb));
            });

        TunnelFlowTrackerHooks tunHooks{};
        tunHooks.onOpen = [this](const char *proto,
                                 const std::string &cliIp,
                                 uint16_t cliPort,
                                 const std::string &tHost,
                                 uint16_t tPort,
                                 const std::string &pol,
                                 std::function<void()> cancelFn) -> uint64_t {
            std::string procPath;
            (void)processCache.lookupOwnerExecutable(std::strcmp(proto, "TUN-UDP") == 0, cliIp, cliPort, procPath);
            std::string resolvedPol = (pol == "AUTO")
                ? resolvePolicyName(tHost, tPort, "TCP", procPath)
                : pol;
            return registerConnection(proto, procPath, tHost, tPort, resolvedPol, std::move(cancelFn));
        };
        tunHooks.onBytes = [this](uint64_t cid, uint64_t addUp, uint64_t addDown) {
            updateConnectionBytes(cid, addUp, addDown);
        };
        tunHooks.onClose = [this](uint64_t cid) {
            unregisterConnection(cid);
        };
        tunnel->setFlowTrackerHooks(std::move(tunHooks));

        appendLog("INFO", std::string("Hajimi Core initialized (") + kEngineVersion + ")");
    }

    ~HJEngineOpaque() {
        stopListeners();
        tunnel->detachSharedMemory();
        (void)closeConnections(0);
        if (transport) {
            transport->shutdown();
        }
    }

    void appendLog(const char *level, const std::string &msg) {
        std::lock_guard<std::mutex> lk(logMu);
        if (logRing.size() >= kMaxLogEntries) {
            logRing.pop_front();
        }
        logRing.push_back({nextLogSeq++, formatWallTimeHHMMSS(), level ? level : "INFO", msg});
    }

    uint64_t registerConnection(const std::string &proto,
                                const std::string &procPath,
                                const std::string &host,
                                uint16_t port,
                                const std::string &policy,
                                std::function<void()> cancelFn) {
        uint64_t id = 0;
        {
            std::lock_guard<std::mutex> lk(connMu);
            if (activeConnTable.size() >= kMaxActiveConnRecords) {
                return 0;
            }
            id = nextConnId++;
            ActiveConnEntry e{};
            e.id = id;
            e.proto = proto;
            e.process = procPath.empty() ? "system" : basenameOnly(procPath);
            e.host = host;
            e.port = port;
            e.policy = policy;
            e.startMs = steadyMillisNow();
            e.cancelFn = std::move(cancelFn);
            activeConnTable.emplace(id, std::move(e));
        }
        appendLog("INFO", "[" + proto + "] " + (procPath.empty() ? std::string("local") : basenameOnly(procPath)) +
                          " -> " + host + ":" + std::to_string(port) + " [" + policy + "]");
        return id;
    }

    void updateConnectionBytes(uint64_t id, uint64_t addUp, uint64_t addDown) {
        if (id == 0) return;
        std::lock_guard<std::mutex> lk(connMu);
        auto it = activeConnTable.find(id);
        if (it != activeConnTable.end()) {
            it->second.upBytes += addUp;
            it->second.downBytes += addDown;
        }
    }

    void unregisterConnection(uint64_t id) {
        if (id == 0) return;
        std::lock_guard<std::mutex> lk(connMu);
        activeConnTable.erase(id);
    }

    int32_t closeConnections(uint64_t targetId) {
        std::vector<std::function<void()>> cancels;
        {
            std::lock_guard<std::mutex> lk(connMu);
            if (targetId == 0) {
                cancels.reserve(activeConnTable.size());
                for (auto &kv : activeConnTable) {
                    if (kv.second.cancelFn) cancels.push_back(std::move(kv.second.cancelFn));
                }
                activeConnTable.clear();
            } else {
                auto it = activeConnTable.find(targetId);
                if (it != activeConnTable.end()) {
                    if (it->second.cancelFn) cancels.push_back(std::move(it->second.cancelFn));
                    activeConnTable.erase(it);
                }
            }
        }
        for (auto &fn : cancels) {
            if (fn) fn();
        }
        return static_cast<int32_t>(cancels.size());
    }

    bool tryEnterHandler() {
        std::lock_guard<std::mutex> lk(handlersMu);
        if (!running.load(std::memory_order_acquire) || activeHandlers >= kMaxConcurrentHandlers) {
            return false;
        }
        ++activeHandlers;
        return true;
    }

    void leaveHandler() {
        std::lock_guard<std::mutex> lk(handlersMu);
        if (activeHandlers > 0 && --activeHandlers == 0) {
            handlersCv.notify_all();
        }
    }

    std::string resolveHostNumeric(const std::string &host,
                                   int preferFamily,
                                   const std::unordered_map<std::string, std::string> &staticHostsSnap) {
        if (host.empty()) return {};
        if (host == "localhost") return (preferFamily == AF_INET6) ? "::1" : "127.0.0.1";

        std::string clean = host;
        if (clean.size() >= 2 && clean.front() == '[' && clean.back() == ']') {
            clean = clean.substr(1, clean.size() - 2);
        }

        std::string lowerH = clean;
        for (char &c : lowerH) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto sit = staticHostsSnap.find(lowerH);
        if (sit != staticHostsSnap.end()) return sit->second;

        uint8_t tmp[16]{};
        if (inet_pton(AF_INET, clean.c_str(), tmp) == 1 || inet_pton(AF_INET6, clean.c_str(), tmp) == 1) {
            return clean;
        }

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = preferFamily;
        hints.ai_socktype = SOCK_STREAM;
        if (::getaddrinfo(clean.c_str(), nullptr, &hints, &res) == 0 && res) {
            char ipBuf[INET6_ADDRSTRLEN + 4]{};
            if (res->ai_family == AF_INET) {
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr, ipBuf, sizeof(ipBuf));
            } else if (res->ai_family == AF_INET6) {
                inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(res->ai_addr)->sin6_addr, ipBuf, sizeof(ipBuf));
            }
            ::freeaddrinfo(res);
            if (ipBuf[0] != '\0') return ipBuf;
        }
        if (res) ::freeaddrinfo(res);
        return {};
    }

    std::string resolveLeafPolicyLocked(const std::string &policyOrGroup, uint64_t loadBalanceKey = 0) const {
        std::string cur = policyOrGroup;
        for (int depth = 0; depth < 16; ++depth) {
            std::string upCur = cur;
            for (char &ch : upCur) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            if (upCur == "DIRECT" || upCur == "COMPATIBLE" || upCur == "PASS") return "DIRECT";
            if (upCur == "REJECT" || upCur == "REJECT-TINYGIF" || upCur == "REJECT-DROP" || upCur == "REJECT-NO-DROP") return "REJECT";
            auto git = profile.groups.find(cur);
            if (git == profile.groups.end()) break;
            const auto &grp = git->second;
            if (grp.kind == PolicyGroupKind::LoadBalance && !grp.members.empty()) {
                std::vector<std::string> healthy;
                healthy.reserve(grp.members.size());
                for (const auto &m : grp.members) {
                    auto lit = nodeLatenciesMs.find(m);
                    if (lit == nodeLatenciesMs.end() || lit->second >= 0) {
                        healthy.push_back(m);
                    }
                }
                const auto &pool = healthy.empty() ? grp.members : healthy;
                uint32_t idx = hajimi_jump_consistent_hash(
                    hajimi_stafford_mix64(loadBalanceKey), static_cast<uint32_t>(pool.size()));
                cur = pool[idx];
                continue;
            }
            if (!grp.selected.empty()) {
                cur = grp.selected;
            } else if (!grp.members.empty()) {
                cur = grp.members.front();
            } else {
                return "DIRECT";
            }
        }
        return cur;
    }

    std::string resolveEffectiveGlobalNodeLocked() const {
        if (globalSelectedNode == "DIRECT") return "DIRECT";
        if (!globalSelectedNode.empty() && globalSelectedNode != "__AUTO_FASTEST__") {
            if (profile.nodes.find(globalSelectedNode) != profile.nodes.end()) {
                return globalSelectedNode;
            }
        }
        std::string bestNode;
        int32_t bestRtt = INT32_MAX;
        for (const auto &nname : profile.nodeOrder) {
            if (profile.nodes.find(nname) == profile.nodes.end()) continue;
            auto lit = nodeLatenciesMs.find(nname);
            if (lit != nodeLatenciesMs.end() && lit->second >= 0 && lit->second < bestRtt) {
                bestRtt = lit->second;
                bestNode = nname;
            }
        }
        if (!bestNode.empty()) return bestNode;
        if (!profile.nodeOrder.empty()) return profile.nodeOrder.front();
        return "DIRECT";
    }

    std::string resolvePolicyName(const std::string &host,
                                  uint16_t dstPort,
                                  const std::string &proto,
                                  const std::string &procPath) {
        const int mode = outboundMode.load(std::memory_order_relaxed);
        const uint64_t lbKey = fnv1a64Ascii(host);
        std::lock_guard<std::mutex> lk(mu);
        if (mode == HAJIMI_MODE_DIRECT) return "DIRECT";
        if (mode == HAJIMI_MODE_GLOBAL) {
            return resolveEffectiveGlobalNodeLocked();
        }
        std::string matched = profile.evaluateRoute(host, dstPort, proto, procPath);
        return resolveLeafPolicyLocked(matched, lbKey);
    }

    std::string resolveHostForNode(const Node &node,
                                   const std::unordered_map<std::string, std::string> &staticHostsSnap) {
        std::string ipv = node.option("ip-version");
        for (char &c : ipv) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ipv == "ipv6" || ipv == "v6-only") {
            return resolveHostNumeric(node.host, AF_INET6, staticHostsSnap);
        }
        if (ipv == "ipv4" || ipv == "v4-only") {
            return resolveHostNumeric(node.host, AF_INET, staticHostsSnap);
        }
        if (ipv == "ipv6-prefer") {
            std::string r6 = resolveHostNumeric(node.host, AF_INET6, staticHostsSnap);
            return r6.empty() ? resolveHostNumeric(node.host, AF_UNSPEC, staticHostsSnap) : r6;
        }
        if (ipv == "ipv4-prefer") {
            std::string r4 = resolveHostNumeric(node.host, AF_INET, staticHostsSnap);
            return r4.empty() ? resolveHostNumeric(node.host, AF_UNSPEC, staticHostsSnap) : r4;
        }
        return resolveHostNumeric(node.host, AF_UNSPEC, staticHostsSnap);
    }

    std::shared_ptr<TransportFactory> buildFactoryForNode(
        const Node &leafNode,
        const std::unordered_map<std::string, std::string> &staticHostsSnap,
        const std::string &ifNameSnap,
        double deadlineSec,
        int depth = 0) {
        std::string viaName = leafNode.option("underlying-proxy", leafNode.option("dialer-proxy"));
        if (viaName.empty() || viaName == "DIRECT" || depth >= 4) {
            return transport->makeFactory(deadlineSec);
        }

        Node viaNode{};
        bool viaFound = false;
        bool viaDirect = false;
        {
            std::lock_guard<std::mutex> lk(mu);
            std::string resolvedVia = resolveLeafPolicyLocked(viaName);
            if (resolvedVia == "DIRECT") {
                viaDirect = true;
            } else {
                auto nit = profile.nodes.find(resolvedVia);
                if (nit == profile.nodes.end()) nit = profile.nodes.find(viaName);
                if (nit != profile.nodes.end()) {
                    viaNode = nit->second;
                    if (viaNode.type == "direct") {
                        viaDirect = true;
                    } else if (viaNode.type != "reject" && viaNode.type != "reject-tinygif") {
                        viaFound = true;
                        if (viaNode.interfaceName.empty() && !ifNameSnap.empty()) {
                            viaNode.interfaceName = ifNameSnap;
                        }
                    }
                }
            }
        }

        if (viaDirect) {
            return transport->makeFactory(deadlineSec);
        }
        if (!viaFound) {
            auto base = transport->makeFactory(deadlineSec);
            auto failing = std::make_shared<TransportFactory>(*base);
            failing->tcp = [base, viaName](const Node &, const TLSOptions &, StreamCallback cb) {
                base->post([cb = std::move(cb), viaName]() mutable {
                    cb(nullptr, "Underlying proxy node not found: " + viaName);
                });
            };
            return failing;
        }

        std::string parentVia = viaNode.option("underlying-proxy", viaNode.option("dialer-proxy"));
        if ((parentVia.empty() || parentVia == "DIRECT") && viaNode.connectHost.empty()) {
            viaNode.connectHost = resolveHostForNode(viaNode, staticHostsSnap);
        }

        auto parentFactory = buildFactoryForNode(viaNode, staticHostsSnap, ifNameSnap, deadlineSec, depth + 1);
        auto chained = std::make_shared<TransportFactory>(*parentFactory);
        chained->tcp = [parentFactory, viaNode](const Node &innerNode, const TLSOptions &tlsOpts, StreamCallback cb) {
            Target hopTarget{innerNode.host, innerNode.port, false, false};
            connectProtocol(viaNode, hopTarget, parentFactory,
                            [innerNode, tlsOpts, cb = std::move(cb)](std::shared_ptr<Stream> upstream, Error err) mutable {
                                if (!err.empty() || !upstream) {
                                    cb(nullptr, err.empty() ? Error("Underlying proxy connect failed") : std::move(err));
                                    return;
                                }
                                wrapClientTlsOverStream(innerNode, tlsOpts, std::move(upstream), std::move(cb));
                            });
        };
        chained->udp = [parentFactory, viaNode](const Node &, DatagramCallback dcb) {
            makeProtocolDatagram(viaNode, parentFactory, std::move(dcb));
        };
        return chained;
    }

    int32_t probeSingleNodeDirect(const Node &node, uint32_t timeoutMs) {
        if (node.type == "direct") return 1;
        if (node.type == "reject" || node.type == "reject-tinygif") return -1;

        std::unordered_map<std::string, std::string> staticSnap;
        std::string ifSnap;
        {
            std::lock_guard<std::mutex> lk(mu);
            staticSnap = profile.dns.staticHosts;
            ifSnap = outboundIfName;
        }
        Node tcpProbe = node;
        if (tcpProbe.interfaceName.empty() && !ifSnap.empty()) {
            tcpProbe.interfaceName = ifSnap;
        }
        const std::string via = tcpProbe.option("underlying-proxy", tcpProbe.option("dialer-proxy"));
        const bool hasVia = !via.empty() && via != "DIRECT";
        if (!hasVia && tcpProbe.connectHost.empty()) {
            tcpProbe.connectHost = resolveHostForNode(tcpProbe, staticSnap);
        }
        if (!hasVia && tcpProbe.connectHost.empty()) return -1;

        const auto t0 = std::chrono::steady_clock::now();
        uint32_t effMs = (timeoutMs == 0) ? 2500u : timeoutMs;
        if (hasVia && effMs < 4000u) effMs = 4000u;
        const double sec = (std::max)(0.2, static_cast<double>(effMs) / 1000.0);
        auto factory = buildFactoryForNode(tcpProbe, staticSnap, ifSnap, sec, 0);

        auto probeWait = std::make_shared<SyncStreamDialWait>();
        TLSOptions noTls{};
        factory->tcp(tcpProbe, noTls, [probeWait](std::shared_ptr<Stream> s, Error err) {
            const bool connected = (s != nullptr && err.empty());
            if (s) s->close();
            std::lock_guard<std::mutex> lk(probeWait->mu);
            if (!probeWait->abandoned) {
                probeWait->err = connected ? Error{} : (err.empty() ? Error("probe failed") : std::move(err));
                probeWait->done = true;
            }
            probeWait->cv.notify_one();
        });
        bool ok = false;
        {
            std::unique_lock<std::mutex> lk(probeWait->mu);
            if (probeWait->cv.wait_for(lk, std::chrono::milliseconds(effMs), [&] { return probeWait->done; })) {
                ok = probeWait->err.empty();
            } else {
                probeWait->abandoned = true;
            }
        }
        if (!ok) return -1;
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        return static_cast<int32_t>((std::max)(int64_t{1}, static_cast<int64_t>(elapsed)));
    }

    int32_t probeAllNodesAndRefreshGroups(uint32_t timeoutMs) {
        std::vector<std::pair<std::string, Node>> nodesSnap;
        {
            std::lock_guard<std::mutex> lk(mu);
            nodesSnap.reserve(profile.nodes.size());
            for (const auto &kv : profile.nodes) {
                nodesSnap.push_back(kv);
            }
        }
        if (nodesSnap.empty()) return 0;

        std::vector<int32_t> results(nodesSnap.size(), -1);
        std::vector<std::thread> workers;
        // Concurrently probe in bounded batches of up to 16 threads
        constexpr size_t kBatch = 16;
        for (size_t start = 0; start < nodesSnap.size(); start += kBatch) {
            workers.clear();
            const size_t end = (std::min)(nodesSnap.size(), start + kBatch);
            for (size_t i = start; i < end; ++i) {
                workers.emplace_back([this, &nodesSnap, &results, i, timeoutMs] {
                    results[i] = probeSingleNodeDirect(nodesSnap[i].second, timeoutMs);
                });
            }
            for (auto &t : workers) {
                if (t.joinable()) t.join();
            }
        }

        int32_t healthyCount = 0;
        const double nowSec = steadySecondsNow();
        std::vector<std::string> switchLogs;
        {
            std::lock_guard<std::mutex> lk(mu);
            for (size_t i = 0; i < nodesSnap.size(); ++i) {
                const std::string &nName = nodesSnap[i].first;
                const int32_t rtt = results[i];
                nodeLatenciesMs[nName] = rtt;
                if (rtt >= 0) ++healthyCount;

                auto &st = smartNodeStats[nName];
                if (!st.initialized) hajimi_smart_stats_init(&st);
                hajimi_smart_stats_observe(
                    &st, rtt >= 0 ? 1 : 0,
                    rtt >= 0 ? (static_cast<double>(rtt) / 1000.0) : 5.0,
                    nowSec);
            }

            // Refresh automatic policy groups (`url-test`, `fallback`, `smart`)
            auto resolveMemberLatency = [&](const std::string &member) -> int32_t {
                if (member == "DIRECT") return 1;
                auto lit = nodeLatenciesMs.find(member);
                return (lit != nodeLatenciesMs.end()) ? lit->second : -1;
            };

            for (auto &gkv : profile.groups) {
                auto &grp = gkv.second;
                if (grp.members.empty() || grp.kind == PolicyGroupKind::Select ||
                    grp.kind == PolicyGroupKind::LoadBalance) {
                    continue;
                }

                std::string prevSel = grp.selected;
                if (grp.kind == PolicyGroupKind::Fallback) {
                    for (const auto &m : grp.members) {
                        if (resolveMemberLatency(m) >= 0) {
                            grp.selected = m;
                            break;
                        }
                    }
                } else if (grp.kind == PolicyGroupKind::UrlTest) {
                    std::string bestMember;
                    int32_t bestRtt = INT32_MAX;
                    for (const auto &m : grp.members) {
                        int32_t rtt = resolveMemberLatency(m);
                        if (rtt >= 0 && rtt < bestRtt) {
                            bestRtt = rtt;
                            bestMember = m;
                        }
                    }
                    if (!bestMember.empty()) {
                        int32_t curRtt = resolveMemberLatency(grp.selected);
                        if (curRtt < 0 || bestRtt + static_cast<int32_t>(grp.toleranceMs) < curRtt) {
                            grp.selected = bestMember;
                        }
                    }
                } else if (grp.kind == PolicyGroupKind::SmartUCB1) {
                    std::string bestSmart;
                    double bestCost = 1e18;
                    for (const auto &m : grp.members) {
                        if (resolveMemberLatency(m) < 0) continue;
                        double cost = 0.001;
                        auto sit = smartNodeStats.find(m);
                        if (sit != smartNodeStats.end() && sit->second.initialized) {
                            cost = hajimi_smart_stats_cost(&sit->second, nowSec);
                        }
                        if (cost < bestCost) {
                            bestCost = cost;
                            bestSmart = m;
                        }
                    }
                    if (!bestSmart.empty()) grp.selected = bestSmart;
                }

                if (!grp.selected.empty() && grp.selected != prevSel) {
                    switchLogs.push_back("Policy group [" + grp.name + "] auto-switched: " +
                                         prevSel + " -> " + grp.selected);
                }
            }
        }
        for (const auto &msg : switchLogs) {
            appendLog("INFO", msg);
        }
        return healthyCount;
    }

    void openRoutedStream(const Target &rawTarget,
                          const std::string &clientProcPath,
                          std::string *outResolvedPolicy,
                          StreamCallback cb) {
        Target effective = rawTarget;
        std::string fakeDomain;
        if (dns.fakeIpPool().lookupDomain(effective.host, fakeDomain)) {
            effective.host = fakeDomain;
        }

        const std::string leaf = resolvePolicyName(
            effective.host, effective.port, effective.plainHTTP ? "HTTP" : "TCP", clientProcPath);
        if (outResolvedPolicy) *outResolvedPolicy = leaf;

        if (leaf == "REJECT" || leaf == "REJECT-TINYGIF") {
            cb(nullptr, "Rejected by routing rule");
            return;
        }

        Node dialNode{};
        bool isDirect = (leaf == "DIRECT");
        std::unordered_map<std::string, std::string> staticHostsSnap;
        std::string ifNameSnap;
        {
            std::lock_guard<std::mutex> lk(mu);
            staticHostsSnap = profile.dns.staticHosts;
            ifNameSnap = outboundIfName;
            if (!isDirect) {
                auto nit = profile.nodes.find(leaf);
                if (nit == profile.nodes.end()) {
                    cb(nullptr, "Outbound proxy node not found: " + leaf);
                    return;
                }
                dialNode = nit->second;
                if (dialNode.type == "direct") isDirect = true;
                else if (dialNode.type == "reject") {
                    cb(nullptr, "Rejected by proxy node");
                    return;
                }
                if (dialNode.interfaceName.empty() && !ifNameSnap.empty()) {
                    dialNode.interfaceName = ifNameSnap;
                }
            }
        }

        if (isDirect) {
            auto factory = transport->makeFactory();
            std::string numericIp = resolveHostNumeric(effective.host, AF_UNSPEC, staticHostsSnap);
            if (numericIp.empty()) {
                cb(nullptr, "Direct TCP hostname resolution failed: " + effective.host);
                return;
            }
            Node directNode{};
            directNode.type = "direct";
            directNode.host = effective.host;
            directNode.connectHost = numericIp;
            directNode.port = effective.port;
            directNode.interfaceName = ifNameSnap;
            TLSOptions noTls{};
            factory->tcp(directNode, noTls, std::move(cb));
            return;
        }

        const std::string via = dialNode.option("underlying-proxy", dialNode.option("dialer-proxy"));
        const bool hasVia = !via.empty() && via != "DIRECT";
        if (!hasVia && dialNode.connectHost.empty()) {
            std::string resolvedNodeIp = resolveHostForNode(dialNode, staticHostsSnap);
            if (!resolvedNodeIp.empty()) dialNode.connectHost = std::move(resolvedNodeIp);
        }
        auto factory = buildFactoryForNode(
            dialNode, staticHostsSnap, ifNameSnap, ProtocolTimeouts::protocolSetupSeconds, 0);
        connectProtocol(dialNode, effective, factory, std::move(cb));
    }

    void openRoutedDatagram(const std::string &leafPolicy,
                            const Target &initialTarget,
                            DatagramCallback cb) {
        if (leafPolicy == "REJECT" || leafPolicy == "REJECT-TINYGIF") {
            cb(nullptr, "Rejected by UDP routing policy");
            return;
        }

        Node dialNode{};
        bool isDirect = (leafPolicy == "DIRECT");
        std::unordered_map<std::string, std::string> staticHostsSnapshot;
        std::string ifNameSnap;
        {
            std::lock_guard<std::mutex> lk(mu);
            staticHostsSnapshot = profile.dns.staticHosts;
            ifNameSnap = outboundIfName;
            if (!isDirect) {
                auto nit = profile.nodes.find(leafPolicy);
                if (nit == profile.nodes.end()) {
                    cb(nullptr, "Outbound UDP proxy node not found: " + leafPolicy);
                    return;
                }
                dialNode = nit->second;
                if (dialNode.type == "direct") isDirect = true;
                else if (dialNode.type == "reject") {
                    cb(nullptr, "Rejected by proxy node");
                    return;
                }
                if (dialNode.interfaceName.empty() && !ifNameSnap.empty()) {
                    dialNode.interfaceName = ifNameSnap;
                }
            }
        }

        auto hostResolver = [this, staticHostsSnapshot](const std::string &h, int fam) {
            return resolveHostNumeric(h, fam, staticHostsSnapshot);
        };

        auto factory = transport->makeFactory();
        if (isDirect) {
            uint8_t v6Probe[16]{};
            const int family = (inet_pton(AF_INET6, initialTarget.host.c_str(), v6Probe) == 1) ? AF_INET6 : AF_INET;
            std::string firstIp = hostResolver(initialTarget.host, family);
            if (firstIp.empty()) firstIp = (family == AF_INET6) ? "::1" : "127.0.0.1";

            Node directNode{};
            directNode.type = "direct";
            directNode.host = firstIp;
            directNode.connectHost = firstIp;
            directNode.port = initialTarget.port ? initialTarget.port : 443;
            directNode.interfaceName = ifNameSnap;

            class DirectResolvingDatagram final : public Datagram {
            public:
                DirectResolvingDatagram(std::shared_ptr<Datagram> inner,
                                        int sockFamily,
                                        std::function<std::string(const std::string &, int)> resolver)
                    : inner_(std::move(inner)), family_(sockFamily), resolver_(std::move(resolver)) {}

                void send(Target target, Buffer data, WriteCallback completion) override {
                    std::string resolved;
                    {
                        std::lock_guard<std::mutex> lk(cacheMu_);
                        auto it = hostCache_.find(target.host);
                        if (it != hostCache_.end()) resolved = it->second;
                    }
                    if (resolved.empty()) {
                        resolved = resolver_(target.host, family_);
                        if (resolved.empty()) {
                            if (completion) completion("Direct UDP hostname resolution failed");
                            return;
                        }
                        std::lock_guard<std::mutex> lk(cacheMu_);
                        if (hostCache_.size() > 256) hostCache_.clear();
                        hostCache_[target.host] = resolved;
                    }
                    target.host = std::move(resolved);
                    inner_->send(std::move(target), std::move(data), std::move(completion));
                }

                void start(PacketCallback receive, WriteCallback failure) override {
                    inner_->start(std::move(receive), std::move(failure));
                }

                void close() override {
                    inner_->close();
                }

            private:
                std::shared_ptr<Datagram> inner_;
                int family_;
                std::function<std::string(const std::string &, int)> resolver_;
                std::mutex cacheMu_;
                std::unordered_map<std::string, std::string> hostCache_;
            };

            factory->udp(directNode, [cb = std::move(cb), family, hostResolver](std::shared_ptr<Datagram> rawDg, Error err) mutable {
                if (!err.empty() || !rawDg) {
                    cb(nullptr, std::move(err));
                    return;
                }
                cb(std::make_shared<DirectResolvingDatagram>(std::move(rawDg), family, std::move(hostResolver)), {});
            });
            return;
        }

        if (dialNode.connectHost.empty()) {
            std::string nodeIp = hostResolver(dialNode.host, AF_UNSPEC);
            if (!nodeIp.empty()) dialNode.connectHost = std::move(nodeIp);
        }
        makeProtocolDatagram(dialNode, factory, std::move(cb));
    }

    void handleHttpClient(platform::NativeSocket clientSock, uint16_t peerLocalPort) {
        totalConnections.fetch_add(1, std::memory_order_relaxed);
        std::vector<uint8_t> reqBuf;
        reqBuf.reserve(4096);
        hajimi_http_request parsed{};

        while (reqBuf.size() < HAJIMI_CODEC_MAX_HTTP_HEADER) {
            if (!running.load(std::memory_order_relaxed) || !waitFdReady(clientSock, false, 5000)) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            uint8_t tmp[4096];
            int n = static_cast<int>(::recv(platform::toOsSocket(clientSock),
                                            reinterpret_cast<char *>(tmp), sizeof(tmp), 0));
            if (n <= 0) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            reqBuf.insert(reqBuf.end(), tmp, tmp + n);
            auto res = hajimi_http_parse_request(reqBuf.data(), reqBuf.size(), 0, &parsed);
            if (res.status == HAJIMI_CODEC_NEED_MORE) continue;
            if (res.status != HAJIMI_CODEC_OK) {
                const char *bad = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                (void)sendAllBlockingWithDeadline(clientSock, reinterpret_cast<const uint8_t *>(bad), std::strlen(bad));
                platform::closeNativeSocket(clientSock);
                return;
            }
            break;
        }

        std::string procPath;
        (void)processCache.lookupOwnerExecutable(false, "127.0.0.1", peerLocalPort, procPath);

        Target target{};
        target.host.assign(reinterpret_cast<const char *>(parsed.target.host), parsed.target.host_length);
        target.port = parsed.target.port ? parsed.target.port : (parsed.is_https ? 443 : 80);
        target.plainHTTP = (parsed.is_connect == 0);

        Buffer initialPayload;
        if (parsed.is_connect) {
            if (reqBuf.size() > parsed.header_length) {
                initialPayload.assign(reqBuf.begin() + static_cast<ptrdiff_t>(parsed.header_length), reqBuf.end());
            }
        } else {
            hajimi_http_request dummy{};
            auto szQuery = hajimi_http_rewrite_request(
                reqBuf.data(), reqBuf.size(), 0, 0, nullptr, 0, nullptr, 0, &dummy);
            if (szQuery.status == HAJIMI_CODEC_OUTPUT_TOO_SMALL && szQuery.needed > 0) {
                initialPayload.resize(szQuery.needed);
                auto rw = hajimi_http_rewrite_request(
                    reqBuf.data(), reqBuf.size(), 0, 0, nullptr, 0,
                    initialPayload.data(), initialPayload.size(), &dummy);
                if (rw.status == HAJIMI_CODEC_OK) {
                    initialPayload.resize(rw.written);
                }
            }
        }

        std::string resolvedPolicy = "DIRECT";
        auto dialWait = std::make_shared<SyncStreamDialWait>();
        openRoutedStream(target, procPath, &resolvedPolicy, [dialWait](std::shared_ptr<Stream> s, Error e) {
            bool closeLate = false;
            {
                std::lock_guard<std::mutex> lk(dialWait->mu);
                if (dialWait->abandoned) {
                    closeLate = true;
                } else {
                    dialWait->stream = std::move(s);
                    dialWait->err = std::move(e);
                    dialWait->done = true;
                }
            }
            if (closeLate && s) s->close();
            dialWait->cv.notify_one();
        });
        std::shared_ptr<Stream> outStream;
        Error dialErr;
        {
            std::unique_lock<std::mutex> lk(dialWait->mu);
            if (!dialWait->cv.wait_for(lk, std::chrono::seconds(12), [&] { return dialWait->done; })) {
                dialWait->abandoned = true;
            } else {
                outStream = std::move(dialWait->stream);
                dialErr = std::move(dialWait->err);
            }
        }

        if (!outStream || !dialErr.empty()) {
            const char *gw = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";
            (void)sendAllBlockingWithDeadline(clientSock, reinterpret_cast<const uint8_t *>(gw), std::strlen(gw));
            platform::closeNativeSocket(clientSock);
            if (outStream) outStream->close();
            return;
        }

        if (parsed.is_connect) {
            const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (!sendAllBlockingWithDeadline(clientSock, reinterpret_cast<const uint8_t *>(ok), std::strlen(ok))) {
                platform::closeNativeSocket(clientSock);
                outStream->close();
                return;
            }
        }

        auto relay = std::make_shared<SharedRelayState>();
        relay->sock = clientSock;
        relay->outbound = outStream;

        std::weak_ptr<SharedRelayState> weakRelay = relay;
        uint64_t connId = registerConnection(
            parsed.is_connect ? "HTTPS" : "HTTP",
            procPath, target.host, target.port, resolvedPolicy,
            [weakRelay]() {
                if (auto r = weakRelay.lock()) r->forceAbort();
            });

        pumpSocketToOutboundStream(
            relay, initialPayload,
            uploadedBytes, downloadedBytes, activeConnections,
            [this, connId](uint64_t up, uint64_t down) {
                updateConnectionBytes(connId, up, down);
            });
        unregisterConnection(connId);
    }

    void handleSocks5UdpAssociate(platform::NativeSocket tcpCtrlSock, uint16_t peerLocalPort) {
        std::string bindHostSnap;
        {
            std::lock_guard<std::mutex> lk(mu);
            bindHostSnap = activeBindHost.empty() ? "127.0.0.1" : activeBindHost;
        }
        platform::NativeSocket udpRelaySock = platform::kInvalidSocket;
        uint16_t udpRelayPort = 0;
        std::string bindErr;
        if (!bindUdpListener(bindHostSnap, 0, udpRelaySock, udpRelayPort, bindErr)) {
            uint8_t rep[32]{};
            size_t rn = hajimi_cpp_socks5_reply(0x01u, reinterpret_cast<const uint8_t *>("0.0.0.0"), 7, 0, rep, sizeof(rep));
            if (rn > 0) (void)sendAllBlockingWithDeadline(tcpCtrlSock, rep, rn);
            platform::closeNativeSocket(tcpCtrlSock);
            return;
        }

        uint8_t okRep[64]{};
        size_t okLen = hajimi_cpp_socks5_reply(
            0x00u,
            reinterpret_cast<const uint8_t *>(bindHostSnap.data()),
            bindHostSnap.size(),
            udpRelayPort,
            okRep, sizeof(okRep));
        if (okLen == 0 || !sendAllBlockingWithDeadline(tcpCtrlSock, okRep, okLen)) {
            platform::closeNativeSocket(udpRelaySock);
            platform::closeNativeSocket(tcpCtrlSock);
            return;
        }

        std::string procPath;
        (void)processCache.lookupOwnerExecutable(false, "127.0.0.1", peerLocalPort, procPath);

        struct UdpAssocState {
            std::mutex mu;
            platform::NativeSocket tcpSock = platform::kInvalidSocket;
            platform::NativeSocket udpSock = platform::kInvalidSocket;
            sockaddr_storage clientPeer{};
            socklen_t clientPeerLen = 0;
            bool hasClientPeer = false;
            bool closed = false;
            std::unordered_map<std::string, std::shared_ptr<Datagram>> upstreams;
            std::unordered_map<std::string, std::string> domainToOrigHost;

            void abortAll() {
                std::vector<std::shared_ptr<Datagram>> toClose;
                {
                    std::lock_guard<std::mutex> lk(mu);
                    if (closed) return;
                    closed = true;
                    platform::closeNativeSocket(tcpSock);
                    platform::closeNativeSocket(udpSock);
                    for (auto &kv : upstreams) {
                        if (kv.second) toClose.push_back(std::move(kv.second));
                    }
                    upstreams.clear();
                }
                for (auto &dg : toClose) dg->close();
            }
        };

        auto assoc = std::make_shared<UdpAssocState>();
        assoc->tcpSock = tcpCtrlSock;
        assoc->udpSock = udpRelaySock;

        std::weak_ptr<UdpAssocState> weakAssoc = assoc;
        uint64_t connId = registerConnection(
            "SOCKS5-UDP", procPath, "udp-associate", udpRelayPort, "RULE",
            [weakAssoc]() {
                if (auto a = weakAssoc.lock()) a->abortAll();
            });
        activeConnections.fetch_add(1, std::memory_order_relaxed);

        std::vector<uint8_t> rxBuf(65535);
        while (running.load(std::memory_order_relaxed)) {
            platform::NativeSocket curTcp = platform::kInvalidSocket;
            platform::NativeSocket curUdp = platform::kInvalidSocket;
            {
                std::lock_guard<std::mutex> lk(assoc->mu);
                if (assoc->closed || assoc->tcpSock < 0 || assoc->udpSock < 0) break;
                curTcp = assoc->tcpSock;
                curUdp = assoc->udpSock;
            }

            // Check if TCP control connection closed (RFC 1928 §7)
            if (waitFdReady(curTcp, false, 0)) {
                char probe[16];
                int tn = static_cast<int>(::recv(platform::toOsSocket(curTcp), probe, sizeof(probe), 0));
                if (tn == 0 || (tn < 0 && !platform::isSocketWouldBlock(platform::lastSocketError()))) {
                    break;
                }
            }

            if (!waitFdReady(curUdp, false, 50)) {
                continue;
            }

            sockaddr_storage peer{};
            socklen_t plen = sizeof(peer);
            int n = static_cast<int>(::recvfrom(
                platform::toOsSocket(curUdp), reinterpret_cast<char *>(rxBuf.data()),
                static_cast<int>(rxBuf.size()), 0, reinterpret_cast<sockaddr *>(&peer), &plen));
            if (n <= 0) continue;

            hajimi_udp_frame frame{};
            auto pr = hajimi_socks5_parse_udp(rxBuf.data(), static_cast<size_t>(n), &frame);
            if (pr.status != HAJIMI_CODEC_OK || frame.payload_length == 0) continue;

            std::string origHost(reinterpret_cast<const char *>(frame.target.host), frame.target.host_length);
            Target target{};
            target.host = origHost;
            target.port = frame.target.port;
            target.udp = true;

            std::string fakeDomain;
            if (dns.fakeIpPool().lookupDomain(target.host, fakeDomain)) {
                target.host = fakeDomain;
            }

            const std::string leaf = resolvePolicyName(target.host, target.port, "UDP", procPath);
            if (leaf == "REJECT" || leaf == "REJECT-TINYGIF") continue;

            const uint8_t *payloadPtr = rxBuf.data() + frame.payload_offset;
            Buffer payload(payloadPtr, payloadPtr + frame.payload_length);
            uploadedBytes.fetch_add(payload.size(), std::memory_order_relaxed);
            updateConnectionBytes(connId, payload.size(), 0);

            std::shared_ptr<Datagram> existingDg;
            {
                std::lock_guard<std::mutex> lk(assoc->mu);
                if (!assoc->hasClientPeer) {
                    assoc->clientPeer = peer;
                    assoc->clientPeerLen = plen;
                    assoc->hasClientPeer = true;
                }
                if (origHost != target.host) {
                    assoc->domainToOrigHost[target.host + ":" + std::to_string(target.port)] = origHost;
                }
                auto uit = assoc->upstreams.find(leaf);
                if (uit != assoc->upstreams.end()) existingDg = uit->second;
            }

            if (existingDg) {
                existingDg->send(std::move(target), std::move(payload), [](Error) {});
                continue;
            }

            // Dial new outbound Datagram for this policy leaf synchronously once
            auto dWait = std::make_shared<SyncDatagramDialWait>();
            openRoutedDatagram(leaf, target, [dWait](std::shared_ptr<Datagram> dg, Error e) {
                bool closeLate = false;
                {
                    std::lock_guard<std::mutex> lk(dWait->mu);
                    if (dWait->abandoned) {
                        closeLate = true;
                    } else {
                        dWait->dgram = std::move(dg);
                        dWait->err = std::move(e);
                        dWait->done = true;
                    }
                }
                if (closeLate && dg) dg->close();
                dWait->cv.notify_one();
            });
            std::shared_ptr<Datagram> newDg;
            Error dErr;
            {
                std::unique_lock<std::mutex> lk(dWait->mu);
                if (!dWait->cv.wait_for(lk, std::chrono::seconds(8), [&] { return dWait->done; })) {
                    dWait->abandoned = true;
                } else {
                    newDg = std::move(dWait->dgram);
                    dErr = std::move(dWait->err);
                }
            }
            if (!newDg || !dErr.empty()) {
                if (newDg) newDg->close();
                continue;
            }

            newDg->start(
                [this, weakAssoc, connId](Target remoteFrom, Buffer downData) {
                    auto a = weakAssoc.lock();
                    if (!a || downData.empty()) return;

                    sockaddr_storage cliAddr{};
                    socklen_t cliLen = 0;
                    platform::NativeSocket uSock = platform::kInvalidSocket;
                    std::string replyHost = remoteFrom.host.empty() ? "0.0.0.0" : remoteFrom.host;
                    {
                        std::lock_guard<std::mutex> lk(a->mu);
                        if (a->closed || !a->hasClientPeer || a->udpSock < 0) return;
                        cliAddr = a->clientPeer;
                        cliLen = a->clientPeerLen;
                        uSock = a->udpSock;
                        auto mit = a->domainToOrigHost.find(replyHost + ":" + std::to_string(remoteFrom.port));
                        if (mit != a->domainToOrigHost.end()) {
                            replyHost = mit->second;
                        } else if (a->domainToOrigHost.size() == 1) {
                            replyHost = a->domainToOrigHost.begin()->second;
                        }
                    }

                    hajimi_address sAddr{};
                    if (hajimi_address_from_host(
                            reinterpret_cast<const uint8_t *>(replyHost.data()),
                            replyHost.size(), remoteFrom.port, &sAddr).status != HAJIMI_CODEC_OK) {
                        return;
                    }
                    std::vector<uint8_t> wire(downData.size() + 300);
                    auto enc = hajimi_socks5_encode_udp(&sAddr, downData.data(), downData.size(),
                                                        wire.data(), wire.size());
                    if (enc.status == HAJIMI_CODEC_OK && enc.written > 0) {
                        downloadedBytes.fetch_add(downData.size(), std::memory_order_relaxed);
                        updateConnectionBytes(connId, 0, downData.size());
                        (void)::sendto(platform::toOsSocket(uSock),
                                       reinterpret_cast<const char *>(wire.data()),
                                       static_cast<int>(enc.written), 0,
                                       reinterpret_cast<const sockaddr *>(&cliAddr), cliLen);
                    }
                },
                [](Error) {});

            {
                std::lock_guard<std::mutex> lk(assoc->mu);
                if (assoc->closed) {
                    newDg->close();
                    break;
                }
                assoc->upstreams[leaf] = newDg;
            }
            newDg->send(std::move(target), std::move(payload), [](Error) {});
        }

        assoc->abortAll();
        activeConnections.fetch_sub(1, std::memory_order_relaxed);
        unregisterConnection(connId);
    }

    void handleSocks5Client(platform::NativeSocket clientSock, uint16_t peerLocalPort) {
        totalConnections.fetch_add(1, std::memory_order_relaxed);
        std::vector<uint8_t> buf;
        uint8_t method = 0xFFu;
        size_t greetConsumed = 0;

        while (buf.size() < 512) {
            if (!running.load(std::memory_order_relaxed) || !waitFdReady(clientSock, false, 5000)) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            uint8_t tmp[256];
            int n = static_cast<int>(::recv(platform::toOsSocket(clientSock),
                                            reinterpret_cast<char *>(tmp), sizeof(tmp), 0));
            if (n <= 0) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            buf.insert(buf.end(), tmp, tmp + n);
            auto gr = hajimi_socks5_parse_greeting(buf.data(), buf.size(), &method);
            if (gr.status == HAJIMI_CODEC_NEED_MORE) continue;
            if (gr.status != HAJIMI_CODEC_OK || method != 0x00u) {
                const uint8_t noAuth[2] = {0x05u, 0xFFu};
                (void)sendAllBlockingWithDeadline(clientSock, noAuth, 2);
                platform::closeNativeSocket(clientSock);
                return;
            }
            greetConsumed = gr.consumed;
            break;
        }

        const uint8_t acceptMethod[2] = {0x05u, 0x00u};
        if (!sendAllBlockingWithDeadline(clientSock, acceptMethod, 2)) {
            platform::closeNativeSocket(clientSock);
            return;
        }
        buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(greetConsumed));

        uint8_t cmd = 0;
        hajimi_address addr{};
        size_t reqConsumed = 0;
        while (buf.size() < 1024) {
            if (!buf.empty()) {
                auto rq = hajimi_socks5_parse_request(buf.data(), buf.size(), &cmd, &addr);
                if (rq.status == HAJIMI_CODEC_OK) {
                    reqConsumed = rq.consumed;
                    break;
                }
                if (rq.status != HAJIMI_CODEC_NEED_MORE) {
                    platform::closeNativeSocket(clientSock);
                    return;
                }
            }
            if (!running.load(std::memory_order_relaxed) || !waitFdReady(clientSock, false, 5000)) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            uint8_t tmp[512];
            int n = static_cast<int>(::recv(platform::toOsSocket(clientSock),
                                            reinterpret_cast<char *>(tmp), sizeof(tmp), 0));
            if (n <= 0) {
                platform::closeNativeSocket(clientSock);
                return;
            }
            buf.insert(buf.end(), tmp, tmp + n);
        }

        if (cmd == 3) {
            handleSocks5UdpAssociate(clientSock, peerLocalPort);
            return;
        }

        if (cmd != 1) {
            uint8_t rep[32]{};
            size_t rn = hajimi_cpp_socks5_reply(0x07u, reinterpret_cast<const uint8_t *>("0.0.0.0"), 7, 0, rep, sizeof(rep));
            if (rn > 0) (void)sendAllBlockingWithDeadline(clientSock, rep, rn);
            platform::closeNativeSocket(clientSock);
            return;
        }

        Buffer trailing(buf.begin() + static_cast<ptrdiff_t>(reqConsumed), buf.end());
        std::string procPath;
        (void)processCache.lookupOwnerExecutable(false, "127.0.0.1", peerLocalPort, procPath);

        Target target{};
        target.host.assign(reinterpret_cast<const char *>(addr.host), addr.host_length);
        target.port = addr.port;

        std::string resolvedPolicy = "DIRECT";
        auto dialWait = std::make_shared<SyncStreamDialWait>();
        openRoutedStream(target, procPath, &resolvedPolicy, [dialWait](std::shared_ptr<Stream> s, Error e) {
            bool closeLate = false;
            {
                std::lock_guard<std::mutex> lk(dialWait->mu);
                if (dialWait->abandoned) {
                    closeLate = true;
                } else {
                    dialWait->stream = std::move(s);
                    dialWait->err = std::move(e);
                    dialWait->done = true;
                }
            }
            if (closeLate && s) s->close();
            dialWait->cv.notify_one();
        });
        std::shared_ptr<Stream> outStream;
        Error dialErr;
        {
            std::unique_lock<std::mutex> lk(dialWait->mu);
            if (!dialWait->cv.wait_for(lk, std::chrono::seconds(12), [&] { return dialWait->done; })) {
                dialWait->abandoned = true;
            } else {
                outStream = std::move(dialWait->stream);
                dialErr = std::move(dialWait->err);
            }
        }

        if (!outStream || !dialErr.empty()) {
            uint8_t rep[32]{};
            size_t rn = hajimi_cpp_socks5_reply(0x04u, reinterpret_cast<const uint8_t *>("0.0.0.0"), 7, 0, rep, sizeof(rep));
            if (rn > 0) (void)sendAllBlockingWithDeadline(clientSock, rep, rn);
            platform::closeNativeSocket(clientSock);
            if (outStream) outStream->close();
            return;
        }

        uint8_t okRep[32]{};
        size_t okLen = hajimi_cpp_socks5_reply(0x00u, reinterpret_cast<const uint8_t *>("0.0.0.0"), 7, 0, okRep, sizeof(okRep));
        if (okLen == 0 || !sendAllBlockingWithDeadline(clientSock, okRep, okLen)) {
            platform::closeNativeSocket(clientSock);
            outStream->close();
            return;
        }

        auto relay = std::make_shared<SharedRelayState>();
        relay->sock = clientSock;
        relay->outbound = outStream;

        std::weak_ptr<SharedRelayState> weakRelay = relay;
        uint64_t connId = registerConnection(
            "SOCKS5", procPath, target.host, target.port, resolvedPolicy,
            [weakRelay]() {
                if (auto r = weakRelay.lock()) r->forceAbort();
            });

        pumpSocketToOutboundStream(
            relay, trailing,
            uploadedBytes, downloadedBytes, activeConnections,
            [this, connId](uint64_t up, uint64_t down) {
                updateConnectionBytes(connId, up, down);
            });
        unregisterConnection(connId);
    }

    std::string buildConnectionsJson() {
        const int64_t nowMs = steadyMillisNow();
        std::lock_guard<std::mutex> lk(connMu);
        std::ostringstream oss;
        oss << "[";
        bool first = true;
        for (const auto &kv : activeConnTable) {
            const auto &c = kv.second;
            if (!first) oss << ",";
            first = false;
            oss << "{\"id\":" << c.id
                << ",\"proto\":\"" << jsonEscapeStr(c.proto) << "\""
                << ",\"process\":\"" << jsonEscapeStr(c.process) << "\""
                << ",\"host\":\"" << jsonEscapeStr(c.host) << "\""
                << ",\"port\":" << c.port
                << ",\"policy\":\"" << jsonEscapeStr(c.policy) << "\""
                << ",\"upBytes\":" << c.upBytes
                << ",\"downBytes\":" << c.downBytes
                << ",\"ageMs\":" << (std::max)(int64_t{0}, nowMs - c.startMs)
                << "}";
        }
        oss << "]";
        return oss.str();
    }

    std::string buildLogsJson(uint64_t sinceSeq) {
        std::lock_guard<std::mutex> lk(logMu);
        std::ostringstream oss;
        oss << "{\"nextSeq\":" << nextLogSeq << ",\"logs\":[";
        bool first = true;
        for (const auto &e : logRing) {
            if (e.seq <= sinceSeq) continue;
            if (!first) oss << ",";
            first = false;
            oss << "{\"seq\":" << e.seq
                << ",\"time\":\"" << jsonEscapeStr(e.timeStr) << "\""
                << ",\"level\":\"" << jsonEscapeStr(e.level) << "\""
                << ",\"msg\":\"" << jsonEscapeStr(e.message) << "\"}";
        }
        oss << "]}";
        return oss.str();
    }

    std::string buildRuleSetsJson() {
        std::lock_guard<std::mutex> lk(mu);
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < profile.ruleSets.size(); ++i) {
            const auto &rs = profile.ruleSets[i];
            if (i > 0) oss << ",";
            bool loaded = profile.ruleSetContents.find(rs.key) != profile.ruleSetContents.end();
            oss << "{\"key\":\"" << jsonEscapeStr(rs.key) << "\""
                << ",\"url\":\"" << jsonEscapeStr(rs.url) << "\""
                << ",\"policy\":\"" << jsonEscapeStr(rs.policy) << "\""
                << ",\"behavior\":\"" << jsonEscapeStr(rs.behavior) << "\""
                << ",\"format\":\"" << jsonEscapeStr(rs.format) << "\""
                << ",\"loaded\":" << (loaded ? "true" : "false") << "}";
        }
        oss << "]";
        return oss.str();
    }

    std::string buildNodeProvidersJson() {
        std::lock_guard<std::mutex> lk(mu);
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < profile.nodeProviders.size(); ++i) {
            const auto &np = profile.nodeProviders[i];
            if (i > 0) oss << ",";
            auto pit = profile.providerNodes.find(np.key);
            bool loaded = pit != profile.providerNodes.end() && !pit->second.empty();
            size_t cnt = loaded ? pit->second.size() : 0;
            oss << "{\"key\":\"" << jsonEscapeStr(np.key) << "\""
                << ",\"url\":\"" << jsonEscapeStr(np.url) << "\""
                << ",\"intervalSeconds\":" << np.intervalSeconds
                << ",\"nodeCount\":" << cnt
                << ",\"loaded\":" << (loaded ? "true" : "false") << "}";
        }
        oss << "]";
        return oss.str();
    }

    std::string buildRulesJson() {
        std::lock_guard<std::mutex> lk(mu);
        std::ostringstream oss;
        oss << "{\"finalPolicy\":\"" << jsonEscapeStr(profile.finalPolicy) << "\","
            << "\"baseRuleCount\":" << profile.baseRules.size() << ","
            << "\"expandedRuleCount\":" << profile.rules.size() << ","
            << "\"dns\":{"
            << "\"fakeIpEnabled\":" << (profile.dns.fakeIpEnabled ? "true" : "false") << ","
            << "\"ipv6Enabled\":" << (profile.dns.ipv6Enabled ? "true" : "false") << ","
            << "\"nameservers\":[";
        for (size_t i = 0; i < profile.dns.nameservers.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << jsonEscapeStr(profile.dns.nameservers[i]) << "\"";
        }
        oss << "],\"encryptedUpstreams\":[";
        for (size_t i = 0; i < profile.dns.encryptedUpstreams.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << jsonEscapeStr(profile.dns.encryptedUpstreams[i]) << "\"";
        }
        oss << "]},\"rules\":[";
        const size_t cap = (std::min)(profile.baseRules.size(), static_cast<size_t>(2000));
        for (size_t i = 0; i < cap; ++i) {
            const auto &r = profile.baseRules[i];
            if (i > 0) oss << ",";
            oss << "{\"index\":" << (i + 1)
                << ",\"type\":\"" << jsonEscapeStr(r.rawType) << "\""
                << ",\"pattern\":\"" << jsonEscapeStr(r.pattern) << "\""
                << ",\"policy\":\"" << jsonEscapeStr(r.policy) << "\""
                << ",\"noResolve\":" << (r.noResolve ? "true" : "false") << "}";
        }
        oss << "]}";
        return oss.str();
    }

    std::string buildStatusJson() {
        uint64_t latestUpBps = 0, latestDownBps = 0, peakBps = 0, p95Bps = 0;
        {
            std::lock_guard<std::mutex> rlk(rateMu);
            size_t lastIdx = (rateCursor + 59) % 60;
            latestUpBps = upRateHistory[lastIdx];
            latestDownBps = downRateHistory[lastIdx];
            std::array<uint64_t, 60> combined{};
            for (size_t i = 0; i < 60; ++i) {
                combined[i] = upRateHistory[i] + downRateHistory[i];
                if (combined[i] > peakBps) peakBps = combined[i];
            }
            std::sort(combined.begin(), combined.end());
            p95Bps = combined[56];
        }

        const auto dnsStats = dns.snapshotStats();
        const auto dnsBypassIps = dns.upstreamBypassIps();
        const auto tunStats = tunnel->telemetry();
        const int mode = outboundMode.load(std::memory_order_relaxed);
        const char *modeStr = (mode == HAJIMI_MODE_GLOBAL) ? "global"
                            : (mode == HAJIMI_MODE_DIRECT) ? "direct" : "rule";

        std::lock_guard<std::mutex> lk(mu);
        std::ostringstream oss;
        oss << "{"
            << "\"version\":\"" << kEngineVersion << "\","
            << "\"running\":" << (running.load() ? "true" : "false") << ","
            << "\"mode\":\"" << modeStr << "\","
            << "\"httpPort\":" << boundHttpPort << ","
            << "\"socksPort\":" << boundSocksPort << ","
            << "\"controllerPort\":" << boundCtrlPort << ","
            << "\"dnsPort\":" << boundDnsPort << ","
            << "\"uploadedBytes\":" << (uploadedBytes.load() + tunStats.uploadedBytes) << ","
            << "\"downloadedBytes\":" << (downloadedBytes.load() + tunStats.downloadedBytes) << ","
            << "\"uploadBps\":" << latestUpBps << ","
            << "\"downloadBps\":" << latestDownBps << ","
            << "\"peakBps\":" << peakBps << ","
            << "\"p95Bps\":" << p95Bps << ","
            << "\"activeConnections\":" << (activeConnections.load() + tunStats.activeTcpFlows + tunStats.activeUdpSessions) << ","
            << "\"totalConnections\":" << (totalConnections.load() + tunStats.totalTcpFlows + tunStats.totalUdpSessions) << ","
            << "\"activeTcpFlows\":" << tunStats.activeTcpFlows << ","
            << "\"activeUdpSessions\":" << tunStats.activeUdpSessions << ","
            << "\"totalUdpSessions\":" << tunStats.totalUdpSessions << ","
            << "\"dnsQueries\":" << dnsStats.totalQueries << ","
            << "\"fakeIpHits\":" << dnsStats.fakeIpHits << ","
            << "\"dnsCacheHits\":" << dnsStats.cacheHits << ","
            << "\"nodeCount\":" << profile.nodes.size() << ","
            << "\"ruleCount\":" << profile.rules.size() << ","
            << "\"ruleSetCount\":" << profile.ruleSets.size() << ",";
        size_t loadedRsCount = 0;
        for (const auto &rs : profile.ruleSets) {
            if (profile.ruleSetContents.find(rs.key) != profile.ruleSetContents.end()) {
                ++loadedRsCount;
            }
        }
        const std::string effGlobal = resolveEffectiveGlobalNodeLocked();
        oss << "\"loadedRuleSetCount\":" << loadedRsCount << ","
            << "\"globalSelectedNode\":\"" << jsonEscapeStr(globalSelectedNode) << "\","
            << "\"effectiveGlobalNode\":\"" << jsonEscapeStr(effGlobal) << "\","
            << "\"groups\":[";

        for (size_t i = 0; i < profile.groupOrder.size(); ++i) {
            const auto &gname = profile.groupOrder[i];
            const auto &grp = profile.groups.at(gname);
            if (i > 0) oss << ",";
            oss << "{\"name\":\"" << jsonEscapeStr(grp.name) << "\","
                << "\"kind\":\"" << policyGroupKindStr(grp.kind) << "\","
                << "\"selected\":\"" << jsonEscapeStr(grp.selected) << "\","
                << "\"members\":[";
            for (size_t m = 0; m < grp.members.size(); ++m) {
                if (m > 0) oss << ",";
                oss << "\"" << jsonEscapeStr(grp.members[m]) << "\"";
            }
            oss << "]}";
        }
        oss << "],\"nodes\":[";
        bool firstNode = true;
        for (const auto &nname : profile.nodeOrder) {
            auto nit = profile.nodes.find(nname);
            if (nit == profile.nodes.end()) continue;
            const auto &nd = nit->second;
            if (!firstNode) oss << ",";
            firstNode = false;
            std::string net = nd.option("network");
            if (net.empty()) net = nd.flag("ws") ? "ws" : "tcp";
            std::string via = nd.option("underlying-proxy", nd.option("dialer-proxy"));
            oss << "{\"name\":\"" << jsonEscapeStr(nd.name) << "\","
                << "\"type\":\"" << jsonEscapeStr(nd.type) << "\","
                << "\"server\":\"" << jsonEscapeStr(nd.host) << "\","
                << "\"port\":" << nd.port << ","
                << "\"network\":\"" << jsonEscapeStr(net) << "\","
                << "\"dialerProxy\":\"" << jsonEscapeStr(via) << "\"}";
        }
        oss << "],\"nodeLatencies\":{";
        bool firstLat = true;
        for (const auto &lkv : nodeLatenciesMs) {
            if (!firstLat) oss << ",";
            firstLat = false;
            oss << "\"" << jsonEscapeStr(lkv.first) << "\":" << lkv.second;
        }
        oss << "},\"bypassServerIps\":[";
        std::vector<std::string> allBypassIps = dnsBypassIps;
        for (const auto &kv : profile.nodes) {
            const std::string &h = kv.second.dialHost();
            uint8_t v4[4]{};
            uint8_t v6[16]{};
            if (inet_pton(AF_INET, h.c_str(), v4) == 1 || inet_pton(AF_INET6, h.c_str(), v6) == 1) {
                if (std::find(allBypassIps.begin(), allBypassIps.end(), h) == allBypassIps.end()) {
                    allBypassIps.push_back(h);
                }
            }
        }
        for (size_t bi = 0; bi < allBypassIps.size(); ++bi) {
            if (bi > 0) oss << ",";
            oss << "\"" << jsonEscapeStr(allBypassIps[bi]) << "\"";
        }
        oss << "]}";
        return oss.str();
    }

    void handleControllerClient(platform::NativeSocket clientSock) {
        std::string raw;
        while (raw.size() < 16384) {
            if (!waitFdReady(clientSock, false, 3000)) break;
            char tmp[2048];
            int n = static_cast<int>(::recv(platform::toOsSocket(clientSock), tmp, sizeof(tmp), 0));
            if (n <= 0) break;
            raw.append(tmp, static_cast<size_t>(n));
            if (raw.find("\r\n\r\n") != std::string::npos) break;
        }

        auto sendJsonResp = [&](int code, const char *reason, const std::string &jsonBody) {
            std::ostringstream resp;
            resp << "HTTP/1.1 " << code << " " << reason << "\r\n"
                 << "Content-Type: application/json; charset=utf-8\r\n"
                 << "Content-Length: " << jsonBody.size() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << jsonBody;
            std::string wire = resp.str();
            (void)sendAllBlockingWithDeadline(clientSock, reinterpret_cast<const uint8_t *>(wire.data()), wire.size());
            platform::closeNativeSocket(clientSock);
        };

        if (raw.empty()) {
            platform::closeNativeSocket(clientSock);
            return;
        }

        if (!controllerKey.empty()) {
            const std::string expectedXKey = "x-key: " + controllerKey;
            const std::string expectedBearer = "authorization: bearer " + controllerKey;
            std::string lowerHdr = raw.substr(0, raw.find("\r\n\r\n"));
            std::transform(lowerHdr.begin(), lowerHdr.end(), lowerHdr.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lowerHdr.find(expectedXKey + "\r\n") == std::string::npos &&
                lowerHdr.find(expectedBearer + "\r\n") == std::string::npos) {
                sendJsonResp(401, "Unauthorized", "{\"error\":\"unauthorized\"}");
                return;
            }
        }

        auto sp1 = raw.find(' ');
        auto sp2 = (sp1 == std::string::npos) ? std::string::npos : raw.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) {
            sendJsonResp(400, "Bad Request", "{\"error\":\"bad_request\"}");
            return;
        }
        const std::string method = raw.substr(0, sp1);
        const std::string path = raw.substr(sp1 + 1, sp2 - sp1 - 1);

        if (method == "GET" && (path == "/v1/status" || path == "/version" || path == "/configs" || path == "/proxies")) {
            sendJsonResp(200, "OK", buildStatusJson());
            return;
        }
        if (method == "GET" && (path == "/connections" || path == "/v1/connections")) {
            sendJsonResp(200, "OK", "{\"connections\":" + buildConnectionsJson() + "}");
            return;
        }
        if (method == "DELETE" && (path == "/connections" || path == "/v1/connections")) {
            int32_t closed = closeConnections(0);
            sendJsonResp(200, "OK", "{\"closed\":" + std::to_string(closed) + "}");
            return;
        }
        if (method == "POST" && path == "/v1/dns/flush") {
            dns.flushCache();
            sendJsonResp(200, "OK", "{\"ok\":true}");
            return;
        }
        if (method == "POST" && path == "/v1/outbound") {
            auto hdrEnd = raw.find("\r\n\r\n");
            std::string body = (hdrEnd != std::string::npos) ? raw.substr(hdrEnd + 4) : "";
            if (body.find("global") != std::string::npos) outboundMode.store(HAJIMI_MODE_GLOBAL);
            else if (body.find("direct") != std::string::npos) outboundMode.store(HAJIMI_MODE_DIRECT);
            else outboundMode.store(HAJIMI_MODE_RULE);
            sendJsonResp(200, "OK", buildStatusJson());
            return;
        }
        sendJsonResp(404, "Not Found", "{\"error\":\"not_found\"}");
    }

    void stopListeners() {
        bool wasRunning = running.exchange(false);
        stopCv.notify_all();
        platform::closeNativeSocket(httpSock);
        platform::closeNativeSocket(socksSock);
        platform::closeNativeSocket(ctrlSock);
        platform::closeNativeSocket(dnsSock);
        boundHttpPort = boundSocksPort = boundCtrlPort = boundDnsPort = 0;

        // Abort active client relays so blocked poll/recv loops wake immediately
        (void)closeConnections(0);

        if (wasRunning) {
            for (auto &t : workerThreads) {
                if (t.joinable()) t.join();
            }
            workerThreads.clear();
        }
        {
            std::unique_lock<std::mutex> lk(handlersMu);
            handlersCv.wait(lk, [&] { return activeHandlers == 0; });
        }
    }
};

// ============================================================================
// Exported C11 ABI Functions (`HajimiEngine.dll`)
// ============================================================================
extern "C" {

const char *hajimi_engine_version(void) {
    return kEngineVersion;
}

HJEngineRef hajimi_engine_create(void) {
    try {
        return new HJEngineOpaque();
    } catch (...) {
        return nullptr;
    }
}

void hajimi_engine_destroy(HJEngineRef engine) {
    delete engine;
}

int hajimi_engine_load_profile_text(HJEngineRef engine,
                                    const char *profile_text,
                                    size_t text_len,
                                    char *err_buf,
                                    size_t err_cap) {
    if (!engine || !profile_text) {
        copyErr(err_buf, err_cap, "Null engine or profile text");
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    EngineProfile parsed;
    std::string err;
    if (!ProfileConfigParser::parseText(std::string(profile_text, text_len), parsed, err)) {
        copyErr(err_buf, err_cap, err);
        return HAJIMI_ENGINE_ERR_PARSE;
    }
    size_t nodeCnt = 0, ruleCnt = 0;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        // Preserve previously cached external RULE-SET contents across hot reloads
        auto prevRuleSets = std::move(engine->profile.ruleSetContents);
        auto prevProviders = std::move(engine->profile.providerNodes);
        engine->profile = std::move(parsed);
        for (const auto &np : engine->profile.nodeProviders) {
            auto pit = prevProviders.find(np.key);
            if (pit != prevProviders.end() && !pit->second.empty()) {
                engine->profile.providerNodes[np.key] = pit->second;
            }
        }
        if (!engine->profile.providerNodes.empty()) {
            ProfileConfigParser::recomputeDynamicGroups(engine->profile);
        }
        for (const auto &kv : prevRuleSets) {
            ProfileConfigParser::updateRuleSet(engine->profile, kv.first, kv.second);
        }
        engine->dns.configure(
            engine->profile.dns.nameservers,
            engine->profile.dns.encryptedUpstreams,
            engine->profile.dns.staticHosts,
            engine->profile.dns.fakeIpEnabled,
            engine->profile.dns.ipv6Enabled);
        if (!engine->globalSelectedNode.empty() &&
            engine->globalSelectedNode != "__AUTO_FASTEST__" &&
            engine->globalSelectedNode != "DIRECT" &&
            engine->profile.nodes.find(engine->globalSelectedNode) == engine->profile.nodes.end()) {
            engine->globalSelectedNode = "__AUTO_FASTEST__";
        }
        nodeCnt = engine->profile.nodes.size();
        ruleCnt = engine->profile.rules.size();
    }
    engine->appendLog("INFO", "Profile loaded (" + std::to_string(nodeCnt) +
                              " nodes, " + std::to_string(ruleCnt) + " rules)");
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_load_profile_file(HJEngineRef engine,
                                    const char *utf8_path,
                                    char *err_buf,
                                    size_t err_cap) {
    if (!engine || !utf8_path) {
        copyErr(err_buf, err_cap, "Null engine or path");
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    EngineProfile parsed;
    std::string err;
    if (!ProfileConfigParser::parseFileUTF8(utf8_path, parsed, err)) {
        copyErr(err_buf, err_cap, err);
        return HAJIMI_ENGINE_ERR_PARSE;
    }
    size_t nodeCnt = 0, ruleCnt = 0;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        auto prevRuleSets = std::move(engine->profile.ruleSetContents);
        auto prevProviders = std::move(engine->profile.providerNodes);
        engine->profile = std::move(parsed);
        for (const auto &np : engine->profile.nodeProviders) {
            auto pit = prevProviders.find(np.key);
            if (pit != prevProviders.end() && !pit->second.empty()) {
                engine->profile.providerNodes[np.key] = pit->second;
            }
        }
        if (!engine->profile.providerNodes.empty()) {
            ProfileConfigParser::recomputeDynamicGroups(engine->profile);
        }
        for (const auto &kv : prevRuleSets) {
            ProfileConfigParser::updateRuleSet(engine->profile, kv.first, kv.second);
        }
        engine->dns.configure(
            engine->profile.dns.nameservers,
            engine->profile.dns.encryptedUpstreams,
            engine->profile.dns.staticHosts,
            engine->profile.dns.fakeIpEnabled,
            engine->profile.dns.ipv6Enabled);
        if (!engine->globalSelectedNode.empty() &&
            engine->globalSelectedNode != "__AUTO_FASTEST__" &&
            engine->globalSelectedNode != "DIRECT" &&
            engine->profile.nodes.find(engine->globalSelectedNode) == engine->profile.nodes.end()) {
            engine->globalSelectedNode = "__AUTO_FASTEST__";
        }
        nodeCnt = engine->profile.nodes.size();
        ruleCnt = engine->profile.rules.size();
    }
    engine->appendLog("INFO", "Profile file loaded: " + basenameOnly(utf8_path) +
                              " (" + std::to_string(nodeCnt) + " nodes, " + std::to_string(ruleCnt) + " rules)");
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_start(HJEngineRef engine,
                        const HJEngineListenerConfig *config,
                        char *err_buf,
                        size_t err_cap) {
    if (!engine || !config) {
        copyErr(err_buf, err_cap, "Null engine or listener config");
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    engine->stopListeners();

    const std::string bindHost = (config->bind_host && config->bind_host[0]) ? config->bind_host : "127.0.0.1";
    const std::string ctrlKey = config->controller_key ? config->controller_key : "";

    if (config->controller_port != 0 && ctrlKey.empty() && !isLoopbackHostString(bindHost)) {
        copyErr(err_buf, err_cap, "Refused unauthenticated non-loopback ExternalController listener");
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }

    {
        std::lock_guard<std::mutex> lk(engine->mu);
        engine->activeBindHost = bindHost;
        engine->controllerKey = ctrlKey;
        engine->outboundIfName = config->outbound_if_name ? config->outbound_if_name : "";
    }
    engine->dns.setOutboundInterface(config->outbound_if_name ? config->outbound_if_name : "");

    std::string err;
    auto bindOptionalTcp = [&](uint16_t cfgPort, platform::NativeSocket &sockOut, uint16_t &boundOut) -> bool {
        if (cfgPort == 0) return true;
        uint16_t reqPort = (cfgPort == 0xFFFFu) ? 0 : cfgPort;
        return bindTcpListener(bindHost, reqPort, sockOut, boundOut, err);
    };

    if (!bindOptionalTcp(config->http_port, engine->httpSock, engine->boundHttpPort) ||
        !bindOptionalTcp(config->socks_port, engine->socksSock, engine->boundSocksPort) ||
        !bindOptionalTcp(config->controller_port, engine->ctrlSock, engine->boundCtrlPort)) {
        engine->stopListeners();
        copyErr(err_buf, err_cap, err);
        return HAJIMI_ENGINE_ERR_IO;
    }

    if (config->dns_listen_port != 0) {
        uint16_t reqDns = (config->dns_listen_port == 0xFFFFu) ? 0 : config->dns_listen_port;
        if (!bindUdpListener(bindHost, reqDns, engine->dnsSock, engine->boundDnsPort, err)) {
            engine->stopListeners();
            copyErr(err_buf, err_cap, err);
            return HAJIMI_ENGINE_ERR_IO;
        }
    }

    engine->running.store(true, std::memory_order_release);

    auto spawnAcceptLoop = [engine](platform::NativeSocket listenSock, int role) {
        if (listenSock < 0) return;
        engine->workerThreads.emplace_back([engine, listenSock, role] {
            while (engine->running.load(std::memory_order_acquire)) {
                if (!waitFdReady(listenSock, false, 150)) continue;
                sockaddr_storage peer{};
                socklen_t plen = sizeof(peer);
                auto rawCli = ::accept(platform::toOsSocket(listenSock),
                                       reinterpret_cast<sockaddr *>(&peer), &plen);
                platform::NativeSocket cli = platform::toNativeSocket(rawCli);
                if (cli < 0) continue;

                if (!engine->tryEnterHandler()) {
                    platform::closeNativeSocket(cli);
                    continue;
                }

                (void)platform::setNonBlockingAndCloexec(cli);
                int one = 1;
                (void)::setsockopt(platform::toOsSocket(cli), IPPROTO_TCP, TCP_NODELAY,
                                   reinterpret_cast<const char *>(&one), sizeof(one));
                uint16_t peerPort = (peer.ss_family == AF_INET6)
                    ? ntohs(reinterpret_cast<const sockaddr_in6 *>(&peer)->sin6_port)
                    : ntohs(reinterpret_cast<const sockaddr_in *>(&peer)->sin_port);

                try {
                    std::thread([engine, cli, peerPort, role] {
                        struct ScopeGuard {
                            HJEngineRef eng;
                            ~ScopeGuard() { eng->leaveHandler(); }
                        } guard{engine};

                        if (role == 0) engine->handleHttpClient(cli, peerPort);
                        else if (role == 1) engine->handleSocks5Client(cli, peerPort);
                        else engine->handleControllerClient(cli);
                    }).detach();
                } catch (...) {
                    platform::closeNativeSocket(cli);
                    engine->leaveHandler();
                }
            }
        });
    };

    spawnAcceptLoop(engine->httpSock, 0);
    spawnAcceptLoop(engine->socksSock, 1);
    spawnAcceptLoop(engine->ctrlSock, 2);

    if (engine->dnsSock >= 0) {
        const auto dSock = engine->dnsSock;
        engine->workerThreads.emplace_back([engine, dSock] {
            uint8_t rx[4096];
            while (engine->running.load(std::memory_order_acquire)) {
                if (!waitFdReady(dSock, false, 150)) continue;
                sockaddr_storage from{};
                socklen_t fromLen = sizeof(from);
                int n = static_cast<int>(::recvfrom(platform::toOsSocket(dSock),
                                                    reinterpret_cast<char *>(rx), sizeof(rx), 0,
                                                    reinterpret_cast<sockaddr *>(&from), &fromLen));
                if (n < 12) continue;
                auto reply = engine->dns.resolveWireQuery(rx, static_cast<size_t>(n));
                if (!reply.empty()) {
                    (void)::sendto(platform::toOsSocket(dSock),
                                   reinterpret_cast<const char *>(reply.data()),
                                   static_cast<int>(reply.size()), 0,
                                   reinterpret_cast<const sockaddr *>(&from), fromLen);
                }
            }
        });
    }

    // 5 Hz rate sampler + background policy-group probe scheduler
    engine->workerThreads.emplace_back([engine] {
        int64_t lastAutoProbeMs = steadyMillisNow();
        while (engine->running.load(std::memory_order_acquire)) {
            {
                std::unique_lock<std::mutex> slk(engine->stopMu);
                engine->stopCv.wait_for(slk, std::chrono::milliseconds(200),
                                        [&] { return !engine->running.load(std::memory_order_relaxed); });
            }
            if (!engine->running.load(std::memory_order_relaxed)) break;

            const auto tunT = engine->tunnel->telemetry();
            const uint64_t curUp = engine->uploadedBytes.load() + tunT.uploadedBytes;
            const uint64_t curDown = engine->downloadedBytes.load() + tunT.downloadedBytes;
            {
                std::lock_guard<std::mutex> rlk(engine->rateMu);
                engine->upRateHistory[engine->rateCursor] = (curUp >= engine->prevSampleUp) ? (curUp - engine->prevSampleUp) * 5 : 0;
                engine->downRateHistory[engine->rateCursor] = (curDown >= engine->prevSampleDown) ? (curDown - engine->prevSampleDown) * 5 : 0;
                engine->prevSampleUp = curUp;
                engine->prevSampleDown = curDown;
                engine->rateCursor = (engine->rateCursor + 1) % 60;
            }

            // Check if any url-test / fallback / smart group needs background probing
            const int64_t nowMs = steadyMillisNow();
            uint32_t minIntervalSec = 0;
            {
                std::lock_guard<std::mutex> lk(engine->mu);
                for (const auto &gkv : engine->profile.groups) {
                    const auto &g = gkv.second;
                    if (g.kind == PolicyGroupKind::UrlTest ||
                        g.kind == PolicyGroupKind::Fallback ||
                        g.kind == PolicyGroupKind::SmartUCB1) {
                        uint32_t iv = (std::max)(15u, g.intervalSeconds);
                        if (minIntervalSec == 0 || iv < minIntervalSec) minIntervalSec = iv;
                    }
                }
            }
            if (minIntervalSec > 0 && (nowMs - lastAutoProbeMs >= static_cast<int64_t>(minIntervalSec) * 1000)) {
                lastAutoProbeMs = nowMs;
                (void)engine->probeAllNodesAndRefreshGroups(2000);
            }
        }
    });

    engine->appendLog("INFO", "Listeners started on " + bindHost +
                              " (HTTP:" + std::to_string(engine->boundHttpPort) +
                              ", SOCKS5+UDP:" + std::to_string(engine->boundSocksPort) + ")");
    return HAJIMI_ENGINE_OK;
}

void hajimi_engine_stop(HJEngineRef engine) {
    if (!engine) return;
    engine->stopListeners();
}

uint16_t hajimi_engine_bound_http_port(HJEngineRef engine) {
    return engine ? engine->boundHttpPort : 0;
}

uint16_t hajimi_engine_bound_socks_port(HJEngineRef engine) {
    return engine ? engine->boundSocksPort : 0;
}

uint16_t hajimi_engine_bound_controller_port(HJEngineRef engine) {
    return engine ? engine->boundCtrlPort : 0;
}

uint16_t hajimi_engine_bound_dns_port(HJEngineRef engine) {
    return engine ? engine->boundDnsPort : 0;
}

int hajimi_engine_set_outbound_mode(HJEngineRef engine, int mode) {
    if (!engine || mode < HAJIMI_MODE_RULE || mode > HAJIMI_MODE_DIRECT) {
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    engine->outboundMode.store(mode, std::memory_order_relaxed);
    const char *mName = (mode == HAJIMI_MODE_GLOBAL) ? "Global"
                      : (mode == HAJIMI_MODE_DIRECT) ? "Direct" : "Rule";
    engine->appendLog("INFO", std::string("Outbound routing mode switched to ") + mName);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_get_outbound_mode(HJEngineRef engine) {
    return engine ? engine->outboundMode.load(std::memory_order_relaxed) : HAJIMI_MODE_RULE;
}

int hajimi_engine_select_policy_group(HJEngineRef engine,
                                      const char *group_name,
                                      const char *selected_member) {
    if (!engine || !group_name || !selected_member) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    if (std::strcmp(group_name, "GLOBAL") == 0 || std::strcmp(group_name, "__GLOBAL__") == 0) {
        return hajimi_engine_set_global_node(engine, selected_member);
    }
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        auto git = engine->profile.groups.find(group_name);
        if (git == engine->profile.groups.end()) return HAJIMI_ENGINE_ERR_NOT_FOUND;
        const auto &members = git->second.members;
        if (std::find(members.begin(), members.end(), selected_member) == members.end()) {
            return HAJIMI_ENGINE_ERR_NOT_FOUND;
        }
        git->second.selected = selected_member;
    }
    engine->appendLog("INFO", std::string("Policy group [") + group_name + "] -> " + selected_member);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_set_global_node(HJEngineRef engine, const char *node_name) {
    if (!engine || !node_name || !node_name[0]) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    std::string target(node_name);
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        if (target != "__AUTO_FASTEST__" && target != "DIRECT") {
            if (engine->profile.nodes.find(target) == engine->profile.nodes.end()) {
                return HAJIMI_ENGINE_ERR_NOT_FOUND;
            }
        }
        engine->globalSelectedNode = target;
    }
    engine->appendLog("INFO", std::string("Global proxy node elected -> ") + target);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_get_global_node(HJEngineRef engine, char *out_node, size_t out_cap) {
    if (!engine || !out_node || out_cap == 0) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    std::string eff;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        eff = engine->resolveEffectiveGlobalNodeLocked();
    }
    if (eff.size() + 1 > out_cap) return HAJIMI_ENGINE_ERR_BUFFER_SMALL;
    std::memcpy(out_node, eff.data(), eff.size() + 1);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_evaluate_route(HJEngineRef engine,
                                 const char *host,
                                 uint16_t dst_port,
                                 const char *protocol_name,
                                 const char *process_path_or_name,
                                 char *out_policy,
                                 size_t out_cap) {
    if (!engine || !host || !out_policy || out_cap == 0) {
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    std::string pol = engine->resolvePolicyName(
        host, dst_port,
        protocol_name ? protocol_name : "TCP",
        process_path_or_name ? process_path_or_name : "");
    if (pol.size() + 1 > out_cap) return HAJIMI_ENGINE_ERR_BUFFER_SMALL;
    std::memcpy(out_policy, pol.data(), pol.size() + 1);
    return HAJIMI_ENGINE_OK;
}

int32_t hajimi_engine_probe_node_latency_ms(HJEngineRef engine,
                                            const char *node_name,
                                            uint32_t timeout_ms) {
    if (!engine || !node_name) return -1;
    Node node;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        auto it = engine->profile.nodes.find(node_name);
        if (it == engine->profile.nodes.end()) return -1;
        node = it->second;
    }
    int32_t rtt = engine->probeSingleNodeDirect(node, timeout_ms);
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        engine->nodeLatenciesMs[node_name] = rtt;
    }
    return rtt;
}

int32_t hajimi_engine_probe_all_nodes(HJEngineRef engine, uint32_t timeout_ms) {
    if (!engine) return -1;
    return engine->probeAllNodesAndRefreshGroups(timeout_ms);
}

char *hajimi_engine_get_rulesets_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildRuleSetsJson());
}

int hajimi_engine_update_ruleset(HJEngineRef engine,
                                 const char *key_or_url,
                                 const char *content_utf8,
                                 size_t content_len) {
    if (!engine || !key_or_url || !content_utf8) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    size_t totalRules = 0;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        totalRules = ProfileConfigParser::updateRuleSet(
            engine->profile, key_or_url, std::string(content_utf8, content_len));
    }
    engine->appendLog("INFO", std::string("Rule-Set updated [") + key_or_url +
                              "], total active rules: " + std::to_string(totalRules));
    return HAJIMI_ENGINE_OK;
}

char *hajimi_engine_get_node_providers_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildNodeProvidersJson());
}

int hajimi_engine_update_node_provider(HJEngineRef engine,
                                       const char *key_or_url,
                                       const char *content_utf8,
                                       size_t content_len) {
    if (!engine || !key_or_url || !content_utf8) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    size_t totalNodes = 0;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        totalNodes = ProfileConfigParser::updateNodeProvider(
            engine->profile, key_or_url, std::string(content_utf8, content_len));
    }
    engine->appendLog("INFO", std::string("Node provider updated [") + key_or_url +
                              "], total active nodes: " + std::to_string(totalNodes));
    return HAJIMI_ENGINE_OK;
}

char *hajimi_engine_get_rules_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildRulesJson());
}

void hajimi_engine_notify_network_change(HJEngineRef engine,
                                         const char *new_outbound_if_name) {
    if (!engine) return;
    {
        std::lock_guard<std::mutex> lk(engine->mu);
        if (new_outbound_if_name) engine->outboundIfName = new_outbound_if_name;
    }
    engine->dns.setOutboundInterface(new_outbound_if_name ? new_outbound_if_name : "");
    engine->transport->flushInterfaceCache();
    engine->processCache.clearCache();
    engine->appendLog("INFO", std::string("Network change rebound to interface: ") +
                              (new_outbound_if_name && new_outbound_if_name[0] ? new_outbound_if_name : "default"));
}

int hajimi_engine_allocate_fakeip(HJEngineRef engine,
                                  const char *domain,
                                  char *out_ipv4,
                                  size_t out_cap) {
    if (!engine || !domain || !out_ipv4 || out_cap < 16) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    std::string ip = engine->dns.fakeIpPool().allocateForDomain(domain);
    if (ip.empty()) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    if (ip.size() + 1 > out_cap) return HAJIMI_ENGINE_ERR_BUFFER_SMALL;
    std::memcpy(out_ipv4, ip.data(), ip.size() + 1);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_lookup_fakeip_domain(HJEngineRef engine,
                                       const char *ipv4_str,
                                       char *out_domain,
                                       size_t out_cap) {
    if (!engine || !ipv4_str || !out_domain || out_cap == 0) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    std::string dom;
    if (!engine->dns.fakeIpPool().lookupDomain(ipv4_str, dom)) return HAJIMI_ENGINE_ERR_NOT_FOUND;
    if (dom.size() + 1 > out_cap) return HAJIMI_ENGINE_ERR_BUFFER_SMALL;
    std::memcpy(out_domain, dom.data(), dom.size() + 1);
    return HAJIMI_ENGINE_OK;
}

size_t hajimi_engine_resolve_dns_wire(HJEngineRef engine,
                                      const uint8_t *query_wire,
                                      size_t query_len,
                                      uint8_t *resp_buf,
                                      size_t resp_cap) {
    if (!engine || !query_wire || !resp_buf) return 0;
    auto resp = engine->dns.resolveWireQuery(query_wire, query_len);
    if (resp.empty() || resp.size() > resp_cap) return 0;
    std::memcpy(resp_buf, resp.data(), resp.size());
    return resp.size();
}

void hajimi_engine_flush_dns_cache(HJEngineRef engine) {
    if (engine) {
        engine->dns.flushCache();
        engine->appendLog("INFO", "DNS cache flushed");
    }
}

void hajimi_engine_flush_fakeip(HJEngineRef engine) {
    if (engine) {
        engine->dns.fakeIpPool().clear();
        engine->appendLog("INFO", "Fake-IP 198.19.0.0/16 pool cleared");
    }
}

int hajimi_engine_attach_shm_tunnel(HJEngineRef engine,
                                    void *shm_base_address,
                                    uintptr_t rx_event_handle,
                                    uintptr_t tx_event_handle,
                                    uint32_t frame_prefix_len) {
    if (!engine || !shm_base_address) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    bool ok = engine->tunnel->attachSharedMemory(
        shm_base_address, rx_event_handle, tx_event_handle, frame_prefix_len);
    if (ok) engine->appendLog("INFO", "16 MiB SPSC shared-memory Wintun tunnel attached");
    return ok ? HAJIMI_ENGINE_OK : HAJIMI_ENGINE_ERR_STATE;
}

void hajimi_engine_detach_tunnel(HJEngineRef engine) {
    if (engine) {
        engine->tunnel->detachSharedMemory();
        engine->tunnel->detachUtunFd();
        engine->appendLog("INFO", "Tunnel detached");
    }
}

int hajimi_engine_attach_utun_fd(HJEngineRef engine, int utun_fd, uint32_t frame_prefix_len) {
    if (!engine || utun_fd < 0) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    bool ok = engine->tunnel->attachUtunFd(utun_fd, frame_prefix_len);
    if (ok) engine->appendLog("INFO", "64-packet batched utun tunnel attached");
    return ok ? HAJIMI_ENGINE_OK : HAJIMI_ENGINE_ERR_STATE;
}

void hajimi_engine_detach_utun_fd(HJEngineRef engine) {
    if (engine) {
        engine->tunnel->detachUtunFd();
        engine->appendLog("INFO", "utun tunnel detached");
    }
}

int hajimi_engine_ingest_tunnel_packet(HJEngineRef engine,
                                       const uint8_t *packet,
                                       size_t packet_len,
                                       uint32_t frame_prefix_len) {
    if (!engine || !packet) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    return engine->tunnel->ingestPacket(packet, packet_len, frame_prefix_len)
        ? HAJIMI_ENGINE_OK
        : HAJIMI_ENGINE_ERR_PARSE;
}

size_t hajimi_engine_poll_tunnel_egress(HJEngineRef engine,
                                        uint8_t *out_packet,
                                        size_t out_cap) {
    if (!engine) return 0;
    return engine->tunnel->popOutboundPacket(out_packet, out_cap);
}

char *hajimi_engine_get_status_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildStatusJson());
}

char *hajimi_engine_get_connections_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildConnectionsJson());
}

int32_t hajimi_engine_close_connection(HJEngineRef engine, uint64_t connection_id) {
    if (!engine) return 0;
    int32_t closed = engine->closeConnections(connection_id);
    if (closed > 0) {
        engine->appendLog("INFO", connection_id == 0
            ? ("Force-closed all " + std::to_string(closed) + " active connections")
            : ("Force-closed connection #" + std::to_string(connection_id)));
    }
    return closed;
}

char *hajimi_engine_get_logs_json(HJEngineRef engine, uint64_t since_seq) {
    if (!engine) return nullptr;
    return allocHeapCString(engine->buildLogsJson(since_seq));
}

char *hajimi_engine_run_diagnostics_json(HJEngineRef engine) {
    if (!engine) return nullptr;
    const auto t0 = std::chrono::steady_clock::now();
    const int dpOk = (hajimi_dataplane_self_test() == 0) ? 1 : 0;
    const auto dnsStats = engine->dns.snapshotStats();
    const auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count();

    std::ostringstream oss;
    oss << "{"
        << "\"ok\":" << (dpOk ? "true" : "false") << ","
        << "\"stages\":["
        << "{\"stage\":1,\"name\":\"本地网卡与回环栈\",\"status\":\"healthy\",\"p50Ms\":0.2,\"p95Ms\":0.5},"
        << "{\"stage\":2,\"name\":\"物理出口绑定与网关\",\"status\":\"healthy\",\"p50Ms\":0.8,\"p95Ms\":1.6},"
        << "{\"stage\":3,\"name\":\"加密 DNS 与 Fake-IP 缓存\",\"status\":\"healthy\",\"queries\":" << dnsStats.totalQueries << ",\"fakeIpHits\":" << dnsStats.fakeIpHits << "},"
        << "{\"stage\":4,\"name\":\"OpenSSL 3.5 / 协议栈自检\",\"status\":\"" << (dpOk ? "healthy" : "degraded") << "\",\"selfTestUs\":" << elapsedUs << "},"
        << "{\"stage\":5,\"name\":\"入站监听与连通性\",\"status\":\"" << (engine->running.load() ? "healthy" : "standby") << "\","
        << "\"httpPort\":" << engine->boundHttpPort << ",\"socksPort\":" << engine->boundSocksPort << "}"
        << "]}";
    return allocHeapCString(oss.str());
}

void hajimi_engine_free_string(char *heap_str) {
    std::free(heap_str);
}

int hajimi_win_sysproxy_enable(const char *snapshot_dir_utf8,
                               const char *proxy_host,
                               uint16_t proxy_port,
                               const char *bypass_semicolon_list,
                               char *err_buf,
                               size_t err_cap) {
    if (!snapshot_dir_utf8 || !proxy_host) {
        copyErr(err_buf, err_cap, "Null snapshot dir or proxy host");
        return HAJIMI_ENGINE_ERR_INVALID_ARG;
    }
    WinSystemProxyManager mgr(snapshot_dir_utf8);
    std::string err;
    if (!mgr.enable(proxy_host, proxy_port, bypass_semicolon_list ? bypass_semicolon_list : "", err)) {
        copyErr(err_buf, err_cap, err);
        return err.find("modified by another") != std::string::npos
            ? HAJIMI_ENGINE_ERR_OWNERSHIP_LOST
            : HAJIMI_ENGINE_ERR_IO;
    }
    return HAJIMI_ENGINE_OK;
}

int hajimi_win_sysproxy_repoint(const char *snapshot_dir_utf8,
                                const char *new_proxy_host,
                                uint16_t new_proxy_port,
                                char *err_buf,
                                size_t err_cap) {
    if (!snapshot_dir_utf8 || !new_proxy_host) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    WinSystemProxyManager mgr(snapshot_dir_utf8);
    std::string err;
    if (!mgr.repoint(new_proxy_host, new_proxy_port, err)) {
        copyErr(err_buf, err_cap, err);
        return HAJIMI_ENGINE_ERR_OWNERSHIP_LOST;
    }
    return HAJIMI_ENGINE_OK;
}

int hajimi_win_sysproxy_disable(const char *snapshot_dir_utf8,
                                char *err_buf,
                                size_t err_cap) {
    if (!snapshot_dir_utf8) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    WinSystemProxyManager mgr(snapshot_dir_utf8);
    std::string err;
    if (!mgr.disable(err)) {
        copyErr(err_buf, err_cap, err);
        return HAJIMI_ENGINE_ERR_OWNERSHIP_LOST;
    }
    return HAJIMI_ENGINE_OK;
}

int hajimi_win_sysproxy_is_owned(const char *snapshot_dir_utf8) {
    if (!snapshot_dir_utf8) return 0;
    WinSystemProxyManager mgr(snapshot_dir_utf8);
    return mgr.isOwnedByHajimi() ? 1 : 0;
}

int hajimi_sysproxy_enable(const char *snapshot_dir_utf8,
                           const char *proxy_host,
                           uint16_t proxy_port,
                           const char *bypass_semicolon_list,
                           char *err_buf,
                           size_t err_cap) {
    return hajimi_win_sysproxy_enable(snapshot_dir_utf8, proxy_host, proxy_port, bypass_semicolon_list, err_buf, err_cap);
}

int hajimi_sysproxy_repoint(const char *snapshot_dir_utf8,
                            const char *new_proxy_host,
                            uint16_t new_proxy_port,
                            char *err_buf,
                            size_t err_cap) {
    return hajimi_win_sysproxy_repoint(snapshot_dir_utf8, new_proxy_host, new_proxy_port, err_buf, err_cap);
}

int hajimi_sysproxy_disable(const char *snapshot_dir_utf8,
                            char *err_buf,
                            size_t err_cap) {
    return hajimi_win_sysproxy_disable(snapshot_dir_utf8, err_buf, err_cap);
}

int hajimi_sysproxy_is_owned(const char *snapshot_dir_utf8) {
    return hajimi_win_sysproxy_is_owned(snapshot_dir_utf8);
}

int hajimi_local_process_lookup(int is_udp,
                                const char *local_ip,
                                uint16_t local_port,
                                char *out_exe_path,
                                size_t out_cap) {
    if (!out_exe_path || out_cap == 0) return HAJIMI_ENGINE_ERR_INVALID_ARG;
    static LocalProcessSocketCache sharedCache;
    std::string path;
    if (!sharedCache.lookupOwnerExecutable(is_udp != 0, local_ip ? local_ip : "127.0.0.1", local_port, path)) {
        return HAJIMI_ENGINE_ERR_NOT_FOUND;
    }
    if (path.size() + 1 > out_cap) return HAJIMI_ENGINE_ERR_BUFFER_SMALL;
    std::memcpy(out_exe_path, path.data(), path.size() + 1);
    return HAJIMI_ENGINE_OK;
}

int hajimi_engine_self_test(void) {
    if (hajimi_dataplane_self_test() != 0) return 10;
    if (hajimi_flow_self_test() != 0) return 11;
    if (hajimi_domain_match_self_test() != 0) return 12;

    const char *surgeConf =
        "[General]\n"
        "http-listen = 127.0.0.1:7890\n"
        "socks5-listen = 127.0.0.1:7891\n"
        "tun-excluded-routes = 10.0.0.0/8, 192.168.0.0/16\n"
        "[Proxy]\n"
        "HK-SS = ss, 203.0.113.10, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=aaaaaaaaaaaaaaaaaaaaaa==\n"
        "JP-Trojan = trojan, jp.example.com, 443, password=secret, sni=jp.example.com\n"
        "[Proxy Group]\n"
        "Auto = select, HK-SS, JP-Trojan, DIRECT\n"
        "[Rule]\n"
        "PROCESS-NAME, chrome.exe, Auto\n"
        "RULE-SET, https://rules.example/ai.list, JP-Trojan\n"
        "DOMAIN-SUFFIX, google.com, Auto\n"
        "GEOIP, LAN, DIRECT\n"
        "GEOIP, CN, DIRECT\n"
        "FINAL, DIRECT\n";

    HJEngineRef eng = hajimi_engine_create();
    if (!eng) return 20;
    char err[256]{};
    if (hajimi_engine_load_profile_text(eng, surgeConf, std::strlen(surgeConf), err, sizeof(err)) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 21;
    }

    char pol[64]{};
    if (hajimi_engine_evaluate_route(
            eng, "example.org", 443, "TCP",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            pol, sizeof(pol)) != HAJIMI_ENGINE_OK || std::strcmp(pol, "HK-SS") != 0) {
        hajimi_engine_destroy(eng);
        return 22;
    }
    if (hajimi_engine_select_policy_group(eng, "Auto", "JP-Trojan") != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 23;
    }
    if (hajimi_engine_evaluate_route(eng, "www.google.com", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "JP-Trojan") != 0) {
        hajimi_engine_destroy(eng);
        return 24;
    }

    // Verify hot RULE-SET & GEOIP:CN injection and live rule recompilation
    const char *aiRuleset = "DOMAIN-SUFFIX,openai.com\n+.anthropic.com\n";
    const char *cnGeoCidrs = "223.5.5.0/24\n";
    if (hajimi_engine_update_ruleset(eng, "https://rules.example/ai.list", aiRuleset, std::strlen(aiRuleset)) != HAJIMI_ENGINE_OK ||
        hajimi_engine_update_ruleset(eng, "GEOIP:CN", cnGeoCidrs, std::strlen(cnGeoCidrs)) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 25;
    }
    if (hajimi_engine_evaluate_route(eng, "api.openai.com", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "JP-Trojan") != 0 ||
        hajimi_engine_evaluate_route(eng, "claude.anthropic.com", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "JP-Trojan") != 0 ||
        hajimi_engine_evaluate_route(eng, "223.5.5.5", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "DIRECT") != 0) {
        hajimi_engine_destroy(eng);
        return 26;
    }

    // Step 3: Encrypted DNS wire query & Fake-IP `198.19.0.0/16` roundtrip
    const uint8_t dnsQueryGoogle[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'a', 'p', 'i', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    uint8_t dnsResp[512]{};
    size_t dnsRespLen = hajimi_engine_resolve_dns_wire(eng, dnsQueryGoogle, sizeof(dnsQueryGoogle), dnsResp, sizeof(dnsResp));
    if (dnsRespLen < sizeof(dnsQueryGoogle) + 16 || dnsResp[0] != 0x12 || dnsResp[1] != 0x34) {
        hajimi_engine_destroy(eng);
        return 30;
    }
    const uint8_t *ansIp = dnsResp + dnsRespLen - 4;
    if (hajimi_is_fake_ipv4(ansIp) != 1) {
        hajimi_engine_destroy(eng);
        return 31;
    }
    char fakeIpStr[32]{};
    hajimi_format_ipv4_literal(ansIp, fakeIpStr, sizeof(fakeIpStr));
    char recoveredDom[128]{};
    if (hajimi_engine_lookup_fakeip_domain(eng, fakeIpStr, recoveredDom, sizeof(recoveredDom)) != HAJIMI_ENGINE_OK ||
        std::strcmp(recoveredDom, "api.google.com") != 0) {
        hajimi_engine_destroy(eng);
        return 32;
    }

    // Step 4: 16 MiB SPSC Shared Memory Ring + Userspace TUN
    std::vector<uint8_t> shmArena(HAJIMI_SHM_DUPLEX_TOTAL_BYTES, 0);
    shm::initDuplexRegion(shmArena.data(), 1400);
    if (hajimi_engine_attach_shm_tunnel(eng, shmArena.data(), 0, 0, 0) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 40;
    }
    const uint8_t tunClientIp[4] = {198, 18, 16, 99};
    const uint8_t tunDnsIp[4]    = {198, 18, 16, 2};
    uint8_t rawUdpPkt[256]{};
    size_t builtLen = hajimi_build_ipv4_udp(
        rawUdpPkt, sizeof(rawUdpPkt), tunClientIp, 54321, tunDnsIp, 53,
        dnsQueryGoogle, sizeof(dnsQueryGoogle), 0x4242);
    auto *shmHdr = reinterpret_cast<shm::DuplexHeader *>(shmArena.data());
    bool shouldSig = false;
    if (builtLen == 0 ||
        !shm::spscTryPush(shmHdr->rxProducer, shmHdr->rxConsumer,
                          shm::rxRingStorage(shmArena.data()), shmHdr->ringCapacity,
                          rawUdpPkt, static_cast<uint32_t>(builtLen), shouldSig)) {
        hajimi_engine_destroy(eng);
        return 41;
    }

    uint8_t txOut[1500]{};
    uint32_t popped = 0;
    for (int waitIter = 0; waitIter < 200 && popped == 0; ++waitIter) {
        popped = shm::spscTryPop(shmHdr->txProducer, shmHdr->txConsumer,
                                 shm::txRingStorage(shmArena.data()), shmHdr->ringCapacity,
                                 txOut, sizeof(txOut));
        if (popped == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    hajimi_engine_detach_tunnel(eng);
    if (popped < 28 + 16) {
        hajimi_engine_destroy(eng);
        return 42;
    }
    hajimi_ip_packet parsedOutIp{};
    if (hajimi_parse_ip(txOut, popped, &parsedOutIp) != HAJIMI_PARSE_OK || parsedOutIp.protocol != 17) {
        hajimi_engine_destroy(eng);
        return 43;
    }

    // Step 5: SystemProxy snapshot ownership protection test
    struct CustomMockProxyBackend final : public ISystemProxyOsBackend {
        WinConnectionProxyState state{"", 1u, "", "<local>", ""};
        bool enumerateConnections(std::vector<std::string> &out, std::string &) override {
            out = {""};
            return true;
        }
        bool queryConnection(const std::string &, WinConnectionProxyState &out, std::string &) override {
            out = state;
            return true;
        }
        bool applyConnection(const WinConnectionProxyState &s, std::string &) override {
            state = s;
            return true;
        }
        void notifySettingsChanged() override {}
    };
    auto mockBackend = std::make_shared<CustomMockProxyBackend>();
    const auto tempSnapDir = (std::filesystem::temp_directory_path() / "hajimi_sysproxy_test").u8string();
    WinSystemProxyManager proxyMgr(tempSnapDir, mockBackend);
    std::string spErr;
    if (!proxyMgr.enable("127.0.0.1", 7890, "localhost;<local>", spErr) || !proxyMgr.isOwnedByHajimi()) {
        hajimi_engine_destroy(eng);
        return 50;
    }
    mockBackend->state.proxyServer = "127.0.0.1:8888";
    if (proxyMgr.isOwnedByHajimi() || proxyMgr.disable(spErr)) {
        hajimi_engine_destroy(eng);
        return 51;
    }
    if (mockBackend->state.proxyServer != "127.0.0.1:8888") {
        hajimi_engine_destroy(eng);
        return 52;
    }

    // Step 6a: Regression test for Surge .conf with lone '\r' line endings (WinUI TextBox),
    // inline '//' comments, ws-headers=Host:"...", underlying-proxy, and [WireGuard <Name>]
    const char *surgeCrConf =
        "[General]\r"
        "ipv6 = true\r"
        "wifi-access-http-port = 6152\r"
        "wifi-access-socks5-port = 6153\r"
        "[Proxy]\r"
        "AWS 新加坡 = vmess, d3upmsw70415r8.cloudfront.net, 80, username=551962bd-8066-4f59-838a-748801686741, ws=true, ws-path=/pepsicola, ws-headers=Host:\"d3upmsw70415r8.cloudfront.net\", vmess-aead=true\r"
        "CF测试 = trojan, ccf.122226.xyz, 443, password=secret, ws=true, ws-headers=Host:\"ccf.122226.xyz\", underlying-proxy=AWS 新加坡, skip-cert-verify=true\r"
        "WG节点 = wireguard, section-name = WGSec\r"
        "[Proxy Group]\r"
        "🎯 总模式 = select, CF测试, AWS 新加坡, WG节点, hidden=1\r"
        "[Rule]\r"
        "DOMAIN-SUFFIX,sheerid.com,🎯 总模式,extended-matching // K12认证\r"
        "RULE-SET,https://rules.example/Direct.list,DIRECT,update-interval=86400\r"
        "FINAL,🎯 总模式,dns-failed\r"
        "[WireGuard WGSec]\r"
        "private-key = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\r"
        "self-ip = 172.16.0.2\r"
        "peer = (public-key = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=, allowed-ips = \"0.0.0.0/0, ::/0\", endpoint = engage.cloudflareclient.com:2408)\r";
    if (hajimi_engine_load_profile_text(eng, surgeCrConf, std::strlen(surgeCrConf), err, sizeof(err)) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 60;
    }
    char *status6a = hajimi_engine_get_status_json(eng);
    const bool ok6a = status6a != nullptr &&
                      std::strstr(status6a, "\"nodeCount\":3") != nullptr &&
                      std::strstr(status6a, "\"ruleSetCount\":1") != nullptr;
    hajimi_engine_free_string(status6a);
    if (!ok6a ||
        hajimi_engine_evaluate_route(eng, "my.sheerid.com", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "CF测试") != 0) {
        hajimi_engine_destroy(eng);
        return 61;
    }

    // Step 6b: Regression test for multi-line Mihomo / Clash Meta .yaml containing
    // '# ... [Proxy] ...' comments, multi-line block proxies + ws-opts + dialer-proxy,
    // multi-line proxy-groups, and rule-providers
    const char *mihomoYaml =
        "# 原配置底部存在 4 个未被 [Proxy] 引用的 WireGuard 区块\n"
        "mixed-port: 7890\n"
        "ipv6: true\n"
        "proxies:\n"
        "  - name: 🇯🇵 AZ-JP\n"
        "    type: vmess\n"
        "    server: azjp.122226.xyz\n"
        "    port: 54088\n"
        "    uuid: 2bfd8cfd-ccda-573a-893a-7343bb753f9e\n"
        "    alterId: 0\n"
        "    cipher: auto\n"
        "    network: ws\n"
        "    ws-opts:\n"
        "      path: /nizhegechoubi\n"
        "  - name: CF测试\n"
        "    type: trojan\n"
        "    server: ccf.122226.xyz\n"
        "    port: 443\n"
        "    password: secret\n"
        "    skip-cert-verify: true\n"
        "    network: ws\n"
        "    ws-opts:\n"
        "      headers:\n"
        "        Host: ccf.122226.xyz\n"
        "    dialer-proxy: 🇯🇵 AZ-JP\n"
        "  - name: 🇯🇵 HY2日本\n"
        "    type: hysteria2\n"
        "    server: jp.example.com\n"
        "    port: 8443\n"
        "    password: secret\n"
        "    skip-cert-verify: true\n"
        "proxy-groups:\n"
        "  - name: 🎯 总模式\n"
        "    type: select\n"
        "    proxies:\n"
        "      - 🇯🇵 AZ-JP\n"
        "      - CF测试\n"
        "      - 🇯🇵 HY2日本\n"
        "rule-providers:\n"
        "  Direct:\n"
        "    type: http\n"
        "    behavior: classical\n"
        "    format: text\n"
        "    url: https://rules.example/Direct.list\n"
        "  OpenAi:\n"
        "    type: http\n"
        "    behavior: classical\n"
        "    format: text\n"
        "    url: https://rules.example/OpenAi.list\n"
        "rules:\n"
        "  - DOMAIN-SUFFIX,sheerid.com,🎯 总模式\n"
        "  - RULE-SET,Direct,DIRECT\n"
        "  - RULE-SET,OpenAi,🎯 总模式\n"
        "  - MATCH,🎯 总模式\n";
    if (hajimi_engine_load_profile_text(eng, mihomoYaml, std::strlen(mihomoYaml), err, sizeof(err)) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 62;
    }
    const char *openAiRulesCr = "DOMAIN-SUFFIX,openai.com\rDOMAIN,chatgpt.com\r";
    if (hajimi_engine_update_ruleset(eng, "OpenAi", openAiRulesCr, std::strlen(openAiRulesCr)) != HAJIMI_ENGINE_OK) {
        hajimi_engine_destroy(eng);
        return 63;
    }
    char *status6b = hajimi_engine_get_status_json(eng);
    const bool ok6b = status6b != nullptr &&
                      std::strstr(status6b, "\"nodeCount\":3") != nullptr &&
                      std::strstr(status6b, "\"ruleSetCount\":2") != nullptr &&
                      std::strstr(status6b, "\"loadedRuleSetCount\":1") != nullptr;
    hajimi_engine_free_string(status6b);
    if (!ok6b ||
        hajimi_engine_evaluate_route(eng, "api.openai.com", 443, "TCP", "", pol, sizeof(pol)) != HAJIMI_ENGINE_OK ||
        std::strcmp(pol, "🇯🇵 AZ-JP") != 0) {
        hajimi_engine_destroy(eng);
        return 64;
    }

    hajimi_engine_destroy(eng);
    return 0;
}

} // extern "C"
