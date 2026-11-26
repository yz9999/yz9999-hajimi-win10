#include "HajimiWinTransportCXX.h"
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"
#include "../HajimiProtocolsCXX/ProtocolCommon.hpp"
#include "../HajimiProtocolsCXX/Crypto.hpp"

#include <openssl/bio.h>
#include "../HajimiPlatformC/include/HajimiAsyncPoller.h"
#if defined(__APPLE__)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#endif
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if defined(_WIN32)
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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <list>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hajimi::win_transport {
namespace {

using SteadyClock = std::chrono::steady_clock;

bool isLoopbackSockaddr(const sockaddr *addr, socklen_t len) noexcept {
    if (!addr || len < static_cast<socklen_t>(sizeof(sockaddr))) return false;
    if (addr->sa_family == AF_INET && len >= static_cast<socklen_t>(sizeof(sockaddr_in))) {
        const auto *v4 = reinterpret_cast<const sockaddr_in *>(addr);
        return (ntohl(v4->sin_addr.s_addr) >> 24) == 127;
    }
    if (addr->sa_family == AF_INET6 && len >= static_cast<socklen_t>(sizeof(sockaddr_in6))) {
        const auto &v6 = reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(&v6)) return true;
        return IN6_IS_ADDR_V4MAPPED(&v6) && v6.s6_addr[12] == 127;
    }
    return false;
}

std::string stripIpv6BracketsAndZone(const std::string &host) {
    std::string clean = host;
    if (clean.size() >= 2 && clean.front() == '[' && clean.back() == ']') {
        clean = clean.substr(1, clean.size() - 2);
    }
    if (clean.find(':') != std::string::npos) {
        auto pct = clean.find('%');
        if (pct != std::string::npos) clean.resize(pct);
    }
    return clean;
}

bool parseNumericEndpoint(const std::string &host, uint16_t port,
                          sockaddr_storage &outStorage, socklen_t &outLen) noexcept {
    std::string clean = stripIpv6BracketsAndZone(host);
    if (clean.empty()) return false;
    sockaddr_in v4{};
    if (inet_pton(AF_INET, clean.c_str(), &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        v4.sin_port = htons(port);
        outLen = sizeof(v4);
        std::memcpy(&outStorage, &v4, sizeof(v4));
        return true;
    }
    sockaddr_in6 v6{};
    if (inet_pton(AF_INET6, clean.c_str(), &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        v6.sin6_port = htons(port);
        outLen = sizeof(v6);
        std::memcpy(&outStorage, &v6, sizeof(v6));
        return true;
    }
    return false;
}

bool formatSockaddrEndpoint(const sockaddr_storage &storage, Target &outTarget) noexcept {
    char ipBuf[INET6_ADDRSTRLEN + 4]{};
    if (storage.ss_family == AF_INET) {
        const auto *v4 = reinterpret_cast<const sockaddr_in *>(&storage);
        if (!inet_ntop(AF_INET, &v4->sin_addr, ipBuf, sizeof(ipBuf))) return false;
        outTarget.host = ipBuf;
        outTarget.port = ntohs(v4->sin_port);
        outTarget.udp = true;
        return true;
    }
    if (storage.ss_family == AF_INET6) {
        const auto *v6 = reinterpret_cast<const sockaddr_in6 *>(&storage);
        if (!inet_ntop(AF_INET6, &v6->sin6_addr, ipBuf, sizeof(ipBuf))) return false;
        outTarget.host = ipBuf;
        outTarget.port = ntohs(v6->sin6_port);
        outTarget.udp = true;
        return true;
    }
    return false;
}

bool loadPemCertStoreUTF8(SSL_CTX *ctx, const std::string &caPath) {
    if (!ctx || caPath.empty()) return false;
    std::string pem;
    try {
        pem = platform::readBoundedRegularFileUTF8(
            caPath, 1024 * 1024, "CA read error", "CA not regular", "CA size error");
    } catch (...) {
        return false;
    }
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) return false;
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return false;
    STACK_OF(X509_INFO) *infos = PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!infos) return false;
    bool added = false;
    int count = sk_X509_INFO_num(infos);
    for (int i = 0; i < count; ++i) {
        X509_INFO *info = sk_X509_INFO_value(infos, i);
        if (!info) continue;
        if (info->x509) {
            if (X509_STORE_add_cert(store, info->x509) == 1) added = true;
            else ERR_clear_error();
        }
        if (info->crl) {
            if (X509_STORE_add_crl(store, info->crl) == 1) added = true;
            else ERR_clear_error();
        }
    }
    sk_X509_INFO_pop_free(infos, X509_INFO_free);
    return added;
}

#if defined(__APPLE__)
bool loadMacSystemRootCertificates(SSL_CTX *ctx) noexcept {
    if (!ctx) return false;
    bool loaded = (SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", nullptr) == 1);
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) return loaded;
    CFArrayRef anchors = nullptr;
    if (SecTrustCopyAnchorCertificates(&anchors) == errSecSuccess && anchors != nullptr) {
        CFIndex n = CFArrayGetCount(anchors);
        for (CFIndex i = 0; i < n; ++i) {
            auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, i);
            if (!cert) continue;
            CFDataRef der = SecCertificateCopyData(cert);
            if (!der) continue;
            const unsigned char *ptr = CFDataGetBytePtr(der);
            long len = static_cast<long>(CFDataGetLength(der));
            X509 *x = d2i_X509(nullptr, &ptr, len);
            if (x) {
                if (X509_STORE_add_cert(store, x) == 1) loaded = true;
                else ERR_clear_error();
                X509_free(x);
            }
            CFRelease(der);
        }
        CFRelease(anchors);
    }
    ERR_clear_error();
    return loaded;
}
#endif

#if defined(_WIN32)
bool verifyWindowsSystemTrust(X509_STORE_CTX *store, const std::string &verifyName) noexcept {
    struct StoreGuard {
        HCERTSTORE h = nullptr;
        ~StoreGuard() { if (h) ::CertCloseStore(h, 0); }
    };
    struct CertGuard {
        PCCERT_CONTEXT p = nullptr;
        ~CertGuard() { if (p) ::CertFreeCertificateContext(p); }
    };
    struct ChainGuard {
        PCCERT_CHAIN_CONTEXT p = nullptr;
        ~ChainGuard() { if (p) ::CertFreeCertificateChain(p); }
    };

    try {
        X509 *leaf = X509_STORE_CTX_get0_cert(store);
        STACK_OF(X509) *chain = X509_STORE_CTX_get0_untrusted(store);
        int count = chain ? sk_X509_num(chain) : 0;
        std::string cleanName = stripIpv6BracketsAndZone(verifyName);
        std::wstring wideHost;
        if (!leaf || count > 16 || cleanName.empty() || !platform::utf8ToWide(cleanName, wideHost)) {
            return false;
        }
        uint8_t ipBuf[16]{};
        const bool isIp = inet_pton(AF_INET, cleanName.c_str(), ipBuf) == 1 ||
                          inet_pton(AF_INET6, cleanName.c_str(), ipBuf) == 1;
        const int sanOk = isIp
            ? X509_check_ip_asc(leaf, cleanName.c_str(), 0)
            : X509_check_host(leaf, cleanName.data(), cleanName.size(),
                              X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, nullptr);
        if (sanOk != 1) return false;

        auto encodeDer = [](X509 *cert, Buffer &out) -> bool {
            int len = i2d_X509(cert, nullptr);
            if (len <= 0 || len > 1024 * 1024) return false;
            out.resize(static_cast<size_t>(len));
            unsigned char *p = out.data();
            return i2d_X509(cert, &p) == len;
        };

        StoreGuard memStore{::CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                            CERT_STORE_CREATE_NEW_FLAG, nullptr)};
        Buffer leafDer;
        if (!memStore.h || !encodeDer(leaf, leafDer)) return false;

        CertGuard leafCtx{::CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            leafDer.data(), static_cast<DWORD>(leafDer.size()))};
        if (!leafCtx.p) return false;

        for (int i = 0; i < count; ++i) {
            X509 *inter = sk_X509_value(chain, i);
            if (!inter || X509_cmp(leaf, inter) == 0) continue;
            Buffer interDer;
            if (!encodeDer(inter, interDer) ||
                !::CertAddEncodedCertificateToStore(
                    memStore.h, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    interDer.data(), static_cast<DWORD>(interDer.size()),
                    CERT_STORE_ADD_ALWAYS, nullptr)) {
                return false;
            }
        }

        LPSTR usageOid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
        CERT_ENHKEY_USAGE enhkeyUsage{1, &usageOid};
        CERT_USAGE_MATCH certUsage{USAGE_MATCH_TYPE_AND, enhkeyUsage};
        CERT_CHAIN_PARA chainPara{};
        chainPara.cbSize = sizeof(chainPara);
        chainPara.RequestedUsage = certUsage;

        PCCERT_CHAIN_CONTEXT rawChain = nullptr;
        if (!::CertGetCertificateChain(nullptr, leafCtx.p, nullptr, memStore.h,
                                       &chainPara, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                                       nullptr, &rawChain)) {
            return false;
        }
        ChainGuard chainGuard{rawChain};
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslPolicy{};
        sslPolicy.cbSize = sizeof(sslPolicy);
        sslPolicy.dwAuthType = AUTHTYPE_SERVER;
        sslPolicy.pwszServerName = isIp ? nullptr : wideHost.data();

        CERT_CHAIN_POLICY_PARA policyPara{};
        policyPara.cbSize = sizeof(policyPara);
        policyPara.pvExtraPolicyPara = &sslPolicy;

        CERT_CHAIN_POLICY_STATUS policyStatus{};
        policyStatus.cbSize = sizeof(policyStatus);
        return ::CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chainGuard.p,
                                                  &policyPara, &policyStatus) &&
               policyStatus.dwError == ERROR_SUCCESS;
    } catch (...) {
        return false;
    }
}
#endif

class ReactorPollable {
public:
    virtual ~ReactorPollable() = default;
    virtual platform::NativeSocket socketHandle() const noexcept = 0;
    virtual short desiredPollEvents() const noexcept = 0;
    virtual void onPollEvents(short revents, SteadyClock::time_point now) = 0;
    virtual SteadyClock::time_point nextDeadline() const noexcept = 0;
    virtual bool isFinished() const noexcept = 0;
    virtual void forceAbort(const Error &reason) = 0;
};

} // namespace

struct WinTransportRuntime::Impl {
    RuntimeConfig config;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> shuttingDown{false};

    // Serialized application strand + monotonic timer heap
    struct TimerEntry {
        SteadyClock::time_point due;
        uint64_t seq;
        std::function<void()> fn;
        bool operator>(const TimerEntry &o) const noexcept {
            return due != o.due ? due > o.due : seq > o.seq;
        }
    };
    std::mutex strandMutex;
    std::condition_variable strandCv;
    std::deque<std::function<void()>> strandTasks;
    std::vector<TimerEntry> strandTimers;
    uint64_t timerSeq = 0;
    bool strandStopped = false;
    std::thread strandThread;

    // Non-blocking socket I/O reactor
    std::mutex reactorMutex;
    std::deque<std::function<void()>> reactorCommands;
    std::vector<std::shared_ptr<ReactorPollable>> pollables;
    platform::NativeSocket wakePair[2]{platform::kInvalidSocket, platform::kInvalidSocket};
    platform_io::AsyncPoller asyncPoller;
    std::atomic<bool> wakePending{false};
    bool reactorStopped = false;
    std::thread reactorThread;

    // Cached interface name/alias -> NET_IFINDEX
    std::mutex ifCacheMutex;
    std::unordered_map<std::string, unsigned int> ifCache;

    explicit Impl(const RuntimeConfig &cfg) : config(cfg) {
        platform::ensureWinsock();
        if (!platform::createWakePair(wakePair)) {
            throw std::runtime_error("WinTransportRuntime failed to create reactor wake socketpair");
        }
        strandThread = std::thread([this] { runStrandLoop(); });
        reactorThread = std::thread([this] { runReactorLoop(); });
    }

    ~Impl() {
        shutdown();
    }

    void postStrand(std::function<void()> work) {
        if (!work) return;
        {
            std::lock_guard<std::mutex> lock(strandMutex);
            if (strandStopped) return;
            strandTasks.push_back(std::move(work));
        }
        strandCv.notify_one();
    }

    void postAfter(double seconds, std::function<void()> work) {
        if (!work) return;
        const double clamped = std::clamp(seconds, 0.0, 86400.0);
        const auto due = SteadyClock::now() + std::chrono::duration_cast<SteadyClock::duration>(
            std::chrono::duration<double>(clamped));
        {
            std::lock_guard<std::mutex> lock(strandMutex);
            if (strandStopped) return;
            strandTimers.push_back({due, ++timerSeq, std::move(work)});
            std::push_heap(strandTimers.begin(), strandTimers.end(), std::greater<TimerEntry>{});
        }
        strandCv.notify_one();
    }

    void postReactor(std::function<void()> cmd) {
        if (!cmd) return;
        {
            std::lock_guard<std::mutex> lock(reactorMutex);
            if (reactorStopped) return;
            reactorCommands.push_back(std::move(cmd));
        }
        notifyReactor();
    }

    void notifyReactor() noexcept {
        asyncPoller.wake(wakePair[1]);
        if (!wakePending.exchange(true, std::memory_order_acq_rel) && wakePair[1] >= 0) {
#if defined(_WIN32)
            platform::writeWakeSignal(wakePair[1]);
#endif
        }
    }

    void cancelAll() {
        cancelled.store(true, std::memory_order_release);
        postReactor([this] {
            for (auto &item : pollables) {
                if (item && !item->isFinished()) {
                    item->forceAbort("Protocol client cancelled");
                }
            }
        });
    }

    void shutdown() {
        if (shuttingDown.exchange(true, std::memory_order_acq_rel)) return;
        cancelled.store(true, std::memory_order_release);

        // 1. Stop reactor first so it stops posting new completions onto strand
        {
            std::lock_guard<std::mutex> lock(reactorMutex);
            reactorStopped = true;
        }
        notifyReactor();
        if (reactorThread.joinable()) {
            if (reactorThread.get_id() == std::this_thread::get_id()) reactorThread.detach();
            else reactorThread.join();
        }
        platform::closeNativeSocket(wakePair[0]);
        platform::closeNativeSocket(wakePair[1]);

        // 2. Drain and stop strand thread
        {
            std::lock_guard<std::mutex> lock(strandMutex);
            strandStopped = true;
        }
        strandCv.notify_all();
        if (strandThread.joinable()) {
            if (strandThread.get_id() == std::this_thread::get_id()) strandThread.detach();
            else strandThread.join();
        }
    }

    void runStrandLoop() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(strandMutex);
                for (;;) {
                    const auto now = SteadyClock::now();
                    while (!strandTimers.empty() && strandTimers.front().due <= now) {
                        std::pop_heap(strandTimers.begin(), strandTimers.end(), std::greater<TimerEntry>{});
                        strandTasks.push_back(std::move(strandTimers.back().fn));
                        strandTimers.pop_back();
                    }
                    if (!strandTasks.empty()) {
                        task = std::move(strandTasks.front());
                        strandTasks.pop_front();
                        break;
                    }
                    if (strandStopped) return;
                    if (strandTimers.empty()) {
                        strandCv.wait(lock);
                    } else {
                        strandCv.wait_until(lock, strandTimers.front().due);
                    }
                }
            }
            try { task(); } catch (...) {}
        }
    }

    void runReactorLoop() {
        for (;;) {
            std::deque<std::function<void()>> cmds;
            bool shouldStop = false;
            {
                std::lock_guard<std::mutex> lock(reactorMutex);
                cmds.swap(reactorCommands);
                shouldStop = reactorStopped;
            }
            for (auto &cmd : cmds) {
                try { cmd(); } catch (...) {}
            }
            if (shouldStop) {
                for (auto &p : pollables) {
                    if (p && !p->isFinished()) p->forceAbort("Protocol client cancelled");
                }
                pollables.clear();
                return;
            }

            const auto now = SteadyClock::now();
            auto earliest = now + std::chrono::milliseconds(50);
            for (auto &p : pollables) {
                if (!p || p->isFinished()) continue;
                p->onPollEvents(0, now);
                auto dl = p->nextDeadline();
                if (dl < earliest) earliest = dl;
            }
            for (auto &p : pollables) {
                if (p && p->isFinished()) {
                    auto fd = p->socketHandle();
                    if (fd >= 0) asyncPoller.removeInterest(fd);
                }
            }
            pollables.erase(std::remove_if(pollables.begin(), pollables.end(),
                [](const std::shared_ptr<ReactorPollable> &p) { return !p || p->isFinished(); }),
                pollables.end());

            int waitMs = 0;
            if (earliest > now) {
                waitMs = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(earliest - now).count());
                if (waitMs < 1) waitMs = 1;
                if (waitMs > 50) waitMs = 50;
            }
            {
                std::lock_guard<std::mutex> lock(reactorMutex);
                if (!reactorCommands.empty() || reactorStopped) waitMs = 0;
            }

            for (size_t i = 0; i < pollables.size(); ++i) {
                auto s = pollables[i]->socketHandle();
                if (s < 0) continue;
                short ev = pollables[i]->desiredPollEvents();
                short mask = 0;
                if (ev & POLLIN) mask |= platform_io::kEventRead;
                if (ev & POLLOUT) mask |= platform_io::kEventWrite;
                asyncPoller.updateInterest(s, mask, static_cast<uintptr_t>(i));
            }

            platform_io::ReadySocketEvent ready[platform_io::AsyncPoller::kMaxBatchEvents];
            size_t nReady = asyncPoller.wait(
                ready, platform_io::AsyncPoller::kMaxBatchEvents, waitMs, wakePair[0]);
            wakePending.store(false, std::memory_order_release);
            if (nReady > 0) {
                const auto afterWait = SteadyClock::now();
                for (size_t k = 0; k < nReady; ++k) {
                    const size_t idx = static_cast<size_t>(ready[k].token);
                    if (idx < pollables.size() && pollables[idx] &&
                        pollables[idx]->socketHandle() == ready[k].fd) {
                        short rev = 0;
                        if (ready[k].revents & platform_io::kEventRead) rev |= POLLIN;
                        if (ready[k].revents & platform_io::kEventWrite) rev |= POLLOUT;
                        if (ready[k].revents & platform_io::kEventError) rev |= POLLERR;
                        if (ready[k].revents & platform_io::kEventHangup) rev |= POLLHUP;
                        pollables[idx]->onPollEvents(rev, afterWait);
                    }
                }
            }
        }
    }

    unsigned int resolveInterfaceIndex(const std::string &name) {
        if (name.empty()) return 0;
        {
            std::lock_guard<std::mutex> lock(ifCacheMutex);
            auto it = ifCache.find(name);
            if (it != ifCache.end()) return it->second;
        }
        unsigned int idx = if_nametoindex(name.c_str());
#if defined(_WIN32)
        if (idx == 0) {
            std::wstring wname;
            if (platform::utf8ToWide(name, wname) && !wname.empty()) {
                NET_LUID luid{};
                if (::ConvertInterfaceAliasToLuid(wname.c_str(), &luid) == NO_ERROR ||
                    ::ConvertInterfaceNameToLuidW(wname.c_str(), &luid) == NO_ERROR) {
                    NET_IFINDEX resolvedIdx = 0;
                    if (::ConvertInterfaceLuidToIndex(&luid, &resolvedIdx) == NO_ERROR) {
                        idx = static_cast<unsigned int>(resolvedIdx);
                    }
                }
            }
        }
#endif
        if (idx != 0) {
            std::lock_guard<std::mutex> lock(ifCacheMutex);
            if (ifCache.size() >= 32) ifCache.clear();
            ifCache[name] = idx;
        }
        return idx;
    }

    void flushInterfaceCache() {
        std::lock_guard<std::mutex> lock(ifCacheMutex);
        ifCache.clear();
    }
};

namespace {

// ============================================================================
// WinTcpTlsChannel: Non-blocking TCP + OpenSSL Memory-BIO TLS 1.2/1.3 + Vision
// ============================================================================
class WinTcpTlsChannel final : public ReactorPollable,
                               public std::enable_shared_from_this<WinTcpTlsChannel> {
public:
    struct WriteItem {
        Buffer bytes;
        size_t offset = 0;
        bool shutdownAfter = false;
        WriteCallback completion;
    };

    WinTcpTlsChannel(WinTransportRuntime::Impl *runtime,
                     Node node,
                     TLSOptions tlsOpts,
                     double setupBudgetSeconds,
                     StreamCallback dialCallback)
        : runtime_(runtime),
          node_(std::move(node)),
          tlsOpts_(std::move(tlsOpts)),
          dialCallback_(std::move(dialCallback)),
          setupDeadline_(SteadyClock::now() + std::chrono::duration_cast<SteadyClock::duration>(
              std::chrono::duration<double>(std::clamp(setupBudgetSeconds, 0.2, 30.0)))) {}

    ~WinTcpTlsChannel() override {
        cleanupNative();
    }

    void startOnReactor() {
        if (runtime_->cancelled.load(std::memory_order_acquire)) {
            failChannel("Protocol client cancelled");
            return;
        }
        const std::string &dialHost = node_.dialHost();
        if (node_.port == 0 || dialHost.empty()) {
            failChannel("Invalid TCP target endpoint");
            return;
        }

        unsigned int ifIndex = 0;
        if (!node_.interfaceName.empty()) {
            ifIndex = runtime_->resolveInterfaceIndex(node_.interfaceName);
            if (ifIndex == 0) {
                failChannel("Configured outbound physical interface does not exist");
                return;
            }
        }

        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        // Prefer numeric literal; allow system resolution only when no connectHost pin was set
        std::string cleanDial = stripIpv6BracketsAndZone(dialHost);
        uint8_t tmpIp[16]{};
        if (inet_pton(AF_INET, cleanDial.c_str(), tmpIp) == 1 ||
            inet_pton(AF_INET6, cleanDial.c_str(), tmpIp) == 1) {
            hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        } else {
            hints.ai_flags = AI_NUMERICSERV;
        }
        int gai = ::getaddrinfo(cleanDial.c_str(), std::to_string(node_.port).c_str(), &hints, &res);
        if (gai != 0 || !res) {
            if (res) ::freeaddrinfo(res);
            failChannel("TCP address resolution failed");
            return;
        }

        bool initiated = false;
        for (auto *ai = res; ai != nullptr; ai = ai->ai_next) {
            platform::NativeSocket cand = platform::toNativeSocket(::socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP));
            if (cand < 0) continue;
            if (!platform::setNonBlockingAndCloexec(cand)) {
                platform::closeNativeSocket(cand);
                continue;
            }
            if (ai->ai_family == AF_INET6) {
                int v6Only = 0;
                (void)::setsockopt(platform::toOsSocket(cand), IPPROTO_IPV6, IPV6_V6ONLY,
                                   reinterpret_cast<const char *>(&v6Only), sizeof(v6Only));
            }
            int noDelay = 1;
            (void)::setsockopt(platform::toOsSocket(cand), IPPROTO_TCP, TCP_NODELAY,
                               reinterpret_cast<const char *>(&noDelay), sizeof(noDelay));
#ifdef SO_NOSIGPIPE
            int noSigPipe = 1;
            (void)::setsockopt(platform::toOsSocket(cand), SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));
#endif
            for (int sz : {4 * 1024 * 1024, 2 * 1024 * 1024, 512 * 1024}) {
                if (::setsockopt(platform::toOsSocket(cand), SOL_SOCKET, SO_RCVBUF,
                                 reinterpret_cast<const char *>(&sz), sizeof(sz)) == 0) break;
            }
            for (int sz : {4 * 1024 * 1024, 2 * 1024 * 1024, 512 * 1024}) {
                if (::setsockopt(platform::toOsSocket(cand), SOL_SOCKET, SO_SNDBUF,
                                 reinterpret_cast<const char *>(&sz), sizeof(sz)) == 0) break;
            }
            if (ifIndex != 0 && !isLoopbackSockaddr(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen))) {
                if (!platform::bindSocketToInterface(cand, ai->ai_family, ifIndex, node_.interfaceName)) {
                    platform::closeNativeSocket(cand);
                    continue;
                }
            }
            int rc = ::connect(platform::toOsSocket(cand), ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen));
            if (rc == 0) {
                sock_ = cand;
                initiated = true;
                onTcpConnected();
                break;
            }
            int err = platform::lastSocketError();
#if defined(_WIN32)
            const bool inProgress = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
            const bool inProgress = (err == EINPROGRESS || err == EWOULDBLOCK || err == EAGAIN);
#endif
            if (inProgress) {
                sock_ = cand;
                stage_ = Stage::Connecting;
                initiated = true;
                break;
            }
            platform::closeNativeSocket(cand);
        }
        ::freeaddrinfo(res);
        if (!initiated) {
            failChannel("TCP connect failed");
        }
    }

    platform::NativeSocket socketHandle() const noexcept override { return sock_; }

    short desiredPollEvents() const noexcept override {
        if (finished_ || sock_ < 0) return 0;
        if (stage_ == Stage::Connecting) return POLLOUT;
        short ev = 0;
        if (!wireOut_.empty() || (!appWrites_.empty() && (stage_ == Stage::Open))) {
            ev |= POLLOUT;
        }
        if (stage_ == Stage::TlsHandshaking || pendingRead_ ||
            (tlsEnabled_ && !visionDirectRead_ && decryptedIn_.size() < 262144)) {
            ev |= POLLIN;
        }
        return ev;
    }

    SteadyClock::time_point nextDeadline() const noexcept override {
        if (stage_ == Stage::Connecting || stage_ == Stage::TlsHandshaking) {
            return setupDeadline_;
        }
        return SteadyClock::now() + std::chrono::seconds(60);
    }

    bool isFinished() const noexcept override { return finished_; }

    void forceAbort(const Error &reason) override {
        failChannel(reason.empty() ? Error("Stream cancelled") : reason);
    }

    void onPollEvents(short revents, SteadyClock::time_point now) override {
        if (finished_) return;
        if (runtime_->cancelled.load(std::memory_order_acquire)) {
            failChannel("Protocol client cancelled");
            return;
        }
        if ((stage_ == Stage::Connecting || stage_ == Stage::TlsHandshaking) && now >= setupDeadline_) {
            failChannel("TCP/TLS handshake timed out");
            return;
        }
        if (stage_ == Stage::Connecting) {
            if (revents & (POLLOUT | POLLERR | POLLHUP)) {
                int soErr = 0;
                socklen_t errLen = sizeof(soErr);
                if (::getsockopt(platform::toOsSocket(sock_), SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char *>(&soErr), &errLen) != 0 || soErr != 0) {
                    failChannel("TCP connection refused or unreachable");
                    return;
                }
                onTcpConnected();
            }
            return;
        }

        if (revents & (POLLIN | POLLERR | POLLHUP)) {
            if (!pumpSocketRead()) return;
        }
        if (stage_ == Stage::TlsHandshaking) {
            if (!stepTlsHandshake()) return;
        }
        if (stage_ == Stage::Open) {
            pumpApplicationWritesToWire();
        }
        if (!wireOut_.empty()) {
            if (!flushWireOutput()) return;
        }
        if (stage_ == Stage::Open) {
            satisfyPendingRead();
            checkDeferredHalfClose();
        }
    }

    // Stream wrapper exposed on the application strand
    class StreamHandle final : public hajimi::Stream {
    public:
        StreamHandle(WinTransportRuntime::Impl *rt, std::shared_ptr<WinTcpTlsChannel> ch)
            : rt_(rt), ch_(std::move(ch)) {}
        ~StreamHandle() override { close(); }

        void write(Buffer data, WriteCallback completion) override {
            auto ch = ch_;
            if (!ch) { if (completion) completion("Stream closed"); return; }
            const size_t sz = data.size();
            size_t prev = ch->stagedWriteBytes_.load(std::memory_order_relaxed);
            do {
                if (sz > rt_->config.maxQueuedStreamBytes - prev) {
                    rt_->postStrand([completion] { if (completion) completion("TCP stream write queue limit exceeded"); });
                    return;
                }
            } while (!ch->stagedWriteBytes_.compare_exchange_weak(prev, prev + sz));

            rt_->postReactor([ch, data = std::move(data), completion = std::move(completion)]() mutable {
                ch->enqueueWriteOnReactor(std::move(data), false, std::move(completion));
            });
        }

        void shutdownWrite(WriteCallback completion) override {
            auto ch = ch_;
            if (!ch) { if (completion) completion("Stream closed"); return; }
            rt_->postReactor([ch, completion = std::move(completion)]() mutable {
                ch->enqueueWriteOnReactor({}, true, std::move(completion));
            });
        }

        void read(size_t maximum, ReadCallback completion) override {
            auto ch = ch_;
            if (!ch) { if (completion) completion({}, true, "Stream closed"); return; }
            rt_->postReactor([ch, maximum, completion = std::move(completion)]() mutable {
                ch->enqueueReadOnReactor(maximum, std::move(completion));
            });
        }

        void close() override {
            if (auto ch = std::exchange(ch_, nullptr)) {
                rt_->postReactor([ch] { ch->failChannel("Stream closed"); });
            }
        }

        bool supportsHalfClose() const override { return true; }
        bool supportsVisionDirect() const override { return true; }
        void enableVisionDirectWrite() override {
            if (auto ch = ch_) rt_->postReactor([ch] { ch->visionDirectWrite_ = true; });
        }
        void enableVisionDirectRead() override {
            if (auto ch = ch_) rt_->postReactor([ch] { ch->enableVisionDirectReadOnReactor(); });
        }

    private:
        WinTransportRuntime::Impl *rt_;
        std::shared_ptr<WinTcpTlsChannel> ch_;
    };

private:
    enum class Stage { Idle, Connecting, TlsHandshaking, Open, Closed };

    WinTransportRuntime::Impl *runtime_;
    Node node_;
    TLSOptions tlsOpts_;
    StreamCallback dialCallback_;
    SteadyClock::time_point setupDeadline_;

    platform::NativeSocket sock_ = platform::kInvalidSocket;
    Stage stage_ = Stage::Idle;
    bool finished_ = false;
    bool tlsEnabled_ = false;
    bool socketEOF_ = false;
    bool writeHalfClosed_ = false;
    bool visionDirectRead_ = false;
    bool visionDirectWrite_ = false;

    SSL_CTX *sslCtx_ = nullptr;
    SSL *ssl_ = nullptr;
    BIO *rbio_ = nullptr; // owned by ssl_ once SSL_set_bio is called
    BIO *wbio_ = nullptr;
    std::string verifyName_;

    proto_common::CursorBuffer rawSocketIn_;
    proto_common::CursorBuffer decryptedIn_;
    proto_common::CursorBuffer wireOut_;

    std::atomic<size_t> stagedWriteBytes_{0};
    std::deque<WriteItem> appWrites_;
    size_t pendingReadMax_ = 0;
    ReadCallback pendingRead_;

    void cleanupNative() noexcept {
        if (ssl_) {
            SSL_set_app_data(ssl_, nullptr);
            SSL_free(ssl_);
            ssl_ = nullptr;
            rbio_ = nullptr;
            wbio_ = nullptr;
        }
        if (sslCtx_) {
            SSL_CTX_free(sslCtx_);
            sslCtx_ = nullptr;
        }
        platform::closeNativeSocket(sock_);
    }

    void onTcpConnected() {
        tlsEnabled_ = tlsOpts_.enabled;
        if (!tlsEnabled_) {
            stage_ = Stage::Open;
            completeDialSuccess();
            return;
        }
        if (!initTlsEngine()) return;
        stage_ = Stage::TlsHandshaking;
        (void)stepTlsHandshake();
    }

    static int tlsVerifyCallback(X509_STORE_CTX *store, void *arg) {
        auto *self = static_cast<WinTcpTlsChannel *>(arg);
        if (!self || self->finished_ || self->runtime_->cancelled.load(std::memory_order_acquire)) {
            X509_STORE_CTX_set_error(store, X509_V_ERR_CERT_REJECTED);
            return 0;
        }
#if defined(_WIN32)
        bool ok = verifyWindowsSystemTrust(store, self->verifyName_);
        X509_STORE_CTX_set_error(store, ok ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
        return ok ? 1 : 0;
#else
        return X509_verify_cert(store);
#endif
    }

    bool initTlsEngine() {
        sslCtx_ = SSL_CTX_new(TLS_client_method());
        if (!sslCtx_) {
            failChannel("TLS context allocation failed");
            return false;
        }
        // RFC 8996 floor: TLS 1.2 minimum; TLS 1.3 minimum if ALPN is exclusively h3/doq
        bool requireTls13 = !tlsOpts_.alpn.empty();
        for (const auto &proto : tlsOpts_.alpn) {
            if (proto != "h3" && proto != "doq") { requireTls13 = false; break; }
        }
        if (!SSL_CTX_set_min_proto_version(sslCtx_, requireTls13 ? TLS1_3_VERSION : TLS1_2_VERSION)) {
            failChannel("TLS minimum version configuration failed");
            return false;
        }

        // RFC 10024 / FIPS 203 hybrid PQC group negotiation (default auto on TCP TLS)
        auto pqOpt = proto_common::lowerAscii(node_.option("pqc", node_.option("pq", "auto")));
        bool allowPqc = (pqOpt != "false" && pqOpt != "0" && pqOpt != "off" && pqOpt != "no");
#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
        if (!allowPqc || SSL_CTX_set1_groups_list(sslCtx_, "X25519MLKEM768:X25519:P-256:P-384") != 1) {
            ERR_clear_error();
            (void)SSL_CTX_set1_groups_list(sslCtx_, "X25519:P-256:P-384");
        }
#else
        ERR_set_mark();
        if (!allowPqc || SSL_CTX_set1_groups_list(sslCtx_, "*X25519MLKEM768:*X25519:P-256:P-384") != 1) {
            ERR_pop_to_mark();
            (void)SSL_CTX_set1_groups_list(sslCtx_, "X25519:P-256:P-384");
        } else {
            ERR_clear_last_mark();
        }
#endif

        verifyName_ = tlsOpts_.serverName.empty() ? node_.host : tlsOpts_.serverName;
        std::string caPath = node_.option("ca");
        SSL_CTX_set_verify(sslCtx_, tlsOpts_.skipVerify ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, nullptr);
        if (!tlsOpts_.skipVerify) {
            if (!caPath.empty()) {
                if (!loadPemCertStoreUTF8(sslCtx_, caPath)) {
                    failChannel("Configured TLS CA file could not be loaded");
                    return false;
                }
            } else {
#if defined(_WIN32)
                SSL_CTX_set_cert_verify_callback(sslCtx_, tlsVerifyCallback, this);
#elif defined(__APPLE__)
                if (!loadMacSystemRootCertificates(sslCtx_) && !SSL_CTX_set_default_verify_paths(sslCtx_)) {
                    failChannel("macOS System Keychain TLS trust store unavailable");
                    return false;
                }
#else
                if (!SSL_CTX_set_default_verify_paths(sslCtx_)) {
                    failChannel("System TLS trust store unavailable");
                    return false;
                }
#endif
            }
        }

        ssl_ = SSL_new(sslCtx_);
        rbio_ = BIO_new(BIO_s_mem());
        wbio_ = BIO_new(BIO_s_mem());
        if (!ssl_ || !rbio_ || !wbio_) {
            if (rbio_) BIO_free(rbio_);
            if (wbio_) BIO_free(wbio_);
            rbio_ = wbio_ = nullptr;
            failChannel("OpenSSL session/BIO allocation failed");
            return false;
        }
        BIO_set_mem_eof_return(rbio_, -1);
        BIO_set_mem_eof_return(wbio_, -1);
        SSL_set_bio(ssl_, rbio_, wbio_);
        SSL_set_connect_state(ssl_);

        std::string cleanSni = stripIpv6BracketsAndZone(verifyName_);
        uint8_t ipTmp[16]{};
        bool isIp = inet_pton(AF_INET, cleanSni.c_str(), ipTmp) == 1 ||
                    inet_pton(AF_INET6, cleanSni.c_str(), ipTmp) == 1;
        if (!isIp && !node_.flag("disable-sni") && !cleanSni.empty()) {
            if (!SSL_set_tlsext_host_name(ssl_, cleanSni.c_str())) {
                failChannel("TLS SNI configuration failed");
                return false;
            }
        }
        if (!tlsOpts_.skipVerify && !cleanSni.empty()) {
            X509_VERIFY_PARAM *param = SSL_get0_param(ssl_);
            if (isIp) {
                if (!X509_VERIFY_PARAM_set1_ip_asc(param, cleanSni.c_str())) {
                    failChannel("TLS IP verification parameter setup failed");
                    return false;
                }
            } else if (!SSL_set1_host(ssl_, cleanSni.c_str())) {
                failChannel("TLS hostname verification parameter setup failed");
                return false;
            }
        }

        if (!tlsOpts_.alpn.empty()) {
            Buffer wireAlpn;
            for (const auto &p : tlsOpts_.alpn) {
                if (p.empty() || p.size() > 255) {
                    failChannel("Invalid TLS ALPN protocol string");
                    return false;
                }
                wireAlpn.push_back(static_cast<uint8_t>(p.size()));
                wireAlpn.insert(wireAlpn.end(), p.begin(), p.end());
            }
            if (SSL_set_alpn_protos(ssl_, wireAlpn.data(), static_cast<unsigned int>(wireAlpn.size())) != 0) {
                failChannel("TLS ALPN setup failed");
                return false;
            }
        }
        return true;
    }

    void drainWbioToWire() {
        if (!wbio_) return;
        char chunk[16384];
        for (;;) {
            int n = BIO_read(wbio_, chunk, sizeof(chunk));
            if (n <= 0) break;
            wireOut_.append(reinterpret_cast<const uint8_t *>(chunk), static_cast<size_t>(n));
        }
    }

    bool stepTlsHandshake() {
        if (!ssl_ || stage_ != Stage::TlsHandshaking) return true;
        int rc = SSL_do_handshake(ssl_);
        drainWbioToWire();
        if (!wireOut_.empty() && !flushWireOutput()) return false;
        if (rc == 1) {
            if (!tlsOpts_.skipVerify && SSL_get_verify_result(ssl_) != X509_V_OK) {
                failChannel("TLS certificate verification failed");
                return false;
            }
            stage_ = Stage::Open;
            drainSslPlaintext();
            completeDialSuccess();
            return true;
        }
        int sslErr = SSL_get_error(ssl_, rc);
        if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
            if (socketEOF_ && BIO_ctrl_pending(rbio_) == 0) {
                failChannel("Peer closed connection during TLS handshake");
                return false;
            }
            return true;
        }
        failChannel("TLS handshake failed");
        return false;
    }

    void drainSslPlaintext() {
        if (!ssl_ || visionDirectRead_) return;
        uint8_t buf[32768];
        while (decryptedIn_.size() < 512 * 1024) {
            int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n > 0) {
                decryptedIn_.append(buf, static_cast<size_t>(n));
                continue;
            }
            int sslErr = SSL_get_error(ssl_, n);
            if (sslErr == SSL_ERROR_ZERO_RETURN) {
                socketEOF_ = true;
                break;
            }
            if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
                drainWbioToWire();
                break;
            }
            failChannel("TLS record decryption failed");
            return;
        }
    }

    bool pumpSocketRead() {
        if (sock_ < 0 || socketEOF_) return true;
        uint8_t buf[65536];
        for (int iter = 0; iter < 16; ++iter) {
            ssize_t n = ::recv(platform::toOsSocket(sock_), reinterpret_cast<char *>(buf), sizeof(buf), 0);
            if (n > 0) {
                if (tlsEnabled_ && !visionDirectRead_) {
                    int written = BIO_write(rbio_, buf, static_cast<int>(n));
                    if (written <= 0) {
                        failChannel("TLS BIO buffer write failed");
                        return false;
                    }
                    if (stage_ == Stage::Open) {
                        drainSslPlaintext();
                        if (finished_) return false;
                    }
                } else {
                    rawSocketIn_.append(buf, static_cast<size_t>(n));
                }
                continue;
            }
            if (n == 0) {
                socketEOF_ = true;
                if (tlsEnabled_ && stage_ == Stage::Open && !visionDirectRead_) {
                    drainSslPlaintext();
                }
                break;
            }
            int err = platform::lastSocketError();
            if (platform::isSocketWouldBlock(err)) break;
            if (err == EINTR
#if defined(_WIN32)
                || err == WSAEINTR
#endif
            ) continue;
            failChannel("TCP socket receive failed");
            return false;
        }
        return !finished_;
    }

    void enableVisionDirectReadOnReactor() {
        if (visionDirectRead_) return;
        if (tlsEnabled_ && ssl_) {
            drainSslPlaintext();
            // Move any unconsumed bytes already sitting in rbio_ to rawSocketIn_
            char leftover[16384];
            for (;;) {
                int n = BIO_read(rbio_, leftover, sizeof(leftover));
                if (n <= 0) break;
                rawSocketIn_.append(reinterpret_cast<const uint8_t *>(leftover), static_cast<size_t>(n));
            }
        }
        visionDirectRead_ = true;
    }

    void pumpApplicationWritesToWire() {
        if (stage_ != Stage::Open || appWrites_.empty()) return;
        const size_t maxBatch = runtime_->config.maxCoalescedSendBytes;

        while (!appWrites_.empty() && wireOut_.size() < maxBatch) {
            auto &front = appWrites_.front();
            if (front.bytes.empty() && front.shutdownAfter) {
                break; // Handled by checkDeferredHalfClose once wireOut_ drains
            }
            if (!tlsEnabled_ || visionDirectWrite_) {
                // Coalesce contiguous chunks for scatter-gather WSASend
                size_t rem = front.bytes.size() - front.offset;
                wireOut_.append(front.bytes.data() + front.offset, rem);
                stagedWriteBytes_.fetch_sub(front.bytes.size(), std::memory_order_relaxed);
                auto cb = std::move(front.completion);
                bool needHalfClose = front.shutdownAfter;
                appWrites_.pop_front();
                if (cb) runtime_->postStrand([cb] { cb({}); });
                if (needHalfClose) {
                    appWrites_.push_front({{}, 0, true, {}});
                    break;
                }
            } else {
                // Coalesce up to maxBatch plaintext into a single SSL_write pass
                Buffer batch;
                std::vector<WriteCallback> cbs;
                bool hitHalfClose = false;
                while (!appWrites_.empty() && batch.size() < maxBatch) {
                    auto &item = appWrites_.front();
                    if (item.bytes.empty() && item.shutdownAfter) {
                        hitHalfClose = true;
                        break;
                    }
                    if (!batch.empty() && batch.size() + item.bytes.size() > maxBatch) break;
                    batch.insert(batch.end(), item.bytes.begin(), item.bytes.end());
                    stagedWriteBytes_.fetch_sub(item.bytes.size(), std::memory_order_relaxed);
                    if (item.completion) cbs.push_back(std::move(item.completion));
                    if (item.shutdownAfter) {
                        appWrites_.pop_front();
                        appWrites_.push_front({{}, 0, true, {}});
                        hitHalfClose = true;
                        break;
                    }
                    appWrites_.pop_front();
                }
                if (!batch.empty()) {
                    size_t off = 0;
                    while (off < batch.size()) {
                        int n = SSL_write(ssl_, batch.data() + off, static_cast<int>(batch.size() - off));
                        if (n <= 0) {
                            failChannel("TLS record encryption failed");
                            return;
                        }
                        off += static_cast<size_t>(n);
                    }
                    drainWbioToWire();
                    for (auto &cb : cbs) {
                        runtime_->postStrand([cb] { cb({}); });
                    }
                }
                if (hitHalfClose) break;
            }
        }
    }

    bool flushWireOutput() {
        if (sock_ < 0 || wireOut_.empty()) return true;
        while (!wireOut_.empty()) {
            const size_t chunk = (std::min)(wireOut_.size(), runtime_->config.maxCoalescedSendBytes);
#if defined(_WIN32)
            WSABUF wsaBuf{static_cast<ULONG>(chunk),
                          const_cast<CHAR *>(reinterpret_cast<const CHAR *>(wireOut_.data()))};
            DWORD sent = 0;
            int rc = ::WSASend(platform::toOsSocket(sock_), &wsaBuf, 1, &sent, 0, nullptr, nullptr);
            if (rc == SOCKET_ERROR) {
                int err = platform::lastSocketError();
                if (platform::isSocketWouldBlock(err)) return true;
                if (err == WSAEINTR) continue;
                failChannel("TCP socket send failed");
                return false;
            }
            if (sent == 0) return true;
            wireOut_.consume(static_cast<size_t>(sent));
#else
            ssize_t sent = ::send(sock_, wireOut_.data(), chunk, 0);
            if (sent < 0) {
                if (platform::isSocketWouldBlock(errno)) return true;
                if (errno == EINTR) continue;
                failChannel("TCP socket send failed");
                return false;
            }
            if (sent == 0) return true;
            wireOut_.consume(static_cast<size_t>(sent));
#endif
        }
        return true;
    }

    void checkDeferredHalfClose() {
        if (writeHalfClosed_ || !wireOut_.empty() || appWrites_.empty()) return;
        auto &front = appWrites_.front();
        if (!front.bytes.empty() || !front.shutdownAfter) return;
        if (tlsEnabled_ && ssl_ && !visionDirectWrite_) {
            (void)SSL_shutdown(ssl_);
            drainWbioToWire();
            if (!wireOut_.empty() && !flushWireOutput()) return;
            if (!wireOut_.empty()) return; // Wait for close_notify bytes to flush
        }
        writeHalfClosed_ = true;
#if defined(_WIN32)
        (void)::shutdown(platform::toOsSocket(sock_), SD_SEND);
#else
        (void)::shutdown(sock_, SHUT_WR);
#endif
        auto cb = std::move(front.completion);
        appWrites_.pop_front();
        if (cb) runtime_->postStrand([cb] { cb({}); });
    }

    void satisfyPendingRead() {
        if (!pendingRead_ || stage_ != Stage::Open) return;
        Buffer out;
        if (!decryptedIn_.empty()) {
            size_t take = (std::min)(pendingReadMax_, decryptedIn_.size());
            out = decryptedIn_.consume(take);
        } else if (!rawSocketIn_.empty()) {
            size_t take = (std::min)(pendingReadMax_, rawSocketIn_.size());
            out = rawSocketIn_.consume(take);
        }
        if (out.empty() && !socketEOF_) return;
        bool atEof = socketEOF_ && decryptedIn_.empty() && rawSocketIn_.empty();
        auto cb = std::move(pendingRead_);
        pendingRead_ = {};
        pendingReadMax_ = 0;
        runtime_->postStrand([cb = std::move(cb), out = std::move(out), atEof]() mutable {
            cb(std::move(out), atEof, {});
        });
    }

    void enqueueWriteOnReactor(Buffer data, bool shutdownAfter, WriteCallback completion) {
        if (finished_ || writeHalfClosed_) {
            stagedWriteBytes_.fetch_sub(data.size(), std::memory_order_relaxed);
            if (completion) runtime_->postStrand([completion] { completion("Stream closed for writing"); });
            return;
        }
        if (data.empty() && !shutdownAfter) {
            if (completion) runtime_->postStrand([completion] { completion({}); });
            return;
        }
        appWrites_.push_back({std::move(data), 0, shutdownAfter, std::move(completion)});
        if (stage_ == Stage::Open) {
            pumpApplicationWritesToWire();
            if (!wireOut_.empty()) (void)flushWireOutput();
            checkDeferredHalfClose();
        }
    }

    void enqueueReadOnReactor(size_t maximum, ReadCallback completion) {
        if (finished_) {
            if (completion) runtime_->postStrand([completion] { completion({}, true, "Stream closed"); });
            return;
        }
        if (pendingRead_ || maximum == 0 || maximum > maximumReadBytes) {
            if (completion) runtime_->postStrand([completion] { completion({}, false, "Invalid or concurrent stream read"); });
            return;
        }
        pendingReadMax_ = maximum;
        pendingRead_ = std::move(completion);
        if (stage_ == Stage::Open) {
            if (tlsEnabled_ && !visionDirectRead_) drainSslPlaintext();
            if (!finished_) satisfyPendingRead();
        }
    }

    void completeDialSuccess() {
        if (!dialCallback_) return;
        auto cb = std::move(dialCallback_);
        dialCallback_ = {};
        auto handle = std::make_shared<StreamHandle>(runtime_, shared_from_this());
        runtime_->postStrand([cb = std::move(cb), handle = std::move(handle)]() mutable {
            cb(std::move(handle), {});
        });
    }

    void failChannel(Error reason) {
        if (finished_) return;
        finished_ = true;
        stage_ = Stage::Closed;
        cleanupNative();

        auto dialCb = std::move(dialCallback_);
        dialCallback_ = {};
        auto readCb = std::move(pendingRead_);
        pendingRead_ = {};
        std::vector<WriteCallback> writeCbs;
        while (!appWrites_.empty()) {
            stagedWriteBytes_.fetch_sub(appWrites_.front().bytes.size(), std::memory_order_relaxed);
            if (appWrites_.front().completion) writeCbs.push_back(std::move(appWrites_.front().completion));
            appWrites_.pop_front();
        }
        rawSocketIn_.clear();
        decryptedIn_.clear();
        wireOut_.clear();

        if (dialCb) {
            runtime_->postStrand([dialCb = std::move(dialCb), reason] { dialCb(nullptr, reason); });
        }
        if (readCb) {
            runtime_->postStrand([readCb = std::move(readCb), reason] { readCb({}, true, reason); });
        }
        for (auto &wcb : writeCbs) {
            runtime_->postStrand([wcb = std::move(wcb), reason] { wcb(reason); });
        }
    }
};

// ============================================================================
// WinUdpChannel: Non-blocking UDP session with SIO_UDP_CONNRESET & IF pinning
// ============================================================================
class WinUdpChannel final : public ReactorPollable,
                            public std::enable_shared_from_this<WinUdpChannel> {
public:
    struct PendingDatagram {
        sockaddr_storage dest{};
        socklen_t destLen = 0;
        Buffer payload;
        WriteCallback completion;
    };

    WinUdpChannel(WinTransportRuntime::Impl *runtime, Node node, DatagramCallback dialCallback)
        : runtime_(runtime), node_(std::move(node)), dialCallback_(std::move(dialCallback)) {}

    ~WinUdpChannel() override {
        platform::closeNativeSocket(sock_);
    }

    void startOnReactor() {
        if (runtime_->cancelled.load(std::memory_order_acquire)) {
            failChannel("Native UDP connection cancelled");
            return;
        }
        unsigned int ifIndex = 0;
        if (!node_.interfaceName.empty()) {
            ifIndex = runtime_->resolveInterfaceIndex(node_.interfaceName);
            if (ifIndex == 0) {
                failChannel("Configured UDP physical interface does not exist");
                return;
            }
        }

        // Determine socket family from dialHost (default AF_INET, or AF_INET6 for IPv6 literal)
        int family = AF_INET;
        sockaddr_storage remoteHint{};
        socklen_t remoteHintLen = 0;
        bool hasRemoteHint = parseNumericEndpoint(node_.dialHost(), node_.port, remoteHint, remoteHintLen);
        if (hasRemoteHint) {
            family = remoteHint.ss_family;
        } else if (node_.dialHost().find(':') != std::string::npos) {
            family = AF_INET6;
        }

        platform::NativeSocket s = platform::toNativeSocket(::socket(family, SOCK_DGRAM, IPPROTO_UDP));
        if (s < 0 || !platform::setNonBlockingAndCloexec(s)) {
            platform::closeNativeSocket(s);
            failChannel("Native UDP socket creation failed");
            return;
        }
        platform::disableUdpConnReset(s);
        if (family == AF_INET6) {
            int v6Only = 0;
            (void)::setsockopt(platform::toOsSocket(s), IPPROTO_IPV6, IPV6_V6ONLY,
                               reinterpret_cast<const char *>(&v6Only), sizeof(v6Only));
        }
        for (int sz : {4 * 1024 * 1024, 2 * 1024 * 1024, 512 * 1024}) {
            if (::setsockopt(platform::toOsSocket(s), SOL_SOCKET, SO_RCVBUF,
                             reinterpret_cast<const char *>(&sz), sizeof(sz)) == 0) break;
        }
        for (int sz : {4 * 1024 * 1024, 2 * 1024 * 1024, 512 * 1024}) {
            if (::setsockopt(platform::toOsSocket(s), SOL_SOCKET, SO_SNDBUF,
                             reinterpret_cast<const char *>(&sz), sizeof(sz)) == 0) break;
        }
        if (ifIndex != 0 && (!hasRemoteHint || !isLoopbackSockaddr(reinterpret_cast<sockaddr *>(&remoteHint), remoteHintLen))) {
            if (!platform::bindSocketToInterface(s, family, ifIndex, node_.interfaceName)) {
                platform::closeNativeSocket(s);
                failChannel("Native UDP physical interface bind failed");
                return;
            }
        }

        // Bind ephemeral local port so replies can arrive immediately
        if (family == AF_INET) {
            sockaddr_in bind4{};
            bind4.sin_family = AF_INET;
            bind4.sin_addr.s_addr = (hasRemoteHint && isLoopbackSockaddr(reinterpret_cast<sockaddr *>(&remoteHint), remoteHintLen))
                ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
            if (::bind(platform::toOsSocket(s), reinterpret_cast<sockaddr *>(&bind4), sizeof(bind4)) != 0) {
                platform::closeNativeSocket(s);
                failChannel("Native UDP bind failed");
                return;
            }
        } else {
            sockaddr_in6 bind6{};
            bind6.sin6_family = AF_INET6;
            bind6.sin6_addr = (hasRemoteHint && isLoopbackSockaddr(reinterpret_cast<sockaddr *>(&remoteHint), remoteHintLen))
                ? in6addr_loopback : in6addr_any;
            if (::bind(platform::toOsSocket(s), reinterpret_cast<sockaddr *>(&bind6), sizeof(bind6)) != 0) {
                platform::closeNativeSocket(s);
                failChannel("Native UDP IPv6 bind failed");
                return;
            }
        }

        sock_ = s;
        family_ = family;
        auto cb = std::move(dialCallback_);
        dialCallback_ = {};
        auto handle = std::make_shared<DatagramHandle>(runtime_, shared_from_this());
        runtime_->postStrand([cb = std::move(cb), handle = std::move(handle)]() mutable {
            cb(std::move(handle), {});
        });
    }

    platform::NativeSocket socketHandle() const noexcept override { return sock_; }

    short desiredPollEvents() const noexcept override {
        if (finished_ || sock_ < 0) return 0;
        short ev = startedReceiving_ ? POLLIN : 0;
        if (!sendQueue_.empty()) ev |= POLLOUT;
        return ev;
    }

    SteadyClock::time_point nextDeadline() const noexcept override {
        return SteadyClock::now() + std::chrono::seconds(60);
    }

    bool isFinished() const noexcept override { return finished_; }

    void forceAbort(const Error &reason) override {
        failChannel(reason.empty() ? Error("UDP transport closed") : reason);
    }

    void onPollEvents(short revents, SteadyClock::time_point) override {
        if (finished_) return;
        if (runtime_->cancelled.load(std::memory_order_acquire)) {
            failChannel("Native UDP connection cancelled");
            return;
        }
        if (revents & (POLLOUT)) {
            flushSendQueue();
        }
        if (startedReceiving_ && (revents & (POLLIN | POLLERR | POLLHUP))) {
            pumpReceive();
        }
    }

    class DatagramHandle final : public hajimi::Datagram {
    public:
        DatagramHandle(WinTransportRuntime::Impl *rt, std::shared_ptr<WinUdpChannel> ch)
            : rt_(rt), ch_(std::move(ch)) {}
        ~DatagramHandle() override { close(); }

        void send(Target target, Buffer data, WriteCallback completion) override {
            auto ch = ch_;
            if (!ch) { if (completion) completion("UDP transport closed"); return; }
            if (data.size() > 65507) {
                rt_->postStrand([completion] { if (completion) completion("UDP datagram exceeds 65507-byte limit"); });
                return;
            }
            const size_t sz = data.size();
            size_t prev = ch->stagedBytes_.load(std::memory_order_relaxed);
            do {
                if (sz > rt_->config.maxQueuedStreamBytes - prev) {
                    rt_->postStrand([completion] { if (completion) completion("UDP send queue limit exceeded"); });
                    return;
                }
            } while (!ch->stagedBytes_.compare_exchange_weak(prev, prev + sz));

            rt_->postReactor([ch, target = std::move(target), data = std::move(data), completion = std::move(completion)]() mutable {
                ch->enqueueSendOnReactor(std::move(target), std::move(data), std::move(completion));
            });
        }

        void start(PacketCallback receive, WriteCallback failure) override {
            auto ch = ch_;
            if (!ch) { if (failure) failure("UDP transport closed"); return; }
            rt_->postReactor([ch, receive = std::move(receive), failure = std::move(failure)]() mutable {
                ch->startReceiveOnReactor(std::move(receive), std::move(failure));
            });
        }

        void close() override {
            if (auto ch = std::exchange(ch_, nullptr)) {
                rt_->postReactor([ch] { ch->failChannel("UDP transport closed"); });
            }
        }

    private:
        WinTransportRuntime::Impl *rt_;
        std::shared_ptr<WinUdpChannel> ch_;
    };

private:
    WinTransportRuntime::Impl *runtime_;
    Node node_;
    DatagramCallback dialCallback_;
    platform::NativeSocket sock_ = platform::kInvalidSocket;
    int family_ = AF_INET;
    bool finished_ = false;
    bool startedReceiving_ = false;

    std::atomic<size_t> stagedBytes_{0};
    std::deque<PendingDatagram> sendQueue_;
    PacketCallback packetReceive_;
    WriteCallback failureCallback_;

    void enqueueSendOnReactor(Target target, Buffer data, WriteCallback completion) {
        if (finished_ || sock_ < 0) {
            stagedBytes_.fetch_sub(data.size(), std::memory_order_relaxed);
            if (completion) runtime_->postStrand([completion] { completion("UDP transport closed"); });
            return;
        }
        const std::string host = target.host.empty() ? node_.dialHost() : target.host;
        const uint16_t port = target.port ? target.port : node_.port;
        PendingDatagram item;
        if (!parseNumericEndpoint(host, port, item.dest, item.destLen)) {
            // Convert IPv4-mapped IPv6 if socket is dual-stack AF_INET6
            stagedBytes_.fetch_sub(data.size(), std::memory_order_relaxed);
            if (completion) runtime_->postStrand([completion] { completion("UDP target must be a numeric IP literal"); });
            return;
        }
        if (family_ == AF_INET6 && item.dest.ss_family == AF_INET) {
            sockaddr_in v4{};
            std::memcpy(&v4, &item.dest, sizeof(v4));
            sockaddr_in6 mapped{};
            mapped.sin6_family = AF_INET6;
            mapped.sin6_port = v4.sin_port;
            mapped.sin6_addr.s6_addr[10] = 0xff;
            mapped.sin6_addr.s6_addr[11] = 0xff;
            std::memcpy(&mapped.sin6_addr.s6_addr[12], &v4.sin_addr, 4);
            std::memcpy(&item.dest, &mapped, sizeof(mapped));
            item.destLen = sizeof(mapped);
        }
        item.payload = std::move(data);
        item.completion = std::move(completion);
        sendQueue_.push_back(std::move(item));
        flushSendQueue();
    }

    void flushSendQueue() {
        while (!sendQueue_.empty() && sock_ >= 0 && !finished_) {
            auto &front = sendQueue_.front();
            ssize_t sent = ::sendto(platform::toOsSocket(sock_),
                                    reinterpret_cast<const char *>(front.payload.data()),
                                    static_cast<int>(front.payload.size()), 0,
                                    reinterpret_cast<const sockaddr *>(&front.dest),
                                    front.destLen);
            if (sent < 0) {
                int err = platform::lastSocketError();
                if (platform::isSocketWouldBlock(err)) return;
                if (platform::isSocketInterruptedOrTransient(err)) {
                    stagedBytes_.fetch_sub(front.payload.size(), std::memory_order_relaxed);
                    auto cb = std::move(front.completion);
                    sendQueue_.pop_front();
                    if (cb) runtime_->postStrand([cb] { cb({}); });
                    continue;
                }
                failChannel("UDP transport send failed");
                return;
            }
            stagedBytes_.fetch_sub(front.payload.size(), std::memory_order_relaxed);
            auto cb = std::move(front.completion);
            sendQueue_.pop_front();
            if (cb) runtime_->postStrand([cb] { cb({}); });
        }
    }

    void startReceiveOnReactor(PacketCallback receive, WriteCallback failure) {
        if (finished_) {
            if (failure) runtime_->postStrand([failure] { failure("UDP transport closed"); });
            return;
        }
        packetReceive_ = std::move(receive);
        failureCallback_ = std::move(failure);
        startedReceiving_ = true;
        pumpReceive();
    }

    void pumpReceive() {
        if (sock_ < 0 || finished_ || !packetReceive_) return;
        uint8_t buf[65536];
        for (int iter = 0; iter < 64; ++iter) {
            sockaddr_storage src{};
            socklen_t srcLen = sizeof(src);
            ssize_t n = ::recvfrom(platform::toOsSocket(sock_),
                                   reinterpret_cast<char *>(buf), sizeof(buf), 0,
                                   reinterpret_cast<sockaddr *>(&src), &srcLen);
            if (n < 0) {
                int err = platform::lastSocketError();
                if (platform::isSocketWouldBlock(err)) return;
                if (platform::isSocketInterruptedOrTransient(err) || platform::isSocketMsgSize(err)) continue;
                failChannel("UDP transport receive failed");
                return;
            }
            Target sender;
            if (!formatSockaddrEndpoint(src, sender)) continue;
            Buffer pkt(buf, buf + n);
            auto cb = packetReceive_;
            runtime_->postStrand([cb, sender = std::move(sender), pkt = std::move(pkt)]() mutable {
                cb(std::move(sender), std::move(pkt));
            });
        }
    }

    void failChannel(Error reason) {
        if (finished_) return;
        finished_ = true;
        platform::closeNativeSocket(sock_);

        auto dialCb = std::move(dialCallback_);
        dialCallback_ = {};
        auto failCb = std::move(failureCallback_);
        failureCallback_ = {};
        packetReceive_ = {};

        std::vector<WriteCallback> sendCbs;
        while (!sendQueue_.empty()) {
            stagedBytes_.fetch_sub(sendQueue_.front().payload.size(), std::memory_order_relaxed);
            if (sendQueue_.front().completion) sendCbs.push_back(std::move(sendQueue_.front().completion));
            sendQueue_.pop_front();
        }
        if (dialCb) runtime_->postStrand([dialCb = std::move(dialCb), reason] { dialCb(nullptr, reason); });
        for (auto &scb : sendCbs) runtime_->postStrand([scb = std::move(scb), reason] { scb(reason); });
        if (failCb) runtime_->postStrand([failCb = std::move(failCb), reason] { failCb(reason); });
    }
};

} // namespace

// ============================================================================
// WinTransportRuntime Public Methods
// ============================================================================
WinTransportRuntime::WinTransportRuntime(const RuntimeConfig &config)
    : impl_(std::make_unique<Impl>(config)) {}

WinTransportRuntime::~WinTransportRuntime() = default;

std::shared_ptr<WinTransportRuntime> WinTransportRuntime::create(const RuntimeConfig &config) {
    return std::shared_ptr<WinTransportRuntime>(new WinTransportRuntime(config));
}

std::shared_ptr<hajimi::TransportFactory> WinTransportRuntime::makeFactory(double setupDeadlineSeconds) {
    auto self = shared_from_this();
    auto factory = std::make_shared<hajimi::TransportFactory>();
    factory->remainingDeadlineSeconds = hajimi::ProtocolTimeouts::clampSetupBudget(setupDeadlineSeconds);
    factory->cancelled = [self] {
        return self->impl_->cancelled.load(std::memory_order_acquire);
    };
    factory->post = [self](std::function<void()> work) {
        self->impl_->postStrand(std::move(work));
    };
    factory->after = [self](double seconds, std::function<void()> work) {
        self->impl_->postAfter(seconds, std::move(work));
    };
    factory->tcp = [self](const Node &node, const TLSOptions &tls, StreamCallback completion) {
        double budget = self->impl_->config.tcpHandshakeTimeoutSeconds;
        auto ch = std::make_shared<WinTcpTlsChannel>(
            self->impl_.get(), node, tls, budget, std::move(completion));
        self->impl_->postReactor([self, ch] {
            self->impl_->pollables.push_back(ch);
            ch->startOnReactor();
        });
    };
    factory->udp = [self](const Node &node, DatagramCallback completion) {
        auto ch = std::make_shared<WinUdpChannel>(
            self->impl_.get(), node, std::move(completion));
        self->impl_->postReactor([self, ch] {
            self->impl_->pollables.push_back(ch);
            ch->startOnReactor();
        });
    };
    return factory;
}

void WinTransportRuntime::cancelAll() { impl_->cancelAll(); }
void WinTransportRuntime::shutdown() { impl_->shutdown(); }
void WinTransportRuntime::flushInterfaceCache() { impl_->flushInterfaceCache(); }
unsigned int WinTransportRuntime::resolveInterfaceIndex(const std::string &interfaceName) {
    return impl_->resolveInterfaceIndex(interfaceName);
}

} // namespace hajimi::win_transport

// ============================================================================
// Offline Loopback Self-Test Suite (Zero Host Route/Network Side Effects)
// ============================================================================
extern "C" int hajimi_win_transport_self_test(void) {
    using namespace hajimi;
    using namespace hajimi::win_transport;

    try {
        platform::ensureWinsock();

        // 1. Strand FIFO ordering & post-cancellation cleanup delivery contract
        {
            auto rt = WinTransportRuntime::create();
            auto factory = rt->makeFactory();
            std::mutex m;
            std::condition_variable cv;
            std::vector<int> order;
            bool timerDelivered = false;
            bool postCancelDelivered = false;

            for (int i = 1; i <= 4; ++i) {
                factory->post([&, i] {
                    std::lock_guard<std::mutex> g(m);
                    order.push_back(i);
                });
            }
            factory->after(0.015, [&] {
                std::lock_guard<std::mutex> g(m);
                timerDelivered = true;
                cv.notify_all();
            });
            {
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(3), [&] { return timerDelivered; })) return 1;
                if (order != std::vector<int>({1, 2, 3, 4})) return 2;
            }

            rt->cancelAll();
            if (!factory->cancelled()) return 3;
            // Cleanup callbacks posted after cancelAll() MUST still execute before shutdown()
            factory->post([&] {
                std::lock_guard<std::mutex> g(m);
                postCancelDelivered = true;
                cv.notify_all();
            });
            {
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(3), [&] { return postCancelDelivered; })) return 4;
            }
            rt->shutdown();
        }

        // 2. TCP loopback 256 KiB coalesced write + half-close FIN round-trip
        {
            platform::NativeSocket listener = platform::toNativeSocket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
            if (listener < 0) return 10;
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t addrLen = sizeof(addr);
            if (::bind(platform::toOsSocket(listener), reinterpret_cast<sockaddr *>(&addr), addrLen) != 0 ||
                ::getsockname(platform::toOsSocket(listener), reinterpret_cast<sockaddr *>(&addr), &addrLen) != 0 ||
                ::listen(platform::toOsSocket(listener), 2) != 0) {
                platform::closeNativeSocket(listener);
                return 11;
            }
            const uint16_t port = ntohs(addr.sin_port);

            std::thread echoPeer([listener] {
                platform::NativeSocket client = platform::toNativeSocket(
                    ::accept(platform::toOsSocket(listener), nullptr, nullptr));
                platform::NativeSocket ownedListener = listener;
                platform::closeNativeSocket(ownedListener);
                if (client < 0) return;
                char buf[32768];
                for (;;) {
                    ssize_t n = ::recv(platform::toOsSocket(client), buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    size_t off = 0;
                    while (off < static_cast<size_t>(n)) {
                        ssize_t s = ::send(platform::toOsSocket(client), buf + off, static_cast<int>(n - off), 0);
                        if (s <= 0) break;
                        off += static_cast<size_t>(s);
                    }
                }
                platform::closeNativeSocket(client);
            });

            auto rt = WinTransportRuntime::create();
            auto factory = rt->makeFactory();
            Node node;
            node.host = "127.0.0.1";
            node.connectHost = "127.0.0.1";
            node.port = port;

            std::mutex m;
            std::condition_variable cv;
            bool finished = false;
            int stepErr = 0;
            Buffer expected(262144);
            for (size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<uint8_t>((i * 131 + 17) & 0xff);
            Buffer received;

            factory->tcp(node, {}, [&](std::shared_ptr<Stream> stream, Error err) {
                if (!err.empty() || !stream) {
                    std::lock_guard<std::mutex> g(m); stepErr = 12; finished = true; cv.notify_all(); return;
                }
                // Issue 4 back-to-back 64 KiB writes + half-close to exercise 128 KiB coalescing
                for (size_t chunk = 0; chunk < 4; ++chunk) {
                    Buffer slice(expected.begin() + chunk * 65536, expected.begin() + (chunk + 1) * 65536);
                    stream->write(std::move(slice), [&](Error werr) {
                        if (!werr.empty()) { std::lock_guard<std::mutex> g(m); stepErr = 13; finished = true; cv.notify_all(); }
                    });
                }
                stream->shutdownWrite([&](Error serr) {
                    if (!serr.empty()) { std::lock_guard<std::mutex> g(m); stepErr = 14; finished = true; cv.notify_all(); }
                });

                auto pumpRead = std::make_shared<std::function<void()>>();
                *pumpRead = [&, stream, pumpRead] {
                    stream->read(65536, [&, stream, pumpRead](Buffer chunk, bool eof, Error rerr) {
                        if (!rerr.empty()) {
                            std::lock_guard<std::mutex> g(m); stepErr = 15; finished = true; cv.notify_all(); return;
                        }
                        received.insert(received.end(), chunk.begin(), chunk.end());
                        if (eof) {
                            std::lock_guard<std::mutex> g(m);
                            if (received != expected) stepErr = 16;
                            finished = true;
                            cv.notify_all();
                            return;
                        }
                        (*pumpRead)();
                    });
                };
                (*pumpRead)();
            });

            {
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(8), [&] { return finished; })) stepErr = 17;
            }
            echoPeer.join();
            rt->shutdown();
            if (stepErr != 0) return stepErr;
        }

        // 3. UDP loopback echo + SIO_UDP_CONNRESET closed-port immunity
        {
            platform::NativeSocket udpPeer = platform::toNativeSocket(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
            if (udpPeer < 0) return 20;
            platform::disableUdpConnReset(udpPeer);
            sockaddr_in peerAddr{};
            peerAddr.sin_family = AF_INET;
            peerAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t peerLen = sizeof(peerAddr);
            if (::bind(platform::toOsSocket(udpPeer), reinterpret_cast<sockaddr *>(&peerAddr), peerLen) != 0 ||
                ::getsockname(platform::toOsSocket(udpPeer), reinterpret_cast<sockaddr *>(&peerAddr), &peerLen) != 0) {
                platform::closeNativeSocket(udpPeer);
                return 21;
            }
            const uint16_t echoPort = ntohs(peerAddr.sin_port);

            // Reserve and close a second UDP port to trigger ICMP Port Unreachable on loopback
            platform::NativeSocket closedSock = platform::toNativeSocket(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
            sockaddr_in closedAddr{};
            closedAddr.sin_family = AF_INET;
            closedAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t closedLen = sizeof(closedAddr);
            (void)::bind(platform::toOsSocket(closedSock), reinterpret_cast<sockaddr *>(&closedAddr), closedLen);
            (void)::getsockname(platform::toOsSocket(closedSock), reinterpret_cast<sockaddr *>(&closedAddr), &closedLen);
            const uint16_t deadPort = ntohs(closedAddr.sin_port);
            platform::closeNativeSocket(closedSock);

            std::thread udpEcho([udpPeer] {
                char buf[4096];
                sockaddr_in client{};
                socklen_t clen = sizeof(client);
                ssize_t n = ::recvfrom(platform::toOsSocket(udpPeer), buf, sizeof(buf), 0,
                                       reinterpret_cast<sockaddr *>(&client), &clen);
                if (n > 0) {
                    (void)::sendto(platform::toOsSocket(udpPeer), buf, static_cast<int>(n), 0,
                                   reinterpret_cast<const sockaddr *>(&client), clen);
                }
                platform::NativeSocket owned = udpPeer;
                platform::closeNativeSocket(owned);
            });

            auto rt = WinTransportRuntime::create();
            auto factory = rt->makeFactory();
            Node node;
            node.host = "127.0.0.1";
            node.connectHost = "127.0.0.1";
            node.port = echoPort;

            std::mutex m;
            std::condition_variable cv;
            bool gotReply = false;
            int udpErr = 0;
            Buffer ping{'h', 'a', 'j', 'i', 'm', 'i', '-', 'u', 'd', 'p'};

            factory->udp(node, [&](std::shared_ptr<Datagram> dgram, Error err) {
                if (!err.empty() || !dgram) {
                    std::lock_guard<std::mutex> g(m); udpErr = 22; gotReply = true; cv.notify_all(); return;
                }
                dgram->start([&, dgram](Target src, Buffer pkt) {
                    std::lock_guard<std::mutex> g(m);
                    if (src.port != echoPort || pkt != ping) udpErr = 23;
                    gotReply = true;
                    cv.notify_all();
                }, [&](Error) {
                    std::lock_guard<std::mutex> g(m);
                    if (!gotReply) { udpErr = 24; gotReply = true; cv.notify_all(); }
                });
                // Fire at closed UDP port first (triggers ICMP 10054 on Windows if SIO_UDP_CONNRESET wasn't disabled!)
                if (deadPort != 0) {
                    dgram->send({"127.0.0.1", deadPort, true, false}, Buffer{1, 2, 3}, [](Error) {});
                }
                dgram->send({"127.0.0.1", echoPort, true, false}, ping, [](Error) {});
            });

            {
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(5), [&] { return gotReply; })) udpErr = 25;
            }
            udpEcho.join();
            rt->shutdown();
            if (udpErr != 0) return udpErr;
        }

        // 4. TLS 1.3 loopback handshake, ALPN negotiation & untrusted cert rejection
        {
            EVP_PKEY *pkey = nullptr;
            if (EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) {
                if (EC_KEY_generate_key(ec) == 1) {
                    pkey = EVP_PKEY_new();
                    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
                        if (pkey) { EVP_PKEY_free(pkey); pkey = nullptr; }
                        EC_KEY_free(ec);
                    }
                } else {
                    EC_KEY_free(ec);
                }
            }
            if (!pkey) return 30;
            X509 *cert = X509_new();
            X509_set_version(cert, 2); // X.509 v3 required by AWS-LC/BoringSSL when SAN/BasicConstraints extensions are present
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
            X509_gmtime_adj(X509_getm_notBefore(cert), -60);
            X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
            X509_set_pubkey(cert, pkey);
            X509_NAME *subj = X509_get_subject_name(cert);
            X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("hajimi-win.test"), -1, -1, 0);
            X509_set_issuer_name(cert, subj);

            X509V3_CTX v3ctx;
            X509V3_set_ctx_nodb(&v3ctx);
            X509V3_set_ctx(&v3ctx, cert, cert, nullptr, nullptr, 0);
            if (X509_EXTENSION *sanExt = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name,
                                                             const_cast<char *>("DNS:hajimi-win.test,IP:127.0.0.1"))) {
                X509_add_ext(cert, sanExt, -1);
                X509_EXTENSION_free(sanExt);
            }
            if (X509_EXTENSION *bcExt = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints,
                                                            const_cast<char *>("critical,CA:TRUE"))) {
                X509_add_ext(cert, bcExt, -1);
                X509_EXTENSION_free(bcExt);
            }
            X509_sign(cert, pkey, EVP_sha256());

            // Write CA PEM to a UTF-8 path including non-ASCII characters (哈基米) to verify UTF-16 path handling!
            namespace fs = std::filesystem;
            auto suffix = proto_common::encodeHexLower(crypto::randomBytes(4));
            fs::path tempCaDir = fs::temp_directory_path() / fs::u8path(u8"hajimi-ca-哈基米-" + suffix);
            fs::create_directories(tempCaDir);
            fs::path caFile = tempCaDir / "ca.pem";
            {
                BIO *mem = BIO_new(BIO_s_mem());
                PEM_write_bio_X509(mem, cert);
                char *pemPtr = nullptr;
                long pemLen = BIO_get_mem_data(mem, &pemPtr);
                std::ofstream out(caFile, std::ios::binary | std::ios::trunc);
                out.write(pemPtr, pemLen);
                out.close();
                BIO_free(mem);
            }

            SSL_CTX *srvCtx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_set_min_proto_version(srvCtx, TLS1_3_VERSION);
            SSL_CTX_use_certificate(srvCtx, cert);
            SSL_CTX_use_PrivateKey(srvCtx, pkey);
            SSL_CTX_set_alpn_select_cb(srvCtx, [](SSL *, const unsigned char **out, unsigned char *outlen,
                                                  const unsigned char *in, unsigned int inlen, void *) -> int {
                if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                                          reinterpret_cast<const unsigned char *>("\x02h2"), 3, in, inlen) == OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_NOACK;
            }, nullptr);

            platform::NativeSocket tlsListener = platform::toNativeSocket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
            sockaddr_in laddr{};
            laddr.sin_family = AF_INET;
            laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t lLen = sizeof(laddr);
            (void)::bind(platform::toOsSocket(tlsListener), reinterpret_cast<sockaddr *>(&laddr), lLen);
            (void)::getsockname(platform::toOsSocket(tlsListener), reinterpret_cast<sockaddr *>(&laddr), &lLen);
            (void)::listen(platform::toOsSocket(tlsListener), 4);
            const uint16_t tlsPort = ntohs(laddr.sin_port);

            // Serve 2 connections: (a) untrusted default system store -> MUST FAIL; (b) pinned UTF-8 CA -> MUST SUCCEED
            std::thread tlsServer([tlsListener, srvCtx] {
                for (int round = 0; round < 2; ++round) {
                    platform::NativeSocket client = platform::toNativeSocket(
                        ::accept(platform::toOsSocket(tlsListener), nullptr, nullptr));
                    if (client < 0) break;
                    SSL *ssl = SSL_new(srvCtx);
                    SSL_set_fd(ssl, static_cast<int>(platform::toOsSocket(client)));
                    if (SSL_accept(ssl) == 1) {
                        char buf[1024];
                        int n = SSL_read(ssl, buf, sizeof(buf));
                        if (n > 0) (void)SSL_write(ssl, buf, n);
                        SSL_shutdown(ssl);
                    }
                    SSL_free(ssl);
                    platform::closeNativeSocket(client);
                }
                platform::NativeSocket owned = tlsListener;
                platform::closeNativeSocket(owned);
            });

            auto rt = WinTransportRuntime::create();
            auto factory = rt->makeFactory();
            int tlsErr = 0;

            // (a) Untrusted self-signed cert MUST be rejected by system trust callback
            {
                Node untrustedNode;
                untrustedNode.host = "hajimi-win.test";
                untrustedNode.connectHost = "127.0.0.1";
                untrustedNode.port = tlsPort;
                TLSOptions opts;
                opts.enabled = true;
                opts.skipVerify = false;
                opts.serverName = "hajimi-win.test";
                opts.alpn = {"h2"};

                std::mutex m;
                std::condition_variable cv;
                bool done = false;
                bool rejected = false;
                factory->tcp(untrustedNode, opts, [&](std::shared_ptr<Stream> s, Error err) {
                    std::lock_guard<std::mutex> g(m);
                    rejected = (!s && !err.empty());
                    done = true;
                    cv.notify_all();
                });
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(5), [&] { return done; }) || !rejected) {
                    tlsErr = 31;
                }
            }

            // (b) Pinned CA in non-ASCII UTF-8 directory MUST succeed and echo over TLS 1.3
            if (tlsErr == 0) {
                Node trustedNode;
                trustedNode.host = "hajimi-win.test";
                trustedNode.connectHost = "127.0.0.1";
                trustedNode.port = tlsPort;
                trustedNode.parameters["ca"] = caFile.u8string();
                TLSOptions opts;
                opts.enabled = true;
                opts.skipVerify = false;
                opts.serverName = "hajimi-win.test";
                opts.alpn = {"h2"};

                std::mutex m;
                std::condition_variable cv;
                bool done = false;
                Buffer echoOut;
                Buffer hello{'t', 'l', 's', '1', '3', '-', 'o', 'k'};

                factory->tcp(trustedNode, opts, [&](std::shared_ptr<Stream> s, Error err) {
                    if (!err.empty() || !s) {
                        std::fprintf(stderr, "WinTransport TLS self-test step 32 error: %s\n", err.c_str());
                        std::lock_guard<std::mutex> g(m); tlsErr = 32; done = true; cv.notify_all(); return;
                    }
                    s->write(hello, [&](Error werr) {
                        if (!werr.empty()) { std::lock_guard<std::mutex> g(m); tlsErr = 33; done = true; cv.notify_all(); }
                    });
                    s->read(1024, [&, s](Buffer data, bool, Error rerr) {
                        std::lock_guard<std::mutex> g(m);
                        if (!rerr.empty() || data != hello) tlsErr = 34;
                        s->close();
                        done = true;
                        cv.notify_all();
                    });
                });
                std::unique_lock<std::mutex> u(m);
                if (!cv.wait_for(u, std::chrono::seconds(5), [&] { return done; })) tlsErr = 35;
            }

            tlsServer.join();
            rt->shutdown();
            SSL_CTX_free(srvCtx);
            X509_free(cert);
            EVP_PKEY_free(pkey);
            std::error_code ec;
            fs::remove_all(tempCaDir, ec);
            if (tlsErr != 0) return tlsErr;
        }

        return 0;
    } catch (...) {
        return 99;
    }
}
