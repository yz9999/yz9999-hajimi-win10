#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace hajimi::helper {

constexpr int kHelperProtocolVersion = 8;
constexpr int kHelperBuildRevision   = 4;
constexpr const char *kHelperPipeName = "\\\\.\\pipe\\HajimiHelperPipe";
constexpr const char *kVirtualTunIpv4 = "198.18.16.1";
constexpr uint8_t     kVirtualTunIpv4Prefix = 16;
constexpr const char *kVirtualTunDnsIpv4 = "198.18.16.2";
constexpr const char *kVirtualTunIpv6 = "fd00:6861:6a69::1";
constexpr uint8_t     kVirtualTunIpv6Prefix = 64;

enum class HelperAction : uint8_t {
    Unknown = 0,
    Ping,
    Status,
    Prepare,
    Commit,
    StartLegacyRejected, // Protocol v8 explicitly rejects `start` (lacks reader-ready ACK)
    Reload,
    Stop
};

enum class TunnelPhase : uint8_t {
    Stopped = 0,
    Prepared,
    Committing,
    Running
};

struct HelperRequest {
    HelperAction action = HelperAction::Unknown;
    bool fakeIpEnabled = false;
    std::vector<std::string> bypassAddresses;
    std::vector<std::string> excludedRoutes;
    std::vector<std::string> includedRoutes;
    std::string sessionToken;
};

struct PeerIdentity {
    uint32_t pid = 0;
    std::string imagePathUTF8;
    bool fixedLocalDrive = false;
    bool signatureVerified = false;
};

struct SharedMemoryGrant {
    uintptr_t clientSectionHandle = 0;
    uintptr_t clientRxEventHandle = 0;
    uintptr_t clientTxEventHandle = 0;
    uint32_t ringCapacityBytes = 8u * 1024u * 1024u;
};

/// Abstract privileged OS operations (`Wintun` + `iphlpapi` routes/DNS + `WFP` dynamic leak guard)
/// so `--self-test` executes full chaos & security red-team scenarios with zero host side effects.
class IPrivilegedPlatformOps {
public:
    virtual ~IPrivilegedPlatformOps() = default;

    virtual bool queryPhysicalDefaultUplink(std::string &outIfAlias, uint32_t &outIfIndex) = 0;
    virtual bool prepareWintunAndSharedRing(uint32_t clientPid,
                                            std::string &outTunAlias,
                                            SharedMemoryGrant &outClientHandles,
                                            std::string &outError) = 0;
    virtual bool commitSplitRoutesAndDns(const std::string &tunAlias,
                                         const std::string &physAlias,
                                         bool dnsProtectionEnabled,
                                         const std::vector<std::string> &bypassAddresses,
                                         const std::vector<std::string> &excludedRoutes,
                                         const std::vector<std::string> &includedRoutes,
                                         const std::string &authorizedClientExeUTF8,
                                         std::string &outError) = 0;
    virtual void rollbackAllNetworkChanges() noexcept = 0;
};

/// Zero-trust two-phase (`prepare` -> `commit`) privileged helper state machine
/// implementing Protocol v8 Revision 4 + 3-second client liveness watchdog.
class HelperSessionCoordinator {
public:
    explicit HelperSessionCoordinator(std::shared_ptr<IPrivilegedPlatformOps> ops);

    /// Validates client executable location (rejecting `%TEMP%`, `\AppData\Local\Temp`, UNC `\\`,
    /// removable/network drives) and Authenticode signature status (`WinVerifyTrust`).
    static bool verifyZeroTrustPeer(const PeerIdentity &peer, std::string &outReason);

    static bool parseRequestJsonLine(const std::string &jsonLine, HelperRequest &outReq);

    /// Processes a single JSON line request from `peer` and returns a newline-terminated JSON v8 response.
    std::string handleJsonLine(const PeerIdentity &peer, const std::string &jsonLine);

    /// Invoked every 250ms–1000ms by the service watchdog loop; tears down routes/DNS/WFP in <100ms
    /// if `nowSteadyMs - lastHeartbeatMs > 3000` or if the owning client process exited.
    bool checkWatchdogTimeout(int64_t nowSteadyMs, bool ownerProcessAlive);

    TunnelPhase currentPhase() const;
    uint32_t ownerPid() const;
    std::string activeSessionToken() const;

    /// Executes comprehensive zero-side-effect M3 + M5 red-team & chaos self-tests.
    static int runOfflineSelfTest();

private:
    std::string formatResponseJsonLocked(bool ok,
                                         const std::string &message,
                                         const std::string &errorCode,
                                         bool includeShmGrant) const;
    std::string generateNextTokenLocked();
    void teardownSessionLocked(bool recordRestoredToken) noexcept;

    mutable std::mutex mu_;
    std::shared_ptr<IPrivilegedPlatformOps> ops_;
    TunnelPhase phase_ = TunnelPhase::Stopped;
    uint32_t ownerPid_ = 0;
    std::string ownerExePath_;
    std::string sessionToken_;
    std::string lastRestoredSessionToken_;
    std::string tunnelInterface_;
    std::string physicalInterface_;
    SharedMemoryGrant lastGrant_{};
    int64_t lastHeartbeatSteadyMs_ = 0;
    uint64_t tokenCounter_ = 0;
};

} // namespace hajimi::helper
