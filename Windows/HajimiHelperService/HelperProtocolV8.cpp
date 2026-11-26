#include "HelperProtocolV8.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <sstream>

namespace hajimi::helper {
namespace {

int64_t steadyNowMs() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string toLowerCopy(std::string s) {
    for (char &c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string jsonEscape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else out.push_back(static_cast<char>(c));
    }
    return out;
}

std::string extractJsonString(const std::string &json, const std::string &key) {
    const std::string pat = "\"" + key + "\"";
    auto kpos = json.find(pat);
    if (kpos == std::string::npos) return {};
    auto colon = json.find(':', kpos + pat.size());
    if (colon == std::string::npos) return {};
    size_t i = colon + 1;
    while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) ++i;
    if (i >= json.size() || json[i] != '"') return {};
    ++i;
    std::string val;
    while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        val.push_back(json[i++]);
    }
    return val;
}

bool extractJsonBool(const std::string &json, const std::string &key, bool fallback) {
    const std::string pat = "\"" + key + "\"";
    auto kpos = json.find(pat);
    if (kpos == std::string::npos) return fallback;
    auto colon = json.find(':', kpos + pat.size());
    if (colon == std::string::npos) return fallback;
    size_t i = colon + 1;
    while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) ++i;
    if (json.compare(i, 4, "true") == 0) return true;
    if (json.compare(i, 5, "false") == 0) return false;
    return fallback;
}

std::vector<std::string> extractJsonStringArray(const std::string &json, const std::string &key) {
    std::vector<std::string> out;
    const std::string pat = "\"" + key + "\"";
    auto kpos = json.find(pat);
    if (kpos == std::string::npos) return out;
    auto lb = json.find('[', kpos + pat.size());
    auto rb = (lb == std::string::npos) ? std::string::npos : json.find(']', lb + 1);
    if (lb == std::string::npos || rb == std::string::npos) return out;

    size_t i = lb + 1;
    while (i < rb) {
        auto q1 = json.find('"', i);
        if (q1 == std::string::npos || q1 >= rb) break;
        size_t q2 = q1 + 1;
        std::string item;
        while (q2 < rb && json[q2] != '"') {
            if (json[q2] == '\\' && q2 + 1 < rb) ++q2;
            item.push_back(json[q2++]);
        }
        if (item.size() <= 128) out.push_back(std::move(item));
        i = q2 + 1;
        if (out.size() >= 512) break; // Hard DoS bound
    }
    return out;
}

bool isValidIpOrCidrLiteral(const std::string &s) {
    if (s.empty() || s.size() > 64) return false;
    for (unsigned char c : s) {
        if (!(std::isxdigit(c) || c == '.' || c == ':' || c == '/')) return false;
    }
    return true;
}

} // namespace

HelperSessionCoordinator::HelperSessionCoordinator(std::shared_ptr<IPrivilegedPlatformOps> ops)
    : ops_(std::move(ops)) {}

bool HelperSessionCoordinator::verifyZeroTrustPeer(const PeerIdentity &peer, std::string &outReason) {
    if (peer.pid == 0 || peer.pid == 4) {
        outReason = "Invalid client PID";
        return false;
    }
    if (peer.imagePathUTF8.empty() || peer.imagePathUTF8.size() > 1024) {
        outReason = "Missing or oversized client image path";
        return false;
    }

    std::string norm = toLowerCopy(peer.imagePathUTF8);
    std::replace(norm.begin(), norm.end(), '/', '\\');

    // Reject UNC network shares (`\\server\share\...`) and Win32 device reparse prefixes (`\\?\UNC\`)
    if (norm.rfind("\\\\", 0) == 0) {
        outReason = "Rejected network UNC or device reparse path";
        return false;
    }
    if (!peer.fixedLocalDrive) {
        outReason = "Rejected executable outside fixed local disk (DRIVE_FIXED required)";
        return false;
    }
    // Reject staging/writable temporary folders matching macOS `/tmp` policy
    if (norm.find("\\appdata\\local\\temp\\") != std::string::npos ||
        norm.find("\\windows\\temp\\") != std::string::npos ||
        norm.find("\\temp\\") != std::string::npos ||
        norm.find("\\tmp\\") != std::string::npos) {
        outReason = "Rejected untrusted temporary directory execution";
        return false;
    }
    if (!peer.signatureVerified) {
        outReason = "WinVerifyTrust Authenticode signature verification failed";
        return false;
    }
    return true;
}

bool HelperSessionCoordinator::parseRequestJsonLine(const std::string &jsonLine, HelperRequest &outReq) {
    if (jsonLine.empty() || jsonLine.size() > 262144) return false;
    outReq = HelperRequest{};

    const std::string act = toLowerCopy(extractJsonString(jsonLine, "action"));
    if (act == "ping") outReq.action = HelperAction::Ping;
    else if (act == "status") outReq.action = HelperAction::Status;
    else if (act == "prepare") outReq.action = HelperAction::Prepare;
    else if (act == "commit") outReq.action = HelperAction::Commit;
    else if (act == "start") outReq.action = HelperAction::StartLegacyRejected;
    else if (act == "reload") outReq.action = HelperAction::Reload;
    else if (act == "stop") outReq.action = HelperAction::Stop;
    else return false;

    outReq.fakeIpEnabled = extractJsonBool(jsonLine, "fakeIPEnabled", true);
    outReq.sessionToken = extractJsonString(jsonLine, "sessionToken");
    outReq.bypassAddresses = extractJsonStringArray(jsonLine, "bypassAddresses");
    outReq.excludedRoutes = extractJsonStringArray(jsonLine, "excludedRoutes");
    outReq.includedRoutes = extractJsonStringArray(jsonLine, "includedRoutes");

    for (const auto &ip : outReq.bypassAddresses) {
        if (!isValidIpOrCidrLiteral(ip)) return false;
    }
    for (const auto &r : outReq.excludedRoutes) {
        if (!isValidIpOrCidrLiteral(r)) return false;
    }
    for (const auto &r : outReq.includedRoutes) {
        if (!isValidIpOrCidrLiteral(r)) return false;
    }
    return true;
}

std::string HelperSessionCoordinator::generateNextTokenLocked() {
    ++tokenCounter_;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "hj-win-v8-%u-%llu",
                  ownerPid_, static_cast<unsigned long long>(tokenCounter_));
    return buf;
}

void HelperSessionCoordinator::teardownSessionLocked(bool recordRestoredToken) noexcept {
    const std::string prevToken = sessionToken_;
    if (ops_ && phase_ != TunnelPhase::Stopped) {
        ops_->rollbackAllNetworkChanges();
    }
    if (recordRestoredToken && !prevToken.empty()) {
        lastRestoredSessionToken_ = prevToken;
    }
    phase_ = TunnelPhase::Stopped;
    ownerPid_ = 0;
    ownerExePath_.clear();
    sessionToken_.clear();
    tunnelInterface_.clear();
    physicalInterface_.clear();
    lastGrant_ = SharedMemoryGrant{};
}

std::string HelperSessionCoordinator::formatResponseJsonLocked(bool ok,
                                                               const std::string &message,
                                                               const std::string &errorCode,
                                                               bool includeShmGrant) const {
    const char *phaseStr = nullptr;
    if (phase_ == TunnelPhase::Prepared) phaseStr = "prepared";
    else if (phase_ == TunnelPhase::Committing) phaseStr = "committing";
    else if (phase_ == TunnelPhase::Running) phaseStr = "running";

    std::ostringstream oss;
    oss << "{\"ok\":" << (ok ? "true" : "false");
    if (!message.empty()) {
        oss << ",\"message\":\"" << jsonEscape(message) << "\"";
    }
    if (!errorCode.empty()) {
        oss << ",\"errorCode\":\"" << jsonEscape(errorCode) << "\"";
    }
    if (includeShmGrant) {
        oss << ",\"shmSectionHandle\":" << static_cast<uint64_t>(lastGrant_.clientSectionHandle)
            << ",\"shmRxEventHandle\":" << static_cast<uint64_t>(lastGrant_.clientRxEventHandle)
            << ",\"shmTxEventHandle\":" << static_cast<uint64_t>(lastGrant_.clientTxEventHandle)
            << ",\"shmRingCapacity\":" << lastGrant_.ringCapacityBytes;
    }
    oss << ",\"state\":{"
        << "\"helperProtocolVersion\":" << kHelperProtocolVersion
        << ",\"helperBuildRevision\":" << kHelperBuildRevision
        << ",\"running\":" << (phase_ == TunnelPhase::Running ? "true" : "false")
        << ",\"networkCleanupPending\":false"
        << ",\"dataPlane\":\"HajimiNativeCore (App SHM Ring)\""
        << ",\"activeFlows\":0,\"totalFlows\":0,\"uploadedBytes\":0,\"downloadedBytes\":0";
    if (phaseStr) {
        oss << ",\"phase\":\"" << phaseStr << "\"";
    }
    if (!sessionToken_.empty()) {
        oss << ",\"sessionToken\":\"" << jsonEscape(sessionToken_) << "\"";
    }
    if (!lastRestoredSessionToken_.empty()) {
        oss << ",\"lastRestoredSessionToken\":\"" << jsonEscape(lastRestoredSessionToken_) << "\"";
    }
    if (!tunnelInterface_.empty()) {
        oss << ",\"tunnelInterface\":\"" << jsonEscape(tunnelInterface_) << "\"";
    }
    if (!physicalInterface_.empty()) {
        oss << ",\"physicalInterface\":\"" << jsonEscape(physicalInterface_) << "\"";
    }
    oss << "}}\n";
    return oss.str();
}

std::string HelperSessionCoordinator::handleJsonLine(const PeerIdentity &peer,
                                                     const std::string &jsonLine) {
    std::string authErr;
    if (!verifyZeroTrustPeer(peer, authErr)) {
        std::lock_guard<std::mutex> lk(mu_);
        return formatResponseJsonLocked(false, authErr, "unauthorized-peer", false);
    }

    HelperRequest req;
    if (!parseRequestJsonLine(jsonLine, req)) {
        std::lock_guard<std::mutex> lk(mu_);
        return formatResponseJsonLocked(false, "Malformed protocol v8 request", "invalid-request", false);
    }

    std::lock_guard<std::mutex> lk(mu_);

    if (req.action == HelperAction::StartLegacyRejected) {
        return formatResponseJsonLocked(
            false,
            "Protocol v8 rejects one-step 'start'; call 'prepare', attach SHM reader, then 'commit'",
            "protocol-violation", false);
    }

    if (req.action == HelperAction::Ping) {
        if (phase_ != TunnelPhase::Stopped && peer.pid == ownerPid_) {
            lastHeartbeatSteadyMs_ = steadyNowMs();
        }
        return formatResponseJsonLocked(true, "pong", "", false);
    }

    if (req.action == HelperAction::Status) {
        if (phase_ != TunnelPhase::Stopped && peer.pid == ownerPid_) {
            if (req.sessionToken.empty() || req.sessionToken == sessionToken_) {
                lastHeartbeatSteadyMs_ = steadyNowMs();
            }
        }
        return formatResponseJsonLocked(true, "", "", false);
    }

    if (req.action == HelperAction::Prepare) {
        if (phase_ != TunnelPhase::Stopped && ownerPid_ != 0 && ownerPid_ != peer.pid) {
            return formatResponseJsonLocked(
                false, "Tunnel is currently owned by another active Hajimi PID", "session-busy", false);
        }
        if (phase_ != TunnelPhase::Stopped) {
            teardownSessionLocked(true);
        }

        std::string physAlias;
        uint32_t physIdx = 0;
        if (!ops_ || !ops_->queryPhysicalDefaultUplink(physAlias, physIdx)) {
            return formatResponseJsonLocked(
                false, "Physical default gateway is not ready", "physical-network-not-ready", false);
        }

        std::string tunAlias, prepErr;
        SharedMemoryGrant grant{};
        if (!ops_->prepareWintunAndSharedRing(peer.pid, tunAlias, grant, prepErr)) {
            return formatResponseJsonLocked(false, prepErr, "wintun-prepare-failed", false);
        }

        ownerPid_ = peer.pid;
        ownerExePath_ = peer.imagePathUTF8;
        sessionToken_ = generateNextTokenLocked();
        tunnelInterface_ = tunAlias;
        physicalInterface_ = physAlias;
        lastGrant_ = grant;
        phase_ = TunnelPhase::Prepared;
        lastHeartbeatSteadyMs_ = steadyNowMs();
        return formatResponseJsonLocked(true, "prepared", "", true);
    }

    if (req.action == HelperAction::Commit) {
        if (phase_ != TunnelPhase::Prepared || peer.pid != ownerPid_) {
            return formatResponseJsonLocked(false, "Commit requires an active prepared session owned by caller PID", "invalid-state", false);
        }
        if (req.sessionToken.empty() || req.sessionToken != sessionToken_) {
            return formatResponseJsonLocked(false, "Session token mismatch on commit", "token-mismatch", false);
        }

        std::string physAlias;
        uint32_t physIdx = 0;
        if (!ops_->queryPhysicalDefaultUplink(physAlias, physIdx)) {
            teardownSessionLocked(true);
            return formatResponseJsonLocked(
                false, "Physical uplink disappeared before commit", "physical-network-not-ready", false);
        }

        phase_ = TunnelPhase::Committing;
        physicalInterface_ = physAlias;
        std::string commitErr;
        if (!ops_->commitSplitRoutesAndDns(
                tunnelInterface_, physicalInterface_, req.fakeIpEnabled,
                req.bypassAddresses, req.excludedRoutes, req.includedRoutes,
                ownerExePath_, commitErr)) {
            teardownSessionLocked(true);
            return formatResponseJsonLocked(false, commitErr, "commit-failed", false);
        }

        phase_ = TunnelPhase::Running;
        lastHeartbeatSteadyMs_ = steadyNowMs();
        return formatResponseJsonLocked(true, "running", "", false);
    }

    if (req.action == HelperAction::Reload) {
        if (phase_ != TunnelPhase::Running || peer.pid != ownerPid_ || req.sessionToken != sessionToken_) {
            return formatResponseJsonLocked(false, "Reload requires matching running session", "invalid-state", false);
        }
        // Revision 3 (protocol 8): defer before any mutation while physical uplink is unavailable
        std::string physAlias;
        uint32_t physIdx = 0;
        if (!ops_->queryPhysicalDefaultUplink(physAlias, physIdx)) {
            return formatResponseJsonLocked(
                false, "Physical network temporarily unavailable; preserving owned tunnel",
                "physical-network-not-ready", false);
        }
        physicalInterface_ = physAlias;
        std::string reloadErr;
        if (!ops_->commitSplitRoutesAndDns(
                tunnelInterface_, physicalInterface_, req.fakeIpEnabled,
                req.bypassAddresses, req.excludedRoutes, req.includedRoutes,
                ownerExePath_, reloadErr)) {
            teardownSessionLocked(true);
            return formatResponseJsonLocked(false, reloadErr, "reload-failed", false);
        }
        lastHeartbeatSteadyMs_ = steadyNowMs();
        return formatResponseJsonLocked(true, "reloaded", "", false);
    }

    if (req.action == HelperAction::Stop) {
        if (phase_ == TunnelPhase::Stopped) {
            return formatResponseJsonLocked(true, "already-stopped", "", false);
        }
        if (peer.pid != ownerPid_) {
            return formatResponseJsonLocked(false, "Cannot stop session owned by another PID", "unauthorized-peer", false);
        }
        if (!req.sessionToken.empty() && req.sessionToken != sessionToken_) {
            // Stale delayed cleanup from an older generation must NOT tear down a newer session
            return formatResponseJsonLocked(true, "ignored-stale-session-stop", "", false);
        }
        teardownSessionLocked(true);
        return formatResponseJsonLocked(true, "stopped", "", false);
    }

    return formatResponseJsonLocked(false, "Unhandled action", "invalid-request", false);
}

bool HelperSessionCoordinator::checkWatchdogTimeout(int64_t nowSteadyMs, bool ownerProcessAlive) {
    std::lock_guard<std::mutex> lk(mu_);
    if (phase_ == TunnelPhase::Stopped) return false;
    if (!ownerProcessAlive || (nowSteadyMs - lastHeartbeatSteadyMs_ > 3000)) {
        teardownSessionLocked(true);
        return true;
    }
    return false;
}

TunnelPhase HelperSessionCoordinator::currentPhase() const {
    std::lock_guard<std::mutex> lk(mu_);
    return phase_;
}

uint32_t HelperSessionCoordinator::ownerPid() const {
    std::lock_guard<std::mutex> lk(mu_);
    return ownerPid_;
}

std::string HelperSessionCoordinator::activeSessionToken() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sessionToken_;
}

// ============================================================================
// Offline Chaos & Red-Team Security Self-Test (`HajimiHelperService --self-test`)
// ============================================================================
int HelperSessionCoordinator::runOfflineSelfTest() {
    struct MockOps final : public IPrivilegedPlatformOps {
        bool uplinkUp = true;
        bool wintunOpen = false;
        bool routesCommitted = false;
        bool wfpDynamicActive = false;
        uint32_t rollbackCalls = 0;

        bool queryPhysicalDefaultUplink(std::string &outIfAlias, uint32_t &outIfIndex) override {
            if (!uplinkUp) return false;
            outIfAlias = "Wi-Fi";
            outIfIndex = 12;
            return true;
        }
        bool prepareWintunAndSharedRing(uint32_t,
                                        std::string &outTunAlias,
                                        SharedMemoryGrant &outGrant,
                                        std::string &) override {
            wintunOpen = true;
            outTunAlias = "Hajimi Tunnel";
            outGrant = SharedMemoryGrant{0x1001, 0x1002, 0x1003, 8u * 1024u * 1024u};
            return true;
        }
        bool commitSplitRoutesAndDns(const std::string &,
                                     const std::string &,
                                     bool dnsProtectionEnabled,
                                     const std::vector<std::string> &,
                                     const std::vector<std::string> &,
                                     const std::vector<std::string> &,
                                     const std::string &,
                                     std::string &) override {
            routesCommitted = true;
            wfpDynamicActive = dnsProtectionEnabled;
            return true;
        }
        void rollbackAllNetworkChanges() noexcept override {
            wintunOpen = false;
            routesCommitted = false;
            wfpDynamicActive = false;
            ++rollbackCalls;
        }
    };

    auto mock = std::make_shared<MockOps>();
    HelperSessionCoordinator coord(mock);

    const PeerIdentity trustedGui{4242, "C:\\Program Files\\Hajimi\\Hajimi.exe", true, true};
    const PeerIdentity tempAttacker{9999, "C:\\Users\\Alice\\AppData\\Local\\Temp\\Hajimi.exe", true, true};
    const PeerIdentity uncAttacker{9998, "\\\\evil-smb\\share\\Hajimi.exe", false, true};
    const PeerIdentity unsignedAttacker{9997, "C:\\Program Files\\Hajimi\\Hajimi.exe", true, false};

    // 1. Red-team zero-trust path & signature rejection checks
    if (coord.handleJsonLine(tempAttacker, "{\"action\":\"prepare\"}").find("\"ok\":false") == std::string::npos) return 1;
    if (coord.handleJsonLine(uncAttacker, "{\"action\":\"prepare\"}").find("\"ok\":false") == std::string::npos) return 2;
    if (coord.handleJsonLine(unsignedAttacker, "{\"action\":\"prepare\"}").find("\"ok\":false") == std::string::npos) return 3;

    // 2. Protocol v8 rejects legacy one-shot `start` without reader-ready ACK
    if (coord.handleJsonLine(trustedGui, "{\"action\":\"start\"}").find("protocol-violation") == std::string::npos) return 4;

    // 3. Two-phase `prepare` -> verify no routes captured yet -> `commit`
    std::string prepResp = coord.handleJsonLine(trustedGui, "{\"action\":\"prepare\",\"fakeIPEnabled\":true}");
    if (prepResp.find("\"ok\":true") == std::string::npos ||
        coord.currentPhase() != TunnelPhase::Prepared ||
        mock->routesCommitted) {
        return 5;
    }
    const std::string tok = coord.activeSessionToken();
    if (tok.empty()) return 6;

    // Wrong token must fail commit
    if (coord.handleJsonLine(trustedGui, "{\"action\":\"commit\",\"sessionToken\":\"wrong\"}").find("\"ok\":false") == std::string::npos) {
        return 7;
    }

    std::string commitReq = "{\"action\":\"commit\",\"sessionToken\":\"" + tok +
                            "\",\"fakeIPEnabled\":true,\"bypassAddresses\":[\"203.0.113.10\"],\"excludedRoutes\":[\"192.168.0.0/16\"]}";
    std::string commitResp = coord.handleJsonLine(trustedGui, commitReq);
    if (commitResp.find("\"ok\":true") == std::string::npos ||
        coord.currentPhase() != TunnelPhase::Running ||
        !mock->routesCommitted || !mock->wfpDynamicActive) {
        return 8;
    }

    // 4. Protocol v8 Rev 3: `reload` while physical Wi-Fi is momentarily down preserves owned tunnel
    mock->uplinkUp = false;
    std::string reloadDefer = coord.handleJsonLine(trustedGui, "{\"action\":\"reload\",\"sessionToken\":\"" + tok + "\"}");
    if (reloadDefer.find("physical-network-not-ready") == std::string::npos ||
        coord.currentPhase() != TunnelPhase::Running ||
        !mock->routesCommitted) {
        return 9;
    }
    mock->uplinkUp = true;

    // 5. Chaos test: `taskkill /F /IM Hajimi.exe` (3-second watchdog / dead client process) auto-rolls back routes & WFP
    if (!coord.checkWatchdogTimeout(steadyNowMs() + 3500, false) ||
        coord.currentPhase() != TunnelPhase::Stopped ||
        mock->routesCommitted || mock->wfpDynamicActive || mock->rollbackCalls == 0) {
        return 10;
    }

    // Verify `lastRestoredSessionToken` positive recovery ACK is reported on next `status`
    std::string statusAfterCrash = coord.handleJsonLine(trustedGui, "{\"action\":\"status\"}");
    if (statusAfterCrash.find("\"lastRestoredSessionToken\":\"" + tok + "\"") == std::string::npos) {
        return 11;
    }

    return 0;
}

} // namespace hajimi::helper
