#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace hajimi::engine {

class LocalProcessSocketCache {
public:
    LocalProcessSocketCache() = default;

    bool lookupOwnerExecutable(bool isUdp,
                               const std::string &localIp,
                               uint16_t localPort,
                               std::string &outExePath);

    void setTestOverride(bool isUdp, uint16_t localPort, const std::string &exePath);
    void clearCache();

private:
    struct CachedPidPath {
        std::string exePath;
        int64_t expiresAtMs = 0;
    };

    mutable std::mutex mu_;
    std::unordered_map<uint32_t, CachedPidPath> pidPathCache_;
    std::unordered_map<uint32_t, std::string> testPortOverrides_;
};

struct WinConnectionProxyState {
    std::string connectionName;
    uint32_t flags = 1u;
    std::string proxyServer;
    std::string proxyBypass;
    std::string autoConfigUrl;
};

class ISystemProxyOsBackend {
public:
    virtual ~ISystemProxyOsBackend() = default;
    virtual bool enumerateConnections(std::vector<std::string> &outConnections, std::string &outError) = 0;
    virtual bool queryConnection(const std::string &connName, WinConnectionProxyState &outState, std::string &outError) = 0;
    virtual bool applyConnection(const WinConnectionProxyState &state, std::string &outError) = 0;
    virtual void notifySettingsChanged() = 0;
};

class WinSystemProxyManager {
public:
    explicit WinSystemProxyManager(std::string snapshotDirectoryUTF8,
                                   std::shared_ptr<ISystemProxyOsBackend> customBackend = nullptr);

    static std::shared_ptr<ISystemProxyOsBackend> createNativeBackend();

    bool enable(const std::string &proxyHost,
                uint16_t proxyPort,
                const std::string &bypassSemicolonList,
                std::string &outError);

    bool repoint(const std::string &newProxyHost,
                 uint16_t newProxyPort,
                 std::string &outError);

    bool disable(std::string &outError);

    bool isOwnedByHajimi() const;

    std::string snapshotFilePath() const { return snapshotPath_; }

private:
    struct ManagedSnapshot {
        std::vector<WinConnectionProxyState> originals;
        std::vector<std::string> acceptedServers;
        std::unordered_map<std::string, std::string> expectedBypass;
    };

    bool loadSnapshot(ManagedSnapshot &outSnap) const;
    bool saveSnapshot(const ManagedSnapshot &snap, std::string &outError) const;
    void removeSnapshotFile() const noexcept;
    bool verifyCurrentOwnership(const ManagedSnapshot &snap, std::string &outLostConn) const;

    std::string snapshotDir_;
    std::string snapshotPath_;
    std::shared_ptr<ISystemProxyOsBackend> backend_;
};

} // namespace hajimi::engine
