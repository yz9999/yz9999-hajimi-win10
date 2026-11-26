#include "WinSystemProxyAndProcess.hpp"
#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#include <arpa/inet.h>
#include <vector>
#endif
#include "../HajimiProtocolsCXX/PlatformCompat.hpp"

#if defined(_WIN32)
#include <wininet.h>
#ifndef INTERNET_PER_CONN_FLAGS_UI
#define INTERNET_PER_CONN_FLAGS_UI 10
#endif
#include <ras.h>
#include <raserror.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "rasapi32.lib")
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace hajimi::engine {
namespace {

constexpr uint32_t kProxyTypeDirect = 0x00000001u;
constexpr uint32_t kProxyTypeProxy  = 0x00000002u;

[[maybe_unused]] int64_t monotonicMillis() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string jsonEscape(const std::string &s) {
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
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x", c);
                    out += hex;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

std::string jsonUnescape(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[++i];
            switch (next) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                default:   out.push_back(next); break;
            }
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

#if defined(_WIN32)
std::string wideToUtf8(const std::wstring &w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                       nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                          out.data(), needed, nullptr, nullptr);
    return out;
}

bool queryWinProcessPath(DWORD pid, std::string &outPath) {
    if (pid == 0 || pid == 4) return false;
    HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    wchar_t buf[2048]{};
    DWORD cap = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
    BOOL ok = ::QueryFullProcessImageNameW(hProc, 0, buf, &cap);
    ::CloseHandle(hProc);
    if (!ok || cap == 0) return false;
    outPath = wideToUtf8(std::wstring(buf, cap));
    return !outPath.empty();
}

class WinInetSystemProxyBackend final : public ISystemProxyOsBackend {
public:
    bool enumerateConnections(std::vector<std::string> &outConnections, std::string &) override {
        outConnections.clear();
        outConnections.push_back(""); // Default LAN connection (`NULL` in WinINet)

        DWORD cb = 0;
        DWORD count = 0;
        DWORD rc = ::RasEnumEntriesW(nullptr, nullptr, nullptr, &cb, &count);
        if (rc == ERROR_BUFFER_TOO_SMALL && cb > 0 && cb <= 4 * 1024 * 1024) {
            std::vector<uint8_t> storage(cb, 0);
            auto *entries = reinterpret_cast<RASENTRYNAMEW *>(storage.data());
            entries[0].dwSize = sizeof(RASENTRYNAMEW);
            if (::RasEnumEntriesW(nullptr, nullptr, entries, &cb, &count) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < count; ++i) {
                    std::string name = wideToUtf8(entries[i].szEntryName);
                    if (!name.empty()) outConnections.push_back(std::move(name));
                }
            }
        }
        return true;
    }

    bool queryConnection(const std::string &connName,
                         WinConnectionProxyState &outState,
                         std::string &outError) override {
        std::wstring wConn;
        if (!connName.empty() && !platform::utf8ToWide(connName, wConn)) {
            outError = "Invalid UTF-8 connection name";
            return false;
        }

        INTERNET_PER_CONN_OPTIONW opts[4]{};
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        opts[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;

        INTERNET_PER_CONN_OPTION_LISTW list{};
        list.dwSize = sizeof(list);
        list.pszConnection = connName.empty() ? nullptr : const_cast<LPWSTR>(wConn.c_str());
        list.dwOptionCount = 4;
        list.pOptions = opts;

        DWORD listSize = sizeof(list);
        if (!::InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &listSize)) {
            opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
            listSize = sizeof(list);
            if (!::InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &listSize)) {
                outError = "InternetQueryOptionW failed (" + std::to_string(::GetLastError()) + ")";
                return false;
            }
        }

        outState = WinConnectionProxyState{};
        outState.connectionName = connName;
        outState.flags = opts[0].Value.dwValue;
        if (opts[1].Value.pszValue) {
            outState.proxyServer = wideToUtf8(opts[1].Value.pszValue);
            ::GlobalFree(opts[1].Value.pszValue);
        }
        if (opts[2].Value.pszValue) {
            outState.proxyBypass = wideToUtf8(opts[2].Value.pszValue);
            ::GlobalFree(opts[2].Value.pszValue);
        }
        if (opts[3].Value.pszValue) {
            outState.autoConfigUrl = wideToUtf8(opts[3].Value.pszValue);
            ::GlobalFree(opts[3].Value.pszValue);
        }
        return true;
    }

    bool applyConnection(const WinConnectionProxyState &state, std::string &outError) override {
        std::wstring wConn, wServer, wBypass, wAutoUrl;
        if ((!state.connectionName.empty() && !platform::utf8ToWide(state.connectionName, wConn)) ||
            !platform::utf8ToWide(state.proxyServer, wServer) ||
            !platform::utf8ToWide(state.proxyBypass, wBypass) ||
            !platform::utf8ToWide(state.autoConfigUrl, wAutoUrl)) {
            outError = "Invalid UTF-8 proxy parameters";
            return false;
        }

        INTERNET_PER_CONN_OPTIONW opts[4]{};
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
        opts[0].Value.dwValue = state.flags;

        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        opts[1].Value.pszValue = const_cast<LPWSTR>(wServer.c_str());

        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        opts[2].Value.pszValue = const_cast<LPWSTR>(wBypass.c_str());

        opts[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        opts[3].Value.pszValue = state.autoConfigUrl.empty() ? nullptr : const_cast<LPWSTR>(wAutoUrl.c_str());

        INTERNET_PER_CONN_OPTION_LISTW list{};
        list.dwSize = sizeof(list);
        list.pszConnection = state.connectionName.empty() ? nullptr : const_cast<LPWSTR>(wConn.c_str());
        list.dwOptionCount = 4;
        list.pOptions = opts;

        if (!::InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) {
            outError = "InternetSetOptionW failed (" + std::to_string(::GetLastError()) + ")";
            return false;
        }
        return true;
    }

    void notifySettingsChanged() override {
        (void)::InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
        (void)::InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    }
};
#else
// Non-Windows in-memory backend so offline unit tests can exercise snapshot persistence & ownership loss
class InMemorySystemProxyBackend final : public ISystemProxyOsBackend {
public:
    InMemorySystemProxyBackend() {
        states_[""] = WinConnectionProxyState{"", kProxyTypeDirect, "", "<local>", ""};
    }
    bool enumerateConnections(std::vector<std::string> &outConnections, std::string &) override {
        std::lock_guard<std::mutex> lk(mu_);
        outConnections.clear();
        for (const auto &kv : states_) outConnections.push_back(kv.first);
        return true;
    }
    bool queryConnection(const std::string &connName, WinConnectionProxyState &outState, std::string &outError) override {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = states_.find(connName);
        if (it == states_.end()) {
            outError = "Connection not found";
            return false;
        }
        outState = it->second;
        return true;
    }
    bool applyConnection(const WinConnectionProxyState &state, std::string &) override {
        std::lock_guard<std::mutex> lk(mu_);
        states_[state.connectionName] = state;
        return true;
    }
    void notifySettingsChanged() override {}
private:
    std::mutex mu_;
    std::unordered_map<std::string, WinConnectionProxyState> states_;
};
#endif

} // namespace

// ============================================================================
// LocalProcessSocketCache
// ============================================================================
void LocalProcessSocketCache::setTestOverride(bool isUdp, uint16_t localPort, const std::string &exePath) {
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t key = (static_cast<uint32_t>(isUdp ? 1u : 0u) << 16) | localPort;
    if (exePath.empty()) testPortOverrides_.erase(key);
    else testPortOverrides_[key] = exePath;
}

void LocalProcessSocketCache::clearCache() {
    std::lock_guard<std::mutex> lk(mu_);
    pidPathCache_.clear();
    portPathCache_.clear();
    testPortOverrides_.clear();
}

bool LocalProcessSocketCache::lookupOwnerExecutable(bool isUdp,
                                                    const std::string &localIp,
                                                    uint16_t localPort,
                                                    std::string &outExePath) {
    if (localPort == 0) return false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const uint32_t key = (static_cast<uint32_t>(isUdp ? 1u : 0u) << 16) | localPort;
        auto ov = testPortOverrides_.find(key);
        if (ov != testPortOverrides_.end()) {
            outExePath = ov->second;
            return true;
        }
    }

#if defined(_WIN32)
    (void)localIp;
    const uint16_t netPort = htons(localPort);
    DWORD ownerPid = 0;

    if (!isUdp) {
        DWORD sz = 0;
        if (::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER &&
            sz > 0 && sz <= 16 * 1024 * 1024) {
            std::vector<uint8_t> buf(sz);
            if (::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                const auto *tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID *>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    if (static_cast<uint16_t>(tbl->table[i].dwLocalPort) == netPort) {
                        ownerPid = tbl->table[i].dwOwningPid;
                        break;
                    }
                }
            }
        }
        if (ownerPid == 0) {
            sz = 0;
            if (::GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER &&
                sz > 0 && sz <= 16 * 1024 * 1024) {
                std::vector<uint8_t> buf(sz);
                if (::GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    const auto *tbl = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID *>(buf.data());
                    for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                        if (static_cast<uint16_t>(tbl->table[i].dwLocalPort) == netPort) {
                            ownerPid = tbl->table[i].dwOwningPid;
                            break;
                        }
                    }
                }
            }
        }
    } else {
        DWORD sz = 0;
        if (::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER &&
            sz > 0 && sz <= 16 * 1024 * 1024) {
            std::vector<uint8_t> buf(sz);
            if (::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                const auto *tbl = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID *>(buf.data());
                for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                    if (static_cast<uint16_t>(tbl->table[i].dwLocalPort) == netPort) {
                        ownerPid = tbl->table[i].dwOwningPid;
                        break;
                    }
                }
            }
        }
        if (ownerPid == 0) {
            sz = 0;
            if (::GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER &&
                sz > 0 && sz <= 16 * 1024 * 1024) {
                std::vector<uint8_t> buf(sz);
                if (::GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                    const auto *tbl = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID *>(buf.data());
                    for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
                        if (static_cast<uint16_t>(tbl->table[i].dwLocalPort) == netPort) {
                            ownerPid = tbl->table[i].dwOwningPid;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (ownerPid == 0) return false;

    const int64_t nowMs = monotonicMillis();
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = pidPathCache_.find(ownerPid);
        if (it != pidPathCache_.end() && it->second.expiresAtMs > nowMs) {
            outExePath = it->second.exePath;
            return true;
        }
    }

    std::string resolved;
    if (!queryWinProcessPath(ownerPid, resolved)) return false;

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (pidPathCache_.size() > 2048) pidPathCache_.clear();
        pidPathCache_[ownerPid] = CachedPidPath{resolved, nowMs + 2000};
    }
    outExePath = std::move(resolved);
    return true;
#elif defined(__APPLE__)
    (void)localIp;
    const uint32_t portCacheKey = (static_cast<uint32_t>(isUdp ? 1u : 0u) << 16) | localPort;
    const int64_t nowMs = monotonicMillis();
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto pit = portPathCache_.find(portCacheKey);
        if (pit != portPathCache_.end() && pit->second.expiresAtMs > nowMs) {
            if (pit->second.exePath.empty()) return false;
            outExePath = pit->second.exePath;
            return true;
        }
    }

    int numBytes = ::proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (numBytes <= 0) return false;
    std::vector<pid_t> pids(static_cast<size_t>(numBytes) / sizeof(pid_t) + 16u);
    numBytes = ::proc_listpids(pid_t(PROC_ALL_PIDS), 0, pids.data(),
                               static_cast<int>(pids.size() * sizeof(pid_t)));
    if (numBytes <= 0) return false;
    const size_t pidCount = static_cast<size_t>(numBytes) / sizeof(pid_t);
    std::string foundPath;
    for (size_t i = 0; i < pidCount; ++i) {
        const pid_t pid = pids[i];
        if (pid <= 0) continue;
        int fdBytes = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (fdBytes <= 0) continue;
        std::vector<proc_fdinfo> fds(static_cast<size_t>(fdBytes) / sizeof(proc_fdinfo) + 8u);
        fdBytes = ::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                 static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (fdBytes <= 0) continue;
        const size_t fdCount = static_cast<size_t>(fdBytes) / sizeof(proc_fdinfo);
        for (size_t f = 0; f < fdCount; ++f) {
            if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            socket_fdinfo sinfo{};
            if (::proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDSOCKETINFO,
                                 &sinfo, sizeof(sinfo)) != sizeof(sinfo)) {
                continue;
            }
            const int kind = sinfo.psi.soi_kind;
            if (isUdp && kind != SOCKINFO_IN) continue;
            if (!isUdp && kind != SOCKINFO_TCP) continue;
            const in_sockinfo &insi = (kind == SOCKINFO_TCP)
                ? sinfo.psi.soi_proto.pri_tcp.tcpsi_ini
                : sinfo.psi.soi_proto.pri_in;
            const uint16_t lport = ntohs(static_cast<uint16_t>(insi.insi_lport));
            if (lport == localPort) {
                char pathBuf[PROC_PIDPATHINFO_MAXSIZE]{};
                if (::proc_pidpath(pid, pathBuf, sizeof(pathBuf)) > 0) {
                    foundPath = pathBuf;
                    break;
                }
            }
        }
        if (!foundPath.empty()) break;
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (portPathCache_.size() > 2048) portPathCache_.clear();
        portPathCache_[portCacheKey] = CachedPidPath{
            foundPath,
            nowMs + (foundPath.empty() ? 350 : 2500)
        };
    }
    if (!foundPath.empty()) {
        outExePath = std::move(foundPath);
        return true;
    }
    return false;
#else
    (void)localIp;
    (void)isUdp;
    (void)localPort;
    (void)outExePath;
    return false;
#endif
}

// ============================================================================
// WinSystemProxyManager
// ============================================================================
std::shared_ptr<ISystemProxyOsBackend> WinSystemProxyManager::createNativeBackend() {
#if defined(_WIN32)
    return std::make_shared<WinInetSystemProxyBackend>();
#else
    static auto sharedMock = std::make_shared<InMemorySystemProxyBackend>();
    return sharedMock;
#endif
}

WinSystemProxyManager::WinSystemProxyManager(std::string snapshotDirectoryUTF8,
                                             std::shared_ptr<ISystemProxyOsBackend> customBackend)
    : snapshotDir_(std::move(snapshotDirectoryUTF8)),
      backend_(customBackend ? std::move(customBackend) : createNativeBackend()) {
    if (!snapshotDir_.empty() && snapshotDir_.back() != '/' && snapshotDir_.back() != '\\') {
#if defined(_WIN32)
        snapshotPath_ = snapshotDir_ + "\\system-proxy-snapshot.json";
#else
        snapshotPath_ = snapshotDir_ + "/system-proxy-snapshot.json";
#endif
    } else {
        snapshotPath_ = snapshotDir_ + "system-proxy-snapshot.json";
    }
}

bool WinSystemProxyManager::saveSnapshot(const ManagedSnapshot &snap, std::string &outError) const {
    try {
        std::filesystem::path dirPath = std::filesystem::u8path(snapshotDir_);
        std::filesystem::create_directories(dirPath);
        std::filesystem::path filePath = std::filesystem::u8path(snapshotPath_);

        std::ostringstream oss;
        oss << "{\n  \"schema\": 1,\n  \"acceptedServers\": [";
        for (size_t i = 0; i < snap.acceptedServers.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << jsonEscape(snap.acceptedServers[i]) << "\"";
        }
        oss << "],\n  \"originals\": [\n";
        for (size_t i = 0; i < snap.originals.size(); ++i) {
            const auto &o = snap.originals[i];
            auto bpIt = snap.expectedBypass.find(o.connectionName);
            const std::string expBp = (bpIt != snap.expectedBypass.end()) ? bpIt->second : "";
            oss << "    {\"conn\":\"" << jsonEscape(o.connectionName)
                << "\",\"flags\":" << o.flags
                << ",\"server\":\"" << jsonEscape(o.proxyServer)
                << "\",\"bypass\":\"" << jsonEscape(o.proxyBypass)
                << "\",\"autoUrl\":\"" << jsonEscape(o.autoConfigUrl)
                << "\",\"expectedBypass\":\"" << jsonEscape(expBp) << "\"}";
            if (i + 1 < snap.originals.size()) oss << ",";
            oss << "\n";
        }
        oss << "  ]\n}\n";

        std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            outError = "Failed to write system-proxy-snapshot.json";
            return false;
        }
        const std::string data = oss.str();
        ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
        return ofs.good();
    } catch (const std::exception &ex) {
        outError = ex.what();
        return false;
    }
}

bool WinSystemProxyManager::loadSnapshot(ManagedSnapshot &outSnap) const {
    outSnap = ManagedSnapshot{};
    std::string raw;
    try {
        raw = platform::readBoundedRegularFileUTF8(
            snapshotPath_, 1024 * 1024, "read error", "not regular", "bounds");
    } catch (...) {
        return false;
    }

    auto extractField = [](const std::string &obj, const std::string &key) -> std::string {
        std::string needle = "\"" + key + "\":\"";
        auto p = obj.find(needle);
        if (p == std::string::npos) return {};
        p += needle.size();
        std::string val;
        while (p < obj.size()) {
            if (obj[p] == '\\' && p + 1 < obj.size()) {
                val.push_back(obj[p]);
                val.push_back(obj[p + 1]);
                p += 2;
                continue;
            }
            if (obj[p] == '"') break;
            val.push_back(obj[p++]);
        }
        return jsonUnescape(val);
    };

    auto accPos = raw.find("\"acceptedServers\":");
    if (accPos != std::string::npos) {
        auto lb = raw.find('[', accPos);
        auto rb = raw.find(']', lb == std::string::npos ? accPos : lb);
        if (lb != std::string::npos && rb != std::string::npos) {
            std::string arr = raw.substr(lb + 1, rb - lb - 1);
            size_t pos = 0;
            while ((pos = arr.find('"', pos)) != std::string::npos) {
                size_t end = arr.find('"', pos + 1);
                if (end == std::string::npos) break;
                outSnap.acceptedServers.push_back(jsonUnescape(arr.substr(pos + 1, end - pos - 1)));
                pos = end + 1;
            }
        }
    }

    auto origPos = raw.find("\"originals\":");
    if (origPos == std::string::npos) return false;
    size_t scan = origPos;
    while ((scan = raw.find('{', scan)) != std::string::npos) {
        size_t close = raw.find('}', scan);
        if (close == std::string::npos) break;
        std::string item = raw.substr(scan, close - scan + 1);
        WinConnectionProxyState st;
        st.connectionName = extractField(item, "conn");
        st.proxyServer = extractField(item, "server");
        st.proxyBypass = extractField(item, "bypass");
        st.autoConfigUrl = extractField(item, "autoUrl");
        std::string expBp = extractField(item, "expectedBypass");
        auto flPos = item.find("\"flags\":");
        if (flPos != std::string::npos) {
            st.flags = static_cast<uint32_t>(std::strtoul(item.c_str() + flPos + 8, nullptr, 10));
        }
        outSnap.expectedBypass[st.connectionName] = expBp;
        outSnap.originals.push_back(std::move(st));
        scan = close + 1;
    }
    return !outSnap.originals.empty() && !outSnap.acceptedServers.empty();
}

void WinSystemProxyManager::removeSnapshotFile() const noexcept {
    try {
        std::error_code ec;
        std::filesystem::remove(std::filesystem::u8path(snapshotPath_), ec);
    } catch (...) {}
}

bool WinSystemProxyManager::verifyCurrentOwnership(const ManagedSnapshot &snap,
                                                   std::string &outLostConn) const {
    for (const auto &orig : snap.originals) {
        WinConnectionProxyState live;
        std::string err;
        if (!backend_->queryConnection(orig.connectionName, live, err)) {
            outLostConn = orig.connectionName.empty() ? "Default LAN" : orig.connectionName;
            return false;
        }
        const bool proxyBitOn = ((live.flags & kProxyTypeProxy) != 0);
        const bool serverMatches = std::find(
            snap.acceptedServers.begin(), snap.acceptedServers.end(), live.proxyServer) != snap.acceptedServers.end();
        if (!proxyBitOn || !serverMatches) {
            outLostConn = orig.connectionName.empty() ? "Default LAN" : orig.connectionName;
            return false;
        }
    }
    return true;
}

bool WinSystemProxyManager::isOwnedByHajimi() const {
    ManagedSnapshot snap;
    if (!loadSnapshot(snap)) return false;
    std::string lost;
    return verifyCurrentOwnership(snap, lost);
}

bool WinSystemProxyManager::enable(const std::string &proxyHost,
                                   uint16_t proxyPort,
                                   const std::string &bypassSemicolonList,
                                   std::string &outError) {
    if (proxyHost.empty() || proxyPort == 0) {
        outError = "Invalid proxy host or port";
        return false;
    }

    // If an active Hajimi snapshot already exists, verify ownership and cleanly restore first
    ManagedSnapshot existing;
    if (loadSnapshot(existing)) {
        std::string lostConn;
        if (!verifyCurrentOwnership(existing, lostConn)) {
            outError = "System proxy on '" + lostConn + "' was modified by another program; refusing to overwrite";
            return false;
        }
        if (!disable(outError)) {
            return false;
        }
    }

    std::vector<std::string> conns;
    if (!backend_->enumerateConnections(conns, outError) || conns.empty()) {
        if (outError.empty()) outError = "No WinINet network connections available";
        return false;
    }

    const std::string targetServer = proxyHost + ":" + std::to_string(proxyPort);
    const std::string defaultBypass = bypassSemicolonList.empty()
        ? "localhost;127.*;10.*;172.16.*;192.168.*;<local>"
        : bypassSemicolonList;

    ManagedSnapshot snap;
    snap.acceptedServers.push_back(targetServer);
    for (const auto &c : conns) {
        WinConnectionProxyState orig;
        if (!backend_->queryConnection(c, orig, outError)) {
            return false;
        }
        snap.expectedBypass[c] = defaultBypass;
        snap.originals.push_back(std::move(orig));
    }

    if (!saveSnapshot(snap, outError)) {
        return false;
    }

    std::vector<WinConnectionProxyState> appliedOriginals;
    for (const auto &orig : snap.originals) {
        WinConnectionProxyState target;
        target.connectionName = orig.connectionName;
        target.flags = kProxyTypeDirect | kProxyTypeProxy;
        target.proxyServer = targetServer;
        target.proxyBypass = defaultBypass;
        target.autoConfigUrl.clear();
        if (!backend_->applyConnection(target, outError)) {
            // Atomic rollback of already modified connections
            std::string ignored;
            for (const auto &rb : appliedOriginals) {
                (void)backend_->applyConnection(rb, ignored);
            }
            backend_->notifySettingsChanged();
            removeSnapshotFile();
            return false;
        }
        appliedOriginals.push_back(orig);
    }

    backend_->notifySettingsChanged();
    return true;
}

bool WinSystemProxyManager::repoint(const std::string &newProxyHost,
                                    uint16_t newProxyPort,
                                    std::string &outError) {
    ManagedSnapshot snap;
    if (!loadSnapshot(snap)) {
        outError = "No active Hajimi system proxy snapshot found";
        return false;
    }
    std::string lostConn;
    if (!verifyCurrentOwnership(snap, lostConn)) {
        outError = "System proxy on '" + lostConn + "' was modified by another program; refusing to repoint";
        return false;
    }

    const std::string newServer = newProxyHost + ":" + std::to_string(newProxyPort);
    if (std::find(snap.acceptedServers.begin(), snap.acceptedServers.end(), newServer) == snap.acceptedServers.end()) {
        snap.acceptedServers.push_back(newServer);
    }
    if (!saveSnapshot(snap, outError)) return false;

    for (const auto &orig : snap.originals) {
        WinConnectionProxyState target;
        target.connectionName = orig.connectionName;
        target.flags = kProxyTypeDirect | kProxyTypeProxy;
        target.proxyServer = newServer;
        target.proxyBypass = snap.expectedBypass[orig.connectionName];
        if (!backend_->applyConnection(target, outError)) {
            return false;
        }
    }
    backend_->notifySettingsChanged();
    return true;
}

bool WinSystemProxyManager::disable(std::string &outError) {
    ManagedSnapshot snap;
    if (!loadSnapshot(snap)) {
        return true; // Nothing owned by Hajimi
    }
    std::string lostConn;
    if (!verifyCurrentOwnership(snap, lostConn)) {
        // Leave external proxy untouched and retire our stale snapshot
        removeSnapshotFile();
        outError = "System proxy on '" + lostConn + "' is now owned by another application; Hajimi left it untouched";
        return false;
    }

    for (const auto &orig : snap.originals) {
        if (!backend_->applyConnection(orig, outError)) {
            return false;
        }
    }
    backend_->notifySettingsChanged();
    removeSnapshotFile();
    return true;
}

} // namespace hajimi::engine
