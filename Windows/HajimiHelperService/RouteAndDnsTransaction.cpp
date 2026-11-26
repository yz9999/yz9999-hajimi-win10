#include "RouteAndDnsTransaction.hpp"
#include "HelperProtocolV8.hpp"

#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <limits>

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000B
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <fwpmu.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

namespace {

// {48616A69-6D69-5746-5053-75626C617972}
constexpr GUID kHajimiWfpSublayerGuid = {
    0x48616A69u, 0x6D69u, 0x5746u, {0x50u, 0x53u, 0x75u, 0x62u, 0x6Cu, 0x61u, 0x79u, 0x72u}
};

bool utf8ToWideLocal(const std::string &s, std::wstring &out) {
    out.clear();
    if (s.empty()) return true;
    int n = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return false;
    out.resize(static_cast<size_t>(n));
    return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), out.data(), n) == n;
}

std::string wideToUtf8Local(const wchar_t *w) {
    if (!w || !*w) return {};
    int len = static_cast<int>(std::wcslen(w));
    int n = ::WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, len, out.data(), n, nullptr, nullptr);
    return out;
}

bool parseCidrString(const std::string &cidr, IP_ADDRESS_PREFIX &outPrefix) {
    std::memset(&outPrefix, 0, sizeof(outPrefix));
    std::string ipPart = cidr;
    int prefixLen = -1;
    auto slash = cidr.find('/');
    if (slash != std::string::npos) {
        ipPart = cidr.substr(0, slash);
        prefixLen = std::atoi(cidr.substr(slash + 1).c_str());
    }

    IN_ADDR v4{};
    if (::inet_pton(AF_INET, ipPart.c_str(), &v4) == 1) {
        if (prefixLen < 0) prefixLen = 32;
        if (prefixLen > 32) return false;
        outPrefix.Prefix.si_family = AF_INET;
        outPrefix.Prefix.Ipv4.sin_family = AF_INET;
        outPrefix.Prefix.Ipv4.sin_addr = v4;
        outPrefix.PrefixLength = static_cast<UINT8>(prefixLen);
        return true;
    }
    IN6_ADDR v6{};
    if (::inet_pton(AF_INET6, ipPart.c_str(), &v6) == 1) {
        if (prefixLen < 0) prefixLen = 128;
        if (prefixLen > 128) return false;
        outPrefix.Prefix.si_family = AF_INET6;
        outPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        outPrefix.Prefix.Ipv6.sin6_addr = v6;
        outPrefix.PrefixLength = static_cast<UINT8>(prefixLen);
        return true;
    }
    return false;
}

} // namespace
#endif // _WIN32

namespace hajimi::helper {

// ============================================================================
// WfpLeakGuard (`FWPM_SESSION_FLAG_DYNAMIC`)
// ============================================================================
WfpLeakGuard::~WfpLeakGuard() {
    disableProtection();
}

bool WfpLeakGuard::enableDynamicDnsProtection(const std::string &authorizedClientExeUTF8,
                                              uint64_t tunnelAdapterLuid,
                                              std::string &outError) {
    disableProtection();
#if defined(_WIN32)
    std::wstring wideExe;
    if (!utf8ToWideLocal(authorizedClientExeUTF8, wideExe) || wideExe.empty()) {
        outError = "Invalid UTF-8 client executable path for WFP AppId";
        return false;
    }

    FWPM_SESSION0 session{};
    wchar_t sessionName[] = L"Hajimi Dynamic SMHNR DNS Leak Guard";
    session.displayData.name = sessionName;
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Kernel auto-cleans on service crash!

    HANDLE hEngine = nullptr;
    DWORD status = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &hEngine);
    if (status != ERROR_SUCCESS || !hEngine) {
        outError = "FwpmEngineOpen0(DYNAMIC) failed (" + std::to_string(status) + ")";
        return false;
    }
    engineHandle_ = reinterpret_cast<uintptr_t>(hEngine);

    status = ::FwpmTransactionBegin0(hEngine, 0);
    if (status != ERROR_SUCCESS) {
        disableProtection();
        outError = "FwpmTransactionBegin0 failed";
        return false;
    }

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kHajimiWfpSublayerGuid;
    wchar_t subName[] = L"Hajimi DNS Protection Sublayer";
    sublayer.displayData.name = subName;
    sublayer.weight = 0x7FF0;
    status = ::FwpmSubLayerAdd0(hEngine, &sublayer, nullptr);
    if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
        ::FwpmTransactionAbort0(hEngine);
        disableProtection();
        outError = "FwpmSubLayerAdd0 failed";
        return false;
    }

    FWP_BYTE_BLOB *appBlob = nullptr;
    status = ::FwpmGetAppIdFromFileName0(wideExe.c_str(), &appBlob);
    if (status != ERROR_SUCCESS || !appBlob) {
        ::FwpmTransactionAbort0(hEngine);
        disableProtection();
        outError = "FwpmGetAppIdFromFileName0 failed";
        return false;
    }

    auto addPermitAppFilter = [&](const GUID &layerKey, wchar_t *title) -> DWORD {
        FWPM_FILTER0 f{};
        f.displayData.name = title;
        f.layerKey = layerKey;
        f.subLayerKey = kHajimiWfpSublayerGuid;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 15; // Highest priority permit
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond{};
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.byteBlob = appBlob;
        f.numFilterConditions = 1;
        f.filterCondition = &cond;
        return ::FwpmFilterAdd0(hEngine, &f, nullptr, nullptr);
    };

    wchar_t p4Name[] = L"Hajimi Permit Client V4";
    wchar_t p6Name[] = L"Hajimi Permit Client V6";
    DWORD s1 = addPermitAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, p4Name);
    DWORD s2 = addPermitAppFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, p6Name);
    ::FwpmFreeMemory0(reinterpret_cast<void **>(&appBlob));
    if (s1 != ERROR_SUCCESS || s2 != ERROR_SUCCESS) {
        ::FwpmTransactionAbort0(hEngine);
        disableProtection();
        outError = "Failed to add WFP client permit filters";
        return false;
    }

    // Permit DNS queries directed to Hajimi virtual TUN DNS `198.18.16.2` (or on Wintun LUID)
    {
        FWPM_FILTER0 f{};
        wchar_t tunDnsName[] = L"Hajimi Permit Virtual TUN DNS";
        f.displayData.name = tunDnsName;
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        f.subLayerKey = kHajimiWfpSublayerGuid;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 14;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond{};
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = 0xC6121002u; // 198.18.16.2 in host order
        f.numFilterConditions = 1;
        f.filterCondition = &cond;
        (void)::FwpmFilterAdd0(hEngine, &f, nullptr, nullptr);
    }
    (void)tunnelAdapterLuid;

    // Block rogue SMHNR DNS/DoT (port 53 & 853) connections bypassing virtual TUN DNS
    auto addBlockPortFilter = [&](const GUID &layerKey, UINT16 port, wchar_t *title) -> DWORD {
        FWPM_FILTER0 f{};
        f.displayData.name = title;
        f.layerKey = layerKey;
        f.subLayerKey = kHajimiWfpSublayerGuid;
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 5;
        f.action.type = FWP_ACTION_BLOCK;

        FWPM_FILTER_CONDITION0 cond{};
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT16;
        cond.conditionValue.uint16 = port;
        f.numFilterConditions = 1;
        f.filterCondition = &cond;
        return ::FwpmFilterAdd0(hEngine, &f, nullptr, nullptr);
    };

    wchar_t b53v4[] = L"Hajimi Block Leak Port 53 V4";
    wchar_t b53v6[] = L"Hajimi Block Leak Port 53 V6";
    wchar_t b853v4[] = L"Hajimi Block Leak Port 853 V4";
    wchar_t b853v6[] = L"Hajimi Block Leak Port 853 V6";
    if (addBlockPortFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 53, b53v4) != ERROR_SUCCESS ||
        addBlockPortFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 53, b53v6) != ERROR_SUCCESS ||
        addBlockPortFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 853, b853v4) != ERROR_SUCCESS ||
        addBlockPortFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 853, b853v6) != ERROR_SUCCESS) {
        ::FwpmTransactionAbort0(hEngine);
        disableProtection();
        outError = "Failed to add WFP port 53/853 block filters";
        return false;
    }

    if (::FwpmTransactionCommit0(hEngine) != ERROR_SUCCESS) {
        ::FwpmTransactionAbort0(hEngine);
        disableProtection();
        outError = "FwpmTransactionCommit0 failed";
        return false;
    }
    return true;
#else
    (void)authorizedClientExeUTF8; (void)tunnelAdapterLuid;
    outError = "WFP requires Windows host";
    return false;
#endif
}

void WfpLeakGuard::disableProtection() noexcept {
#if defined(_WIN32)
    if (engineHandle_ != 0) {
        ::FwpmEngineClose0(reinterpret_cast<HANDLE>(engineHandle_));
        engineHandle_ = 0;
    }
#else
    engineHandle_ = 0;
#endif
}

// ============================================================================
// RouteAndDnsTransaction
// ============================================================================
struct RouteAndDnsTransaction::Impl {
#if defined(_WIN32)
    std::vector<MIB_IPFORWARD_ROW2> createdRoutes;
    std::vector<MIB_UNICASTIPADDRESS_ROW> createdAddresses;
    GUID tunInterfaceGuid{};
    bool dnsModified = false;
#endif
};

RouteAndDnsTransaction::~RouteAndDnsTransaction() {
    rollback();
    delete impl_;
    impl_ = nullptr;
}

bool RouteAndDnsTransaction::queryPhysicalDefaultGateway(std::string &outAlias,
                                                         uint32_t &outIfIndex,
                                                         uint64_t &outIfLuid,
                                                         std::string &outNextHopIpv4) {
#if defined(_WIN32)
    MIB_IPFORWARD_TABLE2 *table = nullptr;
    if (::GetIpForwardTable2(AF_INET, &table) != NO_ERROR || !table) {
        return false;
    }

    ULONG bestMetric = (std::numeric_limits<ULONG>::max)();
    bool found = false;
    NET_LUID bestLuid{};
    NET_IFINDEX bestIdx = 0;
    IN_ADDR bestHop{};

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto &row = table->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0) continue; // Default 0.0.0.0/0
        wchar_t aliasBuf[IF_MAX_STRING_SIZE + 1]{};
        if (::ConvertInterfaceLuidToAlias(&row.InterfaceLuid, aliasBuf, IF_MAX_STRING_SIZE) == NO_ERROR) {
            if (std::wcsstr(aliasBuf, L"Hajimi") != nullptr) continue; // Skip our own tunnel
        }
        MIB_IPINTERFACE_ROW ifRow{};
        ifRow.Family = AF_INET;
        ifRow.InterfaceLuid = row.InterfaceLuid;
        ULONG combined = row.Metric + ((::GetIpInterfaceEntry(&ifRow) == NO_ERROR) ? ifRow.Metric : 0);
        if (!found || combined < bestMetric) {
            bestMetric = combined;
            bestLuid = row.InterfaceLuid;
            bestIdx = row.InterfaceIndex;
            bestHop = row.NextHop.Ipv4.sin_addr;
            found = true;
        }
    }
    ::FreeMibTable(table);
    if (!found) return false;

    wchar_t aliasW[IF_MAX_STRING_SIZE + 1]{};
    if (::ConvertInterfaceLuidToAlias(&bestLuid, aliasW, IF_MAX_STRING_SIZE) == NO_ERROR) {
        outAlias = wideToUtf8Local(aliasW);
    }
    char hopBuf[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, &bestHop, hopBuf, sizeof(hopBuf));
    outIfIndex = bestIdx;
    outIfLuid = bestLuid.Value;
    outNextHopIpv4 = hopBuf;
    return true;
#else
    (void)outAlias; (void)outIfIndex; (void)outIfLuid; (void)outNextHopIpv4;
    return false;
#endif
}

bool RouteAndDnsTransaction::assignTunnelAddressesAndMtu(uint64_t tunLuid,
                                                         uint32_t mtu,
                                                         std::string &outError) {
    if (!impl_) impl_ = new Impl();
#if defined(_WIN32)
    NET_LUID luid{};
    luid.Value = tunLuid;

    // Assign IPv4 198.18.16.1/16
    MIB_UNICASTIPADDRESS_ROW v4Row{};
    ::InitializeUnicastIpAddressEntry(&v4Row);
    v4Row.InterfaceLuid = luid;
    v4Row.Address.Ipv4.sin_family = AF_INET;
    ::inet_pton(AF_INET, kVirtualTunIpv4, &v4Row.Address.Ipv4.sin_addr);
    v4Row.OnLinkPrefixLength = kVirtualTunIpv4Prefix;
    v4Row.DadState = IpDadStatePreferred;
    DWORD st = ::CreateUnicastIpAddressEntry(&v4Row);
    if (st != NO_ERROR && st != ERROR_OBJECT_ALREADY_EXISTS) {
        outError = "CreateUnicastIpAddressEntry(IPv4) failed (" + std::to_string(st) + ")";
        return false;
    }
    if (st == NO_ERROR) impl_->createdAddresses.push_back(v4Row);

    // Assign IPv6 fd00:6861:6a69::1/64
    MIB_UNICASTIPADDRESS_ROW v6Row{};
    ::InitializeUnicastIpAddressEntry(&v6Row);
    v6Row.InterfaceLuid = luid;
    v6Row.Address.Ipv6.sin6_family = AF_INET6;
    ::inet_pton(AF_INET6, kVirtualTunIpv6, &v6Row.Address.Ipv6.sin6_addr);
    v6Row.OnLinkPrefixLength = kVirtualTunIpv6Prefix;
    v6Row.DadState = IpDadStatePreferred;
    st = ::CreateUnicastIpAddressEntry(&v6Row);
    if (st == NO_ERROR) impl_->createdAddresses.push_back(v6Row);

    // Configure MTU on IPv4 interface
    MIB_IPINTERFACE_ROW ifRow{};
    ::InitializeIpInterfaceEntry(&ifRow);
    ifRow.Family = AF_INET;
    ifRow.InterfaceLuid = luid;
    if (::GetIpInterfaceEntry(&ifRow) == NO_ERROR) {
        ifRow.NlMtu = mtu;
        ifRow.Metric = 1;
        ifRow.UseAutomaticMetric = FALSE;
        (void)::SetIpInterfaceEntry(&ifRow);
    }
    return true;
#else
    (void)tunLuid; (void)mtu;
    outError = "IP Helper requires Windows host";
    return false;
#endif
}

bool RouteAndDnsTransaction::commitRoutesAndDns(uint64_t tunLuid,
                                                uint64_t physLuid,
                                                const std::string &physNextHopIpv4,
                                                bool configureTunDns,
                                                const std::vector<std::string> &bypassAddresses,
                                                const std::vector<std::string> &excludedRoutes,
                                                const std::vector<std::string> &includedRoutes,
                                                std::string &outError) {
    if (!impl_) impl_ = new Impl();
#if defined(_WIN32)
    auto addRoute = [&](uint64_t targetLuid, const std::string &cidr, const std::string &nextHopV4, ULONG metric) -> bool {
        IP_ADDRESS_PREFIX pfx{};
        if (!parseCidrString(cidr, pfx)) return true; // Ignore unparseable optional item
        MIB_IPFORWARD_ROW2 row{};
        ::InitializeIpForwardEntry(&row);
        row.InterfaceLuid.Value = targetLuid;
        row.DestinationPrefix = pfx;
        row.NextHop.si_family = pfx.Prefix.si_family;
        if (pfx.Prefix.si_family == AF_INET && !nextHopV4.empty()) {
            row.NextHop.Ipv4.sin_family = AF_INET;
            ::inet_pton(AF_INET, nextHopV4.c_str(), &row.NextHop.Ipv4.sin_addr);
        }
        row.Metric = metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        DWORD rc = ::CreateIpForwardEntry2(&row);
        if (rc == NO_ERROR) {
            impl_->createdRoutes.push_back(row);
            return true;
        }
        return rc == ERROR_OBJECT_ALREADY_EXISTS;
    };

    // 1. Split default or `includedRoutes` into Wintun interface (Metric 1)
    if (includedRoutes.empty()) {
        if (!addRoute(tunLuid, "0.0.0.0/1", "0.0.0.0", 1) ||
            !addRoute(tunLuid, "128.0.0.0/1", "0.0.0.0", 1) ||
            !addRoute(tunLuid, "::/1", "", 1) ||
            !addRoute(tunLuid, "8000::/1", "", 1)) {
            rollback();
            outError = "Failed to install split default routes on Wintun";
            return false;
        }
    } else {
        for (const auto &inc : includedRoutes) {
            if (!addRoute(tunLuid, inc, "0.0.0.0", 1)) {
                rollback();
                outError = "Failed to install included route: " + inc;
                return false;
            }
        }
    }

    // 2. Install longest-prefix `bypassAddresses` & `excludedRoutes` on physical gateway
    for (const auto &bp : bypassAddresses) {
        if (!addRoute(physLuid, bp, physNextHopIpv4, 1)) {
            rollback();
            outError = "Failed to install proxy server bypass route: " + bp;
            return false;
        }
    }
    for (const auto &ex : excludedRoutes) {
        if (!addRoute(physLuid, ex, physNextHopIpv4, 1)) {
            rollback();
            outError = "Failed to install excluded CIDR route: " + ex;
            return false;
        }
    }

    // 3. Configure Wintun interface DNS -> `198.18.16.2` via `SetInterfaceDnsSettings`
    if (configureTunDns) {
        NET_LUID luid{};
        luid.Value = tunLuid;
        if (::ConvertInterfaceLuidToGuid(&luid, &impl_->tunInterfaceGuid) == NO_ERROR) {
            DNS_INTERFACE_SETTINGS settings{};
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = DNS_SETTING_NAMESERVER;
            wchar_t dnsSrv[] = L"198.18.16.2";
            settings.NameServer = dnsSrv;
            if (::SetInterfaceDnsSettings(impl_->tunInterfaceGuid, &settings) == NO_ERROR) {
                impl_->dnsModified = true;
            }
        }
    }
    return true;
#else
    (void)tunLuid; (void)physLuid; (void)physNextHopIpv4; (void)configureTunDns;
    (void)bypassAddresses; (void)excludedRoutes; (void)includedRoutes;
    outError = "RouteAndDnsTransaction requires Windows host";
    return false;
#endif
}

void RouteAndDnsTransaction::rollback() noexcept {
#if defined(_WIN32)
    if (!impl_) return;
    if (impl_->dnsModified) {
        DNS_INTERFACE_SETTINGS clearDns{};
        clearDns.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        clearDns.Flags = DNS_SETTING_NAMESERVER;
        clearDns.NameServer = nullptr;
        (void)::SetInterfaceDnsSettings(impl_->tunInterfaceGuid, &clearDns);
        impl_->dnsModified = false;
    }
    for (auto it = impl_->createdRoutes.rbegin(); it != impl_->createdRoutes.rend(); ++it) {
        (void)::DeleteIpForwardEntry2(&(*it));
    }
    impl_->createdRoutes.clear();

    for (auto it = impl_->createdAddresses.rbegin(); it != impl_->createdAddresses.rend(); ++it) {
        (void)::DeleteUnicastIpAddressEntry(&(*it));
    }
    impl_->createdAddresses.clear();
#endif
}

} // namespace hajimi::helper
