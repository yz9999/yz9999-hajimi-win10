#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hajimi::helper {

/// Manages Windows `FWPM_SESSION_FLAG_DYNAMIC` WFP kernel filters to prevent
/// Windows Smart Multi-Homed Name Resolution (SMHNR) DNS leaks on physical NICs.
/// Because the session is opened with `FWPM_SESSION_FLAG_DYNAMIC`, the Windows
/// kernel automatically destroys every filter the instant `HajimiHelperService.exe`
/// exits or is terminated (`taskkill /F`), guaranteeing zero residual network lockouts.
class WfpLeakGuard {
public:
    WfpLeakGuard() = default;
    ~WfpLeakGuard();

    WfpLeakGuard(const WfpLeakGuard &) = delete;
    WfpLeakGuard &operator=(const WfpLeakGuard &) = delete;

    bool enableDynamicDnsProtection(const std::string &authorizedClientExeUTF8,
                                    uint64_t tunnelAdapterLuid,
                                    std::string &outError);

    void disableProtection() noexcept;

    bool isActive() const noexcept { return engineHandle_ != 0; }

private:
    uintptr_t engineHandle_ = 0;
};

/// Atomic two-phase IP Helper (`iphlpapi.dll`) address, split-route, bypass-route,
/// and interface DNS transaction manager with deterministic `< 100 ms` rollback.
class RouteAndDnsTransaction {
public:
    RouteAndDnsTransaction() = default;
    ~RouteAndDnsTransaction();

    static bool queryPhysicalDefaultGateway(std::string &outAlias,
                                            uint32_t &outIfIndex,
                                            uint64_t &outIfLuid,
                                            std::string &outNextHopIpv4);

    /// Phase 1 (`prepare`): assigns `198.18.16.1/16` and `fd00:6861:6a69::1/64` + MTU
    /// on the Wintun adapter without installing any traffic-capturing routes.
    bool assignTunnelAddressesAndMtu(uint64_t tunLuid, uint32_t mtu, std::string &outError);

    /// Phase 2 (`commit`): installs physical-gateway bypass routes (`bypassAddresses` + `excludedRoutes`),
    /// split default routes (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1` or `includedRoutes`),
    /// and sets Wintun interface DNS to `198.18.16.2`. Rolls back atomically on any failure.
    bool commitRoutesAndDns(uint64_t tunLuid,
                            uint64_t physLuid,
                            const std::string &physNextHopIpv4,
                            bool configureTunDns,
                            const std::vector<std::string> &bypassAddresses,
                            const std::vector<std::string> &excludedRoutes,
                            const std::vector<std::string> &includedRoutes,
                            std::string &outError);

    void rollback() noexcept;

private:
    struct Impl;
    Impl *impl_ = nullptr;
};

} // namespace hajimi::helper
