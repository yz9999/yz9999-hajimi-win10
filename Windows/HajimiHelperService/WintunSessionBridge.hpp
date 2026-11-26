#pragma once

#include "HelperProtocolV8.hpp"
#include "../../Sources/HajimiPlatformC/include/HajimiShmRing.h"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace hajimi::helper {

/// Manages verified loading of `wintun.dll`, `WintunStartSession(0x800000)`,
/// 16 MiB anonymous shared-memory duplex ring creation, `DuplicateHandle` grant
/// to the verified unprivileged `Hajimi.exe` client, and SPSC <-> Wintun packet pumping.
class WintunSessionBridge {
public:
    WintunSessionBridge() = default;
    ~WintunSessionBridge();

    WintunSessionBridge(const WintunSessionBridge &) = delete;
    WintunSessionBridge &operator=(const WintunSessionBridge &) = delete;

    /// Verifies `wintun.dll` Authenticode signature via `WinVerifyTrust`, creates/reuses
    /// the `Hajimi Tunnel` NDIS 6.x adapter, starts an 8 MiB Wintun ring session,
    /// allocates the 16 MiB SPSC shared memory mapping, and duplicates section/event
    /// handles into `clientPid`.
    bool startSessionAndGrantHandles(uint32_t clientPid,
                                     uint32_t mtu,
                                     std::string &outAdapterAlias,
                                     uint64_t &outAdapterLuid,
                                     SharedMemoryGrant &outClientGrant,
                                     std::string &outError);

    void stopSession() noexcept;

    bool isRunning() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    struct Impl;
    Impl *impl_ = nullptr;
    std::atomic<bool> running_{false};
};

} // namespace hajimi::helper
