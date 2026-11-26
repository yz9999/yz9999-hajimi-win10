#include "WintunSessionBridge.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <iphlpapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {

typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

using WintunCreateAdapterFn = WINTUN_ADAPTER_HANDLE(WINAPI *)(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
using WintunOpenAdapterFn = WINTUN_ADAPTER_HANDLE(WINAPI *)(LPCWSTR Name);
using WintunCloseAdapterFn = void(WINAPI *)(WINTUN_ADAPTER_HANDLE Adapter);
using WintunGetAdapterLUIDFn = void(WINAPI *)(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
using WintunStartSessionFn = WINTUN_SESSION_HANDLE(WINAPI *)(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
using WintunEndSessionFn = void(WINAPI *)(WINTUN_SESSION_HANDLE Session);
using WintunGetReadWaitEventFn = HANDLE(WINAPI *)(WINTUN_SESSION_HANDLE Session);
using WintunReceivePacketFn = BYTE *(WINAPI *)(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
using WintunReleaseReceivePacketFn = void(WINAPI *)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
using WintunAllocateSendPacketFn = BYTE *(WINAPI *)(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
using WintunSendPacketFn = void(WINAPI *)(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);

// {68616A69-6D69-4E54-9F10-001122334455}
constexpr GUID kHajimiAdapterGuid = {
    0x68616A69u, 0x6D69u, 0x4E54u, {0x9Fu, 0x10u, 0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u}
};

bool verifyAuthenticodeFileW(const std::wstring &filePath) noexcept {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    LONG status = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);
    return status == ERROR_SUCCESS;
}

} // namespace
#endif // _WIN32

namespace hajimi::helper {

struct WintunSessionBridge::Impl {
#if defined(_WIN32)
    HMODULE wintunMod = nullptr;
    WintunCloseAdapterFn fnCloseAdapter = nullptr;
    WintunEndSessionFn fnEndSession = nullptr;
    WintunGetReadWaitEventFn fnGetReadWaitEvent = nullptr;
    WintunReceivePacketFn fnReceivePacket = nullptr;
    WintunReleaseReceivePacketFn fnReleaseReceivePacket = nullptr;
    WintunAllocateSendPacketFn fnAllocateSendPacket = nullptr;
    WintunSendPacketFn fnSendPacket = nullptr;

    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;

    HANDLE hShmMap = nullptr;
    void *shmView = nullptr;
    HANDLE hRxEvent = nullptr;
    HANDLE hTxEvent = nullptr;
    HANDLE hStopEvent = nullptr;
    std::thread rxPumpThread;
    std::thread txPumpThread;
#endif
};

WintunSessionBridge::~WintunSessionBridge() {
    stopSession();
    delete impl_;
    impl_ = nullptr;
}

bool WintunSessionBridge::startSessionAndGrantHandles(uint32_t clientPid,
                                                      uint32_t mtu,
                                                      std::string &outAdapterAlias,
                                                      uint64_t &outAdapterLuid,
                                                      SharedMemoryGrant &outClientGrant,
                                                      std::string &outError) {
    stopSession();
    if (!impl_) impl_ = new Impl();

#if defined(_WIN32)
    wchar_t exePathBuf[2048]{};
    DWORD n = ::GetModuleFileNameW(nullptr, exePathBuf, 2040);
    if (n == 0 || n >= 2040) {
        outError = "GetModuleFileNameW failed";
        return false;
    }
    std::wstring exeDir(exePathBuf, n);
    auto slash = exeDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) exeDir.resize(slash);
    const std::wstring wintunPath = exeDir + L"\\wintun.dll";

    // Mandatory Authenticode verification before loading kernel-facing Wintun DLL
    if (!verifyAuthenticodeFileW(wintunPath)) {
        outError = "wintun.dll failed WinVerifyTrust Authenticode verification";
        return false;
    }

    impl_->wintunMod = ::LoadLibraryExW(wintunPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if (!impl_->wintunMod) {
        outError = "LoadLibraryExW(wintun.dll) failed (" + std::to_string(::GetLastError()) + ")";
        return false;
    }

    auto fnCreateAdapter = reinterpret_cast<WintunCreateAdapterFn>(::GetProcAddress(impl_->wintunMod, "WintunCreateAdapter"));
    auto fnOpenAdapter = reinterpret_cast<WintunOpenAdapterFn>(::GetProcAddress(impl_->wintunMod, "WintunOpenAdapter"));
    impl_->fnCloseAdapter = reinterpret_cast<WintunCloseAdapterFn>(::GetProcAddress(impl_->wintunMod, "WintunCloseAdapter"));
    auto fnGetLuid = reinterpret_cast<WintunGetAdapterLUIDFn>(::GetProcAddress(impl_->wintunMod, "WintunGetAdapterLUID"));
    auto fnStartSession = reinterpret_cast<WintunStartSessionFn>(::GetProcAddress(impl_->wintunMod, "WintunStartSession"));
    impl_->fnEndSession = reinterpret_cast<WintunEndSessionFn>(::GetProcAddress(impl_->wintunMod, "WintunEndSession"));
    impl_->fnGetReadWaitEvent = reinterpret_cast<WintunGetReadWaitEventFn>(::GetProcAddress(impl_->wintunMod, "WintunGetReadWaitEvent"));
    impl_->fnReceivePacket = reinterpret_cast<WintunReceivePacketFn>(::GetProcAddress(impl_->wintunMod, "WintunReceivePacket"));
    impl_->fnReleaseReceivePacket = reinterpret_cast<WintunReleaseReceivePacketFn>(::GetProcAddress(impl_->wintunMod, "WintunReleaseReceivePacket"));
    impl_->fnAllocateSendPacket = reinterpret_cast<WintunAllocateSendPacketFn>(::GetProcAddress(impl_->wintunMod, "WintunAllocateSendPacket"));
    impl_->fnSendPacket = reinterpret_cast<WintunSendPacketFn>(::GetProcAddress(impl_->wintunMod, "WintunSendPacket"));

    if (!fnCreateAdapter || !fnOpenAdapter || !impl_->fnCloseAdapter || !fnGetLuid ||
        !fnStartSession || !impl_->fnEndSession || !impl_->fnGetReadWaitEvent ||
        !impl_->fnReceivePacket || !impl_->fnReleaseReceivePacket ||
        !impl_->fnAllocateSendPacket || !impl_->fnSendPacket) {
        stopSession();
        outError = "wintun.dll missing required entrypoints";
        return false;
    }

    impl_->adapter = fnOpenAdapter(L"Hajimi Tunnel");
    if (!impl_->adapter) {
        impl_->adapter = fnCreateAdapter(L"Hajimi Tunnel", L"Hajimi", &kHajimiAdapterGuid);
    }
    if (!impl_->adapter) {
        stopSession();
        outError = "WintunCreateAdapter failed (" + std::to_string(::GetLastError()) + ")";
        return false;
    }

    NET_LUID luid{};
    fnGetLuid(impl_->adapter, &luid);
    outAdapterLuid = luid.Value;
    outAdapterAlias = "Hajimi Tunnel";

    // Start 8 MiB Wintun kernel ring (`0x800000`)
    impl_->session = fnStartSession(impl_->adapter, 0x800000u);
    if (!impl_->session) {
        stopSession();
        outError = "WintunStartSession(8 MiB) failed (" + std::to_string(::GetLastError()) + ")";
        return false;
    }

    // Allocate 16 MiB anonymous shared-memory section + auto-reset Rx/Tx wakeup events
    impl_->hShmMap = ::CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, HAJIMI_SHM_DUPLEX_TOTAL_BYTES, nullptr);
    if (!impl_->hShmMap) {
        stopSession();
        outError = "CreateFileMappingW(16 MiB) failed";
        return false;
    }
    impl_->shmView = ::MapViewOfFile(impl_->hShmMap, FILE_MAP_ALL_ACCESS, 0, 0, HAJIMI_SHM_DUPLEX_TOTAL_BYTES);
    if (!impl_->shmView) {
        stopSession();
        outError = "MapViewOfFile failed";
        return false;
    }
    shm::initDuplexRegion(impl_->shmView, mtu);

    impl_->hRxEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    impl_->hTxEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    impl_->hStopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!impl_->hRxEvent || !impl_->hTxEvent || !impl_->hStopEvent) {
        stopSession();
        outError = "CreateEventW failed";
        return false;
    }

    // Duplicate handles with least privilege into the verified client process (`clientPid`)
    HANDLE hClientProc = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, clientPid);
    if (!hClientProc) {
        stopSession();
        outError = "OpenProcess(PROCESS_DUP_HANDLE) failed for client PID";
        return false;
    }
    HANDLE dupMap = nullptr, dupRx = nullptr, dupTx = nullptr;
    const BOOL okMap = ::DuplicateHandle(::GetCurrentProcess(), impl_->hShmMap, hClientProc, &dupMap,
                                         FILE_MAP_READ | FILE_MAP_WRITE, FALSE, 0);
    const BOOL okRx = ::DuplicateHandle(::GetCurrentProcess(), impl_->hRxEvent, hClientProc, &dupRx,
                                        SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, 0);
    const BOOL okTx = ::DuplicateHandle(::GetCurrentProcess(), impl_->hTxEvent, hClientProc, &dupTx,
                                        SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, 0);
    ::CloseHandle(hClientProc);
    if (!okMap || !okRx || !okTx) {
        stopSession();
        outError = "DuplicateHandle to client PID failed";
        return false;
    }

    outClientGrant.clientSectionHandle = reinterpret_cast<uintptr_t>(dupMap);
    outClientGrant.clientRxEventHandle = reinterpret_cast<uintptr_t>(dupRx);
    outClientGrant.clientTxEventHandle = reinterpret_cast<uintptr_t>(dupTx);
    outClientGrant.ringCapacityBytes = HAJIMI_SHM_RING_CAPACITY;

    running_.store(true, std::memory_order_release);

    // Pump 1: Wintun -> SPSC RX Ring (towards unprivileged Hajimi.exe)
    impl_->rxPumpThread = std::thread([this] {
        auto *hdr = static_cast<shm::DuplexHeader *>(impl_->shmView);
        uint8_t *rxStorage = shm::rxRingStorage(impl_->shmView);
        HANDLE waitHandles[2] = {impl_->fnGetReadWaitEvent(impl_->session), impl_->hStopEvent};

        while (running_.load(std::memory_order_acquire)) {
            DWORD pktSize = 0;
            BYTE *pkt = impl_->fnReceivePacket(impl_->session, &pktSize);
            if (pkt) {
                bool sig = false;
                (void)shm::spscTryPush(hdr->rxProducer, hdr->rxConsumer, rxStorage,
                                       hdr->ringCapacity, pkt, pktSize, sig);
                impl_->fnReleaseReceivePacket(impl_->session, pkt);
                if (sig) ::SetEvent(impl_->hRxEvent);
                continue;
            }
            if (::GetLastError() == ERROR_NO_MORE_ITEMS) {
                DWORD w = ::WaitForMultipleObjects(2, waitHandles, FALSE, 50);
                if (w == WAIT_OBJECT_0 + 1) break;
            } else {
                break;
            }
        }
    });

    // Pump 2: SPSC TX Ring (from unprivileged Hajimi.exe) -> Wintun
    impl_->txPumpThread = std::thread([this] {
        auto *hdr = static_cast<shm::DuplexHeader *>(impl_->shmView);
        const uint8_t *txStorage = shm::txRingStorage(impl_->shmView);
        std::vector<uint8_t> scratch(HAJIMI_SHM_MAX_PACKET_BYTES);
        HANDLE waitHandles[2] = {impl_->hTxEvent, impl_->hStopEvent};

        while (running_.load(std::memory_order_acquire)) {
            uint32_t popped = shm::spscTryPop(
                hdr->txProducer, hdr->txConsumer, txStorage, hdr->ringCapacity,
                scratch.data(), static_cast<uint32_t>(scratch.size()));
            if (popped > 0) {
                BYTE *dst = impl_->fnAllocateSendPacket(impl_->session, popped);
                if (dst) {
                    std::memcpy(dst, scratch.data(), popped);
                    impl_->fnSendPacket(impl_->session, dst);
                }
                continue;
            }
            hdr->txProducer.consumerSleeping.store(1u, std::memory_order_seq_cst);
            popped = shm::spscTryPop(
                hdr->txProducer, hdr->txConsumer, txStorage, hdr->ringCapacity,
                scratch.data(), static_cast<uint32_t>(scratch.size()));
            if (popped > 0) {
                hdr->txProducer.consumerSleeping.store(0u, std::memory_order_release);
                BYTE *dst = impl_->fnAllocateSendPacket(impl_->session, popped);
                if (dst) {
                    std::memcpy(dst, scratch.data(), popped);
                    impl_->fnSendPacket(impl_->session, dst);
                }
                continue;
            }
            DWORD w = ::WaitForMultipleObjects(2, waitHandles, FALSE, 50);
            hdr->txProducer.consumerSleeping.store(0u, std::memory_order_release);
            if (w == WAIT_OBJECT_0 + 1) break;
        }
    });

    return true;
#else
    (void)clientPid; (void)mtu; (void)outAdapterAlias; (void)outAdapterLuid; (void)outClientGrant;
    outError = "WintunSessionBridge requires Windows host";
    return false;
#endif
}

void WintunSessionBridge::stopSession() noexcept {
    running_.store(false, std::memory_order_release);
#if defined(_WIN32)
    if (!impl_) return;
    if (impl_->shmView) {
        auto *hdr = static_cast<shm::DuplexHeader *>(impl_->shmView);
        hdr->closed.store(1u, std::memory_order_release);
    }
    if (impl_->hStopEvent) ::SetEvent(impl_->hStopEvent);
    if (impl_->hTxEvent) ::SetEvent(impl_->hTxEvent);
    if (impl_->rxPumpThread.joinable()) impl_->rxPumpThread.join();
    if (impl_->txPumpThread.joinable()) impl_->txPumpThread.join();

    if (impl_->session && impl_->fnEndSession) {
        impl_->fnEndSession(impl_->session);
        impl_->session = nullptr;
    }
    if (impl_->adapter && impl_->fnCloseAdapter) {
        impl_->fnCloseAdapter(impl_->adapter);
        impl_->adapter = nullptr;
    }
    if (impl_->shmView) {
        ::UnmapViewOfFile(impl_->shmView);
        impl_->shmView = nullptr;
    }
    if (impl_->hShmMap) { ::CloseHandle(impl_->hShmMap); impl_->hShmMap = nullptr; }
    if (impl_->hRxEvent) { ::CloseHandle(impl_->hRxEvent); impl_->hRxEvent = nullptr; }
    if (impl_->hTxEvent) { ::CloseHandle(impl_->hTxEvent); impl_->hTxEvent = nullptr; }
    if (impl_->hStopEvent) { ::CloseHandle(impl_->hStopEvent); impl_->hStopEvent = nullptr; }
    if (impl_->wintunMod) {
        ::FreeLibrary(impl_->wintunMod);
        impl_->wintunMod = nullptr;
    }
#endif
}

} // namespace hajimi::helper
