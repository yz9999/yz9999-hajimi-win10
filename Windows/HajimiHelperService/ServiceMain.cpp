#include "HelperProtocolV8.hpp"
#include "RouteAndDnsTransaction.hpp"
#include "WintunSessionBridge.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace {

using namespace hajimi::helper;

std::atomic<bool> gServiceStop{false};

[[maybe_unused]] int64_t nowSteadyMillis() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

#if defined(_WIN32)
class Win32PrivilegedPlatformOps final : public IPrivilegedPlatformOps {
public:
    bool queryPhysicalDefaultUplink(std::string &outIfAlias, uint32_t &outIfIndex) override {
        return RouteAndDnsTransaction::queryPhysicalDefaultGateway(
            outIfAlias, outIfIndex, physLuid_, physNextHopV4_);
    }

    bool prepareWintunAndSharedRing(uint32_t clientPid,
                                    std::string &outTunAlias,
                                    SharedMemoryGrant &outClientHandles,
                                    std::string &outError) override {
        if (!wintun_.startSessionAndGrantHandles(
                clientPid, 1400, outTunAlias, tunLuid_, outClientHandles, outError)) {
            return false;
        }
        if (!routes_.assignTunnelAddressesAndMtu(tunLuid_, 1400, outError)) {
            wintun_.stopSession();
            return false;
        }
        return true;
    }

    bool commitSplitRoutesAndDns(const std::string &,
                                 const std::string &,
                                 bool dnsProtectionEnabled,
                                 const std::vector<std::string> &bypassAddresses,
                                 const std::vector<std::string> &excludedRoutes,
                                 const std::vector<std::string> &includedRoutes,
                                 const std::string &authorizedClientExeUTF8,
                                 std::string &outError) override {
        if (!routes_.commitRoutesAndDns(
                tunLuid_, physLuid_, physNextHopV4_, dnsProtectionEnabled,
                bypassAddresses, excludedRoutes, includedRoutes, outError)) {
            return false;
        }
        if (dnsProtectionEnabled) {
            if (!wfp_.enableDynamicDnsProtection(authorizedClientExeUTF8, tunLuid_, outError)) {
                routes_.rollback();
                return false;
            }
        }
        return true;
    }

    void rollbackAllNetworkChanges() noexcept override {
        wfp_.disableProtection();
        routes_.rollback();
        wintun_.stopSession();
    }

private:
    WintunSessionBridge wintun_;
    RouteAndDnsTransaction routes_;
    WfpLeakGuard wfp_;
    uint64_t tunLuid_ = 0;
    uint64_t physLuid_ = 0;
    std::string physNextHopV4_;
};

void hardenServiceProcessMitigations() noexcept {
    (void)::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgPolicy{};
    imgPolicy.NoRemoteImages = 1;
    imgPolicy.NoLowMandatoryLabelImages = 1;
    (void)::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imgPolicy, sizeof(imgPolicy));

    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy{};
    handlePolicy.RaiseExceptionOnInvalidHandleReference = 0;
    (void)::SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));
}

LONG verifyAuthenticodeStatus(const std::wstring &exePath) noexcept {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = exePath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd{};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    LONG rc = ::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wtd);
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wtd);
    return rc;
}

bool isTrustedColocatedSiblingBinary(const std::wstring &clientFullW) noexcept {
    wchar_t selfBuf[2048]{};
    DWORD n = ::GetModuleFileNameW(nullptr, selfBuf, 2040);
    if (n == 0 || n >= 2040) return false;

    std::error_code ec1, ec2;
    auto serviceDir = std::filesystem::weakly_canonical(std::filesystem::path(std::wstring(selfBuf, n)).parent_path(), ec1);
    auto clientPath = std::filesystem::weakly_canonical(std::filesystem::path(clientFullW), ec2);
    if (ec1 || ec2) return false;
    if (clientPath.parent_path() != serviceDir) return false;

    std::wstring fname = clientPath.filename().wstring();
    for (wchar_t &c : fname) c = static_cast<wchar_t>(::towlower(c));
    return fname == L"hajimi.exe" || fname == L"hajimi-cli.exe";
}

bool inspectNamedPipeClient(HANDLE hPipe, PeerIdentity &outPeer) {
    outPeer = PeerIdentity{};
    ULONG clientPid = 0;
    if (!::GetNamedPipeClientProcessId(hPipe, &clientPid) || clientPid == 0) {
        return false;
    }
    outPeer.pid = static_cast<uint32_t>(clientPid);

    HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid);
    if (!hProc) return false;
    wchar_t wPath[2048]{};
    DWORD cap = 2040;
    BOOL ok = ::QueryFullProcessImageNameW(hProc, 0, wPath, &cap);
    ::CloseHandle(hProc);
    if (!ok || cap == 0) return false;

    std::wstring fullW(wPath, cap);
    int u8Len = ::WideCharToMultiByte(CP_UTF8, 0, fullW.data(), static_cast<int>(fullW.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (u8Len <= 0) return false;
    outPeer.imagePathUTF8.resize(static_cast<size_t>(u8Len));
    ::WideCharToMultiByte(CP_UTF8, 0, fullW.data(), static_cast<int>(fullW.size()),
                          outPeer.imagePathUTF8.data(), u8Len, nullptr, nullptr);

    if (fullW.size() >= 3 && fullW[1] == L':' && fullW[2] == L'\\') {
        wchar_t root[4] = {fullW[0], L':', L'\\', L'\0'};
        outPeer.fixedLocalDrive = (::GetDriveTypeW(root) == DRIVE_FIXED);
    }

    LONG trustStatus = verifyAuthenticodeStatus(fullW);
    if (trustStatus == ERROR_SUCCESS) {
        outPeer.signatureVerified = true;
    } else if ((trustStatus == TRUST_E_NOSIGNATURE || trustStatus == TRUST_E_SUBJECT_FORM_UNKNOWN) &&
               outPeer.fixedLocalDrive) {
        // For unsigned CI/open-source builds installed in %ProgramFiles%\Hajimi or extracted as Portable
        // alongside HajimiHelperService.exe: allow only exact co-located Hajimi.exe / hajimi-cli.exe
        // while still rejecting any tampered/badly-signed binary (`TRUST_E_BAD_DIGEST`) or non-sibling path!
        outPeer.signatureVerified = isTrustedColocatedSiblingBinary(fullW);
    }
    return true;
}

bool readPipeLineOverlapped(HANDLE hPipe, std::string &outLine, DWORD timeoutMs = 3000) {
    outLine.clear();
    HANDLE hEv = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEv) return false;

    char chBuf[4096];
    const auto deadline = nowSteadyMillis() + timeoutMs;
    while (outLine.size() < 262144 && nowSteadyMillis() < deadline) {
        ::ResetEvent(hEv);
        OVERLAPPED ov{};
        ov.hEvent = hEv;
        DWORD got = 0;
        BOOL ok = ::ReadFile(hPipe, chBuf, sizeof(chBuf), &got, &ov);
        if (!ok) {
            DWORD err = ::GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD waitRc = ::WaitForSingleObject(hEv, 500);
                if (waitRc != WAIT_OBJECT_0) {
                    ::CancelIoEx(hPipe, &ov);
                    ::GetOverlappedResult(hPipe, &ov, &got, TRUE);
                    break;
                }
                if (!::GetOverlappedResult(hPipe, &ov, &got, FALSE)) break;
            } else {
                break;
            }
        }
        if (got == 0) break;
        outLine.append(chBuf, got);
        auto nl = outLine.find('\n');
        if (nl != std::string::npos) {
            outLine.resize(nl);
            ::CloseHandle(hEv);
            return true;
        }
    }
    ::CloseHandle(hEv);
    return !outLine.empty();
}

bool writePipeAllOverlapped(HANDLE hPipe, const std::string &data, DWORD timeoutMs = 3000) {
    HANDLE hEv = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!hEv) return false;

    size_t offset = 0;
    while (offset < data.size()) {
        ::ResetEvent(hEv);
        OVERLAPPED ov{};
        ov.hEvent = hEv;
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>((std::min)(data.size() - offset, static_cast<size_t>(65536)));
        BOOL ok = ::WriteFile(hPipe, data.data() + offset, chunk, &written, &ov);
        if (!ok) {
            if (::GetLastError() != ERROR_IO_PENDING) {
                ::CloseHandle(hEv);
                return false;
            }
            if (::WaitForSingleObject(hEv, timeoutMs) != WAIT_OBJECT_0 ||
                !::GetOverlappedResult(hPipe, &ov, &written, FALSE)) {
                ::CancelIoEx(hPipe, &ov);
                ::GetOverlappedResult(hPipe, &ov, &written, TRUE);
                ::CloseHandle(hEv);
                return false;
            }
        }
        if (written == 0) {
            ::CloseHandle(hEv);
            return false;
        }
        offset += written;
    }
    ::CloseHandle(hEv);
    return true;
}

bool isProcessStillRunning(uint32_t pid) noexcept {
    if (pid == 0) return false;
    HANDLE h = ::OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD waitRc = ::WaitForSingleObject(h, 0);
    ::CloseHandle(h);
    return waitRc == WAIT_TIMEOUT;
}

void runNamedPipeServerLoop(HelperSessionCoordinator &coord) {
    std::thread watchdog([&coord] {
        while (!gServiceStop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            const uint32_t pid = coord.ownerPid();
            if (pid != 0) {
                const bool alive = isProcessStillRunning(pid);
                (void)coord.checkWatchdogTimeout(nowSteadyMillis(), alive);
            }
        }
    });

    PSECURITY_DESCRIPTOR pSD = nullptr;
    (void)::ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1, &pSD, nullptr);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    while (!gServiceStop.load(std::memory_order_acquire)) {
        HANDLE hPipe = ::CreateNamedPipeW(
            L"\\\\.\\pipe\\HajimiHelperPipe",
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            8, 65536, 65536, 1000, pSD ? &sa : nullptr);
        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        OVERLAPPED ov{};
        ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        BOOL connected = ::ConnectNamedPipe(hPipe, &ov);
        if (!connected) {
            DWORD err = ::GetLastError();
            if (err == ERROR_IO_PENDING) {
                while (!gServiceStop.load(std::memory_order_acquire)) {
                    if (::WaitForSingleObject(ov.hEvent, 250) == WAIT_OBJECT_0) {
                        connected = TRUE;
                        break;
                    }
                }
                if (!connected) {
                    ::CancelIoEx(hPipe, &ov);
                    DWORD dummy = 0;
                    ::GetOverlappedResult(hPipe, &ov, &dummy, TRUE);
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
            }
        }
        ::CloseHandle(ov.hEvent);

        if (!connected || gServiceStop.load(std::memory_order_acquire)) {
            ::CloseHandle(hPipe);
            continue;
        }

        PeerIdentity peer;
        if (inspectNamedPipeClient(hPipe, peer)) {
            std::string lineBuf;
            if (readPipeLineOverlapped(hPipe, lineBuf, 3000)) {
                std::string resp = coord.handleJsonLine(peer, lineBuf);
                (void)writePipeAllOverlapped(hPipe, resp, 3000);
                ::FlushFileBuffers(hPipe);
            }
        }

        ::DisconnectNamedPipe(hPipe);
        ::CloseHandle(hPipe);
    }

    if (pSD) ::LocalFree(pSD);
    if (watchdog.joinable()) watchdog.join();
}

SERVICE_STATUS_HANDLE gSvcStatusHandle = nullptr;
SERVICE_STATUS gSvcStatus{};

void reportSvcStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0) {
    static DWORD checkPoint = 1;
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwCurrentState = state;
    gSvcStatus.dwWin32ExitCode = exitCode;
    gSvcStatus.dwWaitHint = waitHint;
    gSvcStatus.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    gSvcStatus.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;
    if (gSvcStatusHandle) ::SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

DWORD WINAPI svcCtrlHandlerEx(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        reportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        gServiceStop.store(true, std::memory_order_release);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

VOID WINAPI svcMain(DWORD, LPWSTR *) {
    wchar_t svcName[] = L"HajimiHelperService";
    gSvcStatusHandle = ::RegisterServiceCtrlHandlerExW(svcName, svcCtrlHandlerEx, nullptr);
    if (!gSvcStatusHandle) return;

    reportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    auto ops = std::make_shared<Win32PrivilegedPlatformOps>();
    HelperSessionCoordinator coord(ops);
    reportSvcStatus(SERVICE_RUNNING);

    runNamedPipeServerLoop(coord);
    ops->rollbackAllNetworkChanges();
    reportSvcStatus(SERVICE_STOPPED);
}

int installOrRemoveService(bool install) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "OpenSCManagerW failed (" << ::GetLastError() << ")\n";
        return 1;
    }
    if (!install) {
        SC_HANDLE svc = ::OpenServiceW(scm, L"HajimiHelperService", SERVICE_STOP | DELETE);
        if (svc) {
            SERVICE_STATUS st{};
            (void)::ControlService(svc, SERVICE_CONTROL_STOP, &st);
            (void)::DeleteService(svc);
            ::CloseServiceHandle(svc);
        }
        ::CloseServiceHandle(scm);
        return 0;
    }

    wchar_t binPath[2048]{};
    ::GetModuleFileNameW(nullptr, binPath, 2040);
    std::wstring quoted = std::wstring(L"\"") + binPath + L"\"";

    SC_HANDLE svc = ::CreateServiceW(
        scm, L"HajimiHelperService", L"Hajimi Privileged Tunnel & Leak-Guard Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        quoted.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc && ::GetLastError() == ERROR_SERVICE_EXISTS) {
        svc = ::OpenServiceW(scm, L"HajimiHelperService", SERVICE_ALL_ACCESS);
        if (svc) {
            // Stop any older/relocated instance and point the service at this exact binary path
            // so co-located sibling verification succeeds after upgrades or Portable folder moves.
            SERVICE_STATUS st{};
            (void)::ControlService(svc, SERVICE_CONTROL_STOP, &st);
            for (int i = 0; i < 20; ++i) {
                SERVICE_STATUS cur{};
                if (::QueryServiceStatus(svc, &cur) && cur.dwCurrentState == SERVICE_STOPPED) break;
                ::Sleep(150);
            }
            (void)::ChangeServiceConfigW(
                svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                quoted.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                L"Hajimi Privileged Tunnel & Leak-Guard Service");
        }
    }
    if (!svc) {
        ::CloseServiceHandle(scm);
        return 2;
    }
    (void)::StartServiceW(svc, 0, nullptr);
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);
    return 0;
}
#endif // _WIN32

} // namespace

int main(int argc, char **argv) {
#if defined(_WIN32)
    hardenServiceProcessMitigations();
#endif

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--self-test") {
            int rc = HelperSessionCoordinator::runOfflineSelfTest();
            if (rc == 0) {
                std::cout << "[PASS] HajimiHelperService --self-test (Protocol v8 rev 4 + Zero-Trust + 3s Watchdog + WFP Dynamic)\n";
                return 0;
            }
            std::cerr << "[FAIL] HajimiHelperService --self-test failed at step " << rc << "\n";
            return rc;
        }
#if defined(_WIN32)
        if (arg == "--install") return installOrRemoveService(true);
        if (arg == "--uninstall") return installOrRemoveService(false);
        if (arg == "--console") {
            auto ops = std::make_shared<Win32PrivilegedPlatformOps>();
            HelperSessionCoordinator coord(ops);
            std::cout << "HajimiHelperService running in console debug mode...\n";
            runNamedPipeServerLoop(coord);
            ops->rollbackAllNetworkChanges();
            return 0;
        }
#endif
    }

#if defined(_WIN32)
    wchar_t svcName[] = L"HajimiHelperService";
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        {svcName, svcMain},
        {nullptr, nullptr}
    };
    if (!::StartServiceCtrlDispatcherW(dispatchTable)) {
        std::cerr << "StartServiceCtrlDispatcherW failed (" << ::GetLastError()
                  << "). Pass --console or --self-test when running interactively.\n";
        return 1;
    }
    return 0;
#else
    return HelperSessionCoordinator::runOfflineSelfTest();
#endif
}
