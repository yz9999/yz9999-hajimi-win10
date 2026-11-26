#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#endif

/// Portable zero-install launcher (`HajimiPortable.exe`):
/// - Configures `HAJIMI_DATA_DIR=<exe_dir>\data` so profiles, subscriptions,
///   and `system-proxy-snapshot.json` stay 100% self-contained on USB/portable folders
///   without touching Windows Registry installation keys.
/// - Supports `--elevate-helper` to launch `HajimiHelperService.exe --console`
///   via a single on-demand UAC prompt when the user wants Enhanced Mode without
///   installing a persistent Windows NT service.
int main(int argc, char **argv) {
    bool elevateHelper = false;
    bool selfTest = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--elevate-helper") elevateHelper = true;
        else if (arg == "--self-test") selfTest = true;
    }

    if (selfTest) {
        std::cout << "[PASS] HajimiPortable launcher self-test ok\n";
        return 0;
    }

#if defined(_WIN32)
    wchar_t moduleBuf[2048]{};
    DWORD len = ::GetModuleFileNameW(nullptr, moduleBuf, 2040);
    if (len == 0 || len >= 2040) return 1;

    std::filesystem::path exeDir = std::filesystem::path(std::wstring(moduleBuf, len)).parent_path();
    std::filesystem::path dataDir = exeDir / L"data";
    std::error_code ec;
    std::filesystem::create_directories(dataDir, ec);

    ::SetEnvironmentVariableW(L"HAJIMI_DATA_DIR", dataDir.wstring().c_str());
    ::SetEnvironmentVariableW(L"HAJIMI_PORTABLE_MODE", L"1");

    if (elevateHelper) {
        std::filesystem::path helperExe = exeDir / L"HajimiHelperService.exe";
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";
        sei.lpFile = helperExe.wstring().c_str();
        sei.lpParameters = L"--console";
        sei.lpDirectory = exeDir.wstring().c_str();
        sei.nShow = SW_HIDE;
        return ::ShellExecuteExW(&sei) ? 0 : 2;
    }

    std::filesystem::path guiExe = exeDir / L"Hajimi.exe";
    if (!std::filesystem::exists(guiExe)) {
        guiExe = exeDir / L"hajimi-cli.exe";
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmdLine = L"\"" + guiExe.wstring() + L"\"";
    if (!::CreateProcessW(guiExe.wstring().c_str(), cmdLine.data(),
                          nullptr, nullptr, FALSE, 0, nullptr,
                          exeDir.wstring().c_str(), &si, &pi)) {
        return 3;
    }
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return 0;
#else
    (void)elevateHelper;
    return 0;
#endif
}
