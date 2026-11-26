#include "../../Sources/HajimiEngineCAPI/include/HajimiEngineCAPI.h"
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace {
std::atomic<bool> gStopRequested{false};

void onSignal(int) {
    gStopRequested.store(true, std::memory_order_relaxed);
}

void printUsage() {
    std::cout
        << "Hajimi Windows Native Engine CLI (" << hajimi_engine_version() << ")\n"
        << "Usage:\n"
        << "  hajimi-cli --self-test\n"
        << "  hajimi-cli --diagnostics\n"
        << "  hajimi-cli --config <profile.conf|clash.yaml> [--http-port 7890] [--socks-port 7891]\n"
        << "             [--controller-port 9090] [--controller-key secret] [--dns-port 1053]\n"
        << "             [--mode rule|global|direct] [--system-proxy]\n";
}
} // namespace

int main(int argc, char **argv) {
    std::string configPath;
    std::string bindHost = "127.0.0.1";
    std::string ctrlKey;
    std::string modeStr = "rule";
    uint16_t httpPort = 7890;
    uint16_t socksPort = 7891;
    uint16_t ctrlPort = 0;
    uint16_t dnsPort = 0;
    bool runSelfTest = false;
    bool runDiagnostics = false;
    bool enableSysProxy = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--self-test" || arg == "--native-dataplane-self-test") {
            runSelfTest = true;
        } else if (arg == "--diagnostics") {
            runDiagnostics = true;
        } else if (arg == "--system-proxy") {
            enableSysProxy = true;
        } else if (arg == "--config" && i + 1 < argc) {
            configPath = argv[++i];
        } else if (arg == "--bind" && i + 1 < argc) {
            bindHost = argv[++i];
        } else if (arg == "--http-port" && i + 1 < argc) {
            httpPort = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--socks-port" && i + 1 < argc) {
            socksPort = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--controller-port" && i + 1 < argc) {
            ctrlPort = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--controller-key" && i + 1 < argc) {
            ctrlKey = argv[++i];
        } else if (arg == "--dns-port" && i + 1 < argc) {
            dnsPort = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--mode" && i + 1 < argc) {
            modeStr = argv[++i];
        }
    }

    if (runSelfTest) {
        int rc = hajimi_engine_self_test();
        if (rc == 0) {
            std::cout << "[PASS] hajimi_engine_self_test completed (version " << hajimi_engine_version() << ")\n";
            return 0;
        }
        std::cerr << "[FAIL] hajimi_engine_self_test failed at step " << rc << "\n";
        return rc;
    }

    HJEngineRef engine = hajimi_engine_create();
    if (!engine) {
        std::cerr << "Failed to allocate Hajimi engine instance\n";
        return 1;
    }

    char errBuf[512]{};
    if (!configPath.empty()) {
        if (hajimi_engine_load_profile_file(engine, configPath.c_str(), errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
            std::cerr << "Failed to load profile '" << configPath << "': " << errBuf << "\n";
            hajimi_engine_destroy(engine);
            return 2;
        }
    }

    if (modeStr == "global") hajimi_engine_set_outbound_mode(engine, HAJIMI_MODE_GLOBAL);
    else if (modeStr == "direct") hajimi_engine_set_outbound_mode(engine, HAJIMI_MODE_DIRECT);
    else hajimi_engine_set_outbound_mode(engine, HAJIMI_MODE_RULE);

    if (runDiagnostics) {
        char *diag = hajimi_engine_run_diagnostics_json(engine);
        if (diag) {
            std::cout << diag << "\n";
            hajimi_engine_free_string(diag);
        }
        hajimi_engine_destroy(engine);
        return 0;
    }

    HJEngineListenerConfig cfg{};
    cfg.bind_host = bindHost.c_str();
    cfg.http_port = httpPort;
    cfg.socks_port = socksPort;
    cfg.controller_port = ctrlPort;
    cfg.dns_listen_port = dnsPort;
    cfg.controller_key = ctrlKey.empty() ? nullptr : ctrlKey.c_str();

    if (hajimi_engine_start(engine, &cfg, errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
        std::cerr << "Failed to start listeners: " << errBuf << "\n";
        hajimi_engine_destroy(engine);
        return 3;
    }

    const std::string snapDir = (std::filesystem::current_path() / "data").u8string();
    if (enableSysProxy && hajimi_engine_bound_http_port(engine) != 0) {
        if (hajimi_win_sysproxy_enable(
                snapDir.c_str(), "127.0.0.1", hajimi_engine_bound_http_port(engine),
                "localhost;127.*;10.*;172.16.*;192.168.*;<local>", errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
            std::cerr << "Warning: system proxy not enabled: " << errBuf << "\n";
            enableSysProxy = false;
        }
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    std::cout << "Hajimi Engine running — HTTP " << bindHost << ":" << hajimi_engine_bound_http_port(engine)
              << ", SOCKS5 " << bindHost << ":" << hajimi_engine_bound_socks_port(engine) << "\n";

    while (!gStopRequested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (enableSysProxy) {
        (void)hajimi_win_sysproxy_disable(snapDir.c_str(), errBuf, sizeof(errBuf));
    }
    hajimi_engine_stop(engine);
    hajimi_engine_destroy(engine);
    return 0;
}
