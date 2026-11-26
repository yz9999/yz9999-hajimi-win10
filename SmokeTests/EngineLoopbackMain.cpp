#include "../Sources/HajimiEngineCAPI/include/HajimiEngineCAPI.h"
#include "../Sources/HajimiDataPlaneC/include/hajimi_dataplane.h"
#include "../Sources/HajimiPlatformC/include/HajimiShmRing.h"
#include "../Sources/HajimiProtocolCXX/include/HajimiProtocolCXX.h"
#include "../Sources/HajimiProtocolsCXX/PlatformCompat.hpp"
#include "../Windows/HajimiHelperService/HelperProtocolV8.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace hajimi;

bool sendAllTest(platform::NativeSocket s, const void *buf, size_t len) {
    const auto *p = static_cast<const char *>(buf);
    size_t sent = 0;
    while (sent < len) {
        auto n = ::send(platform::toOsSocket(s), p + sent, static_cast<int>(len - sent), 0);
        if (n <= 0) {
            if (platform::isSocketWouldBlock(platform::lastSocketError())) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::string recvUntilClosedOrMarker(platform::NativeSocket s, const std::string &marker, int timeoutMs = 4000) {
    std::string acc;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    char buf[4096];
    while (std::chrono::steady_clock::now() < deadline) {
        auto n = ::recv(platform::toOsSocket(s), buf, sizeof(buf), 0);
        if (n > 0) {
            acc.append(buf, static_cast<size_t>(n));
            if (!marker.empty() && acc.find(marker) != std::string::npos) break;
            continue;
        }
        if (n == 0) break;
        if (platform::isSocketWouldBlock(platform::lastSocketError())) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }
        break;
    }
    return acc;
}

struct EphemeralOriginServer {
    platform::NativeSocket listenSock = platform::kInvalidSocket;
    uint16_t port = 0;
    std::atomic<bool> stop{false};
    std::thread worker;

    bool start() {
        platform::ensureWinsock();
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        auto raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        listenSock = platform::toNativeSocket(raw);
        if (listenSock < 0) return false;
        (void)platform::setNonBlockingAndCloexec(listenSock);
        socklen_t alen = sizeof(addr);
        if (::bind(platform::toOsSocket(listenSock), reinterpret_cast<sockaddr *>(&addr), alen) != 0 ||
            ::getsockname(platform::toOsSocket(listenSock), reinterpret_cast<sockaddr *>(&addr), &alen) != 0 ||
            ::listen(platform::toOsSocket(listenSock), 16) != 0) {
            platform::closeNativeSocket(listenSock);
            return false;
        }
        port = ntohs(addr.sin_port);
        worker = std::thread([this] {
            while (!stop.load(std::memory_order_acquire)) {
                sockaddr_in peer{};
                socklen_t plen = sizeof(peer);
                auto cRaw = ::accept(platform::toOsSocket(listenSock), reinterpret_cast<sockaddr *>(&peer), &plen);
                platform::NativeSocket cli = platform::toNativeSocket(cRaw);
                if (cli < 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    continue;
                }
                std::thread([cli]() mutable {
                    std::string reqStr = recvUntilClosedOrMarker(cli, "\r\n\r\n", 3000);
                    if (!reqStr.empty()) {
                        std::string body = "HAJIMI_ORIGIN_OK:" + std::to_string(reqStr.size());
                        std::ostringstream resp;
                        resp << "HTTP/1.1 200 OK\r\n"
                             << "Content-Length: " << body.size() << "\r\n"
                             << "Connection: close\r\n\r\n"
                             << body;
                        std::string wire = resp.str();
                        (void)sendAllTest(cli, wire.data(), wire.size());
                    }
                    platform::closeNativeSocket(cli);
                }).detach();
            }
        });
        return true;
    }

    ~EphemeralOriginServer() {
        stop.store(true, std::memory_order_release);
        platform::closeNativeSocket(listenSock);
        if (worker.joinable()) worker.join();
    }
};

struct EphemeralUdpEchoServer {
    platform::NativeSocket sock = platform::kInvalidSocket;
    uint16_t port = 0;
    std::atomic<bool> stop{false};
    std::thread worker;

    bool start() {
        platform::ensureWinsock();
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        auto raw = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sock = platform::toNativeSocket(raw);
        if (sock < 0) return false;
        platform::disableUdpConnReset(sock);
        (void)platform::setNonBlockingAndCloexec(sock);
        socklen_t alen = sizeof(addr);
        if (::bind(platform::toOsSocket(sock), reinterpret_cast<sockaddr *>(&addr), alen) != 0 ||
            ::getsockname(platform::toOsSocket(sock), reinterpret_cast<sockaddr *>(&addr), &alen) != 0) {
            platform::closeNativeSocket(sock);
            return false;
        }
        port = ntohs(addr.sin_port);
        worker = std::thread([this] {
            char rx[2048];
            while (!stop.load(std::memory_order_acquire)) {
                sockaddr_in peer{};
                socklen_t plen = sizeof(peer);
                auto n = ::recvfrom(platform::toOsSocket(sock), rx, sizeof(rx), 0,
                                    reinterpret_cast<sockaddr *>(&peer), &plen);
                if (n > 0) {
                    std::string reply = "UDP_NAT_PONG:" + std::string(rx, static_cast<size_t>(n));
                    (void)::sendto(platform::toOsSocket(sock), reply.data(),
                                   static_cast<int>(reply.size()), 0,
                                   reinterpret_cast<const sockaddr *>(&peer), plen);
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                }
            }
        });
        return true;
    }

    ~EphemeralUdpEchoServer() {
        stop.store(true, std::memory_order_release);
        platform::closeNativeSocket(sock);
        if (worker.joinable()) worker.join();
    }
};

platform::NativeSocket connectLoopbackBlocking(uint16_t port) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);
    auto raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    platform::NativeSocket s = platform::toNativeSocket(raw);
    if (s < 0) return platform::kInvalidSocket;
    if (::connect(platform::toOsSocket(s), reinterpret_cast<const sockaddr *>(&dst), sizeof(dst)) != 0) {
        platform::closeNativeSocket(s);
        return platform::kInvalidSocket;
    }
    (void)platform::setNonBlockingAndCloexec(s);
    return s;
}

} // namespace

int main() {
    // 1. Built-in Engine & RULE-SET/GEOIP & SystemProxy & Fake-IP & SHM Ring Self-Test
    int rc = hajimi_engine_self_test();
    if (rc != 0) {
        std::cerr << "[FAIL] hajimi_engine_self_test failed with code " << rc << "\n";
        return 1;
    }
    std::cout << "[PASS] Phase 1: hajimi_engine_self_test (Surge/Clash/RULE-SET/GEOIP, .exe rule, Fake-IP, SHM TUN, WinSystemProxy)\n";

    // 2. HelperService Protocol v8 + Zero-Trust + 3s Watchdog + WFP Dynamic Self-Test
    int helperRc = helper::HelperSessionCoordinator::runOfflineSelfTest();
    if (helperRc != 0) {
        std::cerr << "[FAIL] HelperSessionCoordinator::runOfflineSelfTest failed at step " << helperRc << "\n";
        return 2;
    }
    std::cout << "[PASS] Phase 2: HelperSessionCoordinator Protocol v8 & Chaos Watchdog self-test\n";

    // 3. Live Loopback HTTP CONNECT (including DIRECT domain resolution) + SOCKS5 + ExternalController Auth Gate
    EphemeralOriginServer origin;
    if (!origin.start()) {
        std::cerr << "[FAIL] Could not start loopback origin server\n";
        return 3;
    }

    const char *clashYaml =
        "mixed-port: 0\n"
        "proxies:\n"
        "  - { name: \"LocalDirect\", type: direct, server: 127.0.0.1, port: 80 }\n"
        "proxy-groups:\n"
        "  - name: \"Proxy\"\n"
        "    type: select\n"
        "    proxies:\n"
        "      - LocalDirect\n"
        "      - DIRECT\n"
        "rules:\n"
        "  - DOMAIN-SUFFIX,blocked.invalid,REJECT\n"
        "  - MATCH,Proxy\n";

    HJEngineRef eng = hajimi_engine_create();
    char errBuf[256]{};
    if (hajimi_engine_load_profile_text(eng, clashYaml, std::strlen(clashYaml), errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
        std::cerr << "[FAIL] Clash YAML load error: " << errBuf << "\n";
        hajimi_engine_destroy(eng);
        return 4;
    }

    HJEngineListenerConfig insecureCfg{};
    insecureCfg.bind_host = "0.0.0.0";
    insecureCfg.controller_port = 0xFFFFu;
    insecureCfg.controller_key = "";
    if (hajimi_engine_start(eng, &insecureCfg, errBuf, sizeof(errBuf)) == HAJIMI_ENGINE_OK) {
        std::cerr << "[FAIL] Unauthenticated 0.0.0.0 ExternalController should have been rejected!\n";
        hajimi_engine_destroy(eng);
        return 5;
    }

    HJEngineListenerConfig cfg{};
    cfg.bind_host = "127.0.0.1";
    cfg.http_port = 0xFFFFu;
    cfg.socks_port = 0xFFFFu;
    cfg.controller_port = 0xFFFFu;
    cfg.dns_listen_port = 0xFFFFu;
    cfg.controller_key = "hajimi-secret-token";

    if (hajimi_engine_start(eng, &cfg, errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
        std::cerr << "[FAIL] hajimi_engine_start failed: " << errBuf << "\n";
        hajimi_engine_destroy(eng);
        return 6;
    }

    const uint16_t httpPort = hajimi_engine_bound_http_port(eng);
    const uint16_t socksPort = hajimi_engine_bound_socks_port(eng);
    const uint16_t ctrlPort = hajimi_engine_bound_controller_port(eng);

    // 3a. HTTP CONNECT via hostname `localhost` (verifies P0 DIRECT TCP hostname resolution)
    {
        auto cli = connectLoopbackBlocking(httpPort);
        if (cli < 0) return 7;
        std::string connectReq = "CONNECT localhost:" + std::to_string(origin.port) +
                                 " HTTP/1.1\r\nHost: localhost:" + std::to_string(origin.port) + "\r\n\r\n";
        if (!sendAllTest(cli, connectReq.data(), connectReq.size())) return 8;
        std::string est = recvUntilClosedOrMarker(cli, "\r\n\r\n");
        if (est.find("200 Connection Established") == std::string::npos) {
            std::cerr << "[FAIL] HTTP CONNECT hostname failed: " << est << "\n";
            return 9;
        }
        const char *innerReq = "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if (!sendAllTest(cli, innerReq, std::strlen(innerReq))) return 10;
        std::string body = recvUntilClosedOrMarker(cli, "HAJIMI_ORIGIN_OK:");
        platform::closeNativeSocket(cli);
        if (body.find("HAJIMI_ORIGIN_OK:") == std::string::npos) {
            std::cerr << "[FAIL] HTTP CONNECT payload relay mismatch: " << body << "\n";
            return 11;
        }
    }

    // 3b. SOCKS5 CONNECT -> EphemeralOriginServer
    {
        auto cli = connectLoopbackBlocking(socksPort);
        if (cli < 0) return 12;
        const uint8_t greet[3] = {0x05, 0x01, 0x00};
        if (!sendAllTest(cli, greet, 3)) return 13;
        std::string gr = recvUntilClosedOrMarker(cli, std::string("\x05\x00", 2));
        if (gr.size() < 2 || static_cast<uint8_t>(gr[0]) != 0x05 || static_cast<uint8_t>(gr[1]) != 0x00) {
            return 14;
        }
        uint8_t req[10] = {
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            static_cast<uint8_t>(origin.port >> 8),
            static_cast<uint8_t>(origin.port & 0xFFu)
        };
        if (!sendAllTest(cli, req, sizeof(req))) return 15;
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        const char *innerReq = "GET /socks HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        if (!sendAllTest(cli, innerReq, std::strlen(innerReq))) return 16;
        std::string resp = recvUntilClosedOrMarker(cli, "HAJIMI_ORIGIN_OK:");
        platform::closeNativeSocket(cli);
        if (resp.find("HAJIMI_ORIGIN_OK:") == std::string::npos) {
            std::cerr << "[FAIL] SOCKS5 relay mismatch\n";
            return 17;
        }
    }

    // 3c. ExternalController `/v1/status` unauthorized vs X-Key authorized check
    {
        auto unauthCli = connectLoopbackBlocking(ctrlPort);
        const char *noKeyReq = "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        (void)sendAllTest(unauthCli, noKeyReq, std::strlen(noKeyReq));
        std::string unauthResp = recvUntilClosedOrMarker(unauthCli, "}");
        platform::closeNativeSocket(unauthCli);
        if (unauthResp.find("401 Unauthorized") == std::string::npos) {
            std::cerr << "[FAIL] ExternalController failed to enforce X-Key!\n";
            return 18;
        }

        auto authCli = connectLoopbackBlocking(ctrlPort);
        const char *keyReq = "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: hajimi-secret-token\r\nConnection: close\r\n\r\n";
        (void)sendAllTest(authCli, keyReq, std::strlen(keyReq));
        std::string authResp = recvUntilClosedOrMarker(authCli, "}");
        platform::closeNativeSocket(authCli);
        if (authResp.find("200 OK") == std::string::npos || authResp.find("\"running\":true") == std::string::npos) {
            std::cerr << "[FAIL] Authorized ExternalController /v1/status failed: " << authResp << "\n";
            return 19;
        }
    }
    std::cout << "[PASS] Phase 3: Live Loopback HTTP CONNECT (Hostname DNS), SOCKS5 & ExternalController X-Key Gate\n";

    // 4. M5 Performance Benchmark: 8 MiB SPSC Shared Memory Ring Sustained Throughput
    {
        std::vector<uint8_t> arena(HAJIMI_SHM_DUPLEX_TOTAL_BYTES, 0);
        shm::initDuplexRegion(arena.data(), 1400);
        auto *hdr = reinterpret_cast<shm::DuplexHeader *>(arena.data());
        uint8_t *ring = shm::rxRingStorage(arena.data());

        constexpr uint32_t kTotalPackets = 200000;
        constexpr uint32_t kPktSize = 1400;
        std::vector<uint8_t> samplePkt(kPktSize, 0x5Au);

        const auto t0 = std::chrono::steady_clock::now();
        std::thread producer([&] {
            uint32_t sent = 0;
            while (sent < kTotalPackets) {
                bool sig = false;
                if (shm::spscTryPush(hdr->rxProducer, hdr->rxConsumer, ring,
                                     hdr->ringCapacity, samplePkt.data(), kPktSize, sig)) {
                    ++sent;
                } else {
                    std::this_thread::yield();
                }
            }
        });

        uint32_t received = 0;
        std::vector<uint8_t> outBuf(1500);
        while (received < kTotalPackets) {
            uint32_t n = shm::spscTryPop(hdr->rxProducer, hdr->rxConsumer, ring,
                                         hdr->ringCapacity, outBuf.data(), static_cast<uint32_t>(outBuf.size()));
            if (n == kPktSize) {
                ++received;
            } else {
                std::this_thread::yield();
            }
        }
        producer.join();
        const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        const double gbps = (static_cast<double>(kTotalPackets) * kPktSize * 8.0) / ((std::max)(sec, 1e-6) * 1e9);
        std::cout << "[PASS] Phase 4: 8 MiB SPSC Lock-Free Shared Ring Benchmark — "
                  << kTotalPackets << " x 1400B packets in " << (sec * 1000.0)
                  << " ms (" << gbps << " Gbps, 0 drops)\n";
    }

    // 5. Non-Port-53 General UDP Bidirectional NAT + Fake-IP Source Restoration + Full-Cone Reuse
    EphemeralUdpEchoServer udpOrigin;
    if (!udpOrigin.start() || udpOrigin.port == 53) {
        std::cerr << "[FAIL] Could not start ephemeral UDP echo server\n";
        return 20;
    }

    {
        const char *udpSurgeProfile =
            "[General]\n"
            "dns-server = 1.1.1.1\n"
            "[Host]\n"
            "game.udp.example = 127.0.0.1\n"
            "[Rule]\n"
            "DOMAIN, blocked-udp.example, REJECT\n"
            "FINAL, DIRECT\n";

        HJEngineRef udpEng = hajimi_engine_create();
        if (hajimi_engine_load_profile_text(udpEng, udpSurgeProfile, std::strlen(udpSurgeProfile),
                                            errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
            std::cerr << "[FAIL] UDP test profile load error: " << errBuf << "\n";
            hajimi_engine_destroy(udpEng);
            return 21;
        }

        char gameFakeIpStr[32]{};
        char blockedFakeIpStr[32]{};
        uint8_t gameFakeIp[4]{};
        uint8_t blockedFakeIp[4]{};
        if (hajimi_engine_allocate_fakeip(udpEng, "game.udp.example", gameFakeIpStr, sizeof(gameFakeIpStr)) != HAJIMI_ENGINE_OK ||
            hajimi_engine_allocate_fakeip(udpEng, "blocked-udp.example", blockedFakeIpStr, sizeof(blockedFakeIpStr)) != HAJIMI_ENGINE_OK ||
            hajimi_parse_ipv4_literal(gameFakeIpStr, std::strlen(gameFakeIpStr), gameFakeIp) != 1 ||
            hajimi_parse_ipv4_literal(blockedFakeIpStr, std::strlen(blockedFakeIpStr), blockedFakeIp) != 1) {
            hajimi_engine_destroy(udpEng);
            return 22;
        }

        std::vector<uint8_t> udpArena(HAJIMI_SHM_DUPLEX_TOTAL_BYTES, 0);
        shm::initDuplexRegion(udpArena.data(), 1400);
        if (hajimi_engine_attach_shm_tunnel(udpEng, udpArena.data(), 0, 0, 0) != HAJIMI_ENGINE_OK) {
            hajimi_engine_destroy(udpEng);
            return 23;
        }

        auto *uHdr = reinterpret_cast<shm::DuplexHeader *>(udpArena.data());
        const uint8_t tunCliIp[4] = {198, 18, 16, 88};
        const uint16_t tunCliPort = 55123;
        const uint8_t loopbackIp[4] = {127, 0, 0, 1};

        auto pushTunUdp = [&](const uint8_t dstIp[4], uint16_t dstPort, const std::string &payload, uint16_t ipId) -> bool {
            uint8_t raw[512]{};
            size_t built = hajimi_build_ipv4_udp(
                raw, sizeof(raw), tunCliIp, tunCliPort, dstIp, dstPort,
                reinterpret_cast<const uint8_t *>(payload.data()), payload.size(), ipId);
            bool wake = false;
            return built > 0 && shm::spscTryPush(uHdr->rxProducer, uHdr->rxConsumer,
                                                 shm::rxRingStorage(udpArena.data()), uHdr->ringCapacity,
                                                 raw, static_cast<uint32_t>(built), wake);
        };

        auto popAndVerifyTunUdp = [&](const uint8_t expectedSrcIp[4], const std::string &expectedPayload) -> bool {
            uint8_t outPkt[1500]{};
            uint32_t popped = 0;
            for (int i = 0; i < 400 && popped == 0; ++i) {
                popped = shm::spscTryPop(uHdr->txProducer, uHdr->txConsumer,
                                         shm::txRingStorage(udpArena.data()), uHdr->ringCapacity,
                                         outPkt, sizeof(outPkt));
                if (popped == 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (popped < 28) return false;
            hajimi_ip_packet ipPkt{};
            hajimi_udp_datagram udpPkt{};
            if (hajimi_parse_ip(outPkt, popped, &ipPkt) != HAJIMI_PARSE_OK || ipPkt.protocol != 17 ||
                hajimi_parse_udp(outPkt + ipPkt.payload_offset, ipPkt.payload_length, &udpPkt) != HAJIMI_PARSE_OK) {
                return false;
            }
            if (std::memcmp(ipPkt.source, expectedSrcIp, 4) != 0 ||
                std::memcmp(ipPkt.destination, tunCliIp, 4) != 0 ||
                udpPkt.source_port != udpOrigin.port ||
                udpPkt.destination_port != tunCliPort) {
                return false;
            }
            if (hajimi_transport_checksum(ipPkt.source, ipPkt.destination, 4, 17,
                                          outPkt + ipPkt.payload_offset, ipPkt.payload_length) != 0) {
                return false;
            }
            std::string gotPayload(reinterpret_cast<const char *>(outPkt + ipPkt.payload_offset + udpPkt.payload_offset),
                                   udpPkt.payload_length);
            return gotPayload == expectedPayload;
        };

        if (!pushTunUdp(blockedFakeIp, udpOrigin.port, "BLOCKED_PKT", 0x5101)) return 24;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        if (!pushTunUdp(gameFakeIp, udpOrigin.port, "QUIC_CHLO_1", 0x5102) ||
            !popAndVerifyTunUdp(gameFakeIp, "UDP_NAT_PONG:QUIC_CHLO_1")) return 25;
        if (!pushTunUdp(gameFakeIp, udpOrigin.port, "QUIC_DATA_2", 0x5103) ||
            !popAndVerifyTunUdp(gameFakeIp, "UDP_NAT_PONG:QUIC_DATA_2")) return 26;
        if (!pushTunUdp(loopbackIp, udpOrigin.port, "STUN_BIND_3", 0x5104) ||
            !popAndVerifyTunUdp(loopbackIp, "UDP_NAT_PONG:STUN_BIND_3")) return 27;

        char *statusJson = hajimi_engine_get_status_json(udpEng);
        std::string statusStr = statusJson ? statusJson : "";
        hajimi_engine_free_string(statusJson);
        if (statusStr.find("\"activeUdpSessions\":1") == std::string::npos ||
            statusStr.find("\"totalUdpSessions\":1") == std::string::npos) {
            return 28;
        }

        hajimi_engine_detach_tunnel(udpEng);
        hajimi_engine_destroy(udpEng);
        std::cout << "[PASS] Phase 5: Non-53 General UDP Bidirectional Full-Cone NAT + Fake-IP Restoration ("
                  << gameFakeIpStr << ":" << udpOrigin.port << " <-> 127.0.0.1:" << udpOrigin.port << ")\n";
    }

    // 6. SOCKS5 UDP ASSOCIATE (CMD=0x03) + Active Connection Force-Disconnect + Auto-Failover Group Probe
    {
        auto tcpCtrl = connectLoopbackBlocking(socksPort);
        if (tcpCtrl < 0) return 30;
        const uint8_t greet[3] = {0x05, 0x01, 0x00};
        if (!sendAllTest(tcpCtrl, greet, 3)) return 31;
        std::string gr = recvUntilClosedOrMarker(tcpCtrl, std::string("\x05\x00", 2));
        if (gr.size() < 2) return 32;

        // Send SOCKS5 UDP ASSOCIATE request (CMD = 0x03, 0.0.0.0:0)
        const uint8_t assocReq[10] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        if (!sendAllTest(tcpCtrl, assocReq, sizeof(assocReq))) return 33;

        std::string assocRep;
        auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (assocRep.size() < 10 && std::chrono::steady_clock::now() < dl) {
            char b[32];
            auto n = ::recv(platform::toOsSocket(tcpCtrl), b, sizeof(b), 0);
            if (n > 0) assocRep.append(b, static_cast<size_t>(n));
            else std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (assocRep.size() < 10 || static_cast<uint8_t>(assocRep[1]) != 0x00u) {
            std::cerr << "[FAIL] SOCKS5 UDP ASSOCIATE rejected\n";
            return 34;
        }
        const uint16_t relayPort = (static_cast<uint16_t>(static_cast<uint8_t>(assocRep[8])) << 8) |
                                    static_cast<uint16_t>(static_cast<uint8_t>(assocRep[9]));

        auto cliUdpRaw = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        platform::NativeSocket cliUdp = platform::toNativeSocket(cliUdpRaw);
        (void)platform::setNonBlockingAndCloexec(cliUdp);

        hajimi_address dstAddr{};
        (void)hajimi_address_from_host(reinterpret_cast<const uint8_t *>("127.0.0.1"), 9, udpOrigin.port, &dstAddr);
        const char *msg = "SOCKS5_UDP_GAME_PKT";
        uint8_t wireOut[256]{};
        auto enc = hajimi_socks5_encode_udp(
            &dstAddr, reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), wireOut, sizeof(wireOut));
        if (enc.status != HAJIMI_CODEC_OK) return 35;

        sockaddr_in relaySin{};
        relaySin.sin_family = AF_INET;
        relaySin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        relaySin.sin_port = htons(relayPort);
        (void)::sendto(platform::toOsSocket(cliUdp), reinterpret_cast<const char *>(wireOut),
                       static_cast<int>(enc.written), 0, reinterpret_cast<const sockaddr *>(&relaySin), sizeof(relaySin));

        uint8_t wireIn[512]{};
        int gotUdp = 0;
        for (int i = 0; i < 300 && gotUdp <= 0; ++i) {
            gotUdp = static_cast<int>(::recvfrom(platform::toOsSocket(cliUdp),
                                                 reinterpret_cast<char *>(wireIn), sizeof(wireIn), 0, nullptr, nullptr));
            if (gotUdp <= 0) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        platform::closeNativeSocket(cliUdp);
        if (gotUdp <= 0) {
            std::cerr << "[FAIL] SOCKS5 UDP ASSOCIATE timed out waiting for echoed datagram\n";
            return 36;
        }
        hajimi_udp_frame parsedFrame{};
        if (hajimi_socks5_parse_udp(wireIn, static_cast<size_t>(gotUdp), &parsedFrame).status != HAJIMI_CODEC_OK) {
            return 37;
        }
        std::string echoed(reinterpret_cast<const char *>(wireIn + parsedFrame.payload_offset), parsedFrame.payload_length);
        if (echoed != "UDP_NAT_PONG:SOCKS5_UDP_GAME_PKT") {
            std::cerr << "[FAIL] SOCKS5 UDP payload mismatch: " << echoed << "\n";
            return 38;
        }

        // Verify live active connection table & force-disconnect (`hajimi_engine_close_connection`)
        char *connsJson = hajimi_engine_get_connections_json(eng);
        std::string connsStr = connsJson ? connsJson : "";
        hajimi_engine_free_string(connsJson);
        if (connsStr.find("SOCKS5-UDP") == std::string::npos) {
            std::cerr << "[FAIL] Active connections table missing SOCKS5-UDP: " << connsStr << "\n";
            return 39;
        }
        if (hajimi_engine_close_connection(eng, 0) < 1) {
            std::cerr << "[FAIL] hajimi_engine_close_connection(0) did not close active session\n";
            return 40;
        }
        platform::closeNativeSocket(tcpCtrl);

        char *logsJson = hajimi_engine_get_logs_json(eng, 0);
        std::string logsStr = logsJson ? logsJson : "";
        hajimi_engine_free_string(logsJson);
        if (logsStr.find("SOCKS5-UDP") == std::string::npos) {
            std::cerr << "[FAIL] Streaming log ring missing SOCKS5-UDP event\n";
            return 41;
        }

        // Verify automatic Fallback policy group probe switches away from dead node
        std::string fbProfile =
            "[Proxy]\n"
            "DeadNode = socks5, 127.0.0.1, 1\n"
            "AliveNode = socks5, 127.0.0.1, " + std::to_string(origin.port) + "\n"
            "[Proxy Group]\n"
            "AutoFailover = fallback, DeadNode, AliveNode, interval=60\n"
            "[Rule]\n"
            "FINAL, AutoFailover\n";
        HJEngineRef fbEng = hajimi_engine_create();
        if (hajimi_engine_load_profile_text(fbEng, fbProfile.data(), fbProfile.size(), errBuf, sizeof(errBuf)) != HAJIMI_ENGINE_OK) {
            return 42;
        }
        (void)hajimi_engine_probe_all_nodes(fbEng, 400);
        char selPol[64]{};
        if (hajimi_engine_evaluate_route(fbEng, "example.com", 443, "TCP", "", selPol, sizeof(selPol)) != HAJIMI_ENGINE_OK ||
            std::strcmp(selPol, "AliveNode") != 0) {
            std::cerr << "[FAIL] Fallback policy group failed to switch to AliveNode, got: " << selPol << "\n";
            hajimi_engine_destroy(fbEng);
            return 43;
        }
        hajimi_engine_destroy(fbEng);

        std::cout << "[PASS] Phase 6: SOCKS5 UDP ASSOCIATE (RFC 1928), Live Connection Kill, Streaming Logs & Auto-Failover Group Probe\n";
    }

    hajimi_engine_stop(eng);
    hajimi_engine_destroy(eng);
    std::cout << "ALL M2 + M3 + M5 + UDP NAT + SOCKS5-UDP + AUTO-PROBE GATES PASSED!\n";
    return 0;
}
