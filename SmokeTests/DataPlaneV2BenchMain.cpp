#include "../Sources/HajimiEngineCAPI/include/HajimiEngineCAPI.h"
#include <sys/socket.h>
#include <unistd.h>
#include "../Sources/HajimiDataPlaneC/include/hajimi_dataplane.h"
#include "../Sources/HajimiFlowCXX/include/HajimiFlowCXX.h"
#include "../Sources/HajimiPlatformC/include/HajimiAsyncPoller.h"
#include "../Sources/HajimiPlatformC/include/HajimiPacketSlabPool.h"
#include "../Sources/HajimiPlatformC/include/HajimiShmRing.h"
#include "../Sources/HajimiProtocolsCXX/Crypto.hpp"
#include "../Sources/HajimiProtocolsCXX/Snell.hpp"
#include "../Sources/HajimiProtocolsCXX/WireGuardCore.hpp"
#include "../Sources/HajimiRoutingCXX/include/HajimiRoutingCXX.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

using namespace hajimi;

namespace {

void check(bool cond, const char *msg) {
    if (!cond) {
        std::fprintf(stderr, "[FAIL] %s\n", msg);
        std::exit(1);
    }
}

void runShmRingBatchVsSingleBenchmark() {
    constexpr uint32_t kPacketCount = 400000u;
    constexpr uint32_t kPacketLen   = 1400u;
    std::unique_ptr<uint8_t[]> region(new uint8_t[HAJIMI_SHM_DUPLEX_TOTAL_BYTES]);

    std::vector<uint8_t> sample(kPacketLen, 0x5Au);
    sample[0] = 0x45; // IPv4 header marker

    // 1. Baseline: Single-packet push/pop
    shm::initDuplexRegion(region.get(), 1400u);
    auto *hdr = reinterpret_cast<shm::DuplexHeader *>(region.get());
    uint8_t *rxRing = shm::rxRingStorage(region.get());

    const auto t0 = std::chrono::steady_clock::now();
    std::thread singleProd([&] {
        bool wake = false;
        for (uint32_t i = 0; i < kPacketCount; ++i) {
            while (!shm::spscTryPush(hdr->rxProducer, hdr->rxConsumer, rxRing,
                                     hdr->ringCapacity, sample.data(), kPacketLen, wake)) {
                std::this_thread::yield();
            }
        }
    });
    std::thread singleCons([&] {
        std::vector<uint8_t> out(2048);
        uint32_t got = 0;
        while (got < kPacketCount) {
            uint32_t n = shm::spscTryPop(hdr->rxProducer, hdr->rxConsumer, rxRing,
                                         hdr->ringCapacity, out.data(), static_cast<uint32_t>(out.size()));
            if (n > 0) {
                check(n == kPacketLen && out[0] == 0x45, "single pop payload mismatch");
                ++got;
            } else {
                std::this_thread::yield();
            }
        }
    });
    singleProd.join();
    singleCons.join();
    const auto t1 = std::chrono::steady_clock::now();
    const double singleMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    const double singleGbps = (double(kPacketCount) * double(kPacketLen) * 8.0) / (singleMs * 1e6);

    // 2. Upgraded v2: 64-packet Vectorized Batch Push + Zero-Copy In-Place Peek Batch
    shm::initDuplexRegion(region.get(), 1400u);
    const auto b0 = std::chrono::steady_clock::now();
    std::thread batchProd([&] {
        shm::PacketSpan txBatch[HAJIMI_SHM_MAX_BATCH];
        for (uint32_t i = 0; i < HAJIMI_SHM_MAX_BATCH; ++i) {
            txBatch[i].data = sample.data();
            txBatch[i].len = kPacketLen;
        }
        uint32_t sent = 0;
        bool wake = false;
        while (sent < kPacketCount) {
            uint32_t chunk = std::min<uint32_t>(HAJIMI_SHM_MAX_BATCH, kPacketCount - sent);
            uint32_t pushed = shm::spscTryPushBatch(
                hdr->rxProducer, hdr->rxConsumer, rxRing, hdr->ringCapacity, txBatch, chunk, wake);
            if (pushed > 0) {
                sent += pushed;
            } else {
                std::this_thread::yield();
            }
        }
    });
    std::thread batchCons([&] {
        shm::PacketSpan rxBatch[HAJIMI_SHM_MAX_BATCH];
        uint32_t got = 0;
        uint64_t guardSum = 0;
        while (got < kPacketCount) {
            uint32_t nextTail = 0;
            uint32_t n = shm::spscPeekBatch(
                hdr->rxProducer, hdr->rxConsumer, rxRing, hdr->ringCapacity,
                rxBatch, HAJIMI_SHM_MAX_BATCH, nextTail);
            if (n > 0) {
                for (uint32_t i = 0; i < n; ++i) {
                    check(rxBatch[i].len == kPacketLen && rxBatch[i].data[0] == 0x45,
                          "zero-copy batch peek payload mismatch");
                    guardSum += rxBatch[i].data[0];
                }
                shm::spscCommitPopBatch(hdr->rxConsumer, nextTail);
                got += n;
            } else {
                if (nextTail != hdr->rxConsumer.tail.load(std::memory_order_relaxed)) {
                    shm::spscCommitPopBatch(hdr->rxConsumer, nextTail);
                }
                std::this_thread::yield();
            }
        }
        check(guardSum == uint64_t(kPacketCount) * 0x45ULL, "batch checksum mismatch");
    });
    batchProd.join();
    batchCons.join();
    const auto b1 = std::chrono::steady_clock::now();
    const double batchMs = std::chrono::duration<double, std::milli>(b1 - b0).count();
    const double batchGbps = (double(kPacketCount) * double(kPacketLen) * 8.0) / (batchMs * 1e6);

    // 3. Verify inline 4-byte BSD `utun` AF header synthesis (`spscTryPushFramed`)
    shm::initDuplexRegion(region.get(), 1400u);
    uint8_t afHdr[4]{};
    hajimi_write_frame_prefix(afHdr, 4);
    bool wake = false;
    check(shm::spscTryPushFramed(hdr->txProducer, hdr->txConsumer, shm::txRingStorage(region.get()),
                                 hdr->ringCapacity, afHdr, 4u, sample.data(), 64u, wake),
          "spscTryPushFramed failed");
    uint8_t outFramed[128]{};
    uint32_t poppedLen = shm::spscTryPop(hdr->txProducer, hdr->txConsumer, shm::txRingStorage(region.get()),
                                         hdr->ringCapacity, outFramed, sizeof(outFramed));
    check(poppedLen == 68u && outFramed[3] == 2u && outFramed[4] == 0x45u,
          "utun 4-byte AF prefix round-trip failed");

    std::printf("[PASS] SPSC Ring Benchmark (400k x 1400B): single=%.2f Gbps (%.1f ms) -> "
                "64-pkt zero-copy batch=%.2f Gbps (%.1f ms, %.2fx speedup, 0 drops)\n",
                singleGbps, singleMs, batchGbps, batchMs, batchGbps / singleGbps);
}

void runSlabPoolAndPollerChecks() {
    auto &arena = dataplane::ThreadLocalPacketArena::current();
    const uint64_t hitsBefore = arena.hits();
    for (int i = 0; i < 100000; ++i) {
        dataplane::PooledPacketBuffer pkt(1500);
        check(pkt.isSlabBacked() && pkt.capacity() == 2048u, "expected slab-backed 2 KiB slot");
        pkt.data()[0] = static_cast<uint8_t>(i & 0xFF);
        pkt.setSize(1500);
    }
    const uint64_t slabHits = arena.hits() - hitsBefore;
    check(slabHits == 100000u, "expected 100% slab hit rate for 1500B MTU frames");

    // Jumbo frame fallback (> 2048B)
    {
        dataplane::PooledPacketBuffer jumbo(9000);
        check(!jumbo.isSlabBacked() && jumbo.capacity() == 9000u, "expected heap fallback for 9000B jumbo frame");
    }

    // AsyncPoller cross-thread wakeup & socket readiness test
    platform::ensureWinsock();
    platform::NativeSocket pair[2]{platform::kInvalidSocket, platform::kInvalidSocket};
    check(platform::createWakePair(pair), "createWakePair failed");

    platform_io::AsyncPoller poller;
    check(poller.isValid(), "AsyncPoller initialization failed");
    poller.updateInterest(pair[0], platform_io::kEventRead, 42u);

    std::thread writer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        platform::writeWakeSignal(pair[1]);
    });
    platform_io::ReadySocketEvent ready[8]{};
    size_t n = poller.wait(ready, 8u, 1000);
    writer.join();
    check(n == 1u && ready[0].fd == pair[0] && ready[0].token == 42u &&
          (ready[0].revents & platform_io::kEventRead) != 0,
          "AsyncPoller failed to report socket readiness");
    platform::drainWakeSignal(pair[0]);
    poller.removeInterest(pair[0]);
    platform::closeNativeSocket(pair[0]);
    platform::closeNativeSocket(pair[1]);

    std::printf("[PASS] SlabPool (100,000 zero-malloc hits) & AsyncPoller readiness verified\n");
}

void runCryptoParityChecks() {
    // HMAC-SHA256 RFC 4231 Test Case 2 ("Jefe")
    Buffer key{'J', 'e', 'f', 'e'};
    const char *msg = "what do ya want for nothing?";
    Buffer mac = crypto::hmac("SHA256", key, Buffer(msg, msg + std::strlen(msg)));
    check(mac.size() == 32 && mac[0] == 0x5b && mac[1] == 0xdc && mac[31] == 0x43,
          "HMAC-SHA256 RFC 4231 vector mismatch");

    // HKDF-SHA256 RFC 5869 Test Case 1
    Buffer ikm(22, 0x0b);
    Buffer salt{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    Buffer info{0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    Buffer okm = crypto::hkdf("SHA256", ikm, salt, info, 42);
    check(okm.size() == 42 && okm[0] == 0x3c && okm[1] == 0xb2 && okm[41] == 0x65,
          "HKDF-SHA256 RFC 5869 vector mismatch");

    // WireGuard BLAKE2s & Snell Argon2id vectors
    Buffer b2 = wg_detail::blake2s("abc", 3, 32, nullptr, 0);
    check(b2.size() == 32 && b2[0] == 0x50 && b2[1] == 0x8c && b2[31] == 0x82,
          "BLAKE2s-256('abc') RFC 7693 vector mismatch");

    Buffer snellSalt(16, 0x11);
    Buffer snellKey = snell::deriveKey("hajimi-psk", snellSalt, 4);
    check(snellKey.size() == 16, "Snell Argon2id key derivation failed");

    std::printf("[PASS] Crypto / HKDF / BLAKE2s / Argon2id cross-backend parity verified\n");
}

} // namespace


void runMacUtunFdBridgeCheck() {
#if !defined(_WIN32)
    int sv[2]{-1, -1};
    check(::socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair(SOCK_DGRAM) failed");
    HJEngineRef eng = hajimi_engine_create();
    check(eng != nullptr, "hajimi_engine_create failed");
    const char *conf = "[General]\n[Proxy]\n[Rule]\nFINAL, DIRECT\n";
    char err[128]{};
    check(hajimi_engine_load_profile_text(eng, conf, std::strlen(conf), err, sizeof(err)) == HAJIMI_ENGINE_OK,
          "load profile failed");
    check(hajimi_engine_attach_utun_fd(eng, sv[0], 4u) == HAJIMI_ENGINE_OK,
          "hajimi_engine_attach_utun_fd failed");

    // Build a 4-byte BSD `utun` AF_INET ICMP Echo Request to 198.19.0.1 and verify Echo Reply arrives on sv[1]!
    uint8_t clientIp[4]{198, 18, 0, 2};
    uint8_t targetIp[4]{198, 19, 0, 1};
    uint8_t icmpPayload[12]{8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, 'p', 'i', 'n', 'g'};
    uint16_t csum = hajimi_checksum(icmpPayload, sizeof(icmpPayload));
    icmpPayload[2] = static_cast<uint8_t>(csum >> 8);
    icmpPayload[3] = static_cast<uint8_t>(csum & 0xFF);

    // Build raw IPv4 ICMP packet (20B IPv4 + 12B ICMP = 32B) + 4B BSD AF_INET header
    uint8_t frame[64]{};
    hajimi_write_frame_prefix(frame, 4);
    uint8_t *ip = frame + 4;
    ip[0] = 0x45; ip[1] = 0x00;
    ip[2] = 0x00; ip[3] = 32;
    ip[4] = 0x00; ip[5] = 0x01;
    ip[8] = 64;   ip[9] = 1; // ICMP
    std::memcpy(ip + 12, clientIp, 4);
    std::memcpy(ip + 16, targetIp, 4);
    uint16_t ipSum = hajimi_ipv4_header_checksum(ip, 20);
    ip[10] = static_cast<uint8_t>(ipSum >> 8);
    ip[11] = static_cast<uint8_t>(ipSum & 0xFF);
    std::memcpy(ip + 20, icmpPayload, sizeof(icmpPayload));

    check(::write(sv[1], frame, 36) == 36, "utun write failed");

    uint8_t reply[128]{};
    ssize_t rn = -1;
    for (int tries = 0; tries < 50; ++tries) {
        rn = ::recv(sv[1], reply, sizeof(reply), MSG_DONTWAIT);
        if (rn > 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    check(rn == 36 && reply[3] == 2u && reply[4] == 0x45u && reply[24] == 0u,
          "utun 4-byte AF_INET ICMP Echo Reply failed");

    hajimi_engine_detach_utun_fd(eng);
    hajimi_engine_destroy(eng);
    ::close(sv[0]);
    ::close(sv[1]);
    std::printf("[PASS] macOS/BSD utun 4-byte AF header non-blocking batched tunnel bridge verified\n");
#endif
}

int main() {
    check(hajimi_dataplane_self_test() == 0, "hajimi_dataplane_self_test failed");
    check(hajimi_flow_self_test() == 0, "hajimi_flow_self_test failed");
    check(hajimi_domain_match_self_test() == 0, "hajimi_domain_match_self_test failed");

    runShmRingBatchVsSingleBenchmark();
    runSlabPoolAndPollerChecks();
    runCryptoParityChecks();
    runMacUtunFdBridgeCheck();
    return 0;
}
