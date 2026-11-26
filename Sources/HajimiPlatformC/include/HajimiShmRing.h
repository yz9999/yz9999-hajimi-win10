#ifndef HAJIMI_SHM_RING_H
#define HAJIMI_SHM_RING_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
#include <atomic>
#include <cstring>
#endif

/*
 * Lock-Free Single-Producer Single-Consumer (SPSC) Shared Memory Packet Ring (v2)
 *
 * Cross-platform zero-trust privilege separation for macOS & Windows:
 * - Windows (`HajimiHelperService.exe`): pumps raw Layer-3 IPv4/IPv6 frames
 *   (`frame_prefix_len = 0`) from Wintun across two 8 MiB SPSC rings (`rx` & `tx`).
 * - macOS (`HajimiHelper` / `utun`): supports 4-byte BSD AF header (`frame_prefix_len = 4`)
 *   or raw L3 (`frame_prefix_len = 0`) with inline prefix synthesis (zero heap copies).
 *
 * v2 Performance Upgrades (100% binary-layout compatible with v1):
 * - `spscTryPushFramed`: writes optional 4-byte BSD `utun` AF header + L3 payload directly
 *   into the ring slot without allocating an intermediate `std::vector<uint8_t>`.
 * - `spscTryPushBatch`: amortizes `cons.tail` acquire load, `prod.head` release store,
 *   atomic packet/byte counters, and cross-process wakeup signaling across up to 64 packets.
 * - `spscPeekBatch` + `spscCommitPopBatch`: returns up to 64 zero-copy read-only slices
 *   pointing directly into the shared memory ring so the engine parses L3/L4 headers in-place
 *   and commits `cons.tail` once per burst.
 */

#define HAJIMI_SHM_MAGIC               0x4D4A4853u /* 'SHJM' */
#define HAJIMI_SHM_VERSION             1u
#define HAJIMI_SHM_RING_CAPACITY       (8u * 1024u * 1024u) /* 8 MiB per direction */
#define HAJIMI_SHM_HEADER_BYTES        4096u
#define HAJIMI_SHM_DUPLEX_TOTAL_BYTES  (HAJIMI_SHM_HEADER_BYTES + 2u * HAJIMI_SHM_RING_CAPACITY)
#define HAJIMI_SHM_MAX_PACKET_BYTES    65535u
#define HAJIMI_SHM_WRAP_MARKER         0xFFFFFFFFu
#define HAJIMI_SHM_MAX_BATCH           64u

#if defined(_MSC_VER)
#define HAJIMI_CACHE_ALIGNED __declspec(align(64))
#else
#define HAJIMI_CACHE_ALIGNED __attribute__((aligned(64)))
#endif

#ifdef __cplusplus
namespace hajimi::shm {

struct HAJIMI_CACHE_ALIGNED RingCursor {
    std::atomic<uint32_t> head{0};             // Producer write offset [0, capacity)
    std::atomic<uint64_t> packets{0};          // Total packets enqueued
    std::atomic<uint64_t> bytes{0};            // Total payload bytes enqueued
    std::atomic<uint32_t> consumerSleeping{0}; // 1 when consumer awaits OS wakeup
    uint8_t pad0[36]{};
};

struct HAJIMI_CACHE_ALIGNED RingTail {
    std::atomic<uint32_t> tail{0};             // Consumer read offset [0, capacity)
    std::atomic<uint64_t> dropped{0};          // Producer full-ring drops
    uint8_t pad1[48]{};
};

struct DuplexHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t ringCapacity;
    uint32_t mtu;
    std::atomic<uint32_t> closed;
    uint32_t reserved[11];

    RingCursor rxProducer;
    RingTail   rxConsumer;

    RingCursor txProducer;
    RingTail   txConsumer;
};

static_assert(sizeof(DuplexHeader) <= HAJIMI_SHM_HEADER_BYTES,
              "DuplexHeader must fit within 4096-byte control page");

struct PacketSpan {
    const uint8_t *data{nullptr};
    uint32_t len{0};
};

inline uint32_t alignUp4(uint32_t v) noexcept {
    return (v + 3u) & ~3u;
}

inline void initDuplexRegion(void *baseAddress, uint32_t mtu = 1400u) noexcept {
    if (!baseAddress) return;
    std::memset(baseAddress, 0, HAJIMI_SHM_HEADER_BYTES);
    auto *hdr = static_cast<DuplexHeader *>(baseAddress);
    hdr->magic = HAJIMI_SHM_MAGIC;
    hdr->version = HAJIMI_SHM_VERSION;
    hdr->ringCapacity = HAJIMI_SHM_RING_CAPACITY;
    hdr->mtu = mtu;
    hdr->closed.store(0u, std::memory_order_relaxed);
    hdr->rxProducer.head.store(0u, std::memory_order_relaxed);
    hdr->rxConsumer.tail.store(0u, std::memory_order_relaxed);
    hdr->txProducer.head.store(0u, std::memory_order_relaxed);
    hdr->txConsumer.tail.store(0u, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);
}

inline bool validateDuplexRegion(const void *baseAddress) noexcept {
    if (!baseAddress) return false;
    const auto *hdr = static_cast<const DuplexHeader *>(baseAddress);
    return hdr->magic == HAJIMI_SHM_MAGIC &&
           hdr->version == HAJIMI_SHM_VERSION &&
           hdr->ringCapacity == HAJIMI_SHM_RING_CAPACITY;
}

inline uint8_t *rxRingStorage(void *baseAddress) noexcept {
    return static_cast<uint8_t *>(baseAddress) + HAJIMI_SHM_HEADER_BYTES;
}

inline const uint8_t *rxRingStorage(const void *baseAddress) noexcept {
    return static_cast<const uint8_t *>(baseAddress) + HAJIMI_SHM_HEADER_BYTES;
}

inline uint8_t *txRingStorage(void *baseAddress) noexcept {
    return static_cast<uint8_t *>(baseAddress) + HAJIMI_SHM_HEADER_BYTES + HAJIMI_SHM_RING_CAPACITY;
}

inline const uint8_t *txRingStorage(const void *baseAddress) noexcept {
    return static_cast<const uint8_t *>(baseAddress) + HAJIMI_SHM_HEADER_BYTES + HAJIMI_SHM_RING_CAPACITY;
}

/* Internal helper: writes one framed packet into ring using local `head` & cached `tail`. */
inline bool detailWriteOneRecord(uint8_t *ringBuf,
                                 uint32_t capacity,
                                 uint32_t &head,
                                 uint32_t tail,
                                 const uint8_t *prefix4,
                                 uint32_t prefixLen,
                                 const uint8_t *payload,
                                 uint32_t payloadLen) noexcept {
    const uint32_t totalLen = prefixLen + payloadLen;
    if (totalLen == 0 || totalLen > HAJIMI_SHM_MAX_PACKET_BYTES) return false;
    const uint32_t recordBytes = 4u + alignUp4(totalLen);
    if (recordBytes + 8u >= capacity) return false;

    uint8_t *dst = nullptr;
    uint32_t nextHead = 0;

    if (head >= tail) {
        const uint32_t tailRoom = capacity - head;
        if (tailRoom >= recordBytes + 4u) {
            if (tail == 0 && tailRoom == recordBytes + 4u) {
                return false;
            }
            dst = ringBuf + head;
            nextHead = head + recordBytes;
            if (nextHead == capacity) nextHead = 0;
        } else {
            if (tail <= recordBytes) {
                return false;
            }
            if (tailRoom >= 4u) {
                const uint32_t wrap = HAJIMI_SHM_WRAP_MARKER;
                std::memcpy(ringBuf + head, &wrap, 4u);
            }
            dst = ringBuf;
            nextHead = recordBytes;
        }
    } else {
        const uint32_t avail = tail - head;
        if (avail <= recordBytes) {
            return false;
        }
        dst = ringBuf + head;
        nextHead = head + recordBytes;
    }

    std::memcpy(dst, &totalLen, 4u);
    if (prefixLen > 0 && prefix4) {
        std::memcpy(dst + 4u, prefix4, prefixLen);
    }
    std::memcpy(dst + 4u + prefixLen, payload, payloadLen);
    head = nextHead;
    return true;
}

/* Zero-malloc framed single push (supports optional 4-byte BSD `utun` AF header inline). */
inline bool spscTryPushFramed(RingCursor &prod,
                              RingTail &cons,
                              uint8_t *ringBuf,
                              uint32_t capacity,
                              const uint8_t *prefix4,
                              uint32_t prefixLen,
                              const uint8_t *payload,
                              uint32_t payloadLen,
                              bool &outShouldSignalEvent) noexcept {
    outShouldSignalEvent = false;
    if (!ringBuf || !payload || payloadLen == 0) return false;

    uint32_t head = prod.head.load(std::memory_order_relaxed);
    const uint32_t tail = cons.tail.load(std::memory_order_acquire);
    if (head >= capacity || tail >= capacity) return false;

    const uint32_t totalLen = prefixLen + payloadLen;
    if (!detailWriteOneRecord(ringBuf, capacity, head, tail, prefix4, prefixLen, payload, payloadLen)) {
        cons.dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    prod.packets.fetch_add(1, std::memory_order_relaxed);
    prod.bytes.fetch_add(totalLen, std::memory_order_relaxed);
    prod.head.store(head, std::memory_order_release);
    outShouldSignalEvent = (prod.consumerSleeping.load(std::memory_order_acquire) != 0u);
    return true;
}

inline bool spscTryPush(RingCursor &prod,
                        RingTail &cons,
                        uint8_t *ringBuf,
                        uint32_t capacity,
                        const uint8_t *packet,
                        uint32_t packetLen,
                        bool &outShouldSignalEvent) noexcept {
    return spscTryPushFramed(prod, cons, ringBuf, capacity, nullptr, 0u, packet, packetLen, outShouldSignalEvent);
}

/*
 * Vectorized Batch Push (up to `count` packets, e.g. 64):
 * Amortizes cache-coherency fences to a SINGLE `cons.tail` acquire load and
 * a SINGLE `prod.head` release store for the entire packet burst.
 * Returns number of packets enqueued [0, count].
 */
inline uint32_t spscTryPushBatch(RingCursor &prod,
                                 RingTail &cons,
                                 uint8_t *ringBuf,
                                 uint32_t capacity,
                                 const PacketSpan *spans,
                                 uint32_t count,
                                 bool &outShouldSignalEvent) noexcept {
    outShouldSignalEvent = false;
    if (!ringBuf || !spans || count == 0) return 0u;

    uint32_t head = prod.head.load(std::memory_order_relaxed);
    uint32_t tail = cons.tail.load(std::memory_order_acquire);
    if (head >= capacity || tail >= capacity) return 0u;

    uint32_t pushed = 0;
    uint64_t totalBytes = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *pkt = spans[i].data;
        const uint32_t len = spans[i].len;
        if (!pkt || len == 0 || len > HAJIMI_SHM_MAX_PACKET_BYTES) break;
        if (!detailWriteOneRecord(ringBuf, capacity, head, tail, nullptr, 0u, pkt, len)) {
            // Re-load tail once in case consumer progressed concurrently
            tail = cons.tail.load(std::memory_order_acquire);
            if (!detailWriteOneRecord(ringBuf, capacity, head, tail, nullptr, 0u, pkt, len)) {
                cons.dropped.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        ++pushed;
        totalBytes += len;
    }

    if (pushed > 0) {
        prod.packets.fetch_add(pushed, std::memory_order_relaxed);
        prod.bytes.fetch_add(totalBytes, std::memory_order_relaxed);
        prod.head.store(head, std::memory_order_release);
        outShouldSignalEvent = (prod.consumerSleeping.load(std::memory_order_acquire) != 0u);
    }
    return pushed;
}

/*
 * Zero-Copy Vectorized Batch Peek:
 * Inspects up to `maxSpans` (e.g. 64) consecutive frames directly inside the ring buffer
 * without copying packet payloads out of shared memory.
 * Caller processes `outSpans[0..returned-1]` and then calls `spscCommitPopBatch(cons, outNextTail)`.
 */
inline uint32_t spscPeekBatch(RingCursor &prod,
                              RingTail &cons,
                              const uint8_t *ringBuf,
                              uint32_t capacity,
                              PacketSpan *outSpans,
                              uint32_t maxSpans,
                              uint32_t &outNextTail) noexcept {
    if (!ringBuf || !outSpans || maxSpans == 0) return 0u;

    uint32_t tail = cons.tail.load(std::memory_order_relaxed);
    const uint32_t head = prod.head.load(std::memory_order_acquire);
    outNextTail = tail;
    if (tail == head || tail >= capacity || head >= capacity) {
        return 0u;
    }

    uint32_t count = 0;
    while (count < maxSpans && tail != head) {
        if (capacity - tail < 4u) {
            tail = 0;
            if (tail == head) break;
        }
        uint32_t markerOrLen = 0;
        std::memcpy(&markerOrLen, ringBuf + tail, 4u);
        if (markerOrLen == HAJIMI_SHM_WRAP_MARKER) {
            tail = 0;
            if (tail == head) break;
            std::memcpy(&markerOrLen, ringBuf, 4u);
        }
        if (markerOrLen == 0 || markerOrLen > HAJIMI_SHM_MAX_PACKET_BYTES) {
            tail = head;
            break;
        }
        const uint32_t recordBytes = 4u + alignUp4(markerOrLen);
        if (tail + recordBytes > capacity) {
            tail = head;
            break;
        }
        outSpans[count].data = ringBuf + tail + 4u;
        outSpans[count].len = markerOrLen;
        ++count;
        tail += recordBytes;
        if (tail == capacity) tail = 0;
    }

    outNextTail = tail;
    return count;
}

inline void spscCommitPopBatch(RingTail &cons, uint32_t nextTail) noexcept {
    cons.tail.store(nextTail, std::memory_order_release);
}

inline uint32_t spscTryPop(RingCursor &prod,
                           RingTail &cons,
                           const uint8_t *ringBuf,
                           uint32_t capacity,
                           uint8_t *outBuf,
                           uint32_t outCapacity) noexcept {
    if (!ringBuf || !outBuf || outCapacity == 0) return 0;
    PacketSpan span{};
    uint32_t nextTail = 0;
    if (spscPeekBatch(prod, cons, ringBuf, capacity, &span, 1u, nextTail) == 0u) {
        if (nextTail != cons.tail.load(std::memory_order_relaxed)) {
            spscCommitPopBatch(cons, nextTail);
        }
        return 0u;
    }
    const uint32_t copyLen = span.len <= outCapacity ? span.len : outCapacity;
    std::memcpy(outBuf, span.data, copyLen);
    spscCommitPopBatch(cons, nextTail);
    return span.len <= outCapacity ? span.len : 0u;
}

} // namespace hajimi::shm
#endif /* __cplusplus */

#endif /* HAJIMI_SHM_RING_H */
