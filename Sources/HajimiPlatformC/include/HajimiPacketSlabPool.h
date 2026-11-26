#ifndef HAJIMI_PACKET_SLAB_POOL_H
#define HAJIMI_PACKET_SLAB_POOL_H

#ifdef __cplusplus

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace hajimi::dataplane {

/*
 * Thread-Local O(1) Zero-Malloc Packet Slab Pool (`HajimiPacketSlabPool`)
 *
 * Eliminates `operator new` / `std::vector<uint8_t>` heap allocator lock contention
 * on the packet-forwarding hot path (TUN TCP segmentation, UDP Full-Cone NAT datagrams,
 * and DoH/UDP wire frames).
 *
 * - Slot size: 2048 bytes (covers standard 1500B Ethernet/TUN MTU + 4-byte BSD `utun` AF header).
 * - Capacity: 256 slots per worker thread (512 KiB contiguous L2/L3 cache-warm arena).
 * - Allocation & release: O(1) bit-scan (`ctzll` / `_BitScanForward64`) with zero atomic or mutex overhead.
 * - Jumbo fallback: payloads > 2048 bytes transparently fall back to heap buffer.
 */
class ThreadLocalPacketArena {
public:
    static constexpr size_t kSlotSize = 2048u;
    static constexpr size_t kNumWords = 4u;
    static constexpr size_t kNumSlots = kNumWords * 64u; // 256 slots = 512 KiB

    ThreadLocalPacketArena() noexcept {
        for (size_t i = 0; i < kNumWords; ++i) {
            freeMask_[i] = ~uint64_t{0};
        }
    }

    uint8_t *acquireSlot(int &outSlotIndex) noexcept {
        for (size_t w = 0; w < kNumWords; ++w) {
            uint64_t mask = freeMask_[w];
            if (mask != 0ULL) {
                unsigned bit = trailingZeros64(mask);
                freeMask_[w] = mask & ~(uint64_t{1} << bit);
                outSlotIndex = static_cast<int>(w * 64u + bit);
                ++hits_;
                return storage_ + static_cast<size_t>(outSlotIndex) * kSlotSize;
            }
        }
        outSlotIndex = -1;
        ++misses_;
        return nullptr;
    }

    void releaseSlot(int slotIndex) noexcept {
        if (slotIndex < 0 || static_cast<size_t>(slotIndex) >= kNumSlots) return;
        const size_t w = static_cast<size_t>(slotIndex) >> 6u;
        const unsigned bit = static_cast<unsigned>(slotIndex) & 63u;
        freeMask_[w] |= (uint64_t{1} << bit);
    }

    uint64_t hits() const noexcept { return hits_; }
    uint64_t misses() const noexcept { return misses_; }

    static ThreadLocalPacketArena &current() noexcept {
        thread_local ThreadLocalPacketArena instance;
        return instance;
    }

private:
    static unsigned trailingZeros64(uint64_t x) noexcept {
#if defined(_MSC_VER) && defined(_M_X64) || defined(_MSC_VER) && defined(_M_ARM64)
        unsigned long idx = 0;
        _BitScanForward64(&idx, x);
        return static_cast<unsigned>(idx);
#elif defined(__GNUC__) || defined(__clang__)
        return static_cast<unsigned>(__builtin_ctzll(x));
#else
        unsigned n = 0;
        while ((x & 1ULL) == 0ULL) { x >>= 1u; ++n; }
        return n;
#endif
    }

    alignas(64) uint64_t freeMask_[kNumWords]{};
    uint64_t hits_{0};
    uint64_t misses_{0};
    alignas(64) uint8_t storage_[kNumSlots * kSlotSize];
};

class PooledPacketBuffer {
public:
    PooledPacketBuffer() noexcept = default;

    explicit PooledPacketBuffer(size_t requiredCapacity) {
        reserve(requiredCapacity);
    }

    PooledPacketBuffer(const PooledPacketBuffer &) = delete;
    PooledPacketBuffer &operator=(const PooledPacketBuffer &) = delete;

    PooledPacketBuffer(PooledPacketBuffer &&other) noexcept
        : ownerArena_(other.ownerArena_),
          data_(other.data_),
          size_(other.size_),
          capacity_(other.capacity_),
          slotIndex_(other.slotIndex_),
          heapFallback_(std::move(other.heapFallback_)) {
        other.ownerArena_ = nullptr;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
        other.slotIndex_ = -1;
    }

    PooledPacketBuffer &operator=(PooledPacketBuffer &&other) noexcept {
        if (this != &other) {
            release();
            ownerArena_ = other.ownerArena_;
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            slotIndex_ = other.slotIndex_;
            heapFallback_ = std::move(other.heapFallback_);
            other.ownerArena_ = nullptr;
            other.data_ = nullptr;
            other.size_ = 0;
            other.capacity_ = 0;
            other.slotIndex_ = -1;
        }
        return *this;
    }

    ~PooledPacketBuffer() {
        release();
    }

    void reserve(size_t requiredCapacity) {
        if (capacity_ >= requiredCapacity) return;
        release();
        if (requiredCapacity <= ThreadLocalPacketArena::kSlotSize) {
            auto &arena = ThreadLocalPacketArena::current();
            int idx = -1;
            uint8_t *ptr = arena.acquireSlot(idx);
            if (ptr) {
                ownerArena_ = &arena;
                data_ = ptr;
                capacity_ = ThreadLocalPacketArena::kSlotSize;
                slotIndex_ = idx;
                return;
            }
        }
        heapFallback_.reset(new uint8_t[requiredCapacity]);
        data_ = heapFallback_.get();
        capacity_ = requiredCapacity;
    }

    void assign(const uint8_t *src, size_t len) {
        reserve(len);
        if (len > 0 && src) {
            std::memcpy(data_, src, len);
        }
        size_ = len;
    }

    void assignFramed(const uint8_t *prefix, size_t prefixLen, const uint8_t *payload, size_t payloadLen) {
        const size_t total = prefixLen + payloadLen;
        reserve(total);
        if (prefixLen > 0 && prefix) {
            std::memcpy(data_, prefix, prefixLen);
        }
        if (payloadLen > 0 && payload) {
            std::memcpy(data_ + prefixLen, payload, payloadLen);
        }
        size_ = total;
    }

    void setSize(size_t n) noexcept {
        size_ = (n <= capacity_) ? n : capacity_;
    }

    uint8_t *data() noexcept { return data_; }
    const uint8_t *data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size_ == 0; }
    bool isSlabBacked() const noexcept { return slotIndex_ >= 0; }

    void release() noexcept {
        if (slotIndex_ >= 0 && ownerArena_) {
            // Only return to thread-local arena if destroyed on the owning thread;
            // cross-thread handoffs should use heap or process in-place.
            if (ownerArena_ == &ThreadLocalPacketArena::current()) {
                ownerArena_->releaseSlot(slotIndex_);
            }
        }
        ownerArena_ = nullptr;
        slotIndex_ = -1;
        heapFallback_.reset();
        data_ = nullptr;
        size_ = 0;
        capacity_ = 0;
    }

private:
    ThreadLocalPacketArena *ownerArena_{nullptr};
    uint8_t *data_{nullptr};
    size_t size_{0};
    size_t capacity_{0};
    int slotIndex_{-1};
    std::unique_ptr<uint8_t[]> heapFallback_;
};

} // namespace hajimi::dataplane

#endif /* __cplusplus */

#endif /* HAJIMI_PACKET_SLAB_POOL_H */
