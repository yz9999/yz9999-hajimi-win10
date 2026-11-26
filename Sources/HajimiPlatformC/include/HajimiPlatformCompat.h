#ifndef HAJIMI_PLATFORM_COMPAT_H
#define HAJIMI_PLATFORM_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#if defined(_MSC_VER)
#include <BaseTsd.h>
#include <intrin.h>
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif
#endif
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

/* Compiler function attributes */
#if defined(_MSC_VER) && !defined(__clang__)
#define HAJIMI_NOINLINE __declspec(noinline)
#else
#define HAJIMI_NOINLINE __attribute__((noinline))
#endif

/* Unified little-endian detection (MSVC x86/x64/ARM64 does not define __BYTE_ORDER__) */
#if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define HAJIMI_IS_LITTLE_ENDIAN 1
#else
#define HAJIMI_IS_LITTLE_ENDIAN 0
#endif

/* Portable 64-bit byte swap */
static inline uint64_t hajimi_bswap64_u64(uint64_t value) {
#if defined(_MSC_VER) && !defined(__clang__)
    return _byteswap_uint64(value);
#else
    return __builtin_bswap64(value);
#endif
}

/* Portable bit-manipulation intrinsics (safe across MSVC x64, MSVC ARM64, Clang, GCC) */
static inline int hajimi_popcount32(uint32_t x) {
#if defined(_MSC_VER) && !defined(__clang__)
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    return (int)((((x + (x >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24);
#else
    return __builtin_popcount(x);
#endif
}

static inline int hajimi_popcount64(uint64_t x) {
#if defined(_MSC_VER) && !defined(__clang__)
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    return (int)((((x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL) * 0x0101010101010101ULL) >> 56);
#else
    return __builtin_popcountll(x);
#endif
}

static inline int hajimi_ctz64(uint64_t x) {
    if (x == 0) return 64;
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long index = 0;
    _BitScanForward64(&index, x);
    return (int)index;
#else
    return __builtin_ctzll(x);
#endif
}

static inline int hajimi_clz64(uint64_t x) {
    if (x == 0) return 64;
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long index = 0;
    _BitScanReverse64(&index, x);
    return 63 - (int)index;
#else
    return __builtin_clzll(x);
#endif
}

/* Portable 64x64 -> 128-bit unsigned multiplication (returns low 64 bits, writes high 64 bits) */
static inline uint64_t hajimi_umul128(uint64_t a, uint64_t b, uint64_t *hi_out) {
#if defined(__SIZEOF_INT128__)
    __uint128_t prod = (__uint128_t)a * (__uint128_t)b;
    *hi_out = (uint64_t)(prod >> 64);
    return (uint64_t)prod;
#elif defined(_MSC_VER) && defined(_M_X64)
    return _umul128(a, b, hi_out);
#elif defined(_MSC_VER) && defined(_M_ARM64)
    *hi_out = __umulh(a, b);
    return a * b;
#else
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;
    uint64_t cy = ((p0 >> 32) + (uint32_t)p1 + (uint32_t)p2) >> 32;
    *hi_out = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    return p0 + (p1 << 32) + (p2 << 32);
#endif
}

#endif /* HAJIMI_PLATFORM_COMPAT_H */
