#pragma once

// Pure C, no ESP-IDF/FreeRTOS deps - host-testable. Wraps an in-memory
// bloom.bin buffer (see tools/bloom_format.py for the canonical file format
// and hash spec, which this file must match bit-for-bit).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLOOM_HEADER_MAGIC 0x4D4F4C42u // 'BLOM'
#define BLOOM_HEADER_VERSION 1

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t m_bits;
    uint32_t k_hashes;
    uint64_t n_domains;
    uint32_t hash_seed; // reserved for future seed rotation; 0 = fnv1a64.h's fixed seeds
    uint64_t build_unix_ts;
    uint32_t crc32;     // CRC32 of the bit array that follows - corruption check only
} bloom_header_t;
#pragma pack(pop)

_Static_assert(sizeof(bloom_header_t) == 44, "bloom_header_t must match tools/bloom_format.py's 44-byte layout");

typedef struct {
    const bloom_header_t *header;
    const uint8_t *bits; // bit array, immediately after the header in the source buffer
} bloom_filter_t;

/**
 * Wraps an in-memory bloom.bin buffer without copying it; buf must outlive out.
 * Returns false if the header's magic/version don't match, or buf is shorter
 * than the header claims the bit array should be.
 */
bool bloom_filter_init(const uint8_t *buf, size_t len, bloom_filter_t *out);

/** domain must already be normalized (lowercase, no trailing dot) by the caller. */
bool bloom_filter_test(const bloom_filter_t *filter, const char *domain);

#ifdef __cplusplus
}
#endif
