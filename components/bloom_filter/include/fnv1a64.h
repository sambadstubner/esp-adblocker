#pragma once

// Pure C, no ESP-IDF/FreeRTOS deps - host-testable, mirrored exactly by
// tools/bloom_format.py's fnv1a64().

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FNV_PRIME_64 0x100000001B3ULL
#define FNV_SEED1 0xCBF29CE484222325ULL
#define FNV_SEED2 0x9E3779B97F4A7C15ULL

uint64_t fnv1a64(const uint8_t *data, size_t len, uint64_t seed);

#ifdef __cplusplus
}
#endif
