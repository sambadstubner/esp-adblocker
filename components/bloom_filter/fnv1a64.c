#include "fnv1a64.h"

uint64_t fnv1a64(const uint8_t *data, size_t len, uint64_t seed)
{
    uint64_t h = seed;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= FNV_PRIME_64; // uint64_t multiply wraps mod 2^64 - must match tools/bloom_format.py
    }
    return h;
}
