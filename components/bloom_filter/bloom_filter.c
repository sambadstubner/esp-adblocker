#include "bloom_filter.h"

#include <string.h>

#include "fnv1a64.h"

bool bloom_filter_init(const uint8_t *buf, size_t len, bloom_filter_t *out)
{
    if (len < sizeof(bloom_header_t)) {
        return false;
    }
    const bloom_header_t *hdr = (const bloom_header_t *)buf;
    if (hdr->magic != BLOOM_HEADER_MAGIC || hdr->version != BLOOM_HEADER_VERSION) {
        return false;
    }
    size_t bitarray_bytes = (size_t)((hdr->m_bits + 7) / 8);
    if (len < sizeof(bloom_header_t) + bitarray_bytes) {
        return false;
    }
    out->header = hdr;
    out->bits = buf + sizeof(bloom_header_t);
    return true;
}

bool bloom_filter_test(const bloom_filter_t *filter, const char *domain)
{
    size_t len = strlen(domain);
    uint64_t h1 = fnv1a64((const uint8_t *)domain, len, FNV_SEED1);
    uint64_t h2 = fnv1a64((const uint8_t *)domain, len, FNV_SEED2);
    uint64_t m_bits = filter->header->m_bits;
    uint32_t k = filter->header->k_hashes;

    for (uint32_t i = 0; i < k; i++) {
        // Must match tools/bloom_format.py's bit_indices() wraparound exactly:
        // each step wraps mod 2^64 (natural uint64_t behavior) before the
        // final mod m_bits - do not "simplify" this into wider arithmetic.
        uint64_t idx = (h1 + (uint64_t)i * h2) % m_bits;
        if ((filter->bits[idx / 8] & (1u << (idx % 8))) == 0) {
            return false;
        }
    }
    return true;
}
