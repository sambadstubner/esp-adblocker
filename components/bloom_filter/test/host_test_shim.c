// Tiny C shim so the Python cross-check test can call the real firmware
// bloom filter code via ctypes without needing to mirror bloom_filter_t's
// struct layout in Python.
#include "bloom_filter.h"

int bloom_test_shim(const uint8_t *buf, size_t len, const char *domain)
{
    bloom_filter_t f;
    if (!bloom_filter_init(buf, len, &f)) {
        return -1;
    }
    return bloom_filter_test(&f, domain) ? 1 : 0;
}
