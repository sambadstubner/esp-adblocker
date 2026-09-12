#pragma once

// Portable (no ESP-IDF deps) CRC-32/ISO-HDLC - the same algorithm as Python's
// zlib.crc32/binascii.crc32, used to verify bloom.bin's bit array wasn't
// corrupted in transit/storage (see tools/bloom_format.py - this is a
// corruption check only, not a security control; TLS is the trust boundary).

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t crc32_ieee(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif
