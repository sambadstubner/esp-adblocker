"""
Canonical spec for the esp-dns bloom filter: hash function, sizing math, and
the bloom.bin file format.

THIS FILE IS THE SOURCE OF TRUTH. components/bloom_filter/fnv1a64.c and
bloom_filter.c MUST implement the identical hash/header logic - see
components/bloom_filter/test/ for the cross-check that enforces this.
"""
import math
import struct
import zlib

# --- Hash spec -----------------------------------------------------------
# FNV-1a 64-bit, run twice with two different fixed seeds to get two
# independent-ish hashes from one cheap hash function (Kirsch-Mitzenmacher
# double hashing simulates k hash functions from just h1 and h2):
#
#   h_i(x) = (h1(x) + i * h2(x)) mod m_bits,  for i in 0..k-1
#
# SEED1 is the standard FNV-1a 64-bit offset basis. SEED2 is the 64-bit
# fractional-golden-ratio constant (a common, well-dispersed hash-mixing
# constant) - just needs to be a second fixed value distinct from SEED1.
FNV_PRIME_64 = 0x100000001B3
FNV_SEED1 = 0xCBF29CE484222325
FNV_SEED2 = 0x9E3779B97F4A7C15
MASK_64 = (1 << 64) - 1


def fnv1a64(data: bytes, seed: int) -> int:
    h = seed
    for byte in data:
        h ^= byte
        h = (h * FNV_PRIME_64) & MASK_64
    return h


def normalize_domain(domain: str) -> str:
    """Must match the normalization applied on the firmware side before hashing."""
    d = domain.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def bit_indices(domain: str, m_bits: int, k_hashes: int):
    data = normalize_domain(domain).encode("ascii")
    h1 = fnv1a64(data, FNV_SEED1)
    h2 = fnv1a64(data, FNV_SEED2)
    for i in range(k_hashes):
        # Firmware computes this in C's uint64_t, which wraps mod 2**64 at
        # each operation. Python ints don't wrap on their own, so each step
        # below is masked explicitly to reproduce that wraparound exactly -
        # skipping this (i.e. just doing "(h1 + i * h2) % m_bits" with exact
        # bignum math) gives a DIFFERENT, silently wrong result whenever
        # i * h2 overflows 64 bits, which is common since h2 is itself
        # already close to 2**64.
        term = (i * h2) & MASK_64
        combined = (h1 + term) & MASK_64
        yield combined % m_bits


# --- Sizing math -----------------------------------------------------------
def optimal_size(n_domains: int, target_fp_rate: float):
    """m = -(n * ln p) / (ln 2)^2 ; k = (m / n) * ln 2"""
    if n_domains <= 0:
        raise ValueError("n_domains must be > 0")
    m_bits = math.ceil(-(n_domains * math.log(target_fp_rate)) / (math.log(2) ** 2))
    k_hashes = max(1, round((m_bits / n_domains) * math.log(2)))
    return m_bits, k_hashes


# --- bloom.bin file format ---------------------------------------------
# Little-endian, packed, no implicit padding - mirrored exactly by
# components/bloom_filter/bloom_filter.h's bloom_header_t.
#   uint32_t magic;         'BLOM' -> 0x4D4F4C42
#   uint16_t version;       format version, starts at 1
#   uint16_t reserved;      0
#   uint64_t m_bits;
#   uint32_t k_hashes;
#   uint64_t n_domains;     informational only
#   uint32_t hash_seed;     reserved for future seed rotation; 0 = seeds above
#   uint64_t build_unix_ts;
#   uint32_t crc32;         CRC32 of the bit array that follows (corruption
#                           check only, not a security control - see PLAN.md)
HEADER_FORMAT = "<IHHQIQIQI"
HEADER_MAGIC = 0x4D4F4C42
HEADER_VERSION = 1
HEADER_LEN = struct.calcsize(HEADER_FORMAT)
assert HEADER_LEN == 44, HEADER_LEN


def pack_header(m_bits, k_hashes, n_domains, build_unix_ts, bitarray: bytes) -> bytes:
    crc = zlib.crc32(bitarray) & 0xFFFFFFFF
    return struct.pack(
        HEADER_FORMAT,
        HEADER_MAGIC,
        HEADER_VERSION,
        0,
        m_bits,
        k_hashes,
        n_domains,
        0,
        build_unix_ts,
        crc,
    )


def unpack_header(raw: bytes):
    (magic, version, _reserved, m_bits, k_hashes, n_domains, hash_seed,
     build_unix_ts, crc32) = struct.unpack(HEADER_FORMAT, raw[:HEADER_LEN])
    return {
        "magic": magic,
        "version": version,
        "m_bits": m_bits,
        "k_hashes": k_hashes,
        "n_domains": n_domains,
        "hash_seed": hash_seed,
        "build_unix_ts": build_unix_ts,
        "crc32": crc32,
    }
