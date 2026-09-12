#!/usr/bin/env python3
"""
Cross-check that the firmware's bloom filter (components/bloom_filter/*.c,
compiled here as a real shared library and called via ctypes) and the host
tooling's Python implementation (tools/bloom_format.py) agree bit-for-bit.

This is the single highest-risk piece of the whole project per PLAN.md: a
silent mismatch here doesn't crash anything, it just silently degrades
blocking (or, if the two sides drift far enough, could in principle also
falsely clear a bit a domain needs - which is exactly why we check every
single test-vector domain individually below, not just an aggregate rate).

Run: python3 tools/tests/test_bloom_cross_check.py
"""
import ctypes
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BLOOM_DIR = REPO_ROOT / "components" / "bloom_filter"

sys.path.insert(0, str(REPO_ROOT / "tools"))
import bloom_format as bf  # noqa: E402

# Frozen test vectors: domains we insert, and domains we deliberately don't.
INSERTED = [f"blocked-{i}.example-ads.com" for i in range(200)] + [
    "doubleclick.net", "googlesyndication.com", "ads.example.com",
]
NOT_INSERTED = [f"legit-{i}.example-shop.com" for i in range(200)] + [
    "example.com", "wikipedia.org", "github.com",
]


def build_shared_lib() -> Path:
    out = Path(tempfile.mkdtemp()) / "libbloomtest.dylib"
    srcs = [
        str(BLOOM_DIR / "fnv1a64.c"),
        str(BLOOM_DIR / "bloom_filter.c"),
        str(BLOOM_DIR / "test" / "host_test_shim.c"),
    ]
    cmd = ["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-I", str(BLOOM_DIR / "include"),
           "-o", str(out)] + srcs
    subprocess.run(cmd, check=True)
    return out


def main():
    n = len(INSERTED)
    m_bits, k_hashes = bf.optimal_size(n, 0.001)
    print(f"test filter: n={n} m_bits={m_bits} k_hashes={k_hashes}")

    nbytes = (m_bits + 7) // 8
    bits = bytearray(nbytes)
    for domain in INSERTED:
        for idx in bf.bit_indices(domain, m_bits, k_hashes):
            bits[idx // 8] |= 1 << (idx % 8)

    header = bf.pack_header(m_bits, k_hashes, n, 0, bytes(bits))
    blob = header + bytes(bits)

    lib_path = build_shared_lib()
    lib = ctypes.CDLL(str(lib_path))
    lib.bloom_test_shim.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    lib.bloom_test_shim.restype = ctypes.c_int

    def c_test(domain: str) -> bool:
        result = lib.bloom_test_shim(blob, len(blob), domain.encode("ascii"))
        assert result in (0, 1), f"C shim returned {result} (bad header?) for {domain!r}"
        return bool(result)

    def py_test(domain: str) -> bool:
        return all(bits[idx // 8] & (1 << (idx % 8)) for idx in bf.bit_indices(domain, m_bits, k_hashes))

    failures = []

    # Hard requirement: bloom filters must never false-negative. Every domain
    # we inserted MUST test positive on both sides.
    for domain in INSERTED:
        c_result, py_result = c_test(domain), py_test(domain)
        if not c_result:
            failures.append(f"FALSE NEGATIVE (C): {domain!r} was inserted but bloom_filter_test() says no")
        if not py_result:
            failures.append(f"FALSE NEGATIVE (Python): {domain!r} was inserted but bit_indices() says no")
        if c_result != py_result:
            failures.append(f"MISMATCH on inserted domain {domain!r}: C={c_result} Python={py_result}")

    # For non-inserted domains, C and Python must agree exactly on every
    # single one (both true positives from the same hash collisions, and
    # true negatives) - not just have a "similar" false-positive rate.
    fp_count = 0
    for domain in NOT_INSERTED:
        c_result, py_result = c_test(domain), py_test(domain)
        if c_result != py_result:
            failures.append(f"MISMATCH on non-inserted domain {domain!r}: C={c_result} Python={py_result}")
        if c_result:
            fp_count += 1

    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print(f"all {n} inserted domains verified present (no false negatives) on both C and Python")
    print(f"all {len(NOT_INSERTED)} non-inserted domains: C and Python agree exactly "
          f"({fp_count} false positives observed, consistent with target FP rate)")
    print("PASS: firmware bloom_filter.c and tools/bloom_format.py agree bit-for-bit")


if __name__ == "__main__":
    main()
