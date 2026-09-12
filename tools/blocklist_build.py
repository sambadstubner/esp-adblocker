#!/usr/bin/env python3
"""
Builds bloom.bin + domains.idx from one or more hosts-format blocklist
sources, for the esp-dns firmware to consume.

Usage:
    python3 blocklist_build.py --source hosts.txt --out-dir build/ \\
        [--fp-rate 0.001] [--allowlist allowlist.txt]

    python3 blocklist_build.py --source https://.../hosts --out-dir build/

Output:
    <out-dir>/bloom.bin    - header + bit array, for the firmware bloom filter
    <out-dir>/domains.idx  - full sorted normalized domain list (one per
                             line), for the SD card exact-match confirm step
"""
import argparse
import re
import sys
import time
import urllib.request
from pathlib import Path

import bloom_format as bf

# Matches standard hosts-format lines: "0.0.0.0 domain" or "127.0.0.1 domain",
# optionally with a trailing comment. Ignores comment-only and blank lines.
HOSTS_LINE_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.(?!-)[a-z0-9-]{1,63})+(?<!-)$")


def fetch_source(source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    return Path(source).read_text(encoding="utf-8", errors="replace")


def parse_hosts_format(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = HOSTS_LINE_RE.match(line)
        if not m:
            continue
        domain = bf.normalize_domain(m.group(1))
        if domain in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
            continue
        if not DOMAIN_RE.match(domain):
            continue
        domains.add(domain)
    return domains


def load_allowlist(path: str | None) -> set[str]:
    if not path:
        return set()
    domains = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.add(bf.normalize_domain(line))
    return domains


def build_bitarray(domains: list[str], m_bits: int, k_hashes: int) -> bytearray:
    nbytes = (m_bits + 7) // 8
    bits = bytearray(nbytes)
    for domain in domains:
        for idx in bf.bit_indices(domain, m_bits, k_hashes):
            bits[idx // 8] |= 1 << (idx % 8)
    return bits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", action="append", required=True,
                     help="Hosts-format file path or URL. May be given multiple times.")
    ap.add_argument("--out-dir", required=True, help="Directory to write bloom.bin and domains.idx into.")
    ap.add_argument("--fp-rate", type=float, default=0.001, help="Target bloom filter false-positive rate (default 0.001).")
    ap.add_argument("--allowlist", default=None, help="Optional file of domains (one per line) to always exclude.")
    args = ap.parse_args()

    all_domains: set[str] = set()
    for source in args.source:
        print(f"fetching {source} ...", file=sys.stderr)
        text = fetch_source(source)
        parsed = parse_hosts_format(text)
        print(f"  {len(parsed)} domains parsed", file=sys.stderr)
        all_domains |= parsed

    allowlist = load_allowlist(args.allowlist)
    if allowlist:
        before = len(all_domains)
        all_domains -= allowlist
        print(f"allowlist removed {before - len(all_domains)} domains", file=sys.stderr)

    domains = sorted(all_domains)
    n = len(domains)
    if n == 0:
        print("no domains parsed from any source, aborting", file=sys.stderr)
        sys.exit(1)

    m_bits, k_hashes = bf.optimal_size(n, args.fp_rate)
    print(f"n={n} fp_rate={args.fp_rate} -> m_bits={m_bits} k_hashes={k_hashes} "
          f"({(m_bits + 7) // 8} bytes)", file=sys.stderr)

    bits = build_bitarray(domains, m_bits, k_hashes)
    header = bf.pack_header(m_bits, k_hashes, n, int(time.time()), bytes(bits))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    bloom_path = out_dir / "bloom.bin"
    bloom_path.write_bytes(header + bytes(bits))
    print(f"wrote {bloom_path} ({bloom_path.stat().st_size} bytes)", file=sys.stderr)

    idx_path = out_dir / "domains.idx"
    idx_path.write_text("\n".join(domains) + "\n", encoding="ascii")
    print(f"wrote {idx_path} ({idx_path.stat().st_size} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
