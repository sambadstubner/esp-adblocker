# ESP32-S3 PoE DNS Sinkhole (Ad-Blocker)

## Context

The goal is a network-wide ad/tracker blocker: a small appliance that sits on the LAN, answers DNS for every client, and refuses to resolve domains found in public block lists. It runs on the Waveshare **ESP32-S3-ETH** board, powered over Ethernet, built with ESP-IDF. Rather than storing full domain strings (which would never fit in flash/PSRAM for million-entry block lists), domains are hashed into a **bloom filter** — a compact probabilistic set that can only ever produce false positives (a good domain occasionally misclassified as blocked), never false negatives (a blocked domain is never wrongly let through). That asymmetry is what makes this approach viable on a memory-constrained MCU, at the cost of needing a small allowlist escape hatch for the rare collision.

Scope was narrowed through discussion:
- **Block response**: configurable at runtime (NVS), default NXDOMAIN, with a 0.0.0.0/`::` mode available too.
- **Blocklist distribution**: the user will publish their own denylist / prebuilt bloom filter file publicly on GitHub; the device pulls updates from there over HTTPS.
- **Firmware updates**: OTA from a GitHub Release asset, via ESP-IDF's built-in `esp_https_ota`, trusted via the bundled Mozilla CA store (`esp_crt_bundle_attach`) — no custom signing.
- **No WiFi**: the user walked back an earlier WiFi-provisioning idea. This is Ethernet-only — no SoftAP, no WiFi stack at all.
- **Web UI**: instead of WiFi provisioning, a plain HTTP status/config page served on the existing Ethernet IP (`esp_http_server`).

## Hardware (Waveshare ESP32-S3-ETH, confirmed from the vendor wiki)

- ESP32-S3R8, dual-core LX7 @240MHz, 512KB SRAM, **8MB PSRAM**, **16MB flash**, WiFi/BLE radio present but unused in this design.
- Ethernet is an **onboard W5500** chip (SPI-attached MAC+PHY, not RMII) — confirmed SPI pinout:
  | Signal | GPIO |
  |---|---|
  | MISO | 12 |
  | MOSI | 11 |
  | SCLK | 13 |
  | CS | 14 |
  | RST | 9 |
  | INT | 10 |
- PoE is an **external add-on module** (IEEE 802.3af) that just powers the board via the Ethernet cable (isolated PD + DC-DC to 5V feeding the USB-C/5V rail) — no firmware interaction needed, just a power-budget sanity check.
- Onboard **TF/SD card slot**, also SPI, on a separate bus from the W5500 (confirmed pinout): CS=GPIO4, MOSI(DI)=GPIO6, MISO(DO)=GPIO5, SCLK=GPIO7. The user will provide a card for additional storage — this is used below to store the full exact-match domain list, since it's far roomier than internal flash for a multi-million-entry text list.
- ESP-IDF checkout confirmed locally at `/Users/sam/esp/esp-idf` (v5.5-dev, master) with the needed pieces already present: `esp_eth_mac_new_w5500`/`esp_eth_phy_new_w5500` (`components/esp_eth/include/esp_eth_mac_spi.h`, `esp_eth_phy.h`), the `examples/ethernet/basic` SPI-Ethernet pattern, the `examples/protocols/http_server/captive_portal/components/dns_server` UDP:53 pattern to extend, `esp_https_ota`, and `esp_crt_bundle_attach`.

## Project layout

```
esp-dns/
├── CMakeLists.txt
├── sdkconfig.defaults          # esp32s3 target, octal PSRAM, no WiFi, OTA partitioning
├── partitions.csv              # 2x OTA app slots + nvs + 2x bloom data slots
├── main/
│   ├── app_main.c              # startup sequencing
│   └── Kconfig.projbuild
├── components/
│   ├── app_config/             # single NVS schema owner
│   ├── bloom_filter/           # portable pure C, zero ESP-IDF deps -> host-testable
│   │   ├── bloom_filter.c/.h
│   │   ├── fnv1a64.c/.h
│   │   └── test/               # host-gcc unit tests, fast edit-compile-test loop
│   ├── eth_init/                # esp_eth + esp_netif glue for W5500 over SPI
│   ├── sd_storage/               # mounts TF card (FATFS over SPI), exact-list lookup API
│   ├── dns_proxy/                # UDP:53 server: parse, bloom check, SD confirm, forward/synthesize
│   │   └── dns_wire.c/.h        # pure-C wire format helpers, also host-testable
│   ├── blocklist_updater/       # HTTPS fetch of bloom.bin + domains.idx, A/B swap for both
│   ├── fw_updater/              # esp_https_ota wrapper for GitHub Releases
│   └── web_ui/                  # esp_http_server: status/config page
└── tools/                       # host-side, not part of the ESP-IDF build
    ├── blocklist_build.py       # sources -> normalize/dedupe -> bloom.bin + domains.idx
    ├── bloom_format.py          # single source of truth for header + hash spec
    └── tests/test_bloom_cross_check.py   # asserts host output bit-matches firmware
```

`bloom_filter` and `dns_wire` are kept free of `esp_log`/FreeRTOS/`esp_err_t` so they compile and unit-test on the host in under a second — this is where a silent hash mismatch would otherwise hide, so it gets the tightest test loop of the whole project.

## Implementation phases

**Phase 0 — Skeleton.** `idf.py build` for `esp32s3`, octal PSRAM enabled, boots and logs over USB-serial. Verify: PSRAM detected (8MB) in boot log.

**Phase 1 — Ethernet link-up + SD card mount, no DNS logic.** `eth_init` brings up the W5500 over SPI using the pin table above (as Kconfig values, not hardcoded, so they're easy to correct if a board revision differs) on one SPI host (e.g. `SPI2_HOST`), registers `ETH_EVENT`/`IP_EVENT` handlers, DHCP by default. `sd_storage` mounts the TF card on the *other* SPI host (`SPI3_HOST`, its own pins per the table above — independent bus so Ethernet and SD can be active concurrently without contention) via `esp_vfs_fat_sdspi_mount`, formatted FAT. Verify: device gets an IP, responds to ping, link down/up on cable pull is logged correctly; SD card mounts and a test file can be written/read.

**Phase 2 — Config layer (`app_config`).** NVS-backed settings: network mode (DHCP/static) + static IP/mask/gw, upstream resolver(s), block policy enum, blocklist URL, active bloom slot, firmware update URL. Verify: settings persist across reboot; static-IP mode actually suppresses DHCP.

**Phase 3 — Pass-through DNS proxy (no blocking yet).** `dns_proxy` opens UDP:53, for each query relays the raw datagram to a configured upstream resolver and relays the raw response back — proves socket/parsing plumbing before blocking logic is added, per the request to validate networking independently. Verify: `dig @<device-ip> example.com` from a laptop returns a correct answer; `tcpdump` shows one round trip per query, no loops.

**Phase 4 — Bloom filter + exact-list confirm, wired into blocking.**
- Host (`tools/blocklist_build.py`): normalize domains (lowercase, strip trailing dot), dedupe, subtract a manual override allowlist, then emit **two artifacts** from the same normalized set:
  1. `bloom.bin` — sized via `m = -(n·ln p)/(ln 2)²`, `k = (m/n)·ln 2` (worked example: n=1,000,000 @ p=0.001 → m≈1.8MB, k≈10 — comfortable in 8MB PSRAM/internal flash).
  2. `domains.idx` — the full normalized domain list, sorted, in a fixed-format binary layout (e.g. length-prefixed or newline-delimited sorted text) suitable for binary search directly off the SD card. This is the piece the SD card makes practical: a multi-million-entry text list is tens of MB, trivial for an SD card but well beyond a sane internal-flash budget.
- Firmware (`bloom_filter`): FNV-1a64 base hash, Kirsch–Mitzenmacher double hashing (`h_i = h1 + i·h2 mod m`) so only two real hash computations simulate k hash rounds. Stays in flash/PSRAM (small, fast, no SD dependency).
- Firmware (`sd_storage`): binary-search lookup against `domains.idx` on the mounted FAT filesystem.
- **Blocking decision, per query**: manual override allowlist (NVS) → bloom test. If bloom says "not present," forward upstream immediately (bloom's no-false-negative guarantee makes this safe). If bloom says "present" (candidate block), **confirm against `domains.idx` on the SD card** before actually blocking — a bloom-positive that isn't found in the exact list is a false positive and is forwarded upstream normally instead of blocked. This turns the false-positive problem from "mitigate with a curated allowlist" into "eliminate via exact confirmation," at the cost of one SD read (binary search, O(log n)) only on the minority of queries that hit the bloom filter.
- **Fail-safe if SD is missing/unmounted/corrupt**: fall back to blocking on the bloom-filter result alone (i.e., today's plain bloom behavior, FP risk included) rather than either disabling blocking entirely or hard-failing DNS — logged clearly so it's a visible degraded mode, not a silent one.
- **Critical risk, called out explicitly**: host and firmware hash implementations must match bit-for-bit or the bloom pre-filter silently degrades (more SD confirm lookups than expected, or a missed block if a hash bug caused a genuinely-blocked domain to hash to a false-negative-like state — shouldn't be possible with a correct bloom filter, which is exactly why the cross-check matters). `tools/bloom_format.py` is the single canonical spec for the hash/header, and a cross-check test (`test_bloom_cross_check.py`, using `ctypes` against a compiled `bloom_filter.c`) must pass against a frozen test-vector list before this phase is considered done.
- Verify: known-blocked domain (e.g. an ad-network domain from the list) returns NXDOMAIN/0.0.0.0; known-good domains still resolve even when they happen to collide in the bloom filter (construct a deliberate bloom collision in a test list and confirm the SD lookup rescues it); unplug the SD card and confirm the device degrades to bloom-only blocking rather than failing DNS.

**Phase 5 — Firmware OTA (`fw_updater`).** Two-OTA-slot partition table, `esp_https_ota()` wrapped with `esp_crt_bundle_attach` and redirect-following enabled (GitHub Release assets redirect to `objects.githubusercontent.com`). Enable app rollback (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`) and confirm-boot only after Ethernet + DNS proxy are confirmed healthy, so a bad image auto-reverts. Verify: push a version bump as a GitHub Release, trigger update, confirm new version boots; corrupt a test image and confirm rollback.

**Phase 6 — Blocklist updater over HTTPS, power-loss-safe for both artifacts (`blocklist_updater`).**
- `bloom.bin`: two custom internal-flash data partitions (`bloom_a`/`bloom_b`), sized to the largest filter you plan to support. Header: magic, version, `m_bits`, `k_hashes`, `n_domains`, hash seed, build timestamp, CRC32 of the bit array. Fetch streams into the **inactive** slot; only after magic/version/size/CRC32 validate does the device flip `bloom_active_slot` in NVS in one commit — a power loss at any point before that commit leaves the previously-active (already-known-good) slot untouched. Runtime lookups use `esp_partition_mmap()` on the active slot rather than copying into PSRAM, avoiding both the copy cost and a swap-mid-copy race.
- `domains.idx`: same A/B principle, applied on the SD card instead of a flash partition, since FAT file rewrites aren't atomic — fetch streams into `domains_b.idx` (or whichever isn't currently active) as a new file, validate (size sanity check + a checksum stored alongside, e.g. `domains.idx.sha256` fetched and compared), then flip an `exact_list_active` (0/1) flag in NVS. A power loss mid-download leaves the half-written staging file in place but untouched by anything reading the *previous* file, since the active flag hasn't moved yet.
- CRC32/checksum here is a corruption check, not a security control — TLS is the trust boundary for both artifacts, consistent with the OTA decision.
- Verify: repeatedly power-cut mid-download for both `bloom.bin` and `domains.idx` and confirm the device always boots serving the last-good pair; a clean update reflects a new domain count/timestamp in the web UI; a bit-flipped/truncated artifact is rejected and the previous one keeps serving.

**Phase 7 — Web UI (`web_ui`).** `esp_http_server` on the existing Ethernet IP: `GET /` status page (uptime, queries total/blocked, active filter build info), `GET /api/status` (JSON), `GET/POST /api/config` (upstreams, block policy, blocklist URL — IP changes require an explicit reboot step), manual trigger endpoints for blocklist/firmware update. Verify: edit upstream resolver from a browser, confirm via `tcpdump` that subsequent queries go to the new upstream.

**Phase 8 — Hardening/soak.** Periodic (Kconfig-interval) automatic blocklist refresh, reconnect handling on Ethernet link flap, watchdog feeding in long loops, SNTP client (needed for correct TLS certificate time validation on a freshly-flashed device — added here or pulled forward into Phase 1/2). Verify: 24–72h soak with continuous query traffic + periodic link-pull + a forced update mid-soak, watching heap for leaks.

## DNS proxy concurrency model (Phase 3/4)

Single task, one listening UDP:53 socket, one shared upstream-forwarding socket. Since many clients' queries multiplex through that one upstream socket, the **DNS transaction ID is the only correlation key** on the way back — so the proxy **rewrites** the txid to a locally-unique value per pending-query slot before forwarding (rather than trusting the client's original ID to stay collision-free), and rewrites it back on the reply. A fixed-size pending-query table (Kconfig `MAX_PENDING`, default 32) tracks `{client_addr, client_txid, upstream_txid, sent_at}`; a timeout sweep (default 3s) replies SERVFAIL to the client and frees the slot if upstream never answers; if the table is full, new queries get an immediate SERVFAIL rather than queuing. This also gives a natural place to fail over between two configured upstreams after repeated consecutive timeouts.

## Scope decisions carried forward from planning

- **UDP-only, A/AAAA-passthrough**: the proxy does not re-implement DNS — it relays whatever upstream returns except when synthesizing a block response. **TCP:53 is out of scope for v1** (flagged as a known gap: a client that gets a truncated/TC-bit UDP response has no fallback here).
- **Single flat LAN segment**, one Ethernet interface, device as the sole DNS server for that segment.
- **No auth on the web UI** initially (LAN-trust model) — flagged as a conscious choice, not an oversight; can add basic auth on the config POST routes later if wanted.
- **Bloom filter sizing** (how many domains, what false-positive rate) is deferred to Phase 4 once you've picked actual source list(s) to publish — the worked example above (1M domains, 0.1% FP, ~1.8MB) is the sizing baseline for the internal-flash `bloom_a`/`bloom_b` partitions; since the SD card now hosts the full exact list separately, this filter can stay comfortably small and doesn't need to grow just because the source lists do.
- **SD card is a soft dependency**: it upgrades the design from "bloom filter + hope the FP rate is low enough" to "bloom filter + exact confirmation," but the device is designed to keep functioning (in degraded, bloom-only mode) if the card is absent, unmounted, or its filesystem is corrupt — this should never be a hard boot-blocking dependency for a device whose whole job is answering DNS.

## Verification summary

- Bloom filter: host-side pytest suite (`tools/tests/`) including the firmware cross-check, run on every change to hash/header logic.
- Networking: `dig @<device-ip>` for blocked/allowed/nonexistent domains at each phase; `tcpdump`/Wireshark to confirm round-trip behavior and catch loops.
- Resilience: repeated power-cut-mid-update testing for both OTA firmware and blocklist slot swap (flash-based `bloom.bin` and SD-based `domains.idx`); SD-card-removal testing to confirm graceful fallback to bloom-only blocking.
- Load/soak: simple script driving concurrent `dig` queries to exercise the pending-query table and check for SERVFAIL fallback under upstream slowness; multi-day soak with periodic link flaps before calling it appliance-grade.
