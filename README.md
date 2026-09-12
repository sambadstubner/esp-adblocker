# esp-adblocker

A network-wide DNS-based ad/tracker blocker that runs entirely on a single
[Waveshare ESP32-S3-ETH](https://www.waveshare.com/wiki/ESP32-S3-ETH) board,
powered over Ethernet. It acts as a DNS server for your LAN: legitimate
queries are forwarded to real upstream resolvers, and known ad/tracker
domains are refused, all in single-digit milliseconds on a $15 microcontroller.

## How it works

Large public block lists (millions of domains) don't fit in an ESP32's RAM as
plain text. This project compresses them into a [bloom
filter](https://en.wikipedia.org/wiki/Bloom_filter) - a probabilistic
set that can only ever produce *false positives*, never false negatives - and
keeps it entirely in PSRAM for microsecond-scale lookups on every DNS query.
Because a bloom filter alone can occasionally misclassify a legitimate domain
as blocked, the onboard TF/SD card holds the *exact* full domain list as a
second-stage check: only the rare bloom-positive pays the cost of an SD
lookup, so ordinary traffic never leaves PSRAM.

- **DNS proxy** - UDP:53, forwards non-blocked queries upstream, synthesizes
  NXDOMAIN or `0.0.0.0`/`::` for blocked ones (your choice).
- **Bloom filter + SD exact-match confirm** - no false positives ever reach a
  client; a bloom-filter miss is always trusted, a bloom-filter hit is always
  double-checked against the real list before blocking.
- **OTA firmware updates** - pulls a signed-by-TLS release binary from a
  GitHub Release URL you configure, with automatic rollback if the new image
  never checks in healthy.
- **Blocklist auto-updates** - periodically re-fetches your published block
  list over HTTPS, validates it (header/CRC32 for the filter, SHA-256 for the
  exact list), and only activates it after validation - a failed or
  power-interrupted update never disturbs what's currently serving.
- **Web UI** - status page and live settings at `http://esp-adblocker.local/`, no
  app or account required.
- **mDNS** - reachable as `esp-adblocker.local` out of the box on macOS/iOS/Linux.

## Hardware

| | |
|---|---|
| Board | [Waveshare ESP32-S3-ETH](https://www.waveshare.com/esp32-s3-eth.htm) ([wiki](https://www.waveshare.com/wiki/ESP32-S3-ETH)) |
| SoC | ESP32-S3R8 - dual-core LX7 @240MHz, 8MB PSRAM, 16MB flash |
| Ethernet | Onboard W5500 (SPI) |
| Storage | microSD/TF card, any capacity (formatted automatically) |
| Power | USB-C, or the board's optional PoE add-on module (same product page) |

No wiring is required - the Ethernet and TF card SPI buses are already
etched onto the board. Just insert a microSD card and connect Ethernet.

## Setup

1. **Insert a microSD card** and connect the board to your network over
   Ethernet. Power it via USB-C (or the PoE module, if installed).
2. **Flash the firmware** the first time (see [Development](#development)
   below for building from source, or grab a release `.bin` from this repo's
   [Releases](../../releases) page):
   ```
   python -m esptool --chip esp32s3 -p <PORT> -b 460800 write_flash \
     0x0     bootloader.bin \
     0x8000  partition-table.bin \
     0xf000  ota_data_initial.bin \
     0x20000 esp-adblocker.bin
   ```
3. **Find the device.** It gets an IP via DHCP; open `http://esp-adblocker.local/`
   (macOS/iOS/Linux) or check your router's device list. The status page
   shows its current IP if you need it.
4. **Publish a block list** (or use someone else's HTTPS-reachable one) - see
   [Building and publishing a block list](#building-and-publishing-a-block-list).
   Enter its base URL under **Blocklist & firmware sources** in the web UI,
   then click **Check blocklist update** once. Until you do this, the device
   blocks using a small built-in seed list.
5. **Configure settings** in the web UI as needed: upstream resolvers, block
   response (NXDOMAIN vs `0.0.0.0`/`::`), auto-refresh interval, and
   optionally a firmware release URL for OTA updates.
6. **Point clients at it.** Either configure it as the DNS server for your
   whole network (via your router's DHCP/DNS settings - see your router's
   documentation, and give the device a fixed IP or DHCP reservation first),
   or set it as the manual DNS server on individual devices you want to
   scope this to. The device answers over both IPv4 and IPv6 (check the
   status page for its IPv6 addresses), but on most home routers you can't
   tell the router to *advertise* that IPv6 address to clients the way you
   can for IPv4 via DHCP - if your network has IPv6 enabled, clients will
   likely keep using the router's own advertised IPv6 DNS server unless you
   manually set a device's DNS server to this one, or disable IPv6 client-side
   or router-side.

### Web UI reference

| Setting | Effect |
|---|---|
| Ad blocking (switch) | Master on/off - when off, all queries pass through untouched |
| Block response | NXDOMAIN or `0.0.0.0`/`::` for blocked queries |
| Upstream resolver 1/2 | Where non-blocked queries are forwarded; auto-fails over between the two after repeated timeouts |
| Network mode | DHCP or static IP (static changes need a reboot) |
| Blocklist base URL | HTTPS base path serving `bloom.bin`, `domains.idx`, `domains.idx.sha256` |
| Auto-refresh interval | Hours between automatic blocklist re-checks; 0 disables |
| Firmware release URL | Direct HTTPS URL to a firmware `.bin` (e.g. a GitHub Release asset) |

## Development

### Prerequisites

- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/get-started/) v5.1+ (developed against v5.5-dev), targeting `esp32s3`
- Python 3 for the host-side tooling in `tools/`

### Build, flash, monitor

```
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

The first `idf.py build` fetches the `espressif/mdns` managed component
automatically (via `idf_component.yml`); `dependencies.lock` pins the exact
version.

### Project layout

```
components/
  eth_init/          W5500-over-SPI bring-up, DHCP/static IP, mDNS, SNTP
  sd_storage/         TF card mount, PSRAM-cached exact-domain-list lookup
  app_config/          single NVS-backed settings owner
  dns_proxy/            UDP:53 proxy, blocking decision, bloom filter runtime
  bloom_filter/          portable (host-testable) bloom filter + CRC32 + FNV-1a64
  blocklist_updater/       HTTPS blocklist fetch, A/B validation and activation
  fw_updater/               esp_https_ota wrapper with rollback health-check
  web_ui/                    status/config web server
tools/
  bloom_format.py    canonical hash/header spec - the single source of truth
                     that components/bloom_filter/*.c must match bit-for-bit
  blocklist_build.py builds bloom.bin + domains.idx (+ .sha256) from
                     hosts-format block list sources
  tests/             host-side tests, including a C-vs-Python cross-check
                     for the bloom filter hash
```

`bloom_filter` and `dns_proxy`'s wire-format code are deliberately
dependency-free C (no ESP-IDF/FreeRTOS), so they compile and unit-test on the
host in under a second:

```
cc -I components/bloom_filter/include -o /tmp/t \
   components/bloom_filter/fnv1a64.c components/bloom_filter/bloom_filter.c \
   components/bloom_filter/test/host_test_shim.c   # then wire up your own test main, or:
python3 tools/tests/test_bloom_cross_check.py

cc -I components/dns_proxy/include -o /tmp/t \
   components/dns_proxy/dns_wire.c components/dns_proxy/test/test_dns_wire.c && /tmp/t
```

### Building and publishing a block list

```
python3 tools/blocklist_build.py \
  --source https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
  --out-dir blocklist/ \
  --fp-rate 0.001
git add blocklist/ && git commit -m "Update blocklist" && git push
```

Point a device's **Blocklist base URL** at
`https://raw.githubusercontent.com/<you>/<repo>/main/blocklist` and it will
fetch `bloom.bin`, `domains.idx`, and `domains.idx.sha256` from that path.
`--source` may be repeated to merge multiple hosts-format lists, and
`--allowlist <file>` excludes specific domains regardless of source.

The hash/header format (`tools/bloom_format.py`) and the firmware's
implementation (`components/bloom_filter/`) must match bit-for-bit - if you
touch either, run the cross-check test above before trusting the result.

### Cutting a firmware release

```
idf.py build
gh release create vX.Y.Z build/esp-adblocker.bin --title vX.Y.Z
```

Point a device's **Firmware release URL** at the resulting asset URL
(`.../releases/download/vX.Y.Z/esp-adblocker.bin`) and trigger **Check firmware
update** from the web UI, or wait - OTA is manual-trigger only, there is no
automatic firmware auto-update (unlike the blocklist).

### Partition layout (`partitions.csv`)

| Partition | Purpose | Size |
|---|---|---|
| `nvs` | Runtime settings (`app_config`) | 24KB |
| `otadata` | OTA slot bookkeeping | 8KB |
| `phy_init` | RF calibration data | 4KB |
| `ota_0` / `ota_1` | Firmware A/B slots, with rollback | 1.5MB each |
| `bloom_a` / `bloom_b` | Bloom filter A/B slots | 2MB each |

The exact-match domain list lives on the SD card as `domains_a.idx` /
`domains_b.idx`, not in a flash partition, since it can be far larger than
the bloom filter.

## Known limitations

- UDP DNS only - no TCP:53 fallback (affects some large/DNSSEC-heavy responses)
- No IPv6 DNS transport (see the project discussion for why this mostly
  doesn't help against a home router's own IPv6 DNS advertisements anyway)
- No authentication on the web UI (LAN-trust model - anyone on your network
  can change settings)
- No automatic multi-day soak testing has been performed; heap usage is
  logged periodically (`heap_monitor_task`) for anyone running one
