#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t queries_total;
    uint32_t queries_blocked;
    uint32_t queries_forwarded;
    uint32_t queries_servfail;
    uint32_t queries_blocked_24h; // rolling wall-clock window, unlike queries_blocked which is lifetime-since-boot
    int64_t start_time_us; // esp_timer_get_time() at dns_proxy_start()
} dns_proxy_stats_t;

/**
 * Starts the DNS proxy: binds UDP:53, and for every client query forwards it
 * to the configured upstream resolver (app_config upstream1/upstream2) and
 * relays the real response back. Phase 3 scope: pure pass-through, no
 * blocklist checks yet. Runs in its own FreeRTOS task; returns once the task
 * is created (does not block).
 */
esp_err_t dns_proxy_start(void);

/**
 * (Re)loads the bloom filter from app_config's currently-active bloom_a/
 * bloom_b flash slot, falling back to the embedded seed filter if that slot
 * is empty or invalid. dns_proxy_start() calls this once at startup;
 * blocklist_updater calls it again after activating a freshly-downloaded
 * filter so the update takes effect without a reboot.
 */
void dns_proxy_reload_bloom_filter(void);

/** Fills in current query counters and start time. */
void dns_proxy_get_stats(dns_proxy_stats_t *out);

typedef struct {
    bool ready;
    bool from_embedded_seed; // true if the active flash slot was empty/invalid
    uint64_t n_domains;
    uint64_t m_bits;
    uint32_t k_hashes;
    uint64_t build_unix_ts;
} dns_proxy_bloom_info_t;

/** Fills in details of the currently-loaded bloom filter. */
void dns_proxy_get_bloom_info(dns_proxy_bloom_info_t *out);

/**
 * Forces the upstream socket to reconnect using the currently-configured
 * upstream1 (and resets failover state back to it). Call after changing
 * upstream1/upstream2 via the web UI, otherwise the change only takes
 * effect the next time automatic failover happens.
 */
void dns_proxy_apply_upstream_config(void);

/**
 * (Re)loads the user-managed allowlist from app_config. dns_proxy_start()
 * calls this once at startup; the web UI calls it again after the user edits
 * the allowlist so the change takes effect immediately, no reboot needed.
 * A domain on this list is always let through, checked before both the
 * bloom filter's positive result and the SD exact-list confirm - it wins
 * over a bad blocklist entry or a bloom false-positive.
 */
void dns_proxy_reload_allowlist(void);

typedef enum {
    DNS_PROXY_RESULT_FORWARDED = 0,
    DNS_PROXY_RESULT_BLOCKED = 1,
    DNS_PROXY_RESULT_SERVFAIL = 2,
} dns_proxy_query_result_t;

#define DNS_PROXY_QUERY_LOG_NAME_LEN 255

// Family-tagged client address, compact enough to keep in the query log
// without pulling in a full struct sockaddr_storage per entry. addr holds a
// 4-byte IPv4 or 16-byte IPv6 address in network byte order, family is
// AF_INET or AF_INET6.
typedef struct {
    uint8_t family;
    uint8_t addr[16];
} dns_client_addr_t;

typedef struct {
    int64_t time_us;      // esp_timer_get_time() when logged
    dns_client_addr_t client_addr;
    uint16_t qtype;
    dns_proxy_query_result_t result;
    char qname[DNS_PROXY_QUERY_LOG_NAME_LEN];
} dns_proxy_query_log_entry_t;

/**
 * Copies up to max_entries of the most recent queries (newest first) into
 * out. Returns the number actually copied. Backed by a fixed-size ring
 * buffer (CONFIG_DNS_PROXY_QUERY_LOG_SIZE entries) in internal RAM.
 */
size_t dns_proxy_get_query_log(dns_proxy_query_log_entry_t *out, size_t max_entries);

#ifdef __cplusplus
}
#endif
