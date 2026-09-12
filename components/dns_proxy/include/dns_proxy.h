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

#ifdef __cplusplus
}
#endif
