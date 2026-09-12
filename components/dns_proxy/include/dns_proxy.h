#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif
