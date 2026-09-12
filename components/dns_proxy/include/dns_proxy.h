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

#ifdef __cplusplus
}
#endif
