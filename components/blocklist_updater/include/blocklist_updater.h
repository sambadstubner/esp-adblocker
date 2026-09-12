#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fetches `${base_url}/bloom.bin`, `${base_url}/domains.idx`, and
 * `${base_url}/domains.idx.sha256` over HTTPS (trusted via the built-in CA
 * bundle, same as fw_updater) and, if each validates, activates it:
 *
 *   - bloom.bin is downloaded into the *inactive* bloom_a/bloom_b flash
 *     partition, header- and CRC32-checked, and only then does
 *     app_config's bloom_active_slot flip to it.
 *   - domains.idx is streamed to the *inactive* domains_a.idx/domains_b.idx
 *     file on the SD card, checked against the fetched .sha256 digest, and
 *     only then does app_config's exact_list_active_slot flip to it (and
 *     sd_storage reloads it into PSRAM immediately).
 *
 * The two artifacts are validated and activated independently: a failure on
 * one does not affect the other, and either failure leaves the
 * previously-active artifact serving untouched - a power loss or corrupt
 * download can never leave the device without a working (if stale) filter.
 *
 * Returns ESP_OK only if both artifacts updated successfully; check the logs
 * for which one failed otherwise.
 *
 * Chained HTTPS/mbedTLS calls need a generous stack (TLS handshake + X.509
 * verification is well known to be stack-hungry) - call this only from a
 * dedicated task with several KB of headroom, e.g. via
 * blocklist_updater_check_and_apply_async() below, never directly from a
 * small-stack context like the default main task or a timer callback.
 */
esp_err_t blocklist_updater_check_and_apply(const char *base_url);

/**
 * Spawns a dedicated task (generously stacked, for the reason above) that
 * waits for the network to come up (bounded) and then calls
 * blocklist_updater_check_and_apply(base_url), logging the result. Returns
 * immediately; safe to call from any task, including the default main task.
 */
void blocklist_updater_check_and_apply_async(const char *base_url);

#ifdef __cplusplus
}
#endif
