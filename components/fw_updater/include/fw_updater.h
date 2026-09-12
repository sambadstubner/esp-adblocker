#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Downloads and flashes a firmware image from `url` over HTTPS (trusted via
 * the built-in Mozilla CA bundle - no custom signing, per PLAN.md's OTA
 * security decision), following redirects (so GitHub Release asset URLs,
 * which redirect to objects.githubusercontent.com, work). On success this
 * reboots into the new image and never returns; on failure it returns the
 * error and the device keeps running the current image untouched.
 */
esp_err_t fw_updater_check_and_update(const char *url);

/**
 * Call once from app_main after starting networking. If this boot is a
 * freshly-OTA'd image still pending verification, waits (bounded) for the
 * network to come up and either confirms the image as valid (cancelling
 * rollback) or leaves it unconfirmed so the bootloader reverts to the
 * previous slot on the next reboot. A no-op if this isn't a pending-verify
 * boot (e.g. a normal power-on). Runs in a background task; returns immediately.
 */
void fw_updater_confirm_boot_if_healthy(void);

#ifdef __cplusplus
}
#endif
