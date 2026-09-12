#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SD_STORAGE_MOUNT_POINT "/sdcard"

/**
 * Mount the TF/SD card (SPI) as a FAT filesystem at SD_STORAGE_MOUNT_POINT.
 * If the card can't be read as FAT (e.g. it still has a foreign partition table),
 * it is reformatted as a single FAT32 volume, per CONFIG_SD_STORAGE_FORMAT_IF_MOUNT_FAILED.
 *
 * This is a soft dependency for the rest of the system: callers should treat a
 * failure return here as "run in degraded mode" (bloom-only blocking, no exact-list
 * confirm), not a fatal boot error, since the device's core job is answering DNS
 * regardless of whether the card is present.
 */
esp_err_t sd_storage_mount(void);

/** True if the card is currently mounted and usable. */
bool sd_storage_is_mounted(void);

typedef enum {
    SD_STORAGE_CONFIRM_UNAVAILABLE = 0, // no exact list loaded (SD absent/unmounted/no file) - caller should fail safe (block on bloom alone)
    SD_STORAGE_CONFIRM_BLOCKED = 1,     // domain is genuinely in the list
    SD_STORAGE_CONFIRM_NOT_BLOCKED = 2, // domain is NOT in the list - bloom hit was a false positive
} sd_storage_confirm_t;

/**
 * Loads SD_STORAGE_MOUNT_POINT/domains.idx (one normalized, sorted domain per
 * line) fully into a PSRAM buffer and builds a binary-searchable index over
 * it. Safe to call again after a blocklist update to reload.
 *
 * Soft-fails like sd_storage_mount(): a non-OK return just means
 * sd_storage_confirm() will report SD_STORAGE_CONFIRM_UNAVAILABLE, not that
 * the device should stop serving DNS.
 */
esp_err_t sd_storage_load_domain_list(void);

/** domain must already be normalized (lowercase, no trailing dot) by the caller. */
sd_storage_confirm_t sd_storage_confirm(const char *domain);

#ifdef __cplusplus
}
#endif
