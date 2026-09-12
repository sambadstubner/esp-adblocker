#include "sd_storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "app_config.h"
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

static const char *TAG = "sd_storage";

static bool s_mounted = false;
static sdmmc_card_t *s_card = NULL;

static char *s_domain_buf = NULL;    // PSRAM-backed raw file contents
static char **s_domain_lines = NULL; // PSRAM-backed, sorted array of pointers into s_domain_buf
static size_t s_domain_count = 0;

esp_err_t sd_storage_mount(void)
{
    ESP_RETURN_ON_FALSE(!s_mounted, ESP_ERR_INVALID_STATE, TAG, "already mounted");

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = CONFIG_SD_STORAGE_MOSI_GPIO,
        .miso_io_num = CONFIG_SD_STORAGE_MISO_GPIO,
        .sclk_io_num = CONFIG_SD_STORAGE_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(CONFIG_SD_STORAGE_SPI_HOST, &bus_cfg, SDSPI_DEFAULT_DMA),
                         TAG, "SPI bus init failed");

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = CONFIG_SD_STORAGE_SPI_HOST;

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.host_id = CONFIG_SD_STORAGE_SPI_HOST;
    slot_config.gpio_cs = CONFIG_SD_STORAGE_CS_GPIO;

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = CONFIG_SD_STORAGE_FORMAT_IF_MOUNT_FAILED,
        .max_files = CONFIG_SD_STORAGE_MAX_FILES,
        .allocation_unit_size = 16 * 1024,
    };

    esp_err_t err = esp_vfs_fat_sdspi_mount(SD_STORAGE_MOUNT_POINT, &host, &slot_config, &mount_config, &s_card);
    if (err != ESP_OK) {
        if (err == ESP_FAIL) {
            ESP_LOGE(TAG, "failed to mount filesystem (enable SD_STORAGE_FORMAT_IF_MOUNT_FAILED to auto-format)");
        } else {
            ESP_LOGE(TAG, "failed to initialize card: %s", esp_err_to_name(err));
        }
        spi_bus_free(CONFIG_SD_STORAGE_SPI_HOST);
        return err;
    }

    sdmmc_card_print_info(stdout, s_card);
    s_mounted = true;
    return ESP_OK;
}

bool sd_storage_is_mounted(void)
{
    return s_mounted;
}

static int cmp_domain(const void *key, const void *elem)
{
    const char *k = (const char *)key;
    const char *const *e = (const char *const *)elem;
    return strcmp(k, *e);
}

esp_err_t sd_storage_load_domain_list(void)
{
    if (s_domain_buf != NULL) {
        heap_caps_free(s_domain_buf);
        s_domain_buf = NULL;
    }
    if (s_domain_lines != NULL) {
        heap_caps_free(s_domain_lines);
        s_domain_lines = NULL;
    }
    s_domain_count = 0;

    if (!s_mounted) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t slot = app_config_get_exact_list_active_slot();
    char path[64];
    snprintf(path, sizeof(path), SD_STORAGE_MOUNT_POINT "/domains_%c.idx", slot == 0 ? 'a' : 'b');

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        // Fall back to the pre-A/B filename so a card populated before
        // blocklist_updater existed keeps working without manual migration.
        const char *legacy_path = SD_STORAGE_MOUNT_POINT "/domains.idx";
        f = fopen(legacy_path, "rb");
        if (f == NULL) {
            ESP_LOGW(TAG, "no domain list at %s (or legacy %s)", path, legacy_path);
            return ESP_ERR_NOT_FOUND;
        }
        ESP_LOGW(TAG, "using legacy %s - next blocklist update will migrate to the A/B filenames", legacy_path);
        snprintf(path, sizeof(path), "%s", legacy_path);
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        fclose(f);
        return ESP_ERR_INVALID_SIZE;
    }

    s_domain_buf = heap_caps_malloc((size_t)size + 1, MALLOC_CAP_SPIRAM);
    if (s_domain_buf == NULL) {
        fclose(f);
        ESP_LOGE(TAG, "no PSRAM for %ld-byte domain list", size);
        return ESP_ERR_NO_MEM;
    }
    size_t read_bytes = fread(s_domain_buf, 1, (size_t)size, f);
    fclose(f);
    s_domain_buf[read_bytes] = '\0';

    size_t line_count = 0;
    for (size_t i = 0; i < read_bytes; i++) {
        if (s_domain_buf[i] == '\n') {
            line_count++;
        }
    }
    if (line_count == 0) {
        ESP_LOGW(TAG, "domain list at %s has no newline-terminated entries", path);
        heap_caps_free(s_domain_buf);
        s_domain_buf = NULL;
        return ESP_ERR_INVALID_SIZE;
    }

    s_domain_lines = heap_caps_malloc(line_count * sizeof(char *), MALLOC_CAP_SPIRAM);
    if (s_domain_lines == NULL) {
        heap_caps_free(s_domain_buf);
        s_domain_buf = NULL;
        ESP_LOGE(TAG, "no PSRAM for %zu domain pointers", line_count);
        return ESP_ERR_NO_MEM;
    }

    // domains.idx is written pre-sorted by tools/blocklist_build.py, one domain
    // per line - walking it in file order already yields a sorted pointer
    // array, so no separate sort step is needed here.
    size_t count = 0;
    char *line_start = s_domain_buf;
    for (size_t i = 0; i < read_bytes; i++) {
        if (s_domain_buf[i] == '\n') {
            s_domain_buf[i] = '\0';
            if (line_start[0] != '\0') {
                s_domain_lines[count++] = line_start;
            }
            line_start = &s_domain_buf[i + 1];
        }
    }
    s_domain_count = count;

    ESP_LOGI(TAG, "loaded %zu domains from %s into PSRAM (%ld bytes)", s_domain_count, path, size);
    return ESP_OK;
}

sd_storage_confirm_t sd_storage_confirm(const char *domain)
{
    if (s_domain_lines == NULL || s_domain_count == 0) {
        return SD_STORAGE_CONFIRM_UNAVAILABLE;
    }
    char **found = bsearch(domain, s_domain_lines, s_domain_count, sizeof(char *), cmp_domain);
    return found ? SD_STORAGE_CONFIRM_BLOCKED : SD_STORAGE_CONFIRM_NOT_BLOCKED;
}
