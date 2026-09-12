#include "blocklist_updater.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_config.h"
#include "bloom_filter.h"
#include "crc32.h"
#include "dns_proxy.h"
#include "esp_check.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "eth_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "sd_storage.h"

static const char *TAG = "blocklist_updater";

#define MAX_URL_LEN 300
#define HTTP_TIMEOUT_MS 15000

static long http_get_to_buffer(const char *url, uint8_t *buf, size_t cap)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 4096,
        .buffer_size_tx = 2048,
        .timeout_ms = HTTP_TIMEOUT_MS,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return -1;
    }

    long total = -1;
    if (esp_http_client_open(client, 0) == ESP_OK) {
        esp_http_client_fetch_headers(client);
        int status = esp_http_client_get_status_code(client);
        if (status == 200) {
            size_t written = 0;
            int r;
            while (written < cap &&
                   (r = esp_http_client_read(client, (char *)buf + written, cap - written)) > 0) {
                written += (size_t)r;
            }
            total = (long)written;
        } else {
            ESP_LOGE(TAG, "GET %s -> HTTP %d", url, status);
        }
        esp_http_client_close(client);
    } else {
        ESP_LOGE(TAG, "failed to open %s", url);
    }
    esp_http_client_cleanup(client);
    return total;
}

static long http_get_to_file(const char *url, const char *path)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 4096,
        .buffer_size_tx = 2048,
        .timeout_ms = HTTP_TIMEOUT_MS,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        return -1;
    }

    long total = -1;
    if (esp_http_client_open(client, 0) == ESP_OK) {
        esp_http_client_fetch_headers(client);
        int status = esp_http_client_get_status_code(client);
        if (status == 200) {
            FILE *f = fopen(path, "wb");
            if (f != NULL) {
                char buf[1024];
                size_t written = 0;
                int r;
                while ((r = esp_http_client_read(client, buf, sizeof(buf))) > 0) {
                    fwrite(buf, 1, (size_t)r, f);
                    written += (size_t)r;
                }
                fclose(f);
                total = (long)written;
            } else {
                ESP_LOGE(TAG, "failed to open %s for writing", path);
            }
        } else {
            ESP_LOGE(TAG, "GET %s -> HTTP %d", url, status);
        }
        esp_http_client_close(client);
    } else {
        ESP_LOGE(TAG, "failed to open %s", url);
    }
    esp_http_client_cleanup(client);
    return total;
}

static esp_err_t update_bloom(const char *base_url)
{
    uint8_t active = app_config_get_bloom_active_slot();
    uint8_t target = active == 0 ? 1 : 0;
    const char *target_label = target == 0 ? "bloom_a" : "bloom_b";

    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, target_label);
    if (part == NULL) {
        ESP_LOGE(TAG, "partition %s not found", target_label);
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t *buf = heap_caps_malloc(part->size, MALLOC_CAP_SPIRAM);
    if (buf == NULL) {
        ESP_LOGE(TAG, "no PSRAM for %lu-byte download buffer", (unsigned long)part->size);
        return ESP_ERR_NO_MEM;
    }

    char url[MAX_URL_LEN];
    snprintf(url, sizeof(url), "%s/bloom.bin", base_url);
    long len = http_get_to_buffer(url, buf, part->size);
    if (len <= 0) {
        heap_caps_free(buf);
        return ESP_FAIL;
    }

    bloom_filter_t filter;
    if (!bloom_filter_init(buf, (size_t)len, &filter)) {
        ESP_LOGE(TAG, "downloaded bloom.bin failed header validation");
        heap_caps_free(buf);
        return ESP_ERR_INVALID_RESPONSE;
    }
    size_t bitarray_bytes = (size_t)((filter.header->m_bits + 7) / 8);
    uint32_t computed_crc = crc32_ieee(filter.bits, bitarray_bytes);
    if (computed_crc != filter.header->crc32) {
        ESP_LOGE(TAG, "bloom.bin CRC mismatch (corrupt download): got 0x%08x want 0x%08x",
                 (unsigned)computed_crc, (unsigned)filter.header->crc32);
        heap_caps_free(buf);
        return ESP_ERR_INVALID_CRC;
    }

    esp_err_t err = esp_partition_erase_range(part, 0, part->size);
    if (err == ESP_OK) {
        err = esp_partition_write(part, 0, buf, (size_t)len);
    }
    heap_caps_free(buf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "flash write to %s failed: %s", target_label, esp_err_to_name(err));
        return err;
    }

    ESP_RETURN_ON_ERROR(app_config_set_bloom_active_slot(target), TAG, "activate %s failed", target_label);
    dns_proxy_reload_bloom_filter();
    ESP_LOGI(TAG, "bloom filter updated: %llu domains, now active in %s",
             (unsigned long long)filter.header->n_domains, target_label);
    return ESP_OK;
}

static void hex_encode_lower(char *out, const uint8_t *bytes, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0xF];
    }
    out[n * 2] = '\0';
}

static esp_err_t sha256_file(const char *path, char *out_hex65)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    uint8_t chunk[1024];
    size_t r;
    while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        mbedtls_sha256_update(&ctx, chunk, r);
    }
    fclose(f);
    uint8_t digest[32];
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
    hex_encode_lower(out_hex65, digest, sizeof(digest));
    return ESP_OK;
}

static esp_err_t update_domain_list(const char *base_url)
{
    if (!sd_storage_is_mounted()) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t active = app_config_get_exact_list_active_slot();
    uint8_t target = active == 0 ? 1 : 0;
    char target_path[64];
    snprintf(target_path, sizeof(target_path), SD_STORAGE_MOUNT_POINT "/domains_%c.idx", target == 0 ? 'a' : 'b');

    char url[MAX_URL_LEN];
    snprintf(url, sizeof(url), "%s/domains.idx", base_url);
    long len = http_get_to_file(url, target_path);
    if (len <= 0) {
        return ESP_FAIL;
    }

    char sha_url[MAX_URL_LEN];
    snprintf(sha_url, sizeof(sha_url), "%s/domains.idx.sha256", base_url);
    uint8_t sha_resp[128] = {0};
    long sha_len = http_get_to_buffer(sha_url, sha_resp, sizeof(sha_resp) - 1);
    if (sha_len < 64) {
        ESP_LOGE(TAG, "failed to fetch domains.idx.sha256");
        remove(target_path);
        return ESP_FAIL;
    }
    char expected_hex[65];
    for (int i = 0; i < 64; i++) {
        expected_hex[i] = (char)tolower(sha_resp[i]);
    }
    expected_hex[64] = '\0';

    char actual_hex[65];
    esp_err_t sha_err = sha256_file(target_path, actual_hex);
    if (sha_err != ESP_OK) {
        remove(target_path);
        return sha_err;
    }

    if (strncmp(actual_hex, expected_hex, 64) != 0) {
        ESP_LOGE(TAG, "domains.idx checksum mismatch (corrupt download): got %s want %.64s",
                 actual_hex, expected_hex);
        remove(target_path);
        return ESP_ERR_INVALID_CRC;
    }

    ESP_RETURN_ON_ERROR(app_config_set_exact_list_active_slot(target), TAG, "activate domain list slot failed");
    esp_err_t reload_err = sd_storage_load_domain_list();
    ESP_LOGI(TAG, "domain list updated (%ld bytes), now active as %s", len, target_path);
    return reload_err;
}

esp_err_t blocklist_updater_check_and_apply(const char *base_url)
{
    esp_err_t bloom_err = update_bloom(base_url);
    if (bloom_err != ESP_OK) {
        ESP_LOGW(TAG, "bloom filter update failed: %s (previous filter remains active)", esp_err_to_name(bloom_err));
    }

    esp_err_t list_err = update_domain_list(base_url);
    if (list_err != ESP_OK) {
        ESP_LOGW(TAG, "domain list update failed: %s (previous list remains active)", esp_err_to_name(list_err));
    }

    return (bloom_err == ESP_OK && list_err == ESP_OK) ? ESP_OK : ESP_FAIL;
}

#define ASYNC_TASK_STACK_SIZE 8192
#define ASYNC_NETWORK_WAIT_MS 30000

static void async_task(void *arg)
{
    char *base_url = (char *)arg;
    if (!eth_init_wait_for_ip(pdMS_TO_TICKS(ASYNC_NETWORK_WAIT_MS))) {
        ESP_LOGW(TAG, "network did not come up within %ds, skipping blocklist check", ASYNC_NETWORK_WAIT_MS / 1000);
    } else {
        esp_err_t err = blocklist_updater_check_and_apply(base_url);
        ESP_LOGI(TAG, "blocklist check result: %s", esp_err_to_name(err));
    }
    free(base_url);
    vTaskDelete(NULL);
}

void blocklist_updater_check_and_apply_async(const char *base_url)
{
    char *url_copy = strdup(base_url);
    if (url_copy == NULL) {
        ESP_LOGE(TAG, "strdup failed, cannot start blocklist check");
        return;
    }
    if (xTaskCreate(async_task, "blocklist_upd", ASYNC_TASK_STACK_SIZE, url_copy, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate failed, cannot start blocklist check");
        free(url_copy);
    }
}
