#include <stdio.h>

#include "app_config.h"
#include "blocklist_updater.h"
#include "dns_proxy.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "eth_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "fw_updater.h"
#include "nvs_flash.h"
#include "sd_storage.h"

static const char *TAG = "app_main";

// Phase 5 (OTA) hardware verification scaffolding: same pattern as the Phase 2
// flags above - flip to 1 with a real GitHub Release asset URL, flash, confirm
// the device downloads/reboots/self-confirms, then flip back to 0. Remove once
// Phase 7's web UI can trigger an update at runtime.
#define FW_UPDATER_TRIGGER_TEST 0
#define FW_UPDATER_TEST_URL "https://github.com/sambadstubner/esp-dns/releases/download/v0.1.0/esp-dns.bin"

// Phase 6 (blocklist_updater) hardware verification scaffolding: same pattern.
// blocklist/{bloom.bin,domains.idx,domains.idx.sha256} live at this path in
// the repo, fetched via raw.githubusercontent.com.
#define BLOCKLIST_UPDATER_TRIGGER_TEST 0
#define BLOCKLIST_UPDATER_BASE_URL "https://raw.githubusercontent.com/sambadstubner/esp-dns/main/blocklist"

// Phase 2 (app_config/NVS) hardware verification scaffolding: flip to 1, flash, confirm
// the device comes up static at 192.168.1.50 with the overridden upstream/policy, then
// flip back to 0 and reflash to confirm the *same* values are read back from NVS rather
// than reset to defaults - i.e. that they actually persisted across a full reflash+reboot,
// not just a soft reset. Remove this block once Phase 7's web UI can do this at runtime.
#define APP_CONFIG_PHASE2_WRITE_TEST 0
#define APP_CONFIG_PHASE2_RESET_TO_DEFAULTS 0
#define DEFAULT_UPSTREAM1_FOR_RESET ESP_IP4TOADDR(1, 1, 1, 1)

static void log_current_config(void)
{
    ESP_LOGI(TAG, "net_mode=%d block_policy=%d upstream1=0x%08x upstream2=0x%08x bloom_slot=%u",
             app_config_get_net_mode(), app_config_get_block_policy(),
             (unsigned)app_config_get_upstream1(), (unsigned)app_config_get_upstream2(),
             app_config_get_bloom_active_slot());
    esp_netif_ip_info_t ip_info;
    if (app_config_get_static_ip(&ip_info) == ESP_OK) {
        ESP_LOGI(TAG, "stored static IP:" IPSTR " mask:" IPSTR " gw:" IPSTR,
                 IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "esp-dns starting");
    ESP_LOGI(TAG, "free PSRAM: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    ESP_LOGI(TAG, "free internal RAM: %u bytes", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_err);
    ESP_ERROR_CHECK(app_config_init());

#if APP_CONFIG_PHASE2_WRITE_TEST
    esp_netif_ip_info_t test_ip = {
        .ip.addr = ESP_IP4TOADDR(192, 168, 1, 50),
        .netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0),
        .gw.addr = ESP_IP4TOADDR(192, 168, 1, 1),
    };
    ESP_ERROR_CHECK(app_config_set_static_ip(&test_ip));
    ESP_ERROR_CHECK(app_config_set_net_mode(APP_CONFIG_NET_STATIC));
    ESP_ERROR_CHECK(app_config_set_upstream1(ESP_IP4TOADDR(9, 9, 9, 9)));
    ESP_ERROR_CHECK(app_config_set_block_policy(APP_CONFIG_BLOCK_ZERO_IP));
    ESP_LOGI(TAG, "Phase 2 write-test: wrote static/upstream/policy overrides to NVS");
#elif APP_CONFIG_PHASE2_RESET_TO_DEFAULTS
    ESP_ERROR_CHECK(app_config_set_net_mode(APP_CONFIG_NET_DHCP));
    ESP_ERROR_CHECK(app_config_set_upstream1(DEFAULT_UPSTREAM1_FOR_RESET));
    ESP_ERROR_CHECK(app_config_set_block_policy(APP_CONFIG_BLOCK_NXDOMAIN));
    ESP_LOGI(TAG, "Phase 2 reset: restored net_mode/upstream1/block_policy to defaults");
#endif

    ESP_LOGI(TAG, "config after init:");
    log_current_config();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_err_t eth_err = eth_init_start();
    if (eth_err != ESP_OK) {
        ESP_LOGE(TAG, "Ethernet init failed: %s", esp_err_to_name(eth_err));
    }

    esp_err_t dns_err = dns_proxy_start();
    if (dns_err != ESP_OK) {
        ESP_LOGE(TAG, "DNS proxy start failed: %s", esp_err_to_name(dns_err));
    }

    fw_updater_confirm_boot_if_healthy();

#if FW_UPDATER_TRIGGER_TEST
    vTaskDelay(pdMS_TO_TICKS(15000)); // let DHCP/link come up first
    esp_err_t ota_err = fw_updater_check_and_update(FW_UPDATER_TEST_URL);
    ESP_LOGE(TAG, "OTA test trigger returned (should not happen on success): %s", esp_err_to_name(ota_err));
#endif

    esp_err_t sd_err = sd_storage_mount();
    if (sd_err != ESP_OK) {
        ESP_LOGW(TAG, "SD card mount failed (%s) - continuing without exact-list confirm support",
                 esp_err_to_name(sd_err));
    } else {
        esp_err_t list_err = sd_storage_load_domain_list();
        if (list_err != ESP_OK) {
            ESP_LOGW(TAG, "domains.idx load failed (%s) - bloom-positive queries will fail safe to blocked",
                     esp_err_to_name(list_err));
        }

        const char *path = SD_STORAGE_MOUNT_POINT "/esp_dns_test.txt";
        FILE *f = fopen(path, "w");
        if (f == NULL) {
            ESP_LOGE(TAG, "SD self-test: failed to open %s for writing", path);
        } else {
            fprintf(f, "esp-dns Phase 1 SD self-test\n");
            fclose(f);
            f = fopen(path, "r");
            if (f == NULL) {
                ESP_LOGE(TAG, "SD self-test: failed to open %s for reading", path);
            } else {
                char line[64];
                fgets(line, sizeof(line), f);
                fclose(f);
                ESP_LOGI(TAG, "SD self-test: read back '%s'", line);
            }
        }
    }

#if BLOCKLIST_UPDATER_TRIGGER_TEST
    blocklist_updater_check_and_apply_async(BLOCKLIST_UPDATER_BASE_URL);
#endif
}
