#include <stdio.h>

#include "app_config.h"
#include "blocklist_updater.h"
#include "dns_proxy.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "eth_init.h"
#include "fw_updater.h"
#include "nvs_flash.h"
#include "sd_storage.h"
#include "web_ui.h"

static const char *TAG = "app_main";

static void log_current_config(void)
{
    ESP_LOGI(TAG, "net_mode=%d block_policy=%d blocking_enabled=%d upstream1=0x%08x upstream2=0x%08x bloom_slot=%u",
             app_config_get_net_mode(), app_config_get_block_policy(), app_config_get_blocking_enabled(),
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
    }

    esp_err_t web_err = web_ui_start();
    if (web_err != ESP_OK) {
        ESP_LOGE(TAG, "web UI start failed: %s", esp_err_to_name(web_err));
    }
}
