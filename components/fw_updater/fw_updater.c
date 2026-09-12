#include "fw_updater.h"

#include "esp_crt_bundle.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "eth_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "fw_updater";

#define CONFIRM_BOOT_TIMEOUT_MS 30000

esp_err_t fw_updater_check_and_update(const char *url)
{
    esp_http_client_config_t http_config = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
        // GitHub's redirect/asset response headers exceed esp_http_client's
        // default 512-byte buffer ("Out of buffer" / ESP_FAIL otherwise).
        .buffer_size = 4096,
        .buffer_size_tx = 2048,
        // disable_auto_redirect defaults to false: GitHub Release asset URLs
        // redirect to objects.githubusercontent.com, so this must stay on.
    };
    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    ESP_LOGI(TAG, "starting OTA from %s", url);
    esp_err_t err = esp_https_ota(&ota_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "OTA succeeded, rebooting into new image");
    esp_restart();
    return ESP_OK; // unreachable
}

static void confirm_boot_task(void *arg)
{
    (void)arg;
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK && state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "freshly-updated image pending verification, waiting up to %ds for network",
                 CONFIRM_BOOT_TIMEOUT_MS / 1000);
        if (eth_init_wait_for_ip(pdMS_TO_TICKS(CONFIRM_BOOT_TIMEOUT_MS))) {
            ESP_LOGI(TAG, "network is up, confirming this image as valid");
            esp_ota_mark_app_valid_cancel_rollback();
        } else {
            ESP_LOGE(TAG, "network did not come up in time; leaving image unconfirmed "
                           "(bootloader will roll back to the previous slot on next reboot)");
        }
    }
    vTaskDelete(NULL);
}

void fw_updater_confirm_boot_if_healthy(void)
{
    xTaskCreate(confirm_boot_task, "fw_confirm", 3072, NULL, 4, NULL);
}
