#include "app_config.h"

#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "app_config";
#define NVS_NAMESPACE "espdns"

// Defaults for our two upstream resolvers (1.1.1.1 / 8.8.8.8) happen to have
// identical octets, so their wire-order uint32 representation is endian-independent.
#define DEFAULT_UPSTREAM1 0x01010101u
#define DEFAULT_UPSTREAM2 0x08080808u

static nvs_handle_t s_handle;
static bool s_initialized = false;

esp_err_t app_config_init(void)
{
    ESP_RETURN_ON_FALSE(!s_initialized, ESP_ERR_INVALID_STATE, TAG, "already initialized");
    ESP_RETURN_ON_ERROR(nvs_open(NVS_NAMESPACE, NVS_READWRITE, &s_handle), TAG, "nvs_open failed");
    s_initialized = true;
    return ESP_OK;
}

app_config_net_mode_t app_config_get_net_mode(void)
{
    uint8_t v = APP_CONFIG_NET_DHCP;
    nvs_get_u8(s_handle, "net_mode", &v);
    return (app_config_net_mode_t)v;
}

esp_err_t app_config_set_net_mode(app_config_net_mode_t mode)
{
    ESP_RETURN_ON_ERROR(nvs_set_u8(s_handle, "net_mode", (uint8_t)mode), TAG, "set net_mode failed");
    return nvs_commit(s_handle);
}

esp_err_t app_config_get_static_ip(esp_netif_ip_info_t *out_ip_info)
{
    memset(out_ip_info, 0, sizeof(*out_ip_info));
    size_t sz = sizeof(esp_netif_ip_info_t);
    return nvs_get_blob(s_handle, "static_ip", out_ip_info, &sz);
}

esp_err_t app_config_set_static_ip(const esp_netif_ip_info_t *ip_info)
{
    ESP_RETURN_ON_ERROR(nvs_set_blob(s_handle, "static_ip", ip_info, sizeof(*ip_info)),
                         TAG, "set static_ip failed");
    return nvs_commit(s_handle);
}

uint32_t app_config_get_upstream1(void)
{
    uint32_t v = DEFAULT_UPSTREAM1;
    nvs_get_u32(s_handle, "upstream1", &v);
    return v;
}

uint32_t app_config_get_upstream2(void)
{
    uint32_t v = DEFAULT_UPSTREAM2;
    nvs_get_u32(s_handle, "upstream2", &v);
    return v;
}

esp_err_t app_config_set_upstream1(uint32_t ip4)
{
    ESP_RETURN_ON_ERROR(nvs_set_u32(s_handle, "upstream1", ip4), TAG, "set upstream1 failed");
    return nvs_commit(s_handle);
}

esp_err_t app_config_set_upstream2(uint32_t ip4)
{
    ESP_RETURN_ON_ERROR(nvs_set_u32(s_handle, "upstream2", ip4), TAG, "set upstream2 failed");
    return nvs_commit(s_handle);
}

app_config_block_policy_t app_config_get_block_policy(void)
{
    uint8_t v = APP_CONFIG_BLOCK_NXDOMAIN;
    nvs_get_u8(s_handle, "block_policy", &v);
    return (app_config_block_policy_t)v;
}

esp_err_t app_config_set_block_policy(app_config_block_policy_t policy)
{
    ESP_RETURN_ON_ERROR(nvs_set_u8(s_handle, "block_policy", (uint8_t)policy), TAG, "set block_policy failed");
    return nvs_commit(s_handle);
}

bool app_config_get_blocking_enabled(void)
{
    uint8_t v = 1; // default: blocking on
    nvs_get_u8(s_handle, "block_en", &v);
    return v != 0;
}

esp_err_t app_config_set_blocking_enabled(bool enabled)
{
    ESP_RETURN_ON_ERROR(nvs_set_u8(s_handle, "block_en", enabled ? 1 : 0), TAG, "set block_en failed");
    return nvs_commit(s_handle);
}

esp_err_t app_config_get_blocklist_url(char *out_buf, size_t buf_len)
{
    esp_err_t err = nvs_get_str(s_handle, "blocklist_url", out_buf, &buf_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        out_buf[0] = '\0';
        return ESP_OK;
    }
    return err;
}

esp_err_t app_config_set_blocklist_url(const char *url)
{
    ESP_RETURN_ON_ERROR(nvs_set_str(s_handle, "blocklist_url", url), TAG, "set blocklist_url failed");
    return nvs_commit(s_handle);
}

uint32_t app_config_get_blocklist_refresh_interval_hours(void)
{
    uint32_t v = 24;
    nvs_get_u32(s_handle, "refresh_hrs", &v);
    return v;
}

esp_err_t app_config_set_blocklist_refresh_interval_hours(uint32_t hours)
{
    ESP_RETURN_ON_ERROR(nvs_set_u32(s_handle, "refresh_hrs", hours), TAG, "set refresh_hrs failed");
    return nvs_commit(s_handle);
}

uint8_t app_config_get_bloom_active_slot(void)
{
    uint8_t v = 0;
    nvs_get_u8(s_handle, "bloom_slot", &v);
    return v;
}

esp_err_t app_config_set_bloom_active_slot(uint8_t slot)
{
    ESP_RETURN_ON_ERROR(nvs_set_u8(s_handle, "bloom_slot", slot), TAG, "set bloom_slot failed");
    return nvs_commit(s_handle);
}

esp_err_t app_config_get_fw_update_url(char *out_buf, size_t buf_len)
{
    esp_err_t err = nvs_get_str(s_handle, "fw_url", out_buf, &buf_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        out_buf[0] = '\0';
        return ESP_OK;
    }
    return err;
}

esp_err_t app_config_set_fw_update_url(const char *url)
{
    ESP_RETURN_ON_ERROR(nvs_set_str(s_handle, "fw_url", url), TAG, "set fw_url failed");
    return nvs_commit(s_handle);
}

uint8_t app_config_get_exact_list_active_slot(void)
{
    uint8_t v = 0;
    nvs_get_u8(s_handle, "list_slot", &v);
    return v;
}

esp_err_t app_config_set_exact_list_active_slot(uint8_t slot)
{
    ESP_RETURN_ON_ERROR(nvs_set_u8(s_handle, "list_slot", slot), TAG, "set list_slot failed");
    return nvs_commit(s_handle);
}
