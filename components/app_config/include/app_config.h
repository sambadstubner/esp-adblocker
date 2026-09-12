#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_netif_ip_addr.h"
#include "esp_netif_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Single owner of every runtime (NVS-backed) setting for the device.
 * Other components (eth_init, dns_proxy, blocklist_updater, web_ui, ...) read/write
 * settings only through this API, never touch nvs_* directly, so the schema lives
 * in exactly one place.
 *
 * Must be called once, after nvs_flash_init(), before any getter/setter below.
 */
esp_err_t app_config_init(void);

typedef enum {
    APP_CONFIG_NET_DHCP = 0,
    APP_CONFIG_NET_STATIC = 1,
} app_config_net_mode_t;

typedef enum {
    APP_CONFIG_BLOCK_NXDOMAIN = 0,
    APP_CONFIG_BLOCK_ZERO_IP = 1,
} app_config_block_policy_t;

app_config_net_mode_t app_config_get_net_mode(void);
esp_err_t app_config_set_net_mode(app_config_net_mode_t mode);

/** Only meaningful when net_mode == APP_CONFIG_NET_STATIC. */
esp_err_t app_config_get_static_ip(esp_netif_ip_info_t *out_ip_info);
esp_err_t app_config_set_static_ip(const esp_netif_ip_info_t *ip_info);

/** IPv4 addresses of upstream recursive resolvers, in esp_ip4_addr_t wire order. */
uint32_t app_config_get_upstream1(void);
uint32_t app_config_get_upstream2(void);
esp_err_t app_config_set_upstream1(uint32_t ip4);
esp_err_t app_config_set_upstream2(uint32_t ip4);

app_config_block_policy_t app_config_get_block_policy(void);
esp_err_t app_config_set_block_policy(app_config_block_policy_t policy);

/** Master on/off switch for blocking. When false, dns_proxy is pure pass-through
 * regardless of bloom filter/exact-list contents. Default true. */
bool app_config_get_blocking_enabled(void);
esp_err_t app_config_set_blocking_enabled(bool enabled);

/** out_buf must be at least 256 bytes. Empty string if never configured. */
esp_err_t app_config_get_blocklist_url(char *out_buf, size_t buf_len);
esp_err_t app_config_set_blocklist_url(const char *url);

/** Automatic blocklist refresh interval in hours; 0 disables periodic refresh. Default 24. */
uint32_t app_config_get_blocklist_refresh_interval_hours(void);
esp_err_t app_config_set_blocklist_refresh_interval_hours(uint32_t hours);

/** Which of the two bloom.bin flash slots (0="bloom_a", 1="bloom_b") is currently active. */
uint8_t app_config_get_bloom_active_slot(void);
esp_err_t app_config_set_bloom_active_slot(uint8_t slot);

/** Which of the two domains.idx SD files (0="domains_a.idx", 1="domains_b.idx") is currently active. */
uint8_t app_config_get_exact_list_active_slot(void);
esp_err_t app_config_set_exact_list_active_slot(uint8_t slot);

/** out_buf must be at least 256 bytes. Empty string if never configured. */
esp_err_t app_config_get_fw_update_url(char *out_buf, size_t buf_len);
esp_err_t app_config_set_fw_update_url(const char *url);

#ifdef __cplusplus
}
#endif
