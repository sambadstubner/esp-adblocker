#pragma once

#include "esp_err.h"
#include "esp_eth.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the onboard W5500 (SPI) Ethernet interface and attach it to esp-netif.
 * Must be called after esp_netif_init() and esp_event_loop_create_default().
 * Starts the Ethernet driver; ETH_EVENT/IP_EVENT handlers log link and IP status.
 */
esp_err_t eth_init_start(void);

/** Handle of the Ethernet netif created by eth_init_start(), or NULL before it's called. */
esp_netif_t *eth_init_get_netif(void);

/**
 * Blocks until the interface has obtained an IP (DHCP or static-applied) or
 * timeout expires. Used by fw_updater's post-OTA health check to decide
 * whether to confirm the new image or let it roll back on next boot.
 */
bool eth_init_wait_for_ip(TickType_t timeout);

#ifdef __cplusplus
}
#endif
