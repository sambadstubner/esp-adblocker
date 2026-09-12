#include "eth_init.h"

#include "app_config.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_check.h"
#include "esp_eth_mac_spi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_sntp.h"
#include "freertos/event_groups.h"
#include "mdns.h"

static const char *TAG = "eth_init";

#define MDNS_HOSTNAME "esp-dns"
#define MDNS_INSTANCE_NAME "esp-dns ad blocker"

static esp_netif_t *s_eth_netif = NULL;
static esp_eth_handle_t s_eth_handle = NULL;
static EventGroupHandle_t s_event_group = NULL;
#define ETH_INIT_GOT_IP_BIT BIT0

static void eth_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    uint8_t mac_addr[6] = {0};
    esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;

    switch (event_id) {
    case ETHERNET_EVENT_CONNECTED:
        esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac_addr);
        ESP_LOGI(TAG, "link up, MAC %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "link down");
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "driver started");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "driver stopped");
        break;
    default:
        break;
    }
}

static void got_ip_event_handler(void *arg, esp_event_base_t event_base,
                                  int32_t event_id, void *event_data)
{
    const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "got IP:" IPSTR " mask:" IPSTR " gw:" IPSTR,
             IP2STR(&ip_info->ip), IP2STR(&ip_info->netmask), IP2STR(&ip_info->gw));
    if (s_event_group != NULL) {
        xEventGroupSetBits(s_event_group, ETH_INIT_GOT_IP_BIT);
    }
}

esp_err_t eth_init_start(void)
{
    ESP_RETURN_ON_FALSE(s_eth_handle == NULL, ESP_ERR_INVALID_STATE, TAG, "already started");

    s_event_group = xEventGroupCreate();
    ESP_RETURN_ON_FALSE(s_event_group != NULL, ESP_ERR_NO_MEM, TAG, "event group create failed");

    // The W5500 driver attaches an ISR on the INT GPIO; the ISR service must exist first.
    esp_err_t isr_err = gpio_install_isr_service(0);
    ESP_RETURN_ON_FALSE(isr_err == ESP_OK || isr_err == ESP_ERR_INVALID_STATE, isr_err, TAG,
                         "GPIO ISR service install failed");

    spi_bus_config_t buscfg = {
        .miso_io_num = CONFIG_ETH_INIT_MISO_GPIO,
        .mosi_io_num = CONFIG_ETH_INIT_MOSI_GPIO,
        .sclk_io_num = CONFIG_ETH_INIT_SCLK_GPIO,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_RETURN_ON_ERROR(spi_bus_initialize(CONFIG_ETH_INIT_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO),
                         TAG, "SPI bus init failed");

    spi_device_interface_config_t spi_devcfg = {
        .mode = 0,
        .clock_speed_hz = CONFIG_ETH_INIT_SPI_CLOCK_MHZ * 1000 * 1000,
        .queue_size = 20,
        .spics_io_num = CONFIG_ETH_INIT_CS_GPIO,
    };

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = CONFIG_ETH_INIT_RST_GPIO;

    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(CONFIG_ETH_INIT_SPI_HOST, &spi_devcfg);
    w5500_config.int_gpio_num = CONFIG_ETH_INIT_INT_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
    ESP_RETURN_ON_FALSE(mac != NULL, ESP_FAIL, TAG, "W5500 MAC init failed");
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_config);
    ESP_RETURN_ON_FALSE(phy != NULL, ESP_FAIL, TAG, "W5500 PHY init failed");

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_RETURN_ON_ERROR(esp_eth_driver_install(&eth_config, &s_eth_handle), TAG, "driver install failed");

    // The W5500 has no burned factory MAC; derive a locally-administered one from the
    // chip's own base MAC so the interface has a stable, valid, unique address.
    uint8_t base_mac[6];
    ESP_RETURN_ON_ERROR(esp_efuse_mac_get_default(base_mac), TAG, "get base MAC failed");
    uint8_t local_mac[6];
    esp_derive_local_mac(local_mac, base_mac);
    ESP_RETURN_ON_ERROR(esp_eth_ioctl(s_eth_handle, ETH_CMD_S_MAC_ADDR, local_mac), TAG, "set MAC failed");

    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_config);
    esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(s_eth_handle);
    ESP_RETURN_ON_ERROR(esp_netif_attach(s_eth_netif, glue), TAG, "netif attach failed");

    ESP_RETURN_ON_ERROR(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL),
                         TAG, "eth event handler register failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL),
                         TAG, "ip event handler register failed");

    if (app_config_get_net_mode() == APP_CONFIG_NET_STATIC) {
        esp_netif_ip_info_t ip_info;
        if (app_config_get_static_ip(&ip_info) == ESP_OK) {
            ESP_RETURN_ON_ERROR(esp_netif_dhcpc_stop(s_eth_netif), TAG, "dhcpc stop failed");
            ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(s_eth_netif, &ip_info), TAG, "set static IP failed");
            ESP_LOGI(TAG, "using static IP:" IPSTR, IP2STR(&ip_info.ip));
            // Static assignment doesn't go through the DHCP client, so no
            // IP_EVENT_ETH_GOT_IP will fire for it - signal readiness here instead.
            xEventGroupSetBits(s_event_group, ETH_INIT_GOT_IP_BIT);
        } else {
            ESP_LOGW(TAG, "net_mode is STATIC but no static IP is configured; falling back to DHCP");
        }
    }

    ESP_RETURN_ON_ERROR(esp_eth_start(s_eth_handle), TAG, "driver start failed");

    esp_err_t mdns_err = mdns_init();
    if (mdns_err == ESP_OK) {
        mdns_hostname_set(MDNS_HOSTNAME);
        mdns_instance_name_set(MDNS_INSTANCE_NAME);
        ESP_LOGI(TAG, "mDNS hostname set: http://%s.local/", MDNS_HOSTNAME);
    } else {
        ESP_LOGW(TAG, "mdns_init failed: %s (device will still be reachable by IP)", esp_err_to_name(mdns_err));
    }

    // A freshly-flashed device boots with its clock at epoch 0, which would
    // make TLS certificate validity checks (notBefore/notAfter) wrong for
    // fw_updater/blocklist_updater's HTTPS fetches. Syncs opportunistically
    // in the background once the network is up; no explicit wait here since
    // both of those callers already wait ~30s for IP via eth_init_wait_for_ip(),
    // which is far longer than SNTP typically needs to complete a first sync.
    esp_sntp_config_t sntp_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_err_t sntp_err = esp_netif_sntp_init(&sntp_config);
    if (sntp_err != ESP_OK) {
        ESP_LOGW(TAG, "esp_netif_sntp_init failed: %s", esp_err_to_name(sntp_err));
    }

    return ESP_OK;
}

esp_netif_t *eth_init_get_netif(void)
{
    return s_eth_netif;
}

bool eth_init_wait_for_ip(TickType_t timeout)
{
    if (s_event_group == NULL) {
        return false;
    }
    EventBits_t bits = xEventGroupWaitBits(s_event_group, ETH_INIT_GOT_IP_BIT, pdFALSE, pdTRUE, timeout);
    return (bits & ETH_INIT_GOT_IP_BIT) != 0;
}
