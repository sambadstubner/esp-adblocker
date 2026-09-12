idf_component_register(
    SRCS "app_main.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES eth_init sd_storage app_config nvs_flash esp_netif esp_event dns_proxy fw_updater blocklist_updater web_ui freertos
)
