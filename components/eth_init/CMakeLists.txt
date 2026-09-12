idf_component_register(
    SRCS "eth_init.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_eth esp_netif esp_event
    PRIV_REQUIRES esp_driver_spi esp_driver_gpio app_config
)
