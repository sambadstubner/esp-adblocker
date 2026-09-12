idf_component_register(
    SRCS "fw_updater.c"
    INCLUDE_DIRS "include"
    REQUIRES eth_init
    PRIV_REQUIRES esp_https_ota app_update mbedtls freertos
)
