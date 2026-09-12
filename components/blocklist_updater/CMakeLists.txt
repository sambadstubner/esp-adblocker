idf_component_register(
    SRCS "blocklist_updater.c"
    INCLUDE_DIRS "include"
    REQUIRES app_config bloom_filter sd_storage dns_proxy eth_init
    PRIV_REQUIRES esp_http_client mbedtls esp_partition freertos
)
