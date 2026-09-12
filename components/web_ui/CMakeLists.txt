idf_component_register(
    SRCS "web_ui.c"
    INCLUDE_DIRS "include"
    REQUIRES app_config dns_proxy blocklist_updater fw_updater sd_storage eth_init
    PRIV_REQUIRES esp_http_server json esp_app_format esp_netif esp_timer freertos
    EMBED_TXTFILES "html/index.html"
)
