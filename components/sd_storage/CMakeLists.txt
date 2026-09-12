idf_component_register(
    SRCS "sd_storage.c"
    INCLUDE_DIRS "include"
    REQUIRES fatfs sdmmc app_config
    PRIV_REQUIRES esp_driver_sdspi esp_driver_spi
)
