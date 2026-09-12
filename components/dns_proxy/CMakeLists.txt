# blocklist/bloom.bin is Phase 4 scaffolding: a filter compiled directly into
# the firmware image so blocking logic can be built and tested before Phase 6
# adds the real flash-partition + HTTPS-fetch + A/B-swap update mechanism.
idf_component_register(
    SRCS "dns_proxy.c" "dns_wire.c"
    INCLUDE_DIRS "include"
    REQUIRES app_config bloom_filter sd_storage
    PRIV_REQUIRES freertos esp_timer lwip
    EMBED_FILES "blocklist/bloom.bin"
)
