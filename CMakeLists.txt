idf_component_register(SRCS "src/pagekite_tunnel.c"
    INCLUDE_DIRS "include" PRIV_INCLUDE_DIRS "src"
    REQUIRES esp_common
    PRIV_REQUIRES esp-tls esp_http_client mbedtls esp_timer esp_system lwip freertos)
