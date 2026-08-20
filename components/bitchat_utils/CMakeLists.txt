idf_component_register(SRCS "bitchat_time.c"
                      INCLUDE_DIRS "include"
                      REQUIRES nvs_flash esp_timer)

string(TIMESTAMP HBIT_BUILD_EPOCH_SECONDS "%s" UTC)
target_compile_definitions(
    ${COMPONENT_LIB}
    PRIVATE HBIT_BUILD_EPOCH_SECONDS=${HBIT_BUILD_EPOCH_SECONDS}ULL
)
