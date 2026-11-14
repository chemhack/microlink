idf_component_register(
    SRCS
        "src/wireguard.c"
        "src/wireguardif.c"
        "src/crypto.c"
        "src/wireguard-platform-esp32.c"
        "src/crypto/refc/blake2s.c"
        "src/crypto/refc/chacha20.c"
        "src/crypto/refc/chacha20poly1305.c"
        "src/crypto/refc/poly1305-donna.c"
        "src/crypto/refc/x25519.c"
    INCLUDE_DIRS
        "src"
        "src/crypto/refc"
    REQUIRES
        lwip
        esp_timer
)

# Images for ESP32-P4 v3.x chips also carry an assembly ChaCha20 that uses
# Zbb; crypto.h describes when it runs and enables it on the same terms.
if(CONFIG_IDF_TARGET_ESP32P4 AND NOT CONFIG_ESP32P4_SELECTS_REV_LESS_V3
   AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_sources(${COMPONENT_LIB} PRIVATE "src/crypto/refc/chacha20_esp32p4.S")
endif()

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WIREGUARD_CRYPTO_REFC=1
)

# ESP-IDF projects build at -Og unless they pick another level, and these
# routines run on every tunnelled packet. Build them at -O2 regardless, as
# ESP-IDF does for mbedTLS (which it forces to -Os). Source options come after
# the project's, so this one wins.
set_source_files_properties(
    src/crypto.c
    src/crypto/refc/blake2s.c
    src/crypto/refc/chacha20.c
    src/crypto/refc/chacha20poly1305.c
    src/crypto/refc/poly1305-donna.c
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_OPTIONS "-O2"
)

# Disable stringop-overread warning for x25519.c (false positive in GCC array bounds check)
set_source_files_properties(
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread"
)
