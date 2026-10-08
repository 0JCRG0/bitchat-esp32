cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(bitchat_esp32c6)

target_sources(app PRIVATE 
    src/main.c
    src/bitchat_crypto.c
    src/bitchat_wire.c
    src/noise_xx.c
    src/gesture.c
    src/alert_retry.c
    src/alertam.c
    src/alertam_store.c
    src/alertam_record.c
    lib/monocypher/monocypher.c
    lib/monocypher/monocypher-ed25519.c
)
