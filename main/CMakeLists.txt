idf_component_register(
    SRCS
        "main.cpp"
        "state.cpp"
        "pcap_writer.cpp"
        "sd_card.cpp"
        "wifi_scanner.cpp"
        "deauth_detector.cpp"
        "deauth_attacker.cpp"
        "beacon_spammer.cpp"
        "sniffer.cpp"
        "ble_module.cpp"
        "dns_server.cpp"
        "evil_portal.cpp"
        "serial_control.cpp"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        esp_http_server
        fatfs
        sdmmc
        driver
        esp_timer
        vfs
        bt
        lwip
        esp_hw_support
        esp_system
)
# cJSON comes in via the component manager -- see idf_component.yml.
# No explicit REQUIRES needed; the manifest wires it in automatically
# (matches examples/protocols/http_server/restful_server upstream).

# The -Wl,--allow-multiple-definition flag that lets our own
# ieee80211_raw_frame_sanity_check() (deauth_attacker.cpp) override
# libnet80211.a's copy lives in the top-level CMakeLists.txt, not here --
# target_link_options() on a component's static library target doesn't
# propagate to the final app .elf link step in ESP-IDF's build system, only
# idf_build_set_property(LINK_OPTIONS ...) at the top level actually does.
