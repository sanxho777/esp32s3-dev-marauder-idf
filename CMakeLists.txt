cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Lets our own ieee80211_raw_frame_sanity_check() (main/deauth_attacker.cpp)
# win over libnet80211.a's copy of the same symbol at final link time --
# see main/CMakeLists.txt and deauth_attacker.cpp for the full story.
idf_build_set_property(LINK_OPTIONS "-Wl,--allow-multiple-definition" APPEND)
project(esp32_marauder_idf)
