#pragma once
#include "esp_netif.h"

// The softAP netif, created once in main.cpp's app_main() and used by
// evil_portal.cpp to look up our own IP for the captive DNS responder.
extern esp_netif_t *g_apNetif;

// The device sits in WIFI_MODE_STA at rest -- nothing needs to join our AP
// for control anymore (that's over USB serial), and AP scanning is the
// single best-tested code path in ESP-IDF only when nothing else is
// contending for the radio. Beacon spam, the deauth module, and evil portal
// are the only three things that transmit via WIFI_IF_AP, so they're the
// only three that need AP mode at all, and only for as long as they're
// actually running. Call Acquire() in start() and Release() in stop() --
// they're ref-counted so overlapping users don't step on each other.
void WifiApModeAcquire();
void WifiApModeRelease();
