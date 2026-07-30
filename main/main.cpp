#include <cstring>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "nvs_flash.h"

#include "state.h"
#include "net_globals.h"
#include "sd_card.h"
#include "wifi_scanner.h"
#include "deauth_detector.h"
#include "deauth_attacker.h"
#include "beacon_spammer.h"
#include "sniffer.h"
#include "ble_module.h"
#include "evil_portal.h"
#include "serial_control.h"

// --- Adjust these to your preference -------------------------------------
// This AP is no longer used for control (that's over USB serial now -- see
// serial_control.cpp). It's brought up on demand by WifiApModeAcquire() for
// whichever of beacon spam / deauth / evil portal is currently running, and
// torn back down to STA-only the moment none of them need it -- see
// net_globals.h for why.
#define MARAUDER_AP_SSID     "ESP32-Marauder"
#define MARAUDER_AP_PASSWORD "marauder123"   // WPA2 min 8 chars, or "" for open
#define MARAUDER_AP_CHANNEL  1
#define MARAUDER_AP_MAX_CONN 4
// --------------------------------------------------------------------------

static const char *TAG = "main";
esp_netif_t *g_apNetif = nullptr;
static int s_apRefCount = 0;

static void configureDefaultAp() {
  wifi_config_t wifi_config = {};
  strncpy((char *)wifi_config.ap.ssid, MARAUDER_AP_SSID, sizeof(wifi_config.ap.ssid));
  wifi_config.ap.ssid_len = strlen(MARAUDER_AP_SSID);
  wifi_config.ap.channel = MARAUDER_AP_CHANNEL;
  strncpy((char *)wifi_config.ap.password, MARAUDER_AP_PASSWORD, sizeof(wifi_config.ap.password));
  wifi_config.ap.max_connection = MARAUDER_AP_MAX_CONN;
  wifi_config.ap.authmode = strlen(MARAUDER_AP_PASSWORD) >= 8 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
}

void WifiApModeAcquire() {
  if (s_apRefCount++ == 0) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    configureDefaultAp();
    ESP_LOGI(TAG, "AP interface enabled");
  }
}

void WifiApModeRelease() {
  if (s_apRefCount > 0 && --s_apRefCount == 0) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_LOGI(TAG, "AP interface disabled, back to STA-only");
  }
}

static void wifiEventHandler(void *arg, esp_event_base_t base, int32_t id, void *data) {
  if (id == WIFI_EVENT_AP_STACONNECTED) {
    auto *e = (wifi_event_ap_staconnected_t *)data;
    ESP_LOGI(TAG, "client " MACSTR " connected, aid=%d", MAC2STR(e->mac), e->aid);
  } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
    auto *e = (wifi_event_ap_stadisconnected_t *)data;
    ESP_LOGI(TAG, "client " MACSTR " left, aid=%d", MAC2STR(e->mac), e->aid);
  }
}

static void initWifi() {
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  g_apNetif = esp_netif_create_default_wifi_ap();
  esp_netif_create_default_wifi_sta();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifiEventHandler, nullptr, nullptr));

  // STA-only at rest. AP scanning worked reliably back when this project
  // briefly toggled into APSTA around each scan and dropped straight back
  // out -- it started freezing (hard enough to stall the USB-Serial-JTAG
  // peripheral itself) only after this was changed to boot permanently into
  // APSTA with the AP continuously beaconing from power-on. That's the one
  // variable that changed between "worked" and "hangs", so the fix is to
  // stop leaving AP mode on indefinitely: stay STA-only except for the
  // brief, on-demand windows WifiApModeAcquire()/Release() open for beacon
  // spam / deauth / evil portal.
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "WiFi started in STA-only mode (AP enabled on demand for beacon spam / deauth / evil portal)");
}

// Replaces Arduino's loop(): paces every module's periodic work
// (channel hopping, burst sends, pcap flush bookkeeping, BLE adv cycling).
static void tickTask(void *arg) {
  while (true) {
    WifiScanner::loopStationSniff();
    DeauthDetector::loopHop();
    DeauthAttacker::loopSend();
    BeaconSpammer::loopSend();
    Sniffer::loopHop();
    BleModule::loopSpam();
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

extern "C" void app_main(void) {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  ESP_LOGI(TAG, "ESP32-S3 Marauder starting (USB-serial control)");

  appState.sdCardOk = SdCard::mount();

  initWifi();
  BleModule::begin();
  SerialControl::begin();

  xTaskCreate(tickTask, "tick", 4096, nullptr, 5, nullptr);

  appState.log("[boot] ready. Control this device from the desktop app over USB serial.");
}
