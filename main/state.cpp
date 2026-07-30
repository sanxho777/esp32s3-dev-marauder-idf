#include "state.h"
#include <cstdio>
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "state";

AppState appState;
SemaphoreHandle_t g_stateMutex = xSemaphoreCreateRecursiveMutex();

StateLock::StateLock() { xSemaphoreTakeRecursive(g_stateMutex, portMAX_DELAY); }
StateLock::~StateLock() { xSemaphoreGiveRecursive(g_stateMutex); }

void AppState::log(const std::string &msg) {
  ESP_LOGI(TAG, "%s", msg.c_str());
  if (onLog) onLog(msg);
}

void AppState::notify() {
  // notify() gets called once per newly-discovered station/AP/BLE device,
  // and each call re-serializes the FULL current lists. Left unthrottled, a
  // discovery burst (e.g. station-discovery hitting a busy channel) fires
  // a growing snapshot on every single event -- total bytes sent grows
  // roughly with events*current_list_size. On the receiving end that shows
  // up as the desktop app locking up while it works through a backlog of
  // ever-bigger status messages. Coalesce to at most ~6/sec; the tick task
  // and normal traffic are more than enough for the UI to look live.
  static int64_t s_lastNotifyMs = 0;
  int64_t t = nowMs();
  if (t - s_lastNotifyMs < 150) return;
  s_lastNotifyMs = t;
  if (onStateChanged) onStateChanged();
}

const char *AppState::modeName() const {
  switch (mode) {
    case OpMode::IDLE: return "idle";
    case OpMode::WIFI_SCAN: return "wifi_scan";
    case OpMode::WIDS_DETECT: return "wids_detect";
    case OpMode::DEAUTH_ATTACK: return "deauth_attack";
    case OpMode::BEACON_SPAM: return "beacon_spam";
    case OpMode::SNIFFER_PCAP: return "sniffer_pcap";
    case OpMode::BLE_SCAN: return "ble_scan";
    case OpMode::BLE_SPAM: return "ble_spam";
    case OpMode::EVIL_PORTAL: return "evil_portal";
  }
  return "idle";
}

std::string macToStr(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

void strToMac(const std::string &s, uint8_t *mac) {
  unsigned int vals[6] = {0, 0, 0, 0, 0, 0};
  sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x",
         &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)vals[i];
}

int64_t nowMs() {
  return esp_timer_get_time() / 1000;
}
