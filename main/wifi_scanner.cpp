#include "wifi_scanner.h"
#include "state.h"
#include "ieee80211.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static bool s_stationSniffActive = false;
static int64_t s_lastHop = 0;
static const int64_t HOP_INTERVAL_MS = 400;

// --- AP scan -------------------------------------------------------------

// esp_wifi_scan_start(..., true /* blocking */) run from a dedicated task
// was found to hang the device hard enough to stall the USB peripheral
// itself (idf_monitor's own writes to the port started timing out -- not
// an application-level freeze, the WiFi driver wedged badly enough to take
// interrupts down with it). Switched to the standard non-blocking + event
// pattern instead: esp_wifi_scan_start(..., false) returns immediately, and
// WIFI_EVENT_SCAN_DONE (delivered on the default event loop's own task,
// which is already running and unrelated to our own tasks) is what
// actually harvests results. This is a materially different code path
// inside the driver, not just a cosmetic change.
static void onScanDone(void *arg, esp_event_base_t base, int32_t id, void *data) {
  auto *info = (wifi_event_sta_scan_done_t *)data;
  if (info->status != 0) {
    appState.log("[wifi] scan failed (status=" + std::to_string(info->status) + ")");
    appState.mode = OpMode::IDLE;
    return;
  }

  uint16_t num = 0;
  esp_wifi_scan_get_ap_num(&num);
  if (num > 64) num = 64;
  std::vector<wifi_ap_record_t> records(num);
  esp_wifi_scan_get_ap_records(&num, records.data());

  {
    StateLock lock;
    appState.aps.clear();
    for (uint16_t i = 0; i < num; i++) {
      APInfo apInfo;
      const wifi_ap_record_t &r = records[i];
      apInfo.ssid = r.ssid[0] ? std::string((const char *)r.ssid) : "<hidden>";
      apInfo.bssid = macToStr(r.bssid);
      apInfo.channel = r.primary;
      apInfo.rssi = r.rssi;
      apInfo.secure = r.authmode != WIFI_AUTH_OPEN;
      appState.aps.push_back(apInfo);
    }
  }
  appState.mode = OpMode::IDLE;
  appState.log("[wifi] AP scan complete: " + std::to_string(num) + " networks");
  appState.notify();
}

void WifiScanner::startApScan() {
  static bool handlerRegistered = false;
  if (!handlerRegistered) {
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &onScanDone, nullptr);
    handlerRegistered = true;
  }

  appState.mode = OpMode::WIFI_SCAN;
  appState.log("[wifi] starting AP scan");

  wifi_scan_config_t cfg = {};
  cfg.show_hidden = true;
  esp_err_t err = esp_wifi_scan_start(&cfg, false /* non-blocking */);
  if (err != ESP_OK) {
    appState.log("[wifi] scan failed to start: " + std::string(esp_err_to_name(err)));
    appState.mode = OpMode::IDLE;
  }
}

// --- Passive station discovery --------------------------------------------

static bool macKnownAp(const uint8_t *mac) {
  std::string s = macToStr(mac);
  StateLock lock;
  for (auto &ap : appState.aps) {
    if (ap.bssid == s) return true;
  }
  return false;
}

static void upsertStation(const uint8_t *mac, const uint8_t *bssid, int rssi) {
  if (mac[0] & 0x01) return; // ignore broadcast/multicast source addrs
  std::string macStr = macToStr(mac);
  bool isNew = false;
  {
    StateLock lock;
    bool found = false;
    for (auto &st : appState.stations) {
      if (st.mac == macStr) {
        st.rssi = rssi;
        st.lastSeenMs = nowMs();
        if (bssid) st.assocBssid = macToStr(bssid);
        found = true;
        break;
      }
    }
    if (!found) {
      StationInfo st;
      st.mac = macStr;
      st.assocBssid = bssid ? macToStr(bssid) : "";
      st.rssi = rssi;
      st.lastSeenMs = nowMs();
      appState.stations.push_back(st);
      isNew = true;
    }
  }
  if (isNew) {
    appState.log("[wifi] station seen: " + macStr);
    appState.notify();
  }
}

static void IRAM_ATTR stationSniffCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  auto *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  int rssi = pkt->rx_ctrl.rssi;
  uint8_t t = dot11Type(p);
  uint8_t st = dot11Subtype(p);

  if (t == TYPE_MGMT && st == SUBTYPE_PROBE_REQ) {
    upsertStation(dot11Addr2(p), nullptr, rssi);
  } else if (t == TYPE_DATA) {
    const uint8_t *a1 = dot11Addr1(p);
    const uint8_t *a2 = dot11Addr2(p);
    if (macKnownAp(a1) && !macKnownAp(a2)) {
      upsertStation(a2, a1, rssi);
    } else if (macKnownAp(a2) && !macKnownAp(a1)) {
      upsertStation(a1, a2, rssi);
    }
  }
}

void WifiScanner::startStationSniff() {
  appState.log("[wifi] starting passive station discovery (channel hopping)");
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&stationSniffCb);
  s_stationSniffActive = true;
  s_lastHop = 0;
}

void WifiScanner::stopStationSniff() {
  esp_wifi_set_promiscuous(false);
  s_stationSniffActive = false;
  appState.log("[wifi] station discovery stopped");
}

bool WifiScanner::stationSniffActive() { return s_stationSniffActive; }

void WifiScanner::loopStationSniff() {
  if (!s_stationSniffActive) return;
  if (nowMs() - s_lastHop > HOP_INTERVAL_MS) {
    appState.currentChannel = (appState.currentChannel % 13) + 1;
    esp_wifi_set_channel(appState.currentChannel, WIFI_SECOND_CHAN_NONE);
    s_lastHop = nowMs();
  }
}
