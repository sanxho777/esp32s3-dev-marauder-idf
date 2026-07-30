#include "serial_control.h"
#include "state.h"
#include "wifi_scanner.h"
#include "deauth_detector.h"
#include "deauth_attacker.h"
#include "beacon_spammer.h"
#include "sniffer.h"
#include "ble_module.h"
#include "evil_portal.h"

#include "cJSON.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <cstdio>
#include <cstring>

static const char *TAG_PREFIX = "#MRDR#";

// --- outgoing: log / status -------------------------------------------------

static void emit(cJSON *doc) {
  char *out = cJSON_PrintUnformatted(doc);
  if (out) {
    fputs(TAG_PREFIX, stdout);
    fputs(out, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    cJSON_free(out);
  }
  cJSON_Delete(doc);
}

static void emitLog(const std::string &msg) {
  cJSON *doc = cJSON_CreateObject();
  cJSON_AddStringToObject(doc, "type", "log");
  cJSON_AddStringToObject(doc, "msg", msg.c_str());
  emit(doc);
}

static void emitStatus() {
  StateLock lock;
  cJSON *doc = cJSON_CreateObject();
  cJSON_AddStringToObject(doc, "type", "status");
  cJSON_AddStringToObject(doc, "mode", appState.modeName());
  cJSON_AddNumberToObject(doc, "channel", appState.currentChannel);
  cJSON_AddBoolToObject(doc, "sdCard", appState.sdCardOk);
  cJSON_AddStringToObject(doc, "pcapFile", appState.pcapFilename.c_str());
  cJSON_AddNumberToObject(doc, "pcapPackets", appState.pcapPacketCount);
  cJSON_AddNumberToObject(doc, "deauthSent", appState.deauthFramesSent);
  cJSON_AddNumberToObject(doc, "widsSeen", appState.widsDeauthSeen);

  cJSON *aps = cJSON_CreateArray();
  for (auto &ap : appState.aps) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ssid", ap.ssid.c_str());
    cJSON_AddStringToObject(o, "bssid", ap.bssid.c_str());
    cJSON_AddNumberToObject(o, "channel", ap.channel);
    cJSON_AddNumberToObject(o, "rssi", ap.rssi);
    cJSON_AddBoolToObject(o, "secure", ap.secure);
    cJSON_AddItemToArray(aps, o);
  }
  cJSON_AddItemToObject(doc, "aps", aps);

  cJSON *stations = cJSON_CreateArray();
  for (auto &st : appState.stations) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "mac", st.mac.c_str());
    cJSON_AddStringToObject(o, "ap", st.assocBssid.c_str());
    cJSON_AddNumberToObject(o, "rssi", st.rssi);
    cJSON_AddItemToArray(stations, o);
  }
  cJSON_AddItemToObject(doc, "stations", stations);

  cJSON *alerts = cJSON_CreateArray();
  for (auto &a : appState.alerts) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "attacker", a.attackerMac.c_str());
    cJSON_AddStringToObject(o, "victim", a.victimMac.c_str());
    cJSON_AddNumberToObject(o, "count", a.count);
    cJSON_AddNumberToObject(o, "t", (double)a.timestamp);
    cJSON_AddItemToArray(alerts, o);
  }
  cJSON_AddItemToObject(doc, "alerts", alerts);

  cJSON *ble = cJSON_CreateArray();
  for (auto &d : appState.bleDevices) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "address", d.address.c_str());
    cJSON_AddStringToObject(o, "name", d.name.c_str());
    cJSON_AddNumberToObject(o, "rssi", d.rssi);
    cJSON_AddItemToArray(ble, o);
  }
  cJSON_AddItemToObject(doc, "ble", ble);

  emit(doc);
}

// --- incoming: command dispatch ---------------------------------------------

static std::string jsonStr(cJSON *obj, const char *key, const std::string &def = "") {
  cJSON *v = cJSON_GetObjectItem(obj, key);
  return cJSON_IsString(v) ? std::string(v->valuestring) : def;
}
static int jsonInt(cJSON *obj, const char *key, int def = 0) {
  cJSON *v = cJSON_GetObjectItem(obj, key);
  return cJSON_IsNumber(v) ? v->valueint : def;
}
static bool jsonBool(cJSON *obj, const char *key, bool def = false) {
  cJSON *v = cJSON_GetObjectItem(obj, key);
  return cJSON_IsBool(v) ? cJSON_IsTrue(v) : def;
}

// emitStatus() builds cJSON trees for every list in appState (potentially
// dozens of APs/stations/BLE devices) and can run deep. Calling it directly
// from whatever context triggered a state change -- the WiFi driver task on
// a promiscuous RX callback, the NimBLE host task, apScanTask mid-WiFi-scan,
// commandTask -- means borrowing stack headroom none of those tasks were
// sized for. requestStatus() is the only thing any of those call: it just
// sets a flag. The actual serialization happens in statusTask, which has
// nothing else to do and a stack sized for exactly this.
static volatile bool s_statusDirty = false;
static void requestStatus() { s_statusDirty = true; }

static void dispatch(cJSON *obj) {
  std::string cmd = jsonStr(obj, "cmd");
  if (cmd.empty()) return;

  if (cmd == "status") {
    requestStatus();
  } else if (cmd == "wifi_scan_start") {
    WifiScanner::startApScan();
  } else if (cmd == "wifi_stations_start") {
    WifiScanner::startStationSniff();
  } else if (cmd == "wifi_stations_stop") {
    WifiScanner::stopStationSniff();
  } else if (cmd == "wids_start") {
    DeauthDetector::start();
  } else if (cmd == "wids_stop") {
    DeauthDetector::stop();
  } else if (cmd == "deauth_start") {
    int apIndex = jsonInt(obj, "apIndex", -1);
    std::string client = jsonStr(obj, "client");
    uint32_t burst = (uint32_t)jsonInt(obj, "burst", 5);
    DeauthAttacker::start(apIndex, client, burst);
  } else if (cmd == "deauth_stop") {
    DeauthAttacker::stop();
  } else if (cmd == "beacon_ssids") {
    cJSON *arr = cJSON_GetObjectItem(obj, "ssids");
    if (cJSON_IsArray(arr)) {
      StateLock lock;
      appState.beaconSsids.clear();
      cJSON *item;
      cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsString(item)) appState.beaconSsids.push_back(item->valuestring);
      }
    }
  } else if (cmd == "beacon_start") {
    bool randomMac = jsonBool(obj, "randomMac", true);
    int channel = jsonInt(obj, "channel", 1);
    BeaconSpammer::start(randomMac, channel);
  } else if (cmd == "beacon_stop") {
    BeaconSpammer::stop();
  } else if (cmd == "sniffer_start") {
    int channel = jsonInt(obj, "channel", 0);
    Sniffer::start(channel);
  } else if (cmd == "sniffer_stop") {
    Sniffer::stop();
  } else if (cmd == "ble_scan_start") {
    BleModule::startScan();
  } else if (cmd == "ble_scan_stop") {
    BleModule::stopScan();
  } else if (cmd == "ble_spam_start") {
    BleModule::startSpam();
  } else if (cmd == "ble_spam_stop") {
    BleModule::stopSpam();
  } else if (cmd == "portal_start") {
    std::string ssid = jsonStr(obj, "ssid", "Free WiFi");
    std::string html = jsonStr(obj, "html");
    EvilPortal::start(ssid, html);
  } else if (cmd == "portal_stop") {
    EvilPortal::stop();
  } else {
    emitLog("[serial] unknown command: " + cmd);
    return;
  }

  requestStatus(); // every command that changes state gets a refresh
}

static void statusTask(void *arg) {
  while (true) {
    if (s_statusDirty) {
      s_statusDirty = false;
      emitStatus();
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

static void commandTask(void *arg) {
  char line[1024];
  while (true) {
    if (!fgets(line, sizeof(line), stdin)) {
      vTaskDelay(pdMS_TO_TICKS(50));
      continue;
    }
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
    if (len == 0) continue;

    cJSON *obj = cJSON_Parse(line);
    if (obj) {
      dispatch(obj);
      cJSON_Delete(obj);
    }
  }
}

void SerialControl::begin() {
  appState.onLog = emitLog; // small/cheap, fine to run on the caller's own stack
  appState.onStateChanged = requestStatus; // just sets a flag -- see statusTask
  xTaskCreate(commandTask, "serial_ctl", 4096, nullptr, 5, nullptr);
  xTaskCreate(statusTask, "status_emit", 8192, nullptr, 5, nullptr);
}
