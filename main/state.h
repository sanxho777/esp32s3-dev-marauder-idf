#pragma once
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

enum class OpMode {
  IDLE,
  WIFI_SCAN,
  WIDS_DETECT,
  DEAUTH_ATTACK,
  BEACON_SPAM,
  SNIFFER_PCAP,
  BLE_SCAN,
  BLE_SPAM,
  EVIL_PORTAL
};

struct APInfo {
  std::string ssid;
  std::string bssid;
  int channel;
  int rssi;
  bool secure;
};

struct StationInfo {
  std::string mac;
  std::string assocBssid;
  int rssi;
  int64_t lastSeenMs;
};

struct DeauthAlert {
  std::string attackerMac;
  std::string victimMac;
  int64_t timestamp;
  uint32_t count;
};

struct BLEDeviceInfo {
  std::string address;
  std::string name;
  int rssi;
  int64_t lastSeenMs;
};

// Guards every AppState collection below. Needed because promiscuous WiFi
// callbacks, the NimBLE host task, the tick task and httpd handler threads
// all touch this concurrently (unlike the single-threaded Arduino loop()).
class StateLock {
public:
  StateLock();
  ~StateLock();
private:
  StateLock(const StateLock &) = delete;
};

struct AppState {
  OpMode mode = OpMode::IDLE;

  std::vector<APInfo> aps;
  std::vector<StationInfo> stations;
  std::vector<DeauthAlert> alerts;
  std::vector<BLEDeviceInfo> bleDevices;
  std::vector<std::string> beaconSsids;

  int targetApIndex = -1;
  int currentChannel = 1;

  bool sdCardOk = false;
  std::string pcapFilename;
  uint32_t pcapPacketCount = 0;
  uint32_t deauthFramesSent = 0;
  uint32_t widsDeauthSeen = 0;

  std::function<void(const std::string &)> onLog = nullptr;
  std::function<void()> onStateChanged = nullptr;

  void log(const std::string &msg);
  void notify();
  const char *modeName() const;
};

extern AppState appState;
extern SemaphoreHandle_t g_stateMutex;

std::string macToStr(const uint8_t *mac);
void strToMac(const std::string &s, uint8_t *mac);
int64_t nowMs();
