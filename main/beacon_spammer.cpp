#include "beacon_spammer.h"
#include "state.h"
#include "net_globals.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include <cstring>
#include <algorithm>

static bool s_active = false;
static bool s_randomMac = true;
static size_t s_ssidIdx = 0;
static int64_t s_lastSend = 0;
static const int64_t SEND_INTERVAL_MS = 100;

static void randomLocalMac(uint8_t *mac) {
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)esp_random();
  mac[0] = (mac[0] & 0xFE) | 0x02; // locally administered, unicast
}

static int buildBeacon(uint8_t *out, const uint8_t *bssid, const std::string &ssid, int channel) {
  static const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  static const uint8_t RATES[8] = { 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c };

  int i = 0;
  out[i++] = 0x80; out[i++] = 0x00;          // FC: beacon
  out[i++] = 0x00; out[i++] = 0x00;          // duration
  memcpy(out + i, BROADCAST, 6); i += 6;     // addr1: broadcast
  memcpy(out + i, bssid, 6); i += 6;         // addr2: source
  memcpy(out + i, bssid, 6); i += 6;         // addr3: bssid
  out[i++] = 0x00; out[i++] = 0x00;          // seq-ctrl

  memset(out + i, 0, 8); i += 8;             // timestamp (driver-managed, zero ok)
  out[i++] = 0x64; out[i++] = 0x00;          // beacon interval: 100 TU
  out[i++] = 0x21; out[i++] = 0x04;          // capability info: ESS + short slot

  // SSID IE
  uint8_t ssidLen = (uint8_t)std::min((size_t)32, ssid.length());
  out[i++] = 0x00; out[i++] = ssidLen;
  memcpy(out + i, ssid.c_str(), ssidLen); i += ssidLen;

  // Supported rates IE
  out[i++] = 0x01; out[i++] = sizeof(RATES);
  memcpy(out + i, RATES, sizeof(RATES)); i += sizeof(RATES);

  // DS parameter set IE (channel)
  out[i++] = 0x03; out[i++] = 0x01;
  out[i++] = (uint8_t)channel;

  return i;
}

void BeaconSpammer::start(bool randomMac, int channel) {
  bool empty;
  { StateLock lock; empty = appState.beaconSsids.empty(); }
  if (empty) {
    appState.log("[beacon] no SSIDs configured");
    return;
  }
  s_randomMac = randomMac;
  s_ssidIdx = 0;
  WifiApModeAcquire();
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  appState.currentChannel = channel;
  appState.mode = OpMode::BEACON_SPAM;
  s_active = true;
  s_lastSend = 0;
  appState.log("[beacon] spamming SSID list on ch" + std::to_string(channel));
}

void BeaconSpammer::stop() {
  if (!s_active) return;
  s_active = false;
  appState.mode = OpMode::IDLE;
  WifiApModeRelease();
  appState.log("[beacon] spam stopped");
}

bool BeaconSpammer::active() { return s_active; }

void BeaconSpammer::loopSend() {
  if (!s_active) return;
  if (nowMs() - s_lastSend < SEND_INTERVAL_MS) return;
  s_lastSend = nowMs();

  std::string ssid;
  size_t count;
  {
    StateLock lock;
    count = appState.beaconSsids.size();
    if (count == 0) return;
    if (s_ssidIdx >= count) s_ssidIdx = 0;
    ssid = appState.beaconSsids[s_ssidIdx];
  }

  uint8_t bssid[6];
  if (s_randomMac) {
    randomLocalMac(bssid);
  } else {
    uint32_t h = 0;
    for (char c : ssid) h = h * 31 + (uint8_t)c;
    bssid[0] = 0x02;
    memcpy(bssid + 1, &h, 4);
    bssid[5] = (uint8_t)s_ssidIdx;
  }

  uint8_t frame[128];
  int len = buildBeacon(frame, bssid, ssid, appState.currentChannel);
  esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);

  s_ssidIdx = (s_ssidIdx + 1) % count;
}
