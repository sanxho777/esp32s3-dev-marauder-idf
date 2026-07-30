#include "deauth_detector.h"
#include "state.h"
#include "ieee80211.h"
#include "esp_wifi.h"

static bool s_active = false;
static int64_t s_lastHop = 0;
static const int64_t HOP_INTERVAL_MS = 300;
static const int64_t WINDOW_MS = 2000;
static const uint32_t ALERT_THRESHOLD = 5; // frames within WINDOW_MS

struct TrackEntry {
  std::string attacker;
  std::string victim;
  int64_t windowStart;
  uint32_t count;
};
static TrackEntry s_tracked[16];
static int s_trackedCount = 0;

static TrackEntry *findOrCreate(const std::string &attacker, const std::string &victim) {
  for (int i = 0; i < s_trackedCount; i++) {
    if (s_tracked[i].attacker == attacker && s_tracked[i].victim == victim) return &s_tracked[i];
  }
  if (s_trackedCount < 16) {
    s_tracked[s_trackedCount] = { attacker, victim, nowMs(), 0 };
    return &s_tracked[s_trackedCount++];
  }
  return &s_tracked[0]; // fallback: reuse slot 0 if table full
}

static void IRAM_ATTR widsCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  auto *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  if (dot11Type(p) != TYPE_MGMT) return;
  uint8_t st = dot11Subtype(p);
  if (st != SUBTYPE_DEAUTH && st != SUBTYPE_DISASSOC) return;

  std::string attacker = macToStr(dot11Addr2(p)); // transmitter claiming to be the AP
  std::string victim = macToStr(dot11Addr1(p));
  appState.widsDeauthSeen++;

  int64_t now = nowMs();
  bool shouldAlert = false;
  uint32_t alertCount = 0;
  {
    StateLock lock;
    TrackEntry *e = findOrCreate(attacker, victim);
    if (now - e->windowStart > WINDOW_MS) {
      e->windowStart = now;
      e->count = 0;
    }
    e->count++;
    if (e->count == ALERT_THRESHOLD) {
      shouldAlert = true;
      alertCount = e->count;
      DeauthAlert alert{ attacker, victim, now, alertCount };
      appState.alerts.push_back(alert);
      if (appState.alerts.size() > 100) appState.alerts.erase(appState.alerts.begin());
    }
  }

  if (shouldAlert) {
    appState.log("[wids] possible deauth attack: " + attacker + " -> " + victim +
                 " (" + std::to_string(alertCount) + " frames in " + std::to_string(WINDOW_MS) + "ms)");
    appState.notify();
  }
}

void DeauthDetector::start() {
  appState.mode = OpMode::WIDS_DETECT;
  appState.log("[wids] starting deauth/disassoc monitor (channel hopping)");
  s_trackedCount = 0;
  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&widsCb);
  s_active = true;
  s_lastHop = 0;
}

void DeauthDetector::stop() {
  esp_wifi_set_promiscuous(false);
  s_active = false;
  appState.mode = OpMode::IDLE;
  appState.log("[wids] monitor stopped");
}

bool DeauthDetector::active() { return s_active; }

void DeauthDetector::loopHop() {
  if (!s_active) return;
  if (nowMs() - s_lastHop > HOP_INTERVAL_MS) {
    appState.currentChannel = (appState.currentChannel % 13) + 1;
    esp_wifi_set_channel(appState.currentChannel, WIFI_SECOND_CHAN_NONE);
    s_lastHop = nowMs();
  }
}
