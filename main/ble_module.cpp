#include "ble_module.h"
#include "state.h"

#include "esp_log.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include <cstdio>
#include <cstring>

static const char *TAG = "ble_module";
static uint8_t s_ownAddrType;
static bool s_scanActive = false;
static bool s_spamActive = false;

// --- helpers ---------------------------------------------------------------

static std::string addrToStr(const ble_addr_t &addr) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           addr.val[5], addr.val[4], addr.val[3], addr.val[2], addr.val[1], addr.val[0]);
  return std::string(buf);
}

static void upsertBleDevice(const ble_addr_t &addr, int rssi, const struct ble_hs_adv_fields &fields) {
  std::string address = addrToStr(addr);
  std::string name;
  if (fields.name != nullptr && fields.name_len > 0) {
    name.assign((const char *)fields.name, fields.name_len);
  }

  bool isNew = false;
  {
    StateLock lock;
    bool found = false;
    for (auto &d : appState.bleDevices) {
      if (d.address == address) {
        d.rssi = rssi;
        d.lastSeenMs = nowMs();
        if (!name.empty()) d.name = name;
        found = true;
        break;
      }
    }
    if (!found) {
      BLEDeviceInfo info;
      info.address = address;
      info.name = name;
      info.rssi = rssi;
      info.lastSeenMs = nowMs();
      appState.bleDevices.push_back(info);
      if (appState.bleDevices.size() > 200) appState.bleDevices.erase(appState.bleDevices.begin());
      isNew = true;
    }
  }
  if (isNew) appState.notify();
}

// --- scan --------------------------------------------------------------

static int scanEventCb(struct ble_gap_event *event, void *arg) {
  if (event->type == BLE_GAP_EVENT_DISC) {
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data) == 0) {
      upsertBleDevice(event->disc.addr, event->disc.rssi, fields);
    }
  }
  return 0;
}

void BleModule::startScan() {
  { StateLock lock; appState.bleDevices.clear(); }
  appState.mode = OpMode::BLE_SCAN;

  struct ble_gap_disc_params disc_params = {};
  disc_params.filter_duplicates = 0; // keep updating RSSI on repeat sightings
  disc_params.passive = 0;           // active scan picks up scan-response names too
  disc_params.itvl = 0;
  disc_params.window = 0;
  disc_params.filter_policy = 0;
  disc_params.limited = 0;

  int rc = ble_gap_disc(s_ownAddrType, BLE_HS_FOREVER, &disc_params, scanEventCb, nullptr);
  if (rc != 0) {
    appState.log("[ble] scan start failed rc=" + std::to_string(rc));
    return;
  }
  s_scanActive = true;
  appState.log("[ble] scan started");
}

void BleModule::stopScan() {
  ble_gap_disc_cancel();
  s_scanActive = false;
  appState.mode = OpMode::IDLE;
  size_t n;
  { StateLock lock; n = appState.bleDevices.size(); }
  appState.log("[ble] scan stopped, " + std::to_string(n) + " devices seen");
}

bool BleModule::scanActive() { return s_scanActive; }

// --- advertisement spam ---------------------------------------------------

// Illustrative advertisement payload shapes in the style of "BLE spam" novelty
// tools (e.g. Flipper Zero apps) that trigger iOS/Android pairing popups.
// These carry no exploit payload -- they just mimic proximity-pairing ads.
// Byte-exact popup behavior varies by OS version; tune against a known-good
// capture (e.g. via the sniffer module) if you need reliable popups.
static const uint8_t PAYLOAD_APPLE_AIRPODS[] = {
  0x07, 0x19, 0x07, 0x00, 0x30, 0x0E, 0x83, 0x69, 0x66, 0x2A, 0x8A, 0x21, 0x50, 0x03, 0x02, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t PAYLOAD_ANDROID_FASTPAIR[] = {
  0x03, 0x03, 0x2C, 0xFE
};

struct SpamPayload { const uint8_t *data; size_t len; };
static const SpamPayload PAYLOADS[] = {
  { PAYLOAD_APPLE_AIRPODS, sizeof(PAYLOAD_APPLE_AIRPODS) },
  { PAYLOAD_ANDROID_FASTPAIR, sizeof(PAYLOAD_ANDROID_FASTPAIR) },
};
static const size_t PAYLOAD_COUNT = sizeof(PAYLOADS) / sizeof(PAYLOADS[0]);
static size_t s_payloadIdx = 0;
static int64_t s_lastCycle = 0;
static const int64_t CYCLE_MS = 300;

static int advEventCb(struct ble_gap_event *event, void *arg) {
  return 0; // non-connectable broadcaster: nothing to react to
}

static void advertiseOne(const SpamPayload &p) {
  ble_gap_adv_stop(); // no-op / harmless if not currently advertising

  int rc = ble_gap_adv_set_data(p.data, (int)p.len);
  if (rc != 0) {
    ESP_LOGW(TAG, "adv_set_data rc=%d", rc);
    return;
  }

  struct ble_gap_adv_params adv_params = {};
  adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

  rc = ble_gap_adv_start(s_ownAddrType, nullptr, BLE_HS_FOREVER, &adv_params, advEventCb, nullptr);
  if (rc != 0) {
    ESP_LOGW(TAG, "adv_start rc=%d", rc);
  }
}

void BleModule::startSpam() {
  appState.mode = OpMode::BLE_SPAM;
  s_payloadIdx = 0;
  s_spamActive = true;
  s_lastCycle = 0;
  appState.log("[ble] advertisement spam started");
}

void BleModule::stopSpam() {
  ble_gap_adv_stop();
  s_spamActive = false;
  appState.mode = OpMode::IDLE;
  appState.log("[ble] advertisement spam stopped");
}

bool BleModule::spamActive() { return s_spamActive; }

void BleModule::loopSpam() {
  if (!s_spamActive) return;
  if (nowMs() - s_lastCycle < CYCLE_MS) return;
  s_lastCycle = nowMs();

  advertiseOne(PAYLOADS[s_payloadIdx]);
  s_payloadIdx = (s_payloadIdx + 1) % PAYLOAD_COUNT;
}

// --- host lifecycle --------------------------------------------------------

static void onSync(void) {
  int rc = ble_hs_id_infer_auto(0, &s_ownAddrType);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_hs_id_infer_auto failed rc=%d", rc);
    return;
  }
  ESP_LOGI(TAG, "NimBLE host synced, own_addr_type=%d", s_ownAddrType);
}

static void onReset(int reason) {
  ESP_LOGW(TAG, "NimBLE host reset, reason=%d", reason);
}

static void hostTask(void *param) {
  nimble_port_run(); // returns only when nimble_port_stop() is called
  nimble_port_freertos_deinit();
}

void BleModule::begin() {
  esp_err_t ret = nimble_port_init();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "nimble_port_init failed: %d", ret);
    return;
  }

  ble_hs_cfg.sync_cb = onSync;
  ble_hs_cfg.reset_cb = onReset;

  ble_svc_gap_init();
  ble_svc_gap_device_name_set("esp32-marauder");

  nimble_port_freertos_init(hostTask);
}
