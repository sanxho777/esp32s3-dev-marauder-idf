#include "sniffer.h"
#include "state.h"
#include "pcap_writer.h"
#include "sd_card.h"
#include "esp_wifi.h"
#include <sys/stat.h>
#include <cstdio>

static bool s_active = false;
static bool s_hopping = false;
static int64_t s_lastHop = 0;
static const int64_t HOP_INTERVAL_MS = 400;
static PcapWriter s_pcap;

static void IRAM_ATTR snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  auto *pkt = (wifi_promiscuous_pkt_t *)buf;
  if (!s_pcap.isOpen()) return;
  s_pcap.writePacket(pkt->rx_ctrl.timestamp, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi,
                      pkt->payload, pkt->rx_ctrl.sig_len);
}

static std::string nextFilename() {
  char buf[64];
  struct stat st;
  int idx = 1;
  do {
    snprintf(buf, sizeof(buf), SD_MOUNT_POINT "/pcaps/capture_%04d.pcap", idx++);
  } while (stat(buf, &st) == 0 && idx < 9999);
  return std::string(buf);
}

void Sniffer::start(int channel) {
  if (!appState.sdCardOk) {
    appState.log("[sniffer] SD card not available, cannot start capture");
    return;
  }
  std::string fname = nextFilename();
  if (!s_pcap.begin(fname)) {
    appState.log("[sniffer] failed to open " + fname + " for writing");
    return;
  }
  appState.pcapFilename = fname;
  appState.pcapPacketCount = 0;

  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCb);

  if (channel == 0) {
    s_hopping = true;
  } else {
    s_hopping = false;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    appState.currentChannel = channel;
  }

  appState.mode = OpMode::SNIFFER_PCAP;
  s_active = true;
  s_lastHop = 0;
  appState.log("[sniffer] capturing to " + fname + (s_hopping ? " (hopping)" : (" on ch" + std::to_string(channel))));
}

void Sniffer::stop() {
  esp_wifi_set_promiscuous(false);
  appState.pcapPacketCount = s_pcap.packetCount();
  s_pcap.end();
  s_active = false;
  appState.mode = OpMode::IDLE;
  appState.log("[sniffer] capture stopped: " + std::to_string(appState.pcapPacketCount) + " packets -> " + appState.pcapFilename);
}

bool Sniffer::active() { return s_active; }

void Sniffer::loopHop() {
  if (!s_active) return;
  appState.pcapPacketCount = s_pcap.packetCount();
  if (!s_hopping) return;
  if (nowMs() - s_lastHop > HOP_INTERVAL_MS) {
    appState.currentChannel = (appState.currentChannel % 13) + 1;
    esp_wifi_set_channel(appState.currentChannel, WIFI_SECOND_CHAN_NONE);
    s_lastHop = nowMs();
  }
}
