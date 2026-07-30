#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

// Writes 802.11 frames wrapped in a radiotap header (LINKTYPE_IEEE802_11_RADIO
// = 127) to a pcap file on the SD card, via the standard FATFS VFS mount
// (POSIX stdio). Radiotap wrapping is what lets Wireshark/hcxtools/hashcat
// pull RSSI/channel metadata back out of the capture.
class PcapWriter {
public:
  bool begin(const std::string &path); // e.g. SD_MOUNT_POINT "/pcaps/capture_0001.pcap"

  // timestampUs: radio timestamp from wifi_pkt_rx_ctrl_t.timestamp (microseconds)
  // channel: primary channel the frame was captured on (1-14)
  // rssi: signal strength in dBm from wifi_pkt_rx_ctrl_t.rssi
  void writePacket(uint32_t timestampUs, uint8_t channel, int8_t rssi,
                    const uint8_t *data, uint32_t len);
  void end();
  bool isOpen() const { return file_ != nullptr; }
  uint32_t packetCount() const { return count_; }

private:
  FILE *file_ = nullptr;
  uint32_t count_ = 0;
};
