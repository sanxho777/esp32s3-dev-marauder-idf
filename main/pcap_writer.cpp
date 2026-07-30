#include "pcap_writer.h"
#include "state.h"
#include <cstring>

struct PcapGlobalHeader {
  uint32_t magic_number = 0xa1b2c3d4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  int32_t  thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 65535;
  uint32_t network = 127; // LINKTYPE_IEEE802_11_RADIO (radiotap-wrapped 802.11)
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// The device has no RTC/NTP time source, so wall-clock time isn't available.
// esp_timer_get_time() alone would produce timestamps starting near the Unix
// epoch (Jan 1970), which some pcap consumers (hashcat/hcxtools included)
// balk at when correlating EAPOL handshake frames. Anchoring to a recent,
// plausible date keeps timestamps monotonic and sane-looking without needing
// real time sync.
static const uint32_t PCAP_EPOCH_BASE_SEC = 1704067200; // 2024-01-01T00:00:00Z

// Builds a minimal but correctly-aligned radiotap header covering TSFT,
// Channel, and Antenna Signal (dBm) -- the fields we have real data for.
// See https://www.radiotap.org for field layout/alignment rules.
static int buildRadiotapHeader(uint8_t *out, uint32_t timestampUs, uint8_t channel, int8_t rssi) {
  int i = 0;
  out[i++] = 0; // it_version
  out[i++] = 0; // it_pad
  int lenPos = i;
  i += 2; // it_len, filled in below once total size is known

  uint32_t present = (1u << 0)  // TSFT
                    | (1u << 3)  // Channel
                    | (1u << 5); // dBm Antenna Signal
  memcpy(out + i, &present, 4); i += 4;

  // TSFT: u64 microseconds. Offset is already 8-byte aligned (8 bytes of
  // fixed header precede it).
  uint64_t tsft = timestampUs;
  memcpy(out + i, &tsft, 8); i += 8;

  // Channel: frequency (u16 MHz) + flags (u16). Offset 16 is 2-byte aligned.
  uint16_t freqMhz = (channel == 14) ? 2484 : (uint16_t)(2407 + channel * 5);
  uint16_t chanFlags = 0x0080; // 2 GHz spectrum
  memcpy(out + i, &freqMhz, 2); i += 2;
  memcpy(out + i, &chanFlags, 2); i += 2;

  // dBm Antenna Signal: s8, any alignment.
  out[i++] = (uint8_t)rssi;

  uint16_t totalLen = (uint16_t)i;
  memcpy(out + lenPos, &totalLen, 2);
  return i;
}

bool PcapWriter::begin(const std::string &path) {
  file_ = fopen(path.c_str(), "wb");
  if (!file_) return false;

  PcapGlobalHeader hdr;
  fwrite(&hdr, sizeof(hdr), 1, file_);
  fflush(file_);
  count_ = 0;
  return true;
}

void PcapWriter::writePacket(uint32_t timestampUs, uint8_t channel, int8_t rssi,
                              const uint8_t *data, uint32_t len) {
  if (!file_) return;

  uint8_t radiotap[32];
  int rtLen = buildRadiotapHeader(radiotap, timestampUs, channel, rssi);
  uint32_t totalLen = (uint32_t)rtLen + len;

  PcapPacketHeader ph;
  int64_t uptimeUs = nowMs() * 1000;
  ph.ts_sec = PCAP_EPOCH_BASE_SEC + (uint32_t)(uptimeUs / 1000000);
  ph.ts_usec = (uint32_t)(uptimeUs % 1000000);
  ph.incl_len = totalLen;
  ph.orig_len = totalLen;

  fwrite(&ph, sizeof(ph), 1, file_);
  fwrite(radiotap, 1, rtLen, file_);
  fwrite(data, 1, len, file_);
  count_++;
  if (count_ % 20 == 0) fflush(file_);
}

void PcapWriter::end() {
  if (file_) {
    fflush(file_);
    fclose(file_);
    file_ = nullptr;
  }
}
