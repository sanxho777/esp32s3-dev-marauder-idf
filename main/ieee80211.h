#pragma once
#include <cstdint>

// Minimal 802.11 MAC header field access. `payload` points at the frame
// control field (byte 0) as delivered by esp_wifi's promiscuous callback.

inline uint8_t dot11Type(const uint8_t *p)    { return (p[0] >> 2) & 0x3; }   // 0=mgmt 1=ctrl 2=data
inline uint8_t dot11Subtype(const uint8_t *p) { return (p[0] >> 4) & 0xF; }

// Management subtypes
constexpr uint8_t SUBTYPE_ASSOC_REQ    = 0x0;
constexpr uint8_t SUBTYPE_ASSOC_RESP   = 0x1;
constexpr uint8_t SUBTYPE_PROBE_REQ    = 0x4;
constexpr uint8_t SUBTYPE_PROBE_RESP   = 0x5;
constexpr uint8_t SUBTYPE_BEACON       = 0x8;
constexpr uint8_t SUBTYPE_DISASSOC     = 0xA;
constexpr uint8_t SUBTYPE_AUTH         = 0xB;
constexpr uint8_t SUBTYPE_DEAUTH       = 0xC;

constexpr uint8_t TYPE_MGMT = 0;
constexpr uint8_t TYPE_CTRL = 1;
constexpr uint8_t TYPE_DATA = 2;

inline const uint8_t *dot11Addr1(const uint8_t *p) { return p + 4; }  // dest / RA
inline const uint8_t *dot11Addr2(const uint8_t *p) { return p + 10; } // source / TA
inline const uint8_t *dot11Addr3(const uint8_t *p) { return p + 16; } // BSSID (mgmt/most data)
