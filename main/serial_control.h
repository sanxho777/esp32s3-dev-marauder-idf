#pragma once

// Replaces the old web_server.cpp control channel: a newline-delimited JSON
// protocol carried over the USB console (the same port `idf.py monitor`
// already uses), instead of WiFi. The device no longer needs anything to
// join its softAP for control purposes, which sidesteps the whole class of
// "esp_wifi won't change channel/can't scan while a client is connected"
// problems that plagued the WiFi-GUI version.
//
// Firmware -> host: lines of the form  "#MRDR#{...json...}\n"
//   {"type":"log","msg":"..."}
//   {"type":"status", mode, channel, sdCard, pcapFile, pcapPackets,
//                      deauthSent, widsSeen, aps[], stations[], alerts[], ble[]}
//
// Host -> firmware: one JSON object per line, e.g. {"cmd":"wifi_scan_start"}
// See serial_control.cpp's dispatch() for the full command list.
namespace SerialControl {
  void begin();
}
