#pragma once

// Broadcasts fake AP beacon frames advertising SSIDs from appState.beaconSsids.
// Useful for WiFi-scanner stress testing / SSID spam demos on your own gear.
namespace BeaconSpammer {
  void start(bool randomMac = true, int channel = 1);
  void stop();
  void loopSend();
  bool active();
}
