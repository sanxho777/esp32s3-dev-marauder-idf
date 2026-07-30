#pragma once

namespace BleModule {
  void begin(); // call once from app_main() -- inits the NimBLE host + its task

  void startScan();
  void stopScan();
  bool scanActive();

  // Cycles fake BLE advertisements (iOS/Android pairing-popup style payloads).
  // Novelty/nuisance feature only -- no pairing, no data exfiltration.
  void startSpam();
  void stopSpam();
  void loopSpam(); // call from tick task to cycle payloads
  bool spamActive();
}
