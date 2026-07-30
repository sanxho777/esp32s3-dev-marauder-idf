#pragma once

// Wireless Intrusion Detection: passively watches for deauth/disassoc
// floods (a classic sign of an active deauth attack against the local
// airspace) and raises alerts. Receive-only, transmits nothing.
namespace DeauthDetector {
  void start();
  void stop();
  void loopHop(); // channel hopping timing, call from tick task
  bool active();
}
