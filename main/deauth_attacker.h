#pragma once
#include <string>
#include <cstdint>

// Active 802.11 deauth/disassoc frame injection.
// AUTHORIZED TESTING ONLY: only target APs/clients you own or have
// explicit written permission to test. Sending deauth frames at networks
// you don't control is illegal in most jurisdictions.
namespace DeauthAttacker {
  // apIndex refers to appState.aps[]. If clientMac is empty, broadcast
  // deauth is sent (disconnects all clients of that AP).
  void start(int apIndex, const std::string &clientMac, uint32_t packetsPerBurst = 5);
  void stop();
  void loopSend(); // call from tick task; paces bursts
  bool active();
}
