#pragma once

// Full promiscuous packet capture to a .pcap file on SD (openable in Wireshark).
namespace Sniffer {
  void start(int channel); // channel = 0 means hop across 1-13
  void stop();
  void loopHop();
  bool active();
}
