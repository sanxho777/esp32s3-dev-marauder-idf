#pragma once
#include <cstdint>

// Minimal DNS server that answers every A query with the given IPv4
// address -- used to force captive-portal detection / any DNS lookup
// from associated clients back to our own softAP IP.
namespace DnsServer {
  void start(uint32_t ipv4_hostorder); // e.g. from esp_netif_ip_info_t.ip.addr (already network order -- see .cpp)
  void stop();
  bool active();
}
