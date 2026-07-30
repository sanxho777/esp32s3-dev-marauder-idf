#include "dns_server.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <cstring>

static const char *TAG = "dns_server";
static int s_sock = -1;
static volatile bool s_running = false;
static uint32_t s_ip = 0; // network-byte-order IPv4, as stored by esp_netif/lwIP

#pragma pack(push, 1)
struct DnsHeader {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};
#pragma pack(pop)

static void dnsTask(void *arg) {
  uint8_t rxBuf[512];
  uint8_t txBuf[512];

  while (s_running) {
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    int len = recvfrom(s_sock, rxBuf, sizeof(rxBuf), 0, (struct sockaddr *)&from, &fromLen);
    if (len <= 0) {
      if (!s_running) break;
      continue;
    }
    if (len < (int)sizeof(DnsHeader)) continue;

    auto *hdr = (DnsHeader *)rxBuf;
    // Walk the QNAME to find where the question section ends.
    int pos = sizeof(DnsHeader);
    while (pos < len && rxBuf[pos] != 0) {
      pos += rxBuf[pos] + 1;
    }
    pos += 1;      // terminating zero
    pos += 4;      // QTYPE + QCLASS
    if (pos > len) continue;

    int questionLen = pos - sizeof(DnsHeader);
    memcpy(txBuf, rxBuf, pos); // header + question, echoed back

    auto *outHdr = (DnsHeader *)txBuf;
    outHdr->flags = htons(0x8180); // standard response, recursion available, no error
    outHdr->qdcount = htons(1);
    outHdr->ancount = htons(1);
    outHdr->nscount = 0;
    outHdr->arcount = 0;

    int outPos = pos;
    txBuf[outPos++] = 0xC0; txBuf[outPos++] = 0x0C; // name = pointer to offset 12
    txBuf[outPos++] = 0x00; txBuf[outPos++] = 0x01; // TYPE A
    txBuf[outPos++] = 0x00; txBuf[outPos++] = 0x01; // CLASS IN
    txBuf[outPos++] = 0x00; txBuf[outPos++] = 0x00;
    txBuf[outPos++] = 0x00; txBuf[outPos++] = 0x3C; // TTL 60s
    txBuf[outPos++] = 0x00; txBuf[outPos++] = 0x04; // RDLENGTH 4
    memcpy(txBuf + outPos, &s_ip, 4);
    outPos += 4;

    (void)questionLen;
    sendto(s_sock, txBuf, outPos, 0, (struct sockaddr *)&from, fromLen);
  }

  close(s_sock);
  s_sock = -1;
  vTaskDelete(nullptr);
}

void DnsServer::start(uint32_t ipv4_hostorder) {
  if (s_running) return;
  s_ip = ipv4_hostorder;

  s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s_sock < 0) {
    ESP_LOGE(TAG, "socket() failed");
    return;
  }
  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    ESP_LOGE(TAG, "bind() failed");
    close(s_sock);
    s_sock = -1;
    return;
  }

  struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
  setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  s_running = true;
  xTaskCreate(dnsTask, "dns_server", 4096, nullptr, 5, nullptr);
  ESP_LOGI(TAG, "captive DNS started");
}

void DnsServer::stop() {
  s_running = false; // task's recvfrom times out within 1s and exits
}

bool DnsServer::active() { return s_running; }
