#pragma once
#include <string>

// Captive-portal (evil portal) module for phishing-awareness testing on
// networks/devices you are authorized to assess. Starting this reconfigures
// the device's own AP to the chosen SSID and spins up its own web server for
// the duration (there's no always-on control web server anymore -- control
// happens over USB serial, see serial_control.cpp).
namespace EvilPortal {
  void start(const std::string &apSsid, const std::string &htmlTemplate);
  void stop();
  bool active();

  std::string portalHtml();          // current template content served to victims
  void logCapture(const std::string &clientIp, const std::string &fieldsJson);
}
