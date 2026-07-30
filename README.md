# ESP32-S3 Marauder (native ESP-IDF, USB-serial control)

Native ESP-IDF WiFi/BLE security-testing firmware, controlled by a native
desktop app (Python/Tkinter, `desktop_app/marauder_gui.py`) talking to the
device over USB serial -- not a browser over WiFi. That's a deliberate
architecture change from an earlier version of this project: hosting a
control web server on the ESP32's own AP meant your controlling device had
to *join* that AP, which conflicts with `esp_wifi`'s own rules (it refuses
to change channel while a client is associated to your softAP in AP+STA
mode). Moving control off WiFi entirely removes that conflict -- nobody
needs to ever connect to the device's AP for you to operate it, so
WIDS/sniffer/station-discovery can channel-hop freely regardless of what
else is going on.

## Legal / safety

This firmware can spam fake beacons and run a captive-portal
credential-capture page. Only point those modules at networks and devices
**you own or are explicitly authorized to test** (your own lab gear, or a
pentest engagement with signed authorization). Rogue captive portals
against networks you don't control are illegal in most jurisdictions (FCC
rules, CFAA-style computer-crime statutes, wiretap/interception laws
depending on region). WiFi recon (AP scan, passive sniffing) and the WIDS
detector are receive-only and safe to run anywhere you're allowed to have
the device powered on.

Deauth frame transmission is present in the code but **disabled by
default** (`DEAUTH_ENABLED 0` in `main/deauth_attacker.cpp`) -- see
"Deauth is blocked, not just disabled" below.

## Features

| Module | What it does |
|---|---|
| WiFi Recon | Active AP scan + passive station/client discovery (channel hopping) |
| WIDS | Passive deauth/disassoc flood detection with alerts |
| Deauth Attack | **Disabled** -- see below |
| Beacon Spam | Broadcasts fake AP beacons for a configurable SSID list |
| Sniffer | Full promiscuous capture to `.pcap` on SD, radiotap-wrapped for Wireshark/hashcat/hcxtools |
| BLE | Native NimBLE scanner + novelty advertisement "spam" |
| Evil Portal | Captive DNS (custom UDP:53 responder) + credential-capture login page, logged to SD |

### Deauth is blocked, not just disabled

`esp_wifi_80211_tx()`'s own doc comment states it only supports sending
"beacon/probe request/probe response/action and non-QoS data frame" --
deauth/disassoc frames are rejected at TX time inside the closed-source
WiFi library itself (`wifi:unsupport frame type: 0c0` in the logs). This
was confirmed two ways: the header doc comment, and an exhaustive grep of
every `Kconfig` file in the ESP-IDF tree for anything related to raw TX /
frame types / promiscuous injection -- there is no build option that
changes this. The code is left in place (`DEAUTH_ENABLED` in
`deauth_attacker.cpp`, currently `0`) in case a future `esp_wifi` release
lifts the restriction; flipping it back on won't work today.

## Hardware

Written against a board with an onboard camera, microphone, and microSD
slot (flash LED on GPIO4, status LED on GPIO5, camera interface on
GPIO4/5/6/7/15/16/17/18, microSD wired to the native SDMMC peripheral on
GPIO38=CMD/GPIO39=CLK/GPIO40=DAT0, 1-line mode). If you're on a different
board:

- **SD card**: `main/sd_card.cpp` currently uses the SDMMC driver
  (`esp_vfs_fat_sdmmc_mount`) hardcoded to those pins. A plain devkit with
  an SPI SD breakout instead needs the SPI variant
  (`esp_vfs_fat_sdspi_mount`) -- ask if you need that swapped back in.
- **Camera/mic pins**: irrelevant here since this firmware doesn't use the
  camera or mic, but don't repurpose GPIO4/5/6/7/15/16/17/18 for anything
  else on this specific board -- they're already wired to onboard hardware.

## One-time setup

1. **ESP-IDF**: this was written against the ESP-IDF checkout at
   `~/esp-idf` (currently tracking `master`, a dev branch -- not a tagged
   stable release). If you hit build errors that look like an API mismatch,
   they're most likely from that, not from a hardware issue -- share the
   error and it's a quick fix.
2. **Submodules**: BLE needs the NimBLE host, which ships as a git submodule.
   If not already done:
   ```
   cd ~/esp-idf && git submodule update --init --recursive
   ```
3. **Environment**: source IDF's export script in every new shell before
   using `idf.py`:
   ```
   . ~/esp-idf/export.sh
   ```
4. **Target**: from this project directory, set the chip target once:
   ```
   idf.py set-target esp32s3
   ```

## Building the firmware

1. Edit `main/main.cpp` if you want to change `MARAUDER_AP_SSID` /
   `MARAUDER_AP_PASSWORD` (this AP is only used by beacon spam / evil
   portal now -- nothing needs to join it for control).
2. Build:
   ```
   idf.py build
   ```
   The first build fetches the `espressif/cjson` managed component
   automatically (declared in `main/idf_component.yml`) -- needs network
   access once.
3. Flash:
   ```
   idf.py -p /dev/ttyACM0 flash
   ```
   (adjust the port)

## Running the desktop app

```
cd desktop_app
pip install -r requirements.txt
python3 marauder_gui.py
```

On macOS with Homebrew Python, Tkinter isn't bundled by default -- if the
app fails to launch with a Tkinter import error, run `brew install
python-tk` first.

Pick the device's serial port (the same `/dev/ttyACM0`-style port you flash
with) from the dropdown, click **Connect**, and use the tabs -- they mirror
the modules in the table above. The Deauth tab is present but shows the
same "blocked at the driver level" explanation as above; the Start button
will just get a log line back from the firmware saying so.

**No file transfer over serial**: pcap captures and the evil-portal
credential log live on the SD card (`/pcaps/*.pcap`, `/portal_log.txt`) --
pull the physical microSD card and read it with a card reader rather than
downloading over the serial link.

## Architecture notes

- **Protocol**: newline-delimited JSON, firmware -> host lines prefixed
  `#MRDR#` so the desktop app can tell protocol messages apart from
  ordinary `ESP_LOG` boot/debug noise sharing the same port (see the
  header comment in `main/serial_control.h` for the exact message shapes).
  Host -> firmware is plain `{"cmd": "...", ...}` lines with no prefix.
- **No Arduino `loop()`**: replaced by `tickTask` in `main.cpp`, a FreeRTOS
  task that paces every module's periodic work (channel hopping, BLE adv
  cycling, pcap flush bookkeeping) every 20ms.
- **Concurrency**: IDF has multiple real tasks touching shared state (WiFi
  promiscuous callbacks run in the WiFi task, NimBLE events in the host
  task, the serial command reader in its own task). `state.h`'s
  `StateLock` (a FreeRTOS recursive mutex) guards every `appState`
  collection access -- see its uses in each module.
- **AP scanning vs. channel hopping**: `esp_wifi_scan_start()` requires STA
  to be part of the active WiFi mode, but AP+STA mode refuses
  `esp_wifi_set_channel()` while a client is connected to the softAP.
  `wifi_scanner.cpp`'s `apScanTask` flips into `WIFI_MODE_APSTA` only for
  the few seconds a scan actually runs (harvesting results *before*
  switching back -- switching back first was found to silently discard the
  scan cache), then drops back to plain `WIFI_MODE_AP` so WIDS/sniffer/
  station-discovery hopping keeps working afterward.
- **BLE**: native NimBLE host C API (`ble_gap_disc`, `ble_gap_adv_set_data`,
  etc.), verified against the actual headers/examples in this IDF checkout
  (`examples/bluetooth/nimble/{bleprph,blecent}`) rather than guessed.
- **DNS captive portal**: hand-rolled minimal UDP:53 responder in
  `dns_server.cpp` that answers every A-record query with the AP's own IP.
- **Evil portal owns its own httpd instance**: started/stopped alongside
  the portal itself (`evil_portal.cpp`), rather than a server that's always
  running -- there's no reason to keep `esp_http_server` up when nothing
  needs it (the desktop app doesn't use HTTP at all).
- **SD/pcap**: FATFS mounted via the native SDMMC peripheral at `/sdcard`
  (`esp_vfs_fat_sdmmc_mount`), accessed with plain POSIX `fopen`/`fwrite`.
  Captures are radiotap-wrapped (`LINKTYPE_IEEE802_11_RADIO`) with
  TSFT/channel/RSSI per packet, and timestamps are anchored to a fixed
  recent date rather than device-uptime-since-boot (the device has no
  RTC/NTP time source, and raw uptime timestamps -- effectively Jan 1970 --
  confused hashcat/hcxtools' handshake correlation).

## Project layout

```
CMakeLists.txt        top-level IDF project file
main/CMakeLists.txt    component sources
main/idf_component.yml managed dependency: espressif/cjson
partitions.csv          flash partition table
sdkconfig.defaults      NimBLE / httpd / WiFi / FATFS config baked in at first build
main/
  main.cpp               app_main(), WiFi AP + NVS + SD init, tick task
  state.h/.cpp             shared app state (scan results, alerts, counters) + StateLock mutex
  net_globals.h            extern g_apNetif, used by evil_portal for the DNS responder's IP
  ieee80211.h              802.11 frame-header helpers
  serial_control.*           USB-serial command/status protocol (replaces the old web GUI)
  wifi_scanner.*             AP scan + passive station discovery
  deauth_detector.*           WIDS (receive-only)
  deauth_attacker.*           deauth frame injection -- disabled, see above
  beacon_spammer.*            fake beacon broadcast
  sniffer.*                     promiscuous capture -> radiotap pcap on SD
  pcap_writer.*                  pcap file format + radiotap header writer (POSIX FILE*)
  sd_card.*                       SDMMC mount (this board's onboard slot)
  ble_module.*                     native NimBLE scan + adv spam
  dns_server.*                      minimal captive DNS responder
  evil_portal.*                      AP SSID takeover + own httpd instance + credential logging
desktop_app/
  marauder_gui.py          Tkinter control panel, talks to the firmware over USB serial
  requirements.txt          pyserial
```
# esp32s3-dev-marauder-idf
