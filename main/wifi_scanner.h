#pragma once

namespace WifiScanner {
  // Active AP scan (blocking, runs in its own task). Populates appState.aps
  // and calls appState.notify() when done.
  void startApScan();

  // Passive station/client discovery: promiscuous mode, channel-hops,
  // watches probe requests + data frames to associate clients with APs.
  void startStationSniff();
  void stopStationSniff();
  void loopStationSniff(); // handles channel hop timing, call from tick task
  bool stationSniffActive();
}
