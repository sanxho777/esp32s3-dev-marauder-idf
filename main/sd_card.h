#pragma once

// Mounts a microSD card over SPI as FATFS at MOUNT_POINT. On success,
// appState.sdCardOk is set true and MOUNT_POINT "/pcaps" is created.
#define SD_MOUNT_POINT "/sdcard"

namespace SdCard {
  // Pins are set here rather than passed in -- adjust to your wiring.
  bool mount();
}
