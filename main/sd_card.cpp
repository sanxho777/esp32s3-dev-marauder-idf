#include "sd_card.h"
#include "state.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdmmc_host.h"
#include <sys/stat.h>

static const char *TAG = "sd_card";

// This board has an ONBOARD microSD slot wired to the ESP32-S3's native
// SDMMC peripheral (1-line mode) via GPIO38=CMD, GPIO39=CLK, GPIO40=DAT0 --
// confirmed from the board's own header pinout ("Shared internally with
// MicroSD CMD/CLK/DAT0"). This is NOT an SPI breakout, so it uses the
// sdmmc_host driver, not sdspi. Only D0 is wired (no D1-D3), so this must
// stay in 1-bit bus width.
#define SD_CLK_PIN GPIO_NUM_39
#define SD_CMD_PIN GPIO_NUM_38
#define SD_D0_PIN  GPIO_NUM_40

bool SdCard::mount() {
  // Only the fields stable across IDF versions are set here; if your IDF
  // checkout's esp_vfs_fat_sdmmc_mount_config_t has additional required
  // fields, zero-init covers them (bool/size_t default to false/0).
  esp_vfs_fat_sdmmc_mount_config_t mount_config = {};
  mount_config.format_if_mount_failed = false;
  mount_config.max_files = 5;
  mount_config.allocation_unit_size = 16 * 1024;

  sdmmc_host_t host = SDMMC_HOST_DEFAULT();
  host.flags &= ~SDMMC_HOST_FLAG_4BIT; // only D0 is wired on this board
  host.flags &= ~SDMMC_HOST_FLAG_8BIT;
  host.max_freq_khz = SDMMC_FREQ_DEFAULT;

  sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
  slot_config.width = 1;
  slot_config.clk = SD_CLK_PIN;
  slot_config.cmd = SD_CMD_PIN;
  slot_config.d0 = SD_D0_PIN;
  slot_config.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;

  sdmmc_card_t *card;
  esp_err_t ret = esp_vfs_fat_sdmmc_mount(SD_MOUNT_POINT, &host, &slot_config, &mount_config, &card);
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "no SD card mounted (%s) -- sniffer/pcap logging disabled", esp_err_to_name(ret));
    return false;
  }

  sdmmc_card_print_info(stdout, card);
  mkdir(SD_MOUNT_POINT "/pcaps", 0755);
  ESP_LOGI(TAG, "SD card mounted at %s", SD_MOUNT_POINT);
  return true;
}
