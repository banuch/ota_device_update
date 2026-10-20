// =============================================================================
//  ota_device_update.ino  --  device-specific OTA client
//  ESP32-S3 + Quectel EC200U (cellular), Arduino-ESP32 core 3.x
//
//  Flow: boot -> modem attach -> report result of a just-applied update ->
//        check now -> then every check_interval_s (server-controlled,
//        default 24 h) or on CHECK_OTA from Serial/BLE.
//
//  Build (16 MB flash, two 3 MB OTA app slots):
//    arduino-cli compile --fqbn "esp32:esp32:esp32s3:USBMode=hwcdc,CDCOnBoot=cdc,
//      FlashMode=qio,FlashSize=16M,PartitionScheme=app3M_fat9M_16MB,PSRAM=opi" .
//
//  Your own application code goes in app_loop() below -- keep it
//  non-blocking; ota_run() blocks while a check/download is in progress.   
// =============================================================================
#include "config.h"
#include <esp_ota_ops.h>

OtaState g_ota;

// ── Application hooks (replace with the real product logic) ─────────────────
static void app_setup() {}
static void app_loop() {}

void setup() {
    DEBUG_SERIAL.begin(DEBUG_BAUD);
    delay(1500);
    const esp_partition_t* run = esp_ota_get_running_partition();
    DEBUG_SERIAL.printf("\n=== ota_device_update %s (partition %s) ===\n", FW_VERSION, run ? run->label : "?");

    cfg_load();
    modem_hwInit();
    g_ota.modemReady = modem_init();
    if (g_ota.modemReady) ota_reportBootResult();

    ble_init();
    app_setup();

    g_ota.nextCheckMs = millis() + BOOT_CHECK_DELAY_MS;   // first check shortly after boot
    DEBUG_SERIAL.println("Type HELP for commands.");
}

void loop() {
    cmd_pollSerial();
    ble_poll();
    app_loop();
    if (!g_ota.busy && ota_isDue()) ota_run();
    delay(10);
}
