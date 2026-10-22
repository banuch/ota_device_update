// =============================================================================
//  config.h  --  ota_device_update build-time configuration
//
//  Hardware matches dlms_client (ESP32-S3 + Quectel EC200U on UART2).
//  Runtime values (server host/port, device key, interval, APN) live in NVS
//  and are set over serial or BLE -- see commands.ino. The defaults below are
//  only used until NVS holds a value.
// =============================================================================
#pragma once
#include <Arduino.h>

// ── Firmware identity ───────────────────────────────────────────────────────
#define FW_VERSION            "1.1.0"     // MAJOR.MINOR.PATCH -- bump before each release

// ── Debug console ───────────────────────────────────────────────────────────
#define DEBUG_SERIAL          Serial
#define DEBUG_BAUD            115200

// ── EC200U modem (UART2), same pins as dlms_client ──────────────────────────
#define MODEM                 Serial2
#define MODEM_TX_PIN          17
#define MODEM_RX_PIN          18
#define MODEM_WAKE_PIN        10
// UART rate between ESP32 and EC200U. dlms_client runs 9600 (~1 KB/s): a
// 1 MB image then takes ~17 min. If the module is set to 115200
// (AT+IPR=115200;&W) change this to 115200 for ~10x faster downloads.
#define MODEM_BAUD            9600
#define MODEM_RX_BUFFER       4096
#define MODEM_QUIET_WINDOW_MS 1500UL
#define OTA_CONNECT_ID        0           // QIOPEN connect id used for all OTA traffic
// EC200U AT+CCLK? returns UTC time plus an informational tz field (see
// modem_epochSeconds()). 0 = treat the time as local and subtract tz.
#define MODEM_CCLK_IS_UTC     1

// ── Server / timing defaults (NVS overrides) ────────────────────────────────
#define OTA_HOST_DEFAULT      "65.20.77.137"
#define OTA_PORT_DEFAULT      8080
#define APN_DEFAULT           "airtelgprs.com"
#define CHECK_INTERVAL_DEFAULT_S  86400UL  // 24 h; the server may override per device
#define CHECK_INTERVAL_MIN_S      300UL
#define CHECK_RETRY_S             900UL    // after a failed check / download
#define BOOT_CHECK_DELAY_MS       5000UL   // after the modem attaches

// ── Automatic registration (register.ino) ───────────────────────────────────
// The OTA server's registration public key. Get this line from the server:
//   cd server && npm run pubkey
// Empty = automatic registration off; provision with SET secret=... instead.
#define SERVER_REG_PUBKEY_HEX     ""
#define REGISTER_POLL_S           600UL    // while waiting for approval (server may say otherwise)

// ── Transfer limits ─────────────────────────────────────────────────────────
#define OTA_CHUNK_SIZE        1024        // AT+QIRD request size
#define HTTP_JSON_MAX         2048        // largest JSON reply we accept
#define HTTP_IDLE_TIMEOUT_MS  30000UL     // no bytes for this long -> abort
#define OTA_MIN_FW_SIZE       65536UL

// ── NVS ─────────────────────────────────────────────────────────────────────
#define NVS_NAMESPACE         "otacfg"
#define K_HOST                "host"
#define K_PORT                "port"
#define K_SECRET              "secret"     // 64-char hex device key
#define K_INTERVAL            "interval"
#define K_APN                 "apn"
#define K_PENDING_VER         "pend_ver"   // set before reboot into a new image
#define K_REG_KEY             "reg_key"    // registration key pair (32 priv + 65 pub), until a key arrives

// ── BLE command service (Nordic UART style) ─────────────────────────────────
#define ENABLE_BLE            1
#define BLE_DEVICE_PREFIX     "OTA-"       // + last 6 IMEI digits
#define BLE_SERVICE_UUID      "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define BLE_RX_UUID           "6e400002-b5a3-f393-e0a9-e50e24dcca9e"   // phone -> device (write)
#define BLE_TX_UUID           "6e400003-b5a3-f393-e0a9-e50e24dcca9e"   // device -> phone (notify)

// ── Shared state (defined in the .ino files) ────────────────────────────────
struct DeviceConfig {
    String   host;
    uint16_t port;
    String   secret;        // device key, 64 hex chars ("" = not provisioned)
    uint32_t intervalS;
    String   apn;
};
extern DeviceConfig g_cfg;

struct OtaOffer {
    bool     available = false;
    String   version;
    uint32_t size = 0;
    String   md5;
    String   token;
    uint32_t intervalS = 0;
    String   reason;
};

struct OtaState {
    String   imei;
    bool     modemReady = false;
    String   lastResult = "never_checked";
    String   lastOfferVer;
    uint32_t lastCheckMs = 0;
    uint32_t nextCheckMs = 0;
    bool     checkRequested = false;
    bool     busy = false;
};
extern OtaState g_ota;

// Command source -- BLE gets a restricted command set (see commands.ino).
enum CmdSource { CMD_SERIAL, CMD_BLE };
