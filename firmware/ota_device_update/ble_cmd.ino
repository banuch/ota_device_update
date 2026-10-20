// =============================================================================
//  ble_cmd.ino  --  BLE command channel (Nordic-UART-style service)
//
//  Write a command line to RX (6e400002...), responses arrive as
//  notifications on TX (6e400003...). Any BLE UART app (nRF Connect,
//  Serial Bluetooth Terminal) works. Commands are queued here and executed
//  from loop(), never inside the BLE callback. See commands.ino for the
//  BLE-specific restrictions.
// =============================================================================
#if ENABLE_BLE
#include <BLEDevice.h>
#include <BLEServer.h>

static BLECharacteristic* s_bleTx = nullptr;
static bool               s_bleConnected = false;
static String             s_bleCmd;
static volatile bool      s_bleCmdReady = false;

// Print sink that buffers a response and sends it as notifications.
class BlePrint : public Print {
public:
    String buf;
    size_t write(uint8_t c) override { buf += (char)c; return 1; }
    void flush() override {
        if (!s_bleTx || !s_bleConnected) { buf = ""; return; }
        for (size_t off = 0; off < buf.length(); off += 180) {
            String part = buf.substring(off, min(buf.length(), off + 180));
            s_bleTx->setValue((uint8_t*)part.c_str(), part.length());
            s_bleTx->notify();
            delay(20);
        }
        buf = "";
    }
};

class BleServerCb : public BLEServerCallbacks {
    void onConnect(BLEServer*) override { s_bleConnected = true; }
    void onDisconnect(BLEServer* srv) override {
        s_bleConnected = false;
        srv->startAdvertising();
    }
};

class BleRxCb : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* c) override {
        if (s_bleCmdReady) return;   // previous command still pending
        String v = c->getValue();
        if (v.length() > 200) v = v.substring(0, 200);
        s_bleCmd = v;
        s_bleCmdReady = true;
    }
};

void ble_init() {
    String suffix = g_ota.imei.length() >= 6 ? g_ota.imei.substring(g_ota.imei.length() - 6) : String("000000");
    String name = String(BLE_DEVICE_PREFIX) + suffix;
    BLEDevice::init(name.c_str());
    BLEServer* srv = BLEDevice::createServer();
    srv->setCallbacks(new BleServerCb());
    BLEService* svc = srv->createService(BLE_SERVICE_UUID);
    s_bleTx = svc->createCharacteristic(BLE_TX_UUID, BLECharacteristic::PROPERTY_NOTIFY);
    // CCCD (0x2902) is added automatically by the NimBLE backend for NOTIFY.
    BLECharacteristic* rx = svc->createCharacteristic(
        BLE_RX_UUID, BLECharacteristic::PROPERTY_WRITE | BLECharacteristic::PROPERTY_WRITE_NR);
    rx->setCallbacks(new BleRxCb());
    svc->start();
    BLEAdvertising* adv = BLEDevice::getAdvertising();
    adv->addServiceUUID(BLE_SERVICE_UUID);
    adv->setScanResponse(true);
    BLEDevice::startAdvertising();
    DEBUG_SERIAL.printf("[BLE] Advertising as %s\n", name.c_str());
}

void ble_poll() {
    if (!s_bleCmdReady) return;
    String cmd = s_bleCmd;
    s_bleCmdReady = false;
    BlePrint out;
    cmd_handle(cmd, CMD_BLE, out);
    out.flush();
}
#else
void ble_init() {}
void ble_poll() {}
#endif
