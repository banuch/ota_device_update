// =============================================================================
//  nvs_config.ino  --  persistent runtime configuration (NVS namespace "otacfg")
// =============================================================================
#include <Preferences.h>

DeviceConfig g_cfg;

void cfg_load() {
    Preferences p;
    p.begin(NVS_NAMESPACE, true);
    g_cfg.host      = p.getString(K_HOST, OTA_HOST_DEFAULT);
    g_cfg.port      = (uint16_t)p.getUInt(K_PORT, OTA_PORT_DEFAULT);
    g_cfg.secret    = p.getString(K_SECRET, "");
    g_cfg.intervalS = p.getUInt(K_INTERVAL, CHECK_INTERVAL_DEFAULT_S);
    g_cfg.apn       = p.getString(K_APN, APN_DEFAULT);
    p.end();
    if (g_cfg.host.isEmpty()) g_cfg.host = OTA_HOST_DEFAULT;
    if (g_cfg.port == 0) g_cfg.port = OTA_PORT_DEFAULT;
    if (g_cfg.intervalS < CHECK_INTERVAL_MIN_S) g_cfg.intervalS = CHECK_INTERVAL_DEFAULT_S;
}

static bool cfg_isHex64(const String& s) {
    if (s.length() != 64) return false;
    for (size_t i = 0; i < s.length(); i++) if (!isxdigit(s[i])) return false;
    return true;
}

// Apply one key=value. Returns "" on success, else an error message.
String cfg_set(const String& key, const String& value) {
    Preferences p;
    String err;
    if (key == "host") {
        if (value.isEmpty() || value.length() > 64 || value.indexOf('"') != -1) return "bad host";
        g_cfg.host = value;
        p.begin(NVS_NAMESPACE, false); p.putString(K_HOST, value); p.end();
    } else if (key == "port") {
        long v = value.toInt();
        if (v < 1 || v > 65535) return "bad port";
        g_cfg.port = (uint16_t)v;
        p.begin(NVS_NAMESPACE, false); p.putUInt(K_PORT, v); p.end();
    } else if (key == "secret") {
        String s = value;
        s.toLowerCase();
        if (!cfg_isHex64(s)) return "secret must be the 64-hex-char device key";
        g_cfg.secret = s;
        p.begin(NVS_NAMESPACE, false); p.putString(K_SECRET, s); p.end();
    } else if (key == "interval") {
        long v = value.toInt();
        if (v < (long)CHECK_INTERVAL_MIN_S || v > 30L * 86400L) return "interval must be 300..2592000 s";
        g_cfg.intervalS = (uint32_t)v;
        p.begin(NVS_NAMESPACE, false); p.putUInt(K_INTERVAL, v); p.end();
    } else if (key == "apn") {
        if (value.length() > 63 || value.indexOf('"') != -1) return "bad apn";
        g_cfg.apn = value;
        p.begin(NVS_NAMESPACE, false); p.putString(K_APN, value); p.end();
        g_ota.modemReady = false;   // re-run AT init with the new APN on next check
    } else {
        return "unknown key '" + key + "'";
    }
    return "";
}
