// =============================================================================
//  commands.ino  --  text commands, shared by Serial and BLE
//
//    HELP
//    GET_STATUS                      also shows reg=<state> fp=<key fingerprint>
//    CHECK_OTA                       queue an immediate check (runs in loop())
//    SET key=value [key=value ...]   keys: host port secret interval apn
//    REBOOT
//
//  BLE is reachable by anyone nearby, so over BLE:
//    - SET needs auth=<current device key> once a key is provisioned
//      (first-time commissioning of an unprovisioned device is open), and
//    - the key itself is never echoed back.
//  Even a successful malicious SET host=... cannot push firmware: every
//  offer must carry a valid HMAC from the real server (see ota_client.ino).
// =============================================================================

static void cmd_status(Print& out) {
    const esp_partition_t* run = esp_ota_get_running_partition();
    long nextS = (long)(int32_t)(g_ota.nextCheckMs - millis()) / 1000;
    out.printf("fw=%s imei=%s\n", FW_VERSION, g_ota.imei.length() ? g_ota.imei.c_str() : "?");
    out.printf("server=%s:%u key=%s interval=%lus apn=%s\n", g_cfg.host.c_str(), g_cfg.port,
               g_cfg.secret.length() == 64 ? "set" : "MISSING", (unsigned long)g_cfg.intervalS,
               g_cfg.apn.c_str());
    out.printf("%s\n", reg_statusLine().c_str());
    out.printf("modem=%s busy=%d partition=%s\n", g_ota.modemReady ? "ready" : "down", g_ota.busy,
               run ? run->label : "?");
    out.printf("last=%s offer=%s next_check_in=%lds\n", g_ota.lastResult.c_str(),
               g_ota.lastOfferVer.length() ? g_ota.lastOfferVer.c_str() : "-", nextS < 0 ? 0 : nextS);
}

static void cmd_set(String args, CmdSource src, Print& out) {
    // Collect key=value pairs first so an auth failure applies nothing.
    String keys[8], vals[8];
    int n = 0;
    String auth;
    args.trim();
    while (args.length() && n < 8) {
        int sp = args.indexOf(' ');
        String tok = sp == -1 ? args : args.substring(0, sp);
        args = sp == -1 ? String("") : args.substring(sp + 1);
        args.trim();
        int eq = tok.indexOf('=');
        if (eq <= 0) { out.printf("ERR bad token '%s' (want key=value)\n", tok.c_str()); return; }
        String k = tok.substring(0, eq), v = tok.substring(eq + 1);
        k.toLowerCase();
        if (k == "auth") { auth = v; auth.toLowerCase(); continue; }
        keys[n] = k; vals[n] = v; n++;
    }
    if (n == 0) { out.println("ERR nothing to set"); return; }

    bool authOk = auth.length() == g_cfg.secret.length();
    uint8_t diff = 0;
    for (size_t i = 0; authOk && i < auth.length(); i++) diff |= (uint8_t)(auth[i] ^ g_cfg.secret[i]);
    authOk = authOk && diff == 0;
    if (src == CMD_BLE && g_cfg.secret.length() == 64 && !authOk) {
        out.println("ERR auth=<current device key> required over BLE");
        return;
    }
    for (int i = 0; i < n; i++) {
        String err = cfg_set(keys[i], vals[i]);
        if (err.length()) out.printf("ERR %s: %s\n", keys[i].c_str(), err.c_str());
        else out.printf("OK %s=%s\n", keys[i].c_str(), keys[i] == "secret" ? "(saved)" : vals[i].c_str());
    }
}

void cmd_handle(String line, CmdSource src, Print& out) {
    line.trim();
    if (line.isEmpty()) return;
    int sp = line.indexOf(' ');
    String cmd = sp == -1 ? line : line.substring(0, sp);
    String args = sp == -1 ? String("") : line.substring(sp + 1);
    cmd.toUpperCase();

    if (cmd == "HELP") {
        out.println("GET_STATUS | CHECK_OTA | SET key=value ... (host port secret interval apn"
                    " [auth=<key> over BLE]) | REBOOT");
    } else if (cmd == "GET_STATUS" || cmd == "STATUS") {
        cmd_status(out);
    } else if (cmd == "CHECK_OTA") {
        if (g_ota.busy) out.println("BUSY check already running");
        else { g_ota.checkRequested = true; out.println("OK check queued"); }
    } else if (cmd == "SET") {
        cmd_set(args, src, out);
    } else if (cmd == "REBOOT") {
        if (g_ota.busy) { out.println("BUSY try again after the current check"); return; }
        out.println("OK rebooting");
        delay(300);
        ESP.restart();
    } else {
        out.printf("ERR unknown command '%s' (try HELP)\n", cmd.c_str());
    }
}

// ── Serial line reader (non-blocking) ───────────────────────────────────────
void cmd_pollSerial() {
    static String buf;
    while (DEBUG_SERIAL.available()) {
        char c = (char)DEBUG_SERIAL.read();
        if (c == '\n' || c == '\r') {
            if (buf.length()) { cmd_handle(buf, CMD_SERIAL, DEBUG_SERIAL); buf = ""; }
        } else if (buf.length() < 200) {
            buf += c;
        }
    }
}
