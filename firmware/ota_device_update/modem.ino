// =============================================================================
//  modem.ino  --  Quectel EC200U AT driver (TCP client only)
//
//  Ported from dlms_client server_send.ino / ota_update.ino with the field
//  fixes kept:
//    - PDP context must be activated (AT+QIACT=1) or QIOPEN silently times out
//    - QIOPEN success is the async "+QIOPEN: <id>,<err>" URC, not the leading OK
//    - one retry when that URC never arrives (err -999)
//    - quiet window between closing one socket and opening the next
//  New here: modem_tcpRead() parses the AT+QIRD reply byte-by-byte, so binary
//  firmware data (which can contain "\r\n", "OK", NULs...) is never mangled
//  by String-based searching.
// =============================================================================

static uint32_t s_lastSocketCloseMs = 0;

// ── Low-level helpers ───────────────────────────────────────────────────────
static void modem_drain() {
    while (MODEM.available()) MODEM.read();
}

// Send a command and collect the reply until OK / ERROR / timeout.
String modem_atCollect(const char* cmd, uint32_t timeoutMs) {
    modem_drain();
    DEBUG_SERIAL.printf("[AT]>> %s\n", cmd);
    MODEM.println(cmd);
    String buf;
    uint32_t t = millis();
    while (millis() - t < timeoutMs) {
        while (MODEM.available()) buf += (char)MODEM.read();
        if (buf.indexOf("\r\nOK\r\n") != -1 || buf.endsWith("OK\r\n") ||
            buf.indexOf("ERROR") != -1) break;
        delay(2);
    }
    String shown = buf;
    shown.trim();
    if (shown.length()) DEBUG_SERIAL.printf("[AT]<< %s\n", shown.c_str());
    return buf;
}

static bool modem_atOk(const char* cmd, uint32_t timeoutMs) {
    String r = modem_atCollect(cmd, timeoutMs);
    return r.indexOf("OK") != -1 && r.indexOf("ERROR") == -1;
}

// Read one line (terminated by '\n', '\r' stripped). Returns false on timeout.
static bool modem_readLine(String& line, uint32_t timeoutMs) {
    line = "";
    uint32_t t = millis();
    while (millis() - t < timeoutMs) {
        if (!MODEM.available()) { delay(1); continue; }
        char c = (char)MODEM.read();
        if (c == '\n') return true;
        if (c != '\r') line += c;
        if (line.length() > 256) return true;   // runaway line, hand it back
    }
    return false;
}

// ── Power / init ────────────────────────────────────────────────────────────
void modem_hwInit() {
    DEBUG_SERIAL.println("[MDM] Hardware init");
    pinMode(MODEM_WAKE_PIN, OUTPUT);
    digitalWrite(MODEM_WAKE_PIN, LOW);  delay(200);
    digitalWrite(MODEM_WAKE_PIN, HIGH); delay(200);
    digitalWrite(MODEM_WAKE_PIN, LOW);  delay(500);
    MODEM.setRxBufferSize(MODEM_RX_BUFFER);
    MODEM.begin(MODEM_BAUD, SERIAL_8N1, MODEM_RX_PIN, MODEM_TX_PIN);
    delay(5000);   // EC200U boot time
}

static bool modem_ensurePdp() {
    String r = modem_atCollect("AT+QIACT?", 3000);
    int qi = r.indexOf("+QIACT: 1,");
    if (qi != -1 && qi + 10 < (int)r.length() && r[qi + 10] == '1') return true;
    modem_atCollect("AT+QIACT=1", 15000);
    r = modem_atCollect("AT+QIACT?", 3000);
    return r.indexOf("+QIACT: 1,1") != -1;
}

String modem_readImei() {
    String r = modem_atCollect("AT+GSN", 2000);
    String digits;
    for (size_t i = 0; i < r.length(); i++) {
        if (isDigit(r[i])) digits += r[i];
        else if (digits.length() >= 14) break;
        else digits = "";
    }
    return (digits.length() >= 14 && digits.length() <= 17) ? digits : String("");
}

bool modem_init() {
    DEBUG_SERIAL.println("\n[MDM] --- AT init ---");
    bool alive = false;
    for (int i = 0; i < 10 && !alive; i++) {
        alive = modem_atOk("AT", 1000);
        if (!alive) delay(500);
    }
    if (!alive) {
        DEBUG_SERIAL.println("[MDM] ERR: no response to AT");
        return false;
    }
    modem_atCollect("ATE0", 1000);
    modem_atCollect("AT+CMEE=2", 1000);

    if (g_ota.imei.isEmpty()) g_ota.imei = modem_readImei();
    DEBUG_SERIAL.printf("[MDM] IMEI: %s\n", g_ota.imei.isEmpty() ? "(unreadable)" : g_ota.imei.c_str());

    modem_atCollect("AT+CPIN?", 2000);
    modem_atCollect("AT+CFUN=1", 3000);
    String ctx = modem_atCollect("AT+CGDCONT?", 2000);
    if (ctx.indexOf("+CGDCONT: 1,\"IP\",\"" + g_cfg.apn + "\"") == -1) {
        modem_atCollect(("AT+CGDCONT=1,\"IP\",\"" + g_cfg.apn + "\"").c_str(), 2000);
    }
    modem_atCollect("AT+CTZU=1", 1000);     // keep the clock synced to the network (NITZ)
    modem_atCollect("AT+CSQ", 1000);
    modem_atCollect("AT+CGATT=1", 10000);

    bool attached = false;
    uint32_t deadline = millis() + 60000UL;
    while (!attached && (int32_t)(deadline - millis()) > 0) {
        attached = modem_atCollect("AT+CGATT?", 2000).indexOf("+CGATT: 1") != -1;
        if (!attached) delay(2000);
    }
    if (!attached) {
        DEBUG_SERIAL.println("[MDM] ERR: not attached to packet network");
        return false;
    }
    if (!modem_ensurePdp()) {
        DEBUG_SERIAL.println("[MDM] ERR: PDP context activation failed");
        return false;
    }
    DEBUG_SERIAL.println("[MDM] Attached, PDP active");
    return true;
}

// ── Network clock (AT+CCLK?) ────────────────────────────────────────────────
// Reply: +CCLK: "yy/MM/dd,hh:mm:ss±zz"  (zz = network offset, quarter hours)
// Returns UTC epoch seconds, or 0 if the module has not synced yet.
//
// The EC200U reports hh:mm:ss ALREADY IN UTC; ±zz is the network's local
// offset, informational only. Field-confirmed twice: dlms_client (2026-08,
// modem 17:09:18 vs NTP UTC 17:10:54) and here (2026-10-20, modem 14:42:01
// vs UTC 14:42:33, "+22"). Subtracting zz made every signature 5.5 h stale
// (server: timestamp_out_of_window). If a different module/firmware ever
// reports local time instead, set MODEM_CCLK_IS_UTC to 0 in config.h.
static long modem_daysFromCivil(int y, int m, int d) {
    y -= m <= 2;
    const long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

uint32_t modem_epochSeconds() {
    String r = modem_atCollect("AT+CCLK?", 2000);
    int qi = r.indexOf("+CCLK: \"");
    if (qi == -1) return 0;
    int yy, MM, dd, hh, mi, ss, tzq = 0;
    if (sscanf(r.c_str() + qi + 8, "%d/%d/%d,%d:%d:%d%d", &yy, &MM, &dd, &hh, &mi, &ss, &tzq) < 6) return 0;
    if (yy < 24 || yy > 99) return 0;   // power-on default (2002/1970) -> not synced
    long days = modem_daysFromCivil(2000 + yy, MM, dd);
    long clock = days * 86400L + hh * 3600L + mi * 60L + ss;
#if MODEM_CCLK_IS_UTC
    long utc = clock;
#else
    long utc = clock - (long)tzq * 15L * 60L;
#endif
    DEBUG_SERIAL.printf("[MDM] clock %02d-%02d-%02d %02d:%02d:%02d tz=%+d -> epoch %ld (UTC)\n",
                        yy, MM, dd, hh, mi, ss, tzq, utc);
    return (uint32_t)utc;
}

// ── TCP ─────────────────────────────────────────────────────────────────────
// Waits for "+QIOPEN: <id>,<err>". Returns err (0 = connected) or -999 if
// the URC never arrived.
static int modem_waitQiopen(uint32_t timeoutMs) {
    String line;
    uint32_t t = millis();
    while (millis() - t < timeoutMs) {
        if (!modem_readLine(line, 500)) continue;
        if (line.startsWith("+QIOPEN:")) {
            DEBUG_SERIAL.printf("[AT]<< %s\n", line.c_str());
            int comma = line.indexOf(',');
            return comma == -1 ? -998 : line.substring(comma + 1).toInt();
        }
        if (line.indexOf("ERROR") != -1) {
            DEBUG_SERIAL.printf("[AT]<< %s\n", line.c_str());
            return -997;
        }
    }
    return -999;
}

bool modem_tcpOpen(const String& host, uint16_t port) {
    uint32_t since = millis() - s_lastSocketCloseMs;
    if (s_lastSocketCloseMs && since < MODEM_QUIET_WINDOW_MS) delay(MODEM_QUIET_WINDOW_MS - since);

    for (int attempt = 0; attempt < 2; attempt++) {
        char cmd[16];
        snprintf(cmd, sizeof(cmd), "AT+QICLOSE=%d", OTA_CONNECT_ID);
        modem_atCollect(cmd, 3000);           // ERROR on a cold socket is expected
        modem_ensurePdp();
        modem_drain();

        String open = "AT+QIOPEN=1," + String(OTA_CONNECT_ID) + ",\"TCP\",\"" + host + "\"," +
                      String(port) + ",0,0";  // local port 0, buffer access mode
        DEBUG_SERIAL.printf("[AT]>> %s\n", open.c_str());
        MODEM.println(open);
        int err = modem_waitQiopen(30000);
        if (err == 0) {
            DEBUG_SERIAL.printf("[MDM] TCP connected to %s:%u\n", host.c_str(), port);
            return true;
        }
        DEBUG_SERIAL.printf("[MDM] QIOPEN failed (err=%d)\n", err);
        if (err != -999) break;               // real rejection: don't retry
        delay(500);
    }
    return false;
}

void modem_tcpClose() {
    char cmd[16];
    snprintf(cmd, sizeof(cmd), "AT+QICLOSE=%d", OTA_CONNECT_ID);
    modem_atCollect(cmd, 5000);
    s_lastSocketCloseMs = millis();
}

bool modem_tcpSend(const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t n = min((size_t)1460, len - off);
        modem_drain();
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "AT+QISEND=%d,%u", OTA_CONNECT_ID, (unsigned)n);
        MODEM.println(cmd);
        // Wait for the '>' prompt.
        bool prompt = false;
        uint32_t t = millis();
        while (!prompt && millis() - t < 5000) {
            if (MODEM.available() && MODEM.read() == '>') prompt = true;
        }
        if (!prompt) {
            DEBUG_SERIAL.println("[MDM] QISEND: no '>' prompt");
            return false;
        }
        MODEM.write(data + off, n);
        String line;
        bool ok = false;
        t = millis();
        while (millis() - t < 10000) {
            if (!modem_readLine(line, 500)) continue;
            if (line.indexOf("SEND OK") != -1) { ok = true; break; }
            if (line.indexOf("SEND FAIL") != -1 || line.indexOf("ERROR") != -1) break;
        }
        if (!ok) {
            DEBUG_SERIAL.printf("[MDM] QISEND failed (%s)\n", line.c_str());
            return false;
        }
        off += n;
    }
    return true;
}

// Reads up to maxLen bytes already buffered in the modem for our socket.
// Returns >0 bytes read, 0 if nothing buffered right now, -1 on AT error.
// Sets peerClosed when the modem reports the server closed the connection
// (buffered data may still remain -- keep reading until 0).
int modem_tcpRead(uint8_t* out, int maxLen, bool& peerClosed) {
    // Leftovers from the previous exchange (trailing OK, URCs): scan them
    // for a close notice instead of silently dropping it.
    String stale;
    while (MODEM.available()) stale += (char)MODEM.read();
    if (stale.indexOf("+QIURC: \"closed\"") != -1) peerClosed = true;
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "AT+QIRD=%d,%d", OTA_CONNECT_ID, maxLen);
    MODEM.println(cmd);

    String line;
    int dataLen = -1;
    uint32_t t = millis();
    while (millis() - t < 5000) {
        if (!modem_readLine(line, 500)) continue;
        if (line.indexOf("+QIURC: \"closed\"") != -1) { peerClosed = true; continue; }
        if (line.startsWith("+QIRD:")) { dataLen = line.substring(6).toInt(); break; }
        if (line.indexOf("ERROR") != -1) return -1;
    }
    if (dataLen < 0) return -1;
    if (dataLen > maxLen) dataLen = maxLen;

    int got = 0;
    t = millis();
    while (got < dataLen && millis() - t < 10000) {
        int avail = MODEM.available();
        if (avail <= 0) { delay(1); continue; }
        got += MODEM.readBytes(out + got, min(avail, dataLen - got));
        t = millis();
    }
    if (got < dataLen) {
        DEBUG_SERIAL.printf("[MDM] QIRD short read %d/%d\n", got, dataLen);
        return -1;
    }
    // Consume the trailing "\r\nOK\r\n" (and note a close URC if it rides along).
    t = millis();
    while (millis() - t < 2000) {
        if (!modem_readLine(line, 300)) continue;
        if (line.indexOf("+QIURC: \"closed\"") != -1) peerClosed = true;
        if (line == "OK") break;
    }
    return got;
}
