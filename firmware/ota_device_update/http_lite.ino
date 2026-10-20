// =============================================================================
//  http_lite.ino  --  minimal HTTP/1.1 client over the EC200U TCP socket
//
//  One request per connection ("Connection: close"). Supports a fixed
//  Content-Length body; chunked transfer encoding is rejected (the OTA
//  server never sends it). Two ways to use it:
//
//    http_requestJson()            small JSON request/response in one call
//    http_open() / http_read() / http_close()   stream a large body
// =============================================================================

static uint8_t s_rx[OTA_CHUNK_SIZE];
static int     s_rxLen = 0;
static int     s_rxPos = 0;
static bool    s_peerClosed = false;
static long    s_bodyRemaining = -1;   // -1 = unknown length (read until close)

// Pull more bytes from the modem into s_rx. Returns true if data is ready,
// false on end-of-stream (peer closed and nothing buffered), idle timeout,
// or AT error.
static bool http_fill() {
    if (s_rxPos < s_rxLen) return true;
    s_rxPos = s_rxLen = 0;
    uint32_t idleSince = millis();
    uint32_t backoff = 100;
    while (millis() - idleSince < HTTP_IDLE_TIMEOUT_MS) {
        int n = modem_tcpRead(s_rx, sizeof(s_rx), s_peerClosed);
        if (n > 0) { s_rxLen = n; return true; }
        if (n < 0) return false;
        if (s_peerClosed) return false;       // closed and fully drained
        delay(backoff);
        backoff = min(backoff * 2, (uint32_t)1000);
    }
    DEBUG_SERIAL.println("[HTTP] idle timeout");
    return false;
}

static int http_readByte() {
    if (!http_fill()) return -1;
    return s_rx[s_rxPos++];
}

static bool http_readLine(String& line) {
    line = "";
    while (true) {
        int c = http_readByte();
        if (c < 0) return false;
        if (c == '\n') return true;
        if (c != '\r') line += (char)c;
        if (line.length() > 1024) return false;
    }
}

// Connects, sends the request, parses the status line and headers.
// On success the body is ready to be read with http_read().
bool http_open(const char* method, const String& path, const String& jsonBody,
               int& status, long& contentLength) {
    status = 0;
    contentLength = -1;
    s_rxLen = s_rxPos = 0;
    s_peerClosed = false;

    if (!modem_tcpOpen(g_cfg.host, g_cfg.port)) return false;

    String req = String(method) + " " + path + " HTTP/1.1\r\n" +
                 "Host: " + g_cfg.host + ":" + String(g_cfg.port) + "\r\n" +
                 "User-Agent: ota-device/" FW_VERSION "\r\n" +
                 "Connection: close\r\n";
    if (jsonBody.length()) {
        req += "Content-Type: application/json\r\nContent-Length: " + String(jsonBody.length()) + "\r\n";
    }
    req += "\r\n";
    req += jsonBody;
    DEBUG_SERIAL.printf("[HTTP] %s %s\n", method, path.substring(0, path.indexOf('?') == -1 ? path.length() : path.indexOf('?')).c_str());
    if (!modem_tcpSend((const uint8_t*)req.c_str(), req.length())) {
        modem_tcpClose();
        return false;
    }

    String line;
    if (!http_readLine(line) || !line.startsWith("HTTP/1.")) {
        DEBUG_SERIAL.printf("[HTTP] bad status line: '%s'\n", line.c_str());
        modem_tcpClose();
        return false;
    }
    status = line.substring(9, 12).toInt();

    while (true) {
        if (!http_readLine(line)) { modem_tcpClose(); return false; }
        if (line.length() == 0) break;                 // end of headers
        String lower = line;
        lower.toLowerCase();
        if (lower.startsWith("content-length:")) contentLength = lower.substring(15).toInt();
        if (lower.startsWith("transfer-encoding:") && lower.indexOf("chunked") != -1) {
            DEBUG_SERIAL.println("[HTTP] chunked encoding not supported");
            modem_tcpClose();
            return false;
        }
    }
    s_bodyRemaining = contentLength;
    DEBUG_SERIAL.printf("[HTTP] status %d, content-length %ld\n", status, contentLength);
    return true;
}

// Reads up to maxLen body bytes. Returns >0 bytes, 0 at end of body, -1 on error.
int http_read(uint8_t* out, int maxLen) {
    if (s_bodyRemaining == 0) return 0;
    if (!http_fill()) {
        // End of stream is only clean if the length was unknown.
        return (s_bodyRemaining < 0 && s_peerClosed) ? 0 : -1;
    }
    int n = min(maxLen, s_rxLen - s_rxPos);
    if (s_bodyRemaining > 0 && n > s_bodyRemaining) n = (int)s_bodyRemaining;
    memcpy(out, s_rx + s_rxPos, n);
    s_rxPos += n;
    if (s_bodyRemaining > 0) s_bodyRemaining -= n;
    return n;
}

void http_close() {
    modem_tcpClose();
}

// Small JSON round trip. respBody holds the response body (any status).
bool http_requestJson(const char* method, const String& path, const String& jsonBody,
                      int& status, String& respBody) {
    long len;
    respBody = "";
    if (!http_open(method, path, jsonBody, status, len)) return false;
    if (len > HTTP_JSON_MAX) {
        DEBUG_SERIAL.printf("[HTTP] response too large (%ld)\n", len);
        http_close();
        return false;
    }
    uint8_t buf[256];
    int n;
    while ((n = http_read(buf, sizeof(buf))) > 0) {
        if (respBody.length() + n > HTTP_JSON_MAX) { n = -1; break; }
        respBody.concat((const char*)buf, n);
    }
    http_close();
    if (n < 0) return false;
    DEBUG_SERIAL.printf("[HTTP] body: %s\n", respBody.c_str());
    return true;
}
