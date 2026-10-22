// =============================================================================
//  ota_client.ino  --  device-specific OTA: check -> download -> flash -> report
//
//  Protocol (server/src/routes/device.js):
//    POST /ota/check   {device_id, current_ver, ts, sig}
//         sig = HMAC(key, "<imei>|<current_ver>|<ts>")
//      <- {update_available, version, size, md5, download_token,
//          check_interval_s, reason, sig}
//         reply sig = HMAC(key, "<imei>|<ts>|<version>|<size>|<md5>|<token>")
//         -- verified here before anything is downloaded
//    GET  /ota/firmware?device_id=&token=      raw image, Content-Length set
//    POST /ota/report  {device_id, version, status, detail, ts, sig}
//         sig = HMAC(key, "<imei>|<version>|<status>|<ts>")
//
//  key = the 64-hex-char device key, received through automatic registration
//  (register.ino) or provisioned with "SET secret=...", used as ASCII bytes
//  (same as the server).
//
//  Flash safety: the image is streamed into the inactive OTA slot; the boot
//  partition is switched only after byte count, MD5, and esp_ota_end()'s own
//  image validation all pass. A failed download leaves the running image
//  untouched.
// =============================================================================
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <esp_ota_ops.h>
#include <Preferences.h>

// ── Crypto helpers ──────────────────────────────────────────────────────────
static String ota_toHex(const uint8_t* b, size_t n) {
    static const char* hx = "0123456789abcdef";
    String s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += hx[b[i] >> 4]; s += hx[b[i] & 0x0f]; }
    return s;
}

static String ota_hmac(const String& surface) {
    uint8_t out[32];
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info, (const uint8_t*)g_cfg.secret.c_str(), g_cfg.secret.length(),
                    (const uint8_t*)surface.c_str(), surface.length(), out);
    return ota_toHex(out, sizeof(out));
}

// Constant-time compare of two hex strings.
static bool ota_hexEqual(const String& a, const String& b) {
    if (a.length() != b.length() || a.length() == 0) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.length(); i++) diff |= (uint8_t)(tolower(a[i]) ^ tolower(b[i]));
    return diff == 0;
}

// ── Tiny JSON field extraction (flat objects from our own server only) ──────
static String ota_jsonStr(const String& body, const char* key) {
    String k = String("\"") + key + "\":\"";
    int i = body.indexOf(k);
    if (i == -1) return "";
    i += k.length();
    int e = body.indexOf('"', i);
    return e == -1 ? String("") : body.substring(i, e);
}

static long ota_jsonNum(const String& body, const char* key) {
    String k = String("\"") + key + "\":";
    int i = body.indexOf(k);
    if (i == -1) return -1;
    return body.substring(i + k.length()).toInt();
}

static bool ota_jsonTrue(const String& body, const char* key) {
    return body.indexOf(String("\"") + key + "\":true") != -1;
}

// ── Pending-version marker (survives the reboot into the new image) ─────────
static void ota_setPending(const String& ver) {
    Preferences p;
    p.begin(NVS_NAMESPACE, false);
    if (ver.length()) p.putString(K_PENDING_VER, ver);
    else p.remove(K_PENDING_VER);
    p.end();
}

static String ota_getPending() {
    Preferences p;
    p.begin(NVS_NAMESPACE, true);
    String v = p.isKey(K_PENDING_VER) ? p.getString(K_PENDING_VER, "") : String("");
    p.end();
    return v;
}

// ── Preconditions shared by every signed call ───────────────────────────────
static bool ota_ready(uint32_t& ts) {
    if (g_cfg.secret.length() != 64) {
        g_ota.lastResult = "no_device_key";
        DEBUG_SERIAL.println("[OTA] Device key not provisioned -- registration pending or SET secret=<64 hex>");
        return false;
    }
    if (g_ota.imei.isEmpty()) {
        g_ota.lastResult = "no_imei";
        return false;
    }
    ts = modem_epochSeconds();
    if (ts == 0) {
        g_ota.lastResult = "clock_not_synced";
        DEBUG_SERIAL.println("[OTA] Network clock not synced yet -- cannot sign");
        return false;
    }
    return true;
}

// ── POST /ota/report ────────────────────────────────────────────────────────
static bool ota_report(const String& version, const char* status, const String& detail) {
    uint32_t ts;
    if (!ota_ready(ts)) return false;
    String sig = ota_hmac(g_ota.imei + "|" + version + "|" + status + "|" + String(ts));
    String safeDetail = detail;
    safeDetail.replace("\\", "/");
    safeDetail.replace("\"", "'");
    String body = String("{\"device_id\":\"") + g_ota.imei + "\",\"version\":\"" + version +
                  "\",\"status\":\"" + status + "\",\"detail\":\"" + safeDetail +
                  "\",\"ts\":" + String(ts) + ",\"sig\":\"" + sig + "\"}";
    int code;
    String resp;
    bool ok = http_requestJson("POST", "/ota/report", body, code, resp) && code == 200;
    DEBUG_SERIAL.printf("[OTA] report %s %s -> %s\n", version.c_str(), status, ok ? "ok" : "failed");
    return ok;
}

// ── POST /ota/check ─────────────────────────────────────────────────────────
static bool ota_check(OtaOffer& offer) {
    uint32_t ts;
    if (!ota_ready(ts)) return false;
    String sig = ota_hmac(g_ota.imei + "|" FW_VERSION "|" + String(ts));
    String body = String("{\"device_id\":\"") + g_ota.imei + "\",\"current_ver\":\"" FW_VERSION
                  "\",\"ts\":" + String(ts) + ",\"sig\":\"" + sig + "\"}";
    int code;
    String resp;
    if (!http_requestJson("POST", "/ota/check", body, code, resp)) {
        g_ota.lastResult = "check_network_error";
        return false;
    }
    if (code != 200) {
        String err = ota_jsonStr(resp, "error");
        g_ota.lastResult = "check_rejected:" + (err.length() ? err : String(code));
        DEBUG_SERIAL.printf("[OTA] check rejected: HTTP %d %s\n", code, err.c_str());
        return false;
    }

    long interval = ota_jsonNum(resp, "check_interval_s");
    offer.intervalS = interval > 0 ? (uint32_t)interval : 0;
    offer.reason = ota_jsonStr(resp, "reason");
    offer.available = ota_jsonTrue(resp, "update_available");
    if (!offer.available) return true;

    offer.version = ota_jsonStr(resp, "version");
    long size = ota_jsonNum(resp, "size");
    offer.size = size > 0 ? (uint32_t)size : 0;
    offer.md5 = ota_jsonStr(resp, "md5");
    offer.token = ota_jsonStr(resp, "download_token");
    String replySig = ota_jsonStr(resp, "sig");

    String expected = ota_hmac(g_ota.imei + "|" + String(ts) + "|" + offer.version + "|" +
                               String(offer.size) + "|" + offer.md5 + "|" + offer.token);
    if (!ota_hexEqual(expected, replySig)) {
        DEBUG_SERIAL.println("[OTA] REJECTED: offer signature invalid (wrong server or tampered reply)");
        g_ota.lastResult = "offer_bad_signature";
        offer.available = false;
        return false;
    }
    if (offer.version.isEmpty() || offer.md5.length() != 32 || offer.token.isEmpty() ||
        offer.size < OTA_MIN_FW_SIZE) {
        DEBUG_SERIAL.println("[OTA] REJECTED: incomplete or implausible offer");
        g_ota.lastResult = "offer_invalid";
        offer.available = false;
        return false;
    }
    return true;
}

// ── GET /ota/firmware -> inactive OTA slot ──────────────────────────────────
// Returns "" on success (does not return: reboots), else a failure status.
static String ota_download(const OtaOffer& offer, String& detail) {
    const esp_partition_t* part = esp_ota_get_next_update_partition(NULL);
    if (!part) { detail = "no OTA partition"; return "failed"; }
    if (offer.size > part->size) {
        detail = "image " + String(offer.size) + " > slot " + String(part->size);
        return "failed";
    }

    String path = "/ota/firmware?device_id=" + g_ota.imei + "&token=" + offer.token;
    int code;
    long len;
    if (!http_open("GET", path, "", code, len)) { detail = "connect/headers failed"; return "failed"; }
    if (code != 200) { http_close(); detail = "HTTP " + String(code); return "failed"; }
    if (len != (long)offer.size) {
        http_close();
        detail = "content-length " + String(len) + " != offered " + String(offer.size);
        return "failed";
    }

    esp_ota_handle_t h;
    esp_err_t err = esp_ota_begin(part, offer.size, &h);
    if (err != ESP_OK) { http_close(); detail = String("ota_begin ") + esp_err_to_name(err); return "failed"; }
    DEBUG_SERIAL.printf("[OTA] Writing %lu bytes to %s @0x%06lx\n", (unsigned long)offer.size,
                        part->label, (unsigned long)part->address);

    mbedtls_md5_context md5;
    mbedtls_md5_init(&md5);
    mbedtls_md5_starts(&md5);

    static uint8_t buf[OTA_CHUNK_SIZE];
    uint32_t written = 0, lastPct = 101;
    uint32_t t0 = millis();
    int n;
    while ((n = http_read(buf, sizeof(buf))) > 0) {
        if ((err = esp_ota_write(h, buf, n)) != ESP_OK) break;
        mbedtls_md5_update(&md5, buf, n);
        written += n;
        uint32_t pct = (uint64_t)written * 100 / offer.size;
        if (pct / 5 != lastPct / 5) {
            lastPct = pct;
            DEBUG_SERIAL.printf("[OTA] %lu%%  %lu/%lu bytes  %lus\n", (unsigned long)pct,
                                (unsigned long)written, (unsigned long)offer.size,
                                (unsigned long)((millis() - t0) / 1000));
        }
    }
    http_close();

    uint8_t digest[16];
    mbedtls_md5_finish(&md5, digest);
    mbedtls_md5_free(&md5);

    if (err != ESP_OK) {
        esp_ota_abort(h);
        detail = String("ota_write ") + esp_err_to_name(err);
        return "failed";
    }
    if (written != offer.size) {
        esp_ota_abort(h);
        detail = "short download " + String(written) + "/" + String(offer.size);
        return "failed";
    }
    String got = ota_toHex(digest, 16);
    if (!ota_hexEqual(got, offer.md5)) {
        esp_ota_abort(h);
        detail = "md5 " + got + " != " + offer.md5;
        return "md5_fail";
    }
    if ((err = esp_ota_end(h)) != ESP_OK) {
        detail = String("ota_end ") + esp_err_to_name(err);   // image validation failed
        return "failed";
    }
    if ((err = esp_ota_set_boot_partition(part)) != ESP_OK) {
        detail = String("set_boot ") + esp_err_to_name(err);
        return "failed";
    }
    DEBUG_SERIAL.printf("[OTA] Image OK (md5 %s) in %lus\n", got.c_str(), (millis() - t0) / 1000);
    return "";
}

// ── Scheduling ──────────────────────────────────────────────────────────────
static void ota_scheduleNext(uint32_t seconds) {
    if (seconds < CHECK_INTERVAL_MIN_S) seconds = CHECK_INTERVAL_MIN_S;
    if (seconds > 20UL * 86400UL) seconds = 20UL * 86400UL;   // keep the int32 millis compare valid
    g_ota.nextCheckMs = millis() + seconds * 1000UL;
    DEBUG_SERIAL.printf("[OTA] Next check in %lu s\n", (unsigned long)seconds);
}

bool ota_isDue() {
    return g_ota.checkRequested || (int32_t)(millis() - g_ota.nextCheckMs) >= 0;
}

// ── Called once at boot, after the modem is up ──────────────────────────────
// If we just rebooted into a new image, tell the server whether it took.
void ota_reportBootResult() {
    String pending = ota_getPending();
    if (pending.isEmpty()) return;
    if (pending == FW_VERSION) {
        DEBUG_SERIAL.printf("[OTA] Now running %s -- confirming to server\n", FW_VERSION);
        if (ota_report(FW_VERSION, "running", "boot ok")) ota_setPending("");
    } else {
        DEBUG_SERIAL.printf("[OTA] Expected %s after update but running %s\n", pending.c_str(), FW_VERSION);
        if (ota_report(pending, "failed", String("booted ") + FW_VERSION + " instead")) ota_setPending("");
    }
}

// ── Public entry point (loop(), boot, CHECK_OTA command) ────────────────────
void ota_run() {
    g_ota.busy = true;
    g_ota.checkRequested = false;
    g_ota.lastCheckMs = millis();
    DEBUG_SERIAL.printf("\n[OTA] --- check (running %s, IMEI %s) ---\n", FW_VERSION, g_ota.imei.c_str());

    if (!g_ota.modemReady) {
        g_ota.modemReady = modem_init();
        if (!g_ota.modemReady) {
            g_ota.lastResult = "modem_not_ready";
            ota_scheduleNext(CHECK_RETRY_S);
            g_ota.busy = false;
            return;
        }
        ota_reportBootResult();
    }

    // No device key yet: ask the server for one (automatic registration).
    if (g_cfg.secret.length() != 64) {
        uint32_t wait = reg_run();
        if (wait) {
            ota_scheduleNext(wait);
            g_ota.busy = false;
            return;
        }
    }

    OtaOffer offer;
    if (!ota_check(offer)) {
        // Unprovisioned devices wait a full interval -- retrying won't help.
        bool permanent = g_ota.lastResult == "no_device_key" || g_ota.lastResult == "no_imei";
        if (g_ota.lastResult == "check_network_error") g_ota.modemReady = false;  // re-init next time
        ota_scheduleNext(permanent ? g_cfg.intervalS : CHECK_RETRY_S);
        g_ota.busy = false;
        return;
    }

    uint32_t interval = offer.intervalS ? offer.intervalS : g_cfg.intervalS;
    if (!offer.available) {
        g_ota.lastResult = "no_update:" + offer.reason;
        DEBUG_SERIAL.printf("[OTA] No update (%s)\n", offer.reason.c_str());
        ota_scheduleNext(interval);
        g_ota.busy = false;
        return;
    }

    g_ota.lastOfferVer = offer.version;
    DEBUG_SERIAL.printf("[OTA] Update %s -> %s (%lu bytes, %s)\n", FW_VERSION, offer.version.c_str(),
                        (unsigned long)offer.size, offer.reason.c_str());
    // The token is single-use and expires in minutes, so download first and
    // report afterwards (one socket at a time on the modem).
    g_ota.lastResult = "downloading:" + offer.version;
    String detail;
    String fail = ota_download(offer, detail);
    if (fail.isEmpty()) {
        ota_setPending(offer.version);
        ota_report(offer.version, "flashed", String(offer.size) + " bytes, md5 ok");
        g_ota.lastResult = "flashed:" + offer.version;
        DEBUG_SERIAL.println("[OTA] Rebooting into new firmware...");
        delay(1000);
        ESP.restart();
    }

    DEBUG_SERIAL.printf("[OTA] Update failed: %s (%s)\n", fail.c_str(), detail.c_str());
    g_ota.lastResult = fail + ":" + detail;
    ota_report(offer.version, fail.c_str(), detail);
    ota_scheduleNext(CHECK_RETRY_S);
    g_ota.busy = false;
}
