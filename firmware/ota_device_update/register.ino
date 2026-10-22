// =============================================================================
//  register.ino  --  automatic registration: get the device key by IMEI,
//                    without "SET secret=..."
//
//  Protocol (server/src/routes/device.js, server/src/regkey.js):
//    POST /ota/register  {device_id, current_ver, pub}
//      <- {status:"pending", retry_s}          wait for an admin to approve
//      <- {status:"approved", iv, ct, tag}     our device key, encrypted
//      <- 403 registration_rejected / registration_off
//
//  pub = our P-256 public key (65 bytes uncompressed, hex). The key pair is
//  made once and kept in NVS (K_REG_KEY) so it stays the same across reboots
//  while we wait, then erased once the device key is saved.
//
//    z  = ECDH(our private key, SERVER_REG_PUBKEY_HEX)     32 bytes
//    k  = SHA256(z || imei)
//    key = AES-256-GCM-decrypt(k, iv, ct, tag, aad = imei)  -> 64 hex chars
//
//  The device key never crosses the network in clear, and a reply only
//  decrypts if it came from the server holding the matching private key.
//  The dashboard shows the fingerprint (first 8 hex of SHA256(pub)); compare
//  it with GET_STATUS before approving.
// =============================================================================
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <esp_random.h>
#include <Preferences.h>

static String s_regState = "none";   // none | pending | approved | rejected | off | error
static String s_regFp;               // fingerprint of our registration key

static int reg_rng(void*, unsigned char* out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

static uint8_t reg_hexNibble(char c) {
    return isdigit(c) ? c - '0' : (uint8_t)(tolower(c) - 'a' + 10);
}

static bool reg_hexToBytes(const String& hex, uint8_t* out, size_t n) {
    if (hex.length() != n * 2) return false;
    for (size_t i = 0; i < n; i++) {
        char hi = hex[2 * i], lo = hex[2 * i + 1];
        if (!isxdigit(hi) || !isxdigit(lo)) return false;
        out[i] = (reg_hexNibble(hi) << 4) | reg_hexNibble(lo);
    }
    return true;
}

static String reg_fingerprintOf(const uint8_t pub[65]) {
    uint8_t h[32];
    mbedtls_sha256(pub, 65, h, 0);
    return ota_toHex(h, 4);
}

// ── Key pair in NVS: 32-byte private key + 65-byte public key ───────────────
static bool reg_loadKeyPair(uint8_t priv[32], uint8_t pub[65]) {
    uint8_t blob[97];
    Preferences p;
    p.begin(NVS_NAMESPACE, true);
    size_t n = p.isKey(K_REG_KEY) ? p.getBytes(K_REG_KEY, blob, sizeof(blob)) : 0;
    p.end();
    if (n != sizeof(blob)) return false;
    memcpy(priv, blob, 32);
    memcpy(pub, blob + 32, 65);
    memset(blob, 0, sizeof(blob));
    return true;
}

static bool reg_createKeyPair(uint8_t priv[32], uint8_t pub[65]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    size_t olen = 0;
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_ecp_gen_keypair(&grp, &d, &Q, reg_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65) == 0 &&
              olen == 65;
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    if (!ok) return false;

    uint8_t blob[97];
    memcpy(blob, priv, 32);
    memcpy(blob + 32, pub, 65);
    Preferences p;
    p.begin(NVS_NAMESPACE, false);
    ok = p.putBytes(K_REG_KEY, blob, sizeof(blob)) == sizeof(blob);
    p.end();
    memset(blob, 0, sizeof(blob));
    return ok;
}

static void reg_eraseKeyPair() {
    Preferences p;
    p.begin(NVS_NAMESPACE, false);
    p.remove(K_REG_KEY);
    p.end();
}

// k = SHA256(ECDH(priv, server pub) || imei)
static bool reg_sessionKey(const uint8_t priv[32], uint8_t k[32]) {
    uint8_t srv[65];
    if (!reg_hexToBytes(SERVER_REG_PUBKEY_HEX, srv, sizeof(srv))) return false;

    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Qs;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Qs);
    uint8_t zb[32];
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &Qs, srv, sizeof(srv)) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &Qs) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &Qs, &d, reg_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&z, zb, sizeof(zb)) == 0;
    mbedtls_ecp_point_free(&Qs);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    if (!ok) return false;

    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, zb, sizeof(zb));
    mbedtls_sha256_update(&c, (const uint8_t*)g_ota.imei.c_str(), g_ota.imei.length());
    mbedtls_sha256_finish(&c, k);
    mbedtls_sha256_free(&c);
    memset(zb, 0, sizeof(zb));
    return true;
}

// Decrypt the device key from an "approved" reply. Returns "" on any failure.
static String reg_unwrap(const uint8_t priv[32], const String& resp) {
    uint8_t iv[12], tag[16], ct[64], pt[65], k[32];
    if (!reg_hexToBytes(ota_jsonStr(resp, "iv"), iv, sizeof(iv)) ||
        !reg_hexToBytes(ota_jsonStr(resp, "tag"), tag, sizeof(tag)) ||
        !reg_hexToBytes(ota_jsonStr(resp, "ct"), ct, sizeof(ct))) return "";
    if (!reg_sessionKey(priv, k)) return "";

    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, k, 256) == 0 &&
              mbedtls_gcm_auth_decrypt(&g, sizeof(ct), iv, sizeof(iv),
                                       (const uint8_t*)g_ota.imei.c_str(), g_ota.imei.length(),
                                       tag, sizeof(tag), ct, pt) == 0;
    mbedtls_gcm_free(&g);
    memset(k, 0, sizeof(k));
    if (!ok) return "";
    pt[64] = 0;
    String key((const char*)pt);
    memset(pt, 0, sizeof(pt));
    return key;
}

// ── Public ──────────────────────────────────────────────────────────────────
// For GET_STATUS: "reg=<state> fp=<fingerprint>".
String reg_statusLine() {
    if (g_cfg.secret.length() == 64) return "reg=provisioned";
    if (s_regFp.isEmpty()) {
        uint8_t priv[32], pub[65];
        if (reg_loadKeyPair(priv, pub)) s_regFp = reg_fingerprintOf(pub);
        memset(priv, 0, sizeof(priv));
    }
    return "reg=" + s_regState + " fp=" + (s_regFp.length() ? s_regFp : String("-"));
}

// Ask the server for our device key. Returns 0 once the key is saved,
// otherwise the number of seconds to wait before asking again.
uint32_t reg_run() {
    if (strlen(SERVER_REG_PUBKEY_HEX) != 130) {
        s_regState = "off";
        g_ota.lastResult = "no_device_key";
        DEBUG_SERIAL.println("[REG] SERVER_REG_PUBKEY_HEX not set in config.h -- use SET secret=<64 hex>");
        return g_cfg.intervalS;
    }
    if (g_ota.imei.isEmpty()) {
        g_ota.lastResult = "no_imei";
        return CHECK_RETRY_S;
    }

    uint8_t priv[32], pub[65];
    if (!reg_loadKeyPair(priv, pub) && !reg_createKeyPair(priv, pub)) {
        s_regState = "error";
        g_ota.lastResult = "register_keygen_failed";
        DEBUG_SERIAL.println("[REG] Could not create the registration key pair");
        return CHECK_RETRY_S;
    }
    s_regFp = reg_fingerprintOf(pub);

    String body = String("{\"device_id\":\"") + g_ota.imei + "\",\"current_ver\":\"" FW_VERSION
                  "\",\"pub\":\"" + ota_toHex(pub, sizeof(pub)) + "\"}";
    int code;
    String resp;
    if (!http_requestJson("POST", "/ota/register", body, code, resp)) {
        memset(priv, 0, sizeof(priv));
        g_ota.lastResult = "register_network_error";
        g_ota.modemReady = false;   // re-init next time
        return CHECK_RETRY_S;
    }
    if (code != 200) {
        memset(priv, 0, sizeof(priv));
        String err = ota_jsonStr(resp, "error");
        g_ota.lastResult = "register_rejected:" + (err.length() ? err : String(code));
        DEBUG_SERIAL.printf("[REG] HTTP %d %s\n", code, err.c_str());
        if (code == 403) {
            s_regState = err == "registration_off" ? "off" : "rejected";
            return g_cfg.intervalS;     // an admin has to act; don't hammer the server
        }
        return CHECK_RETRY_S;           // 429 too_frequent, 503 queue full, ...
    }

    String status = ota_jsonStr(resp, "status");
    if (status == "approved") {
        String key = reg_unwrap(priv, resp);
        memset(priv, 0, sizeof(priv));
        String err = key.length() ? cfg_set("secret", key) : String("reply did not decrypt");
        key = "";
        if (err.length()) {
            s_regState = "error";
            g_ota.lastResult = "register_bad_reply";
            DEBUG_SERIAL.printf("[REG] REJECTED approved reply: %s (wrong SERVER_REG_PUBKEY_HEX?)\n", err.c_str());
            return CHECK_RETRY_S;
        }
        reg_eraseKeyPair();
        s_regState = "approved";
        DEBUG_SERIAL.println("[REG] Device key received and saved");
        return 0;
    }
    memset(priv, 0, sizeof(priv));

    s_regState = "pending";
    g_ota.lastResult = "awaiting_approval";
    long retry = ota_jsonNum(resp, "retry_s");
    uint32_t wait = retry > 0 ? (uint32_t)retry : REGISTER_POLL_S;
    if (wait < CHECK_INTERVAL_MIN_S) wait = CHECK_INTERVAL_MIN_S;
    if (wait > 3600UL) wait = 3600UL;
    DEBUG_SERIAL.printf("[REG] Waiting for approval in the dashboard -- IMEI %s, key fingerprint %s\n",
                        g_ota.imei.c_str(), s_regFp.c_str());
    return wait;
}
