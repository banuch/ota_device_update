'use strict';
// =============================================================================
//  regkey.js  --  server registration key (P-256) and device-key wrapping
//
//  Automatic registration (POST /ota/register) hands a device its key over
//  plain TCP, so the key is never sent in clear:
//
//    device:  ephemeral P-256 pair (d_dev, Q_dev), sends Q_dev
//    server:  static  P-256 pair (d_srv, Q_srv), Q_srv compiled into firmware
//    z    = ECDH(d_srv, Q_dev) = ECDH(d_dev, Q_srv)      (32 bytes, x coord)
//    k    = SHA256(z || imei)
//    ct   = AES-256-GCM(k, iv, device_key_hex, aad = imei)
//
//  Only that device can decrypt it, and only the holder of d_srv can produce
//  a tag the device accepts. Must match firmware register.ino exactly.
//
//  The key lives in <DATA_DIR>/server_reg_key.pem (created on first start).
//  Back it up: losing it means firmware with the old public key can no
//  longer register (already registered devices are unaffected).
// =============================================================================
const crypto = require('crypto');
const fs = require('fs');

const PUB_HEX_RE = /^04[0-9a-f]{128}$/;

function loadRegKey(file) {
  let pem;
  if (fs.existsSync(file)) {
    pem = fs.readFileSync(file, 'utf8');
  } else {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.writeFileSync(file, pem, { mode: 0o600 });
  }
  const jwk = crypto.createPrivateKey(pem).export({ format: 'jwk' });
  if (jwk.crv !== 'P-256') throw new Error(`${file}: not a P-256 key`);
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(jwk.d, 'base64url'));

  return {
    /** Uncompressed public point, 130 lower-case hex chars ("04" + x + y). */
    publicKeyHex: () => ecdh.getPublicKey('hex', 'uncompressed'),
    /**
     * Encrypt keyHex for the device that owns devicePubHex.
     * @returns {{iv:string, ct:string, tag:string}|null}  null = invalid point
     */
    wrapDeviceKey: (devicePubHex, imei, keyHex) => {
      let z;
      try {
        z = ecdh.computeSecret(Buffer.from(devicePubHex, 'hex'));
      } catch {
        return null;
      }
      const k = crypto.createHash('sha256').update(z).update(String(imei)).digest();
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', k, iv);
      c.setAAD(Buffer.from(String(imei)));
      const ct = Buffer.concat([c.update(keyHex, 'utf8'), c.final()]);
      return { iv: iv.toString('hex'), ct: ct.toString('hex'), tag: c.getAuthTag().toString('hex') };
    },
  };
}

/** Short fingerprint shown on the device (GET_STATUS) and in the dashboard. */
function pubFingerprint(pubHex) {
  if (!pubHex) return null;
  return crypto.createHash('sha256').update(Buffer.from(pubHex, 'hex')).digest('hex').slice(0, 8);
}

/** Valid uncompressed P-256 point? */
function isValidPub(pubHex) {
  if (!PUB_HEX_RE.test(String(pubHex || ''))) return false;
  try {
    crypto.ECDH.convertKey(pubHex, 'prime256v1', 'hex', 'hex', 'uncompressed');
    return true;
  } catch {
    return false;
  }
}

module.exports = { loadRegKey, pubFingerprint, isValidPub };
