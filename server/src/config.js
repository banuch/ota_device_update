'use strict';
// =============================================================================
//  config.js  --  runtime configuration from environment / .env
//
//  Tiny .env loader (KEY=VALUE lines, # comments) so the server has no
//  dotenv dependency. Real environment variables win over .env values.
// =============================================================================
const fs = require('fs');
const path = require('path');

function loadDotEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
}

/**
 * REGISTRATION_MODE: approval (default) | auto | off.
 * Older .env files may still have AUTO_REGISTER=false, which means off.
 */
function parseRegistrationMode(mode, autoRegister) {
  const m = String(mode || '').trim().toLowerCase();
  if (['approval', 'auto', 'off'].includes(m)) return m;
  if (m) throw new Error(`REGISTRATION_MODE must be approval, auto or off (got '${mode}')`);
  return String(autoRegister || '').toLowerCase() === 'false' ? 'off' : 'approval';
}

/** Express wants a boolean or hop count as such; any other string is an IP/subnet list. */
function parseTrustProxy(v) {
  const s = String(v || '').trim();
  if (!s || s.toLowerCase() === 'false') return '';
  if (s.toLowerCase() === 'true') return true;
  if (/^\d+$/.test(s)) return Number(s);
  return s;
}

function loadConfig(overrides = {}) {
  loadDotEnv(path.join(__dirname, '..', '.env'));
  const dataDir = overrides.dataDir || process.env.DATA_DIR || path.join(__dirname, '..', 'data');
  const cfg = {
    port: Number(process.env.PORT || 8080),
    masterSecret: process.env.MASTER_SECRET || '',
    adminToken: process.env.ADMIN_TOKEN || '',
    dataDir,
    dbFile: path.join(dataDir, 'ota.db'),
    firmwareDir: path.join(dataDir, 'firmware'),
    tsWindowSec: Number(process.env.TS_WINDOW_SEC || 300),
    tokenTtlSec: Number(process.env.TOKEN_TTL_SEC || 600),
    defaultIntervalSec: Number(process.env.DEFAULT_CHECK_INTERVAL_SEC || 86400),
    // Automatic registration (POST /ota/register) -- see regkey.js
    registrationMode: parseRegistrationMode(process.env.REGISTRATION_MODE, process.env.AUTO_REGISTER),
    registerMaxPending: Number(process.env.REGISTER_MAX_PENDING || 500),
    registerPollSec: Number(process.env.REGISTER_POLL_SEC || 600),
    regKeyFile: path.join(dataDir, 'server_reg_key.pem'),
    maxFirmwareBytes: Number(process.env.MAX_FIRMWARE_BYTES || 8 * 1024 * 1024),
    // Dashboard login
    sessionIdleSec: Number(process.env.SESSION_IDLE_SEC || 8 * 3600),
    sessionMaxSec: Number(process.env.SESSION_MAX_SEC || 24 * 3600),
    loginMaxFails: Number(process.env.LOGIN_MAX_FAILS || 5),
    loginLockSec: Number(process.env.LOGIN_LOCK_SEC || 15 * 60),
    // auto = Secure flag only when the request arrived over HTTPS; always / never
    cookieSecure: (process.env.COOKIE_SECURE || 'auto').toLowerCase(),
    // e.g. "loopback" when running behind nginx on the same host
    trustProxy: parseTrustProxy(process.env.TRUST_PROXY),
    clock: Date.now,
    ...overrides,
  };
  // A signed /ota/check from an unknown IMEI (manually provisioned key)
  // creates the device unless registration is off.
  if (!('autoRegister' in overrides)) cfg.autoRegister = cfg.registrationMode !== 'off';
  return cfg;
}

function assertConfig(cfg) {
  const problems = [];
  if (cfg.masterSecret.length < 16) problems.push('MASTER_SECRET must be at least 16 characters');
  if (cfg.adminToken.length < 12) problems.push('ADMIN_TOKEN must be at least 12 characters');
  if (problems.length) {
    throw new Error('Invalid configuration:\n  - ' + problems.join('\n  - ') +
      '\nCopy .env.example to .env and fill it in.');
  }
}

module.exports = { loadConfig, assertConfig, parseTrustProxy, parseRegistrationMode };
