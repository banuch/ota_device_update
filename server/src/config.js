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
    autoRegister: (process.env.AUTO_REGISTER || 'true').toLowerCase() !== 'false',
    maxFirmwareBytes: Number(process.env.MAX_FIRMWARE_BYTES || 8 * 1024 * 1024),
    ...overrides,
  };
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

module.exports = { loadConfig, assertConfig };
