#!/usr/bin/env node
'use strict';
// Print the server registration public key as the line for firmware config.h:
//   npm run pubkey
// Creates <DATA_DIR>/server_reg_key.pem on first use (the server does the
// same at start). Run it on the production server and keep that file backed up.
const fs = require('fs');
const { loadConfig } = require('../src/config');
const { loadRegKey, pubFingerprint } = require('../src/regkey');

const cfg = loadConfig();
fs.mkdirSync(cfg.dataDir, { recursive: true });
const pub = loadRegKey(cfg.regKeyFile).publicKeyHex();
console.log(`// server ${pubFingerprint(pub)} (${cfg.regKeyFile})`);
console.log(`#define SERVER_REG_PUBKEY_HEX "${pub}"`);
