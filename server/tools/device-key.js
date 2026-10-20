#!/usr/bin/env node
'use strict';
// Print the provisioning key for one or more IMEIs:
//   node tools/device-key.js 868123456789012 [more IMEIs...]
// Paste the result into the device:  SET secret=<key>
const { loadConfig, assertConfig } = require('../src/config');
const { deviceKey } = require('../src/hmac');

const cfg = loadConfig();
assertConfig(cfg);
const imeis = process.argv.slice(2);
if (!imeis.length) {
  console.error('usage: node tools/device-key.js <imei> [imei...]');
  process.exit(2);
}
for (const imei of imeis) {
  if (!/^\d{14,17}$/.test(imei)) {
    console.error(`${imei}: not a valid IMEI`);
    process.exitCode = 1;
    continue;
  }
  console.log(`${imei}  ${deviceKey(cfg.masterSecret, imei)}`);
}
