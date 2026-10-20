'use strict';
// =============================================================================
//  routes/device.js  --  endpoints called by the ESP32 over EC200U TCP
//
//    POST /ota/check     {device_id, current_ver, ts, sig}
//         -> {update_available, version, size, md5, download_token,
//             check_interval_s, reason, sig}
//         sig (only when update_available) = HMAC_SHA256(device_key,
//             "<imei>|<req ts>|<version>|<size>|<md5>|<download_token>")
//         The device verifies it before downloading, so a rogue server
//         (no MASTER_SECRET) cannot push an image, and an old genuine
//         offer cannot be replayed (bound to the device's own request ts).
//    GET  /ota/firmware?device_id=&token=   -> raw .bin (Content-Length set,
//                                              never chunked)
//    POST /ota/report    {device_id, version, status, detail, ts, sig}
//         -> {ok:true}
//
//  Responses are flat JSON with Content-Length (the firmware's HTTP parser
//  does not support chunked transfer encoding).
// =============================================================================
const express = require('express');
const fs = require('fs');
const path = require('path');
const { verifyRequest, deviceKey, sign } = require('../hmac');
const { resolveTarget } = require('../resolver');

const REPORT_STATUSES = new Set(['downloading', 'flashed', 'md5_fail', 'failed', 'running']);

function deviceRoutes({ store, cfg, replayGuard }) {
  const r = express.Router();
  r.use(express.json({ limit: '4kb' }));

  const fail = (res, status, error) => res.status(status).json({ error });

  const verify = (body, surface) =>
    verifyRequest({
      masterSecret: cfg.masterSecret,
      imei: body.device_id,
      surface,
      ts: body.ts,
      sig: body.sig,
      windowSec: cfg.tsWindowSec,
      replayGuard,
    });

  r.post('/check', (req, res) => {
    const b = req.body || {};
    const imei = String(b.device_id || '');
    const currentVer = String(b.current_ver || '');
    const v = verify(b, `${imei}|${currentVer}|${b.ts}`);
    if (!v.ok) return fail(res, v.status, v.error);

    let device = store.getDevice(imei);
    if (!device) {
      if (!cfg.autoRegister) return fail(res, 403, 'unknown_device');
      store.addDevice({ imei });
      store.logEvent(imei, 'registered', currentVer);
      device = store.getDevice(imei);
    }
    store.touchDevice(imei, currentVer, req.socket.remoteAddress);
    const interval = device.check_interval_s || cfg.defaultIntervalSec;

    const noUpdate = (reason) =>
      res.json({ update_available: false, check_interval_s: interval, reason });

    if (!device.enabled) return noUpdate('device_disabled');

    const { target, reason } = resolveTarget(device, currentVer, store.channelVersion);
    if (!target) return noUpdate(reason);

    const rel = store.getRelease(target);
    if (!rel || !fs.existsSync(path.join(cfg.firmwareDir, rel.file))) {
      store.logEvent(imei, 'error', target, 'release file missing');
      return noUpdate('release_missing');
    }

    const token = store.issueToken(imei, rel.version, cfg.tokenTtlSec);
    store.logEvent(imei, 'offered', rel.version, `${currentVer} -> ${rel.version} (${reason})`);
    const offerSig = sign(deviceKey(cfg.masterSecret, imei),
      `${imei}|${b.ts}|${rel.version}|${rel.size}|${rel.md5}|${token}`);
    return res.json({
      update_available: true,
      version: rel.version,
      size: rel.size,
      md5: rel.md5,
      download_token: token,
      check_interval_s: interval,
      reason,
      sig: offerSig,
    });
  });

  r.get('/firmware', (req, res) => {
    const imei = String(req.query.device_id || '');
    const token = String(req.query.token || '');
    const t = store.consumeToken(token, imei);
    if (t.error) {
      if (imei) store.logEvent(imei, 'denied', null, t.error);
      return fail(res, t.error === 'invalid_token' ? 401 : 410, t.error);
    }
    const rel = store.getRelease(t.row.version);
    const file = rel && path.join(cfg.firmwareDir, rel.file);
    if (!rel || !fs.existsSync(file)) return fail(res, 404, 'release_missing');

    store.logEvent(imei, 'download_start', rel.version, `${rel.size} bytes`);
    res.status(200).set({
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(rel.size),
      'X-Firmware-Version': rel.version,
      'X-Firmware-MD5': rel.md5,
      'Cache-Control': 'no-store',
    });
    const stream = fs.createReadStream(file);
    let finished = false;
    res.on('finish', () => {
      finished = true;
      store.logEvent(imei, 'download_sent', rel.version);
    });
    res.on('close', () => {
      if (!finished) {
        stream.destroy();
        store.logEvent(imei, 'download_aborted', rel.version, 'connection closed early');
      }
    });
    stream.pipe(res);
  });

  r.post('/report', (req, res) => {
    const b = req.body || {};
    const imei = String(b.device_id || '');
    const version = String(b.version || '');
    const status = String(b.status || '');
    const v = verify(b, `${imei}|${version}|${status}|${b.ts}`);
    if (!v.ok) return fail(res, v.status, v.error);
    if (!REPORT_STATUSES.has(status)) return fail(res, 400, 'bad_status');
    if (!store.getDevice(imei)) return fail(res, 404, 'unknown_device');

    store.setDeviceStatus(imei, status, status === 'running' ? version : null);
    store.logEvent(imei, status, version, b.detail || '');
    return res.json({ ok: true });
  });

  return r;
}

module.exports = { deviceRoutes };
