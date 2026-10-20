'use strict';
// =============================================================================
//  routes/admin.js  --  release / channel / device management
//  All routes require  Authorization: Bearer <ADMIN_TOKEN>
//
//    GET    /api/releases                     list
//    POST   /api/releases   multipart: file, version, notes   upload
//    DELETE /api/releases/:version            (refused while a channel/pin uses it)
//    GET    /api/channels
//    PUT    /api/channels/:name   {version|null}
//    GET    /api/devices
//    POST   /api/devices          {imei, label?, channel?}    pre-register
//    PATCH  /api/devices/:imei    {label, channel, pinned_version,
//                                  check_interval_s, enabled}
//    DELETE /api/devices/:imei
//    GET    /api/devices/:imei/key            provisioning key for this IMEI
//    GET    /api/events?imei=&limit=
// =============================================================================
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { safeEqualHex, deviceKey } = require('../hmac');
const { isValidVersion } = require('../resolver');

const IMEI_RE = /^\d{14,17}$/;
const ESP_IMAGE_MAGIC = 0xe9;

function adminRoutes({ store, cfg }) {
  const r = express.Router();
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: cfg.maxFirmwareBytes, files: 1 },
  });

  r.use((req, res, next) => {
    const h = req.get('authorization') || '';
    const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
    const want = crypto.createHash('sha256').update(cfg.adminToken).digest('hex');
    const got = crypto.createHash('sha256').update(tok).digest('hex');
    if (!tok || !safeEqualHex(want, got)) return res.status(401).json({ error: 'unauthorized' });
    next();
  });
  r.use(express.json({ limit: '16kb' }));

  const bad = (res, error, status = 400) => res.status(status).json({ error });
  const channelExists = (name) => !!store.getChannel(name);

  // ── releases ────────────────────────────────────────────────────────────
  r.get('/releases', (req, res) => res.json(store.listReleases()));

  r.post('/releases', upload.single('file'), (req, res) => {
    const version = String((req.body && req.body.version) || '').trim();
    const notes = String((req.body && req.body.notes) || '');
    if (!isValidVersion(version)) return bad(res, 'version must be MAJOR.MINOR.PATCH');
    if (store.getRelease(version)) return bad(res, 'version already exists', 409);
    if (!req.file || !req.file.buffer.length) return bad(res, 'file is required');
    const buf = req.file.buffer;
    if (buf[0] !== ESP_IMAGE_MAGIC) return bad(res, 'not an ESP32 app image (magic byte 0xE9 missing)');

    const md5 = crypto.createHash('md5').update(buf).digest('hex');
    const file = `fw_${version}.bin`;
    fs.mkdirSync(cfg.firmwareDir, { recursive: true });
    fs.writeFileSync(path.join(cfg.firmwareDir, file), buf);
    store.addRelease({ version, file, size: buf.length, md5, notes });
    res.status(201).json(store.getRelease(version));
  });

  r.delete('/releases/:version', (req, res) => {
    const rel = store.getRelease(req.params.version);
    if (!rel) return bad(res, 'not found', 404);
    const use = store.releaseUsage(rel.version);
    if (use.channels || use.pins) {
      return bad(res, `release in use by ${use.channels} channel(s) and ${use.pins} pinned device(s)`, 409);
    }
    store.deleteRelease(rel.version);
    fs.rmSync(path.join(cfg.firmwareDir, rel.file), { force: true });
    res.json({ ok: true });
  });

  // ── channels ────────────────────────────────────────────────────────────
  r.get('/channels', (req, res) => res.json(store.listChannels()));

  r.put('/channels/:name', (req, res) => {
    if (!channelExists(req.params.name)) return bad(res, 'unknown channel', 404);
    const version = req.body ? req.body.version : undefined;
    if (version !== null && !store.getRelease(String(version))) return bad(res, 'unknown release');
    store.setChannel(req.params.name, version);
    res.json(store.getChannel(req.params.name));
  });

  // ── devices ─────────────────────────────────────────────────────────────
  r.get('/devices', (req, res) => res.json(store.listDevices()));

  r.post('/devices', (req, res) => {
    const { imei, label = '', channel = 'stable' } = req.body || {};
    if (!IMEI_RE.test(String(imei || ''))) return bad(res, 'imei must be 14-17 digits');
    if (!channelExists(channel)) return bad(res, 'unknown channel');
    if (store.getDevice(imei)) return bad(res, 'device already exists', 409);
    store.addDevice({ imei, label: String(label), channel });
    store.logEvent(imei, 'registered', null, 'added by admin');
    res.status(201).json(store.getDevice(imei));
  });

  r.patch('/devices/:imei', (req, res) => {
    const dev = store.getDevice(req.params.imei);
    if (!dev) return bad(res, 'not found', 404);
    const b = req.body || {};
    const fields = {};
    if ('label' in b) fields.label = String(b.label);
    if ('channel' in b) {
      if (!channelExists(b.channel)) return bad(res, 'unknown channel');
      fields.channel = b.channel;
    }
    if ('pinned_version' in b) {
      if (b.pinned_version !== null && !store.getRelease(String(b.pinned_version))) {
        return bad(res, 'unknown release');
      }
      fields.pinned_version = b.pinned_version;
    }
    if ('check_interval_s' in b) {
      const n = b.check_interval_s;
      if (n !== null && !(Number.isInteger(n) && n >= 300 && n <= 30 * 86400)) {
        return bad(res, 'check_interval_s must be null or 300..2592000');
      }
      fields.check_interval_s = n;
    }
    if ('enabled' in b) fields.enabled = b.enabled ? 1 : 0;
    store.updateDevice(dev.imei, fields);
    store.logEvent(dev.imei, 'admin_update', fields.pinned_version || null, JSON.stringify(fields));
    res.json(store.getDevice(dev.imei));
  });

  r.delete('/devices/:imei', (req, res) => {
    if (!store.deleteDevice(req.params.imei)) return bad(res, 'not found', 404);
    res.json({ ok: true });
  });

  r.get('/devices/:imei/key', (req, res) => {
    if (!IMEI_RE.test(req.params.imei)) return bad(res, 'imei must be 14-17 digits');
    res.json({ imei: req.params.imei, device_key: deviceKey(cfg.masterSecret, req.params.imei) });
  });

  // ── events ──────────────────────────────────────────────────────────────
  r.get('/events', (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    res.json(store.listEvents(req.query.imei ? String(req.query.imei) : null, limit));
  });

  // multer / JSON errors -> JSON
  r.use((err, req, res, next) => {
    if (err && err.code === 'LIMIT_FILE_SIZE') return bad(res, 'file too large', 413);
    if (err) return bad(res, err.message || 'bad request');
    next();
  });

  return r;
}

module.exports = { adminRoutes };
