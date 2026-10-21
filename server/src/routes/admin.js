'use strict';
// =============================================================================
//  routes/admin.js  --  release / channel / device management
//  Auth: dashboard session (admin = read/write, viewer = read-only) or
//        Authorization: Bearer <ADMIN_TOKEN> (admin) -- see auth.js.
//
//    GET    /api/stats                        overview numbers
//    GET    /api/releases                     list (+ channels / pinned / running usage)
//    POST   /api/releases   multipart: file, version, notes   upload
//    DELETE /api/releases/:version            (refused while a channel/pin uses it)
//    GET    /api/channels
//    PUT    /api/channels/:name   {version|null}
//    GET    /api/devices                      list (+ online, target, pending)
//    GET    /api/devices/:imei                one device + its last 50 events
//    POST   /api/devices          {imei, label?, channel?}    pre-register
//    PATCH  /api/devices/:imei    {label, channel, pinned_version,
//                                  check_interval_s, enabled}
//    POST   /api/devices/bulk     {imeis:[...], set:{channel|pinned_version|enabled|check_interval_s}}
//    DELETE /api/devices/:imei
//    GET    /api/devices/:imei/key            provisioning key (admin only)
//    GET    /api/events?imei=&type=&actor=&before=&limit=
// =============================================================================
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { deviceKey } = require('../hmac');
const { isValidVersion, resolveTarget } = require('../resolver');

const IMEI_RE = /^\d{14,17}$/;
const ESP_IMAGE_MAGIC = 0xe9;
const ONLINE_GRACE_SEC = 15 * 60;
const BULK_MAX = 1000;

function adminRoutes({ store, cfg, auth }) {
  const r = express.Router();
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: cfg.maxFirmwareBytes, files: 1 },
  });

  r.use(auth.requireApi);
  r.use(express.json({ limit: '64kb' }));

  const bad = (res, error, status = 400) => res.status(status).json({ error });
  const channelExists = (name) => !!store.getChannel(name);
  const actor = (req) => req.actor.username;

  // Adds computed state the UI filters on.
  function decorate(d) {
    const now = store.now();
    const interval = d.check_interval_s || cfg.defaultIntervalSec;
    const online = !!d.last_seen && now - d.last_seen <= interval + ONLINE_GRACE_SEC;
    let target = null;
    let reason = 'never_checked';
    if (d.current_ver) ({ target, reason } = resolveTarget(d, d.current_ver, store.channelVersion));
    if (!d.enabled) reason = 'device_disabled';
    return { ...d, online, effective_interval_s: interval, target, target_reason: reason,
      pending: !!(d.enabled && target) };
  }

  /** Validates a device field patch. Returns {fields} or {error}. */
  function validateDeviceFields(b, { allowLabel = true } = {}) {
    const fields = {};
    if (allowLabel && 'label' in b) fields.label = String(b.label).slice(0, 64);
    if ('channel' in b) {
      if (!channelExists(b.channel)) return { error: 'unknown channel' };
      fields.channel = b.channel;
    }
    if ('pinned_version' in b) {
      if (b.pinned_version !== null && !store.getRelease(String(b.pinned_version))) {
        return { error: 'unknown release' };
      }
      fields.pinned_version = b.pinned_version;
    }
    if ('check_interval_s' in b) {
      const n = b.check_interval_s;
      if (n !== null && !(Number.isInteger(n) && n >= 300 && n <= 30 * 86400)) {
        return { error: 'check_interval_s must be null or 300..2592000' };
      }
      fields.check_interval_s = n;
    }
    if ('enabled' in b) fields.enabled = b.enabled ? 1 : 0;
    return { fields };
  }

  // ── overview ────────────────────────────────────────────────────────────
  r.get('/stats', (req, res) => {
    const devices = store.listDevices().map(decorate);
    const versions = {};
    for (const d of devices) {
      const v = d.current_ver || 'never checked';
      versions[v] = (versions[v] || 0) + 1;
    }
    const fails = store.failuresSince(store.now() - 86400);
    res.json({
      devices: devices.length,
      online: devices.filter((d) => d.online).length,
      disabled: devices.filter((d) => !d.enabled).length,
      pending: devices.filter((d) => d.pending).length,
      failed_24h: { events: fails.events, devices: fails.devices },
      versions: Object.entries(versions).map(([version, count]) => ({ version, count }))
        .sort((a, b) => b.count - a.count),
      channels: store.listChannels(),
      releases: store.listReleases().length,
      recent: store.listEvents({ limit: 10 }),
    });
  });

  // ── releases ────────────────────────────────────────────────────────────
  r.get('/releases', (req, res) => res.json(store.listReleases()));

  r.post('/releases', auth.requireAdmin, upload.single('file'), (req, res) => {
    const version = String((req.body && req.body.version) || '').trim();
    const notes = String((req.body && req.body.notes) || '').slice(0, 500);
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
    store.logEvent('-', 'release_uploaded', version, `${buf.length} bytes, md5 ${md5}`, actor(req));
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
    store.logEvent('-', 'release_deleted', rel.version, '', actor(req));
    res.json({ ok: true });
  });

  // ── channels ────────────────────────────────────────────────────────────
  r.get('/channels', (req, res) => res.json(store.listChannels()));

  r.put('/channels/:name', (req, res) => {
    if (!channelExists(req.params.name)) return bad(res, 'unknown channel', 404);
    const version = req.body ? req.body.version : undefined;
    if (version !== null && !store.getRelease(String(version))) return bad(res, 'unknown release');
    store.setChannel(req.params.name, version);
    store.logEvent('-', 'channel_set', version, `${req.params.name} -> ${version || 'none'}`, actor(req));
    res.json(store.getChannel(req.params.name));
  });

  // ── devices ─────────────────────────────────────────────────────────────
  r.get('/devices', (req, res) => res.json(store.listDevices().map(decorate)));

  r.post('/devices/bulk', (req, res) => {
    const { imeis, set } = req.body || {};
    if (!Array.isArray(imeis) || !imeis.length) return bad(res, 'imeis must be a non-empty array');
    if (imeis.length > BULK_MAX) return bad(res, `at most ${BULK_MAX} devices per request`);
    if (!set || typeof set !== 'object') return bad(res, 'set is required');
    const v = validateDeviceFields(set, { allowLabel: false });
    if (v.error) return bad(res, v.error);
    if (!Object.keys(v.fields).length) return bad(res, 'nothing to set');

    const missing = imeis.filter((i) => !store.getDevice(String(i)));
    if (missing.length) return bad(res, `unknown device(s): ${missing.slice(0, 5).join(', ')}`, 404);
    store.transaction(() => {
      for (const imei of imeis) {
        store.updateDevice(String(imei), v.fields);
        store.logEvent(String(imei), 'admin_update', v.fields.pinned_version || null,
          `bulk: ${JSON.stringify(v.fields)}`, actor(req));
      }
    });
    res.json({ updated: imeis.length });
  });

  r.get('/devices/:imei', (req, res) => {
    const dev = store.getDevice(req.params.imei);
    if (!dev) return bad(res, 'not found', 404);
    res.json({ ...decorate(dev), events: store.listEvents({ imei: dev.imei, limit: 50 }) });
  });

  r.post('/devices', (req, res) => {
    const { imei, label = '', channel = 'stable' } = req.body || {};
    if (!IMEI_RE.test(String(imei || ''))) return bad(res, 'imei must be 14-17 digits');
    if (!channelExists(channel)) return bad(res, 'unknown channel');
    if (store.getDevice(imei)) return bad(res, 'device already exists', 409);
    store.addDevice({ imei, label: String(label).slice(0, 64), channel });
    store.logEvent(imei, 'registered', null, 'added in dashboard', actor(req));
    res.status(201).json(decorate(store.getDevice(imei)));
  });

  r.patch('/devices/:imei', (req, res) => {
    const dev = store.getDevice(req.params.imei);
    if (!dev) return bad(res, 'not found', 404);
    const v = validateDeviceFields(req.body || {});
    if (v.error) return bad(res, v.error);
    store.updateDevice(dev.imei, v.fields);
    store.logEvent(dev.imei, 'admin_update', v.fields.pinned_version || null, JSON.stringify(v.fields), actor(req));
    res.json(decorate(store.getDevice(dev.imei)));
  });

  r.delete('/devices/:imei', (req, res) => {
    if (!store.deleteDevice(req.params.imei)) return bad(res, 'not found', 404);
    store.logEvent(req.params.imei, 'device_deleted', null, '', actor(req));
    res.json({ ok: true });
  });

  r.get('/devices/:imei/key', auth.requireAdmin, (req, res) => {
    if (!IMEI_RE.test(req.params.imei)) return bad(res, 'imei must be 14-17 digits');
    store.logEvent(req.params.imei, 'key_viewed', null, '', actor(req));
    res.json({ imei: req.params.imei, device_key: deviceKey(cfg.masterSecret, req.params.imei) });
  });

  // ── events ──────────────────────────────────────────────────────────────
  r.get('/events', (req, res) => {
    res.json(store.listEvents({
      imei: req.query.imei ? String(req.query.imei) : null,
      type: req.query.type ? String(req.query.type) : null,
      actor: req.query.actor ? String(req.query.actor) : null,
      beforeId: req.query.before ? Number(req.query.before) : null,
      limit: req.query.limit,
    }));
  });

  // multer / JSON errors -> JSON
  r.use((err, req, res, next) => {
    if (err && err.code === 'LIMIT_FILE_SIZE') return bad(res, 'file too large', 413);
    if (err && err.type === 'entity.parse.failed') return bad(res, 'bad_json');
    if (err) return bad(res, err.message || 'bad request');
    next();
  });

  return r;
}

module.exports = { adminRoutes };
