'use strict';
// =============================================================================
//  db.js  --  SQLite store (better-sqlite3, synchronous)
//
//  releases  one row per uploaded firmware image
//  channels  stable / beta -> release version (nullable)
//  devices   one row per IMEI: channel, optional pin, last seen state
//  tokens    one-time download tokens (device + release bound, TTL)
//  events    append-only update history
// =============================================================================
const Database = require('better-sqlite3');
const crypto = require('crypto');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS releases (
  version     TEXT PRIMARY KEY,
  file        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  md5         TEXT NOT NULL,
  notes       TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
  name        TEXT PRIMARY KEY,
  version     TEXT REFERENCES releases(version) ON DELETE SET NULL,
  updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  imei              TEXT PRIMARY KEY,
  label             TEXT NOT NULL DEFAULT '',
  channel           TEXT NOT NULL DEFAULT 'stable' REFERENCES channels(name),
  pinned_version    TEXT REFERENCES releases(version) ON DELETE SET NULL,
  check_interval_s  INTEGER,
  enabled           INTEGER NOT NULL DEFAULT 1,
  current_ver       TEXT,
  last_status       TEXT,
  last_seen         INTEGER,
  last_ip           TEXT,
  created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token       TEXT PRIMARY KEY,
  imei        TEXT NOT NULL,
  version     TEXT NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  imei        TEXT NOT NULL,
  type        TEXT NOT NULL,
  version     TEXT,
  detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_imei_ts ON events(imei, ts DESC);
INSERT OR IGNORE INTO channels(name, version, updated_at) VALUES ('stable', NULL, 0), ('beta', NULL, 0);
`;

const now = () => Math.floor(Date.now() / 1000);

function openDb(file) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);

  const q = {
    // releases
    listReleases: db.prepare('SELECT * FROM releases ORDER BY created_at DESC'),
    getRelease: db.prepare('SELECT * FROM releases WHERE version = ?'),
    insertRelease: db.prepare(`INSERT INTO releases(version, file, size, md5, notes, created_at)
                               VALUES (@version, @file, @size, @md5, @notes, @created_at)`),
    deleteRelease: db.prepare('DELETE FROM releases WHERE version = ?'),
    releaseUsage: db.prepare(`SELECT
        (SELECT COUNT(*) FROM channels WHERE version = @v) AS channels,
        (SELECT COUNT(*) FROM devices  WHERE pinned_version = @v) AS pins`),
    // channels
    listChannels: db.prepare('SELECT * FROM channels ORDER BY name'),
    getChannel: db.prepare('SELECT * FROM channels WHERE name = ?'),
    setChannel: db.prepare('UPDATE channels SET version = ?, updated_at = ? WHERE name = ?'),
    // devices
    listDevices: db.prepare('SELECT * FROM devices ORDER BY COALESCE(last_seen, 0) DESC, imei'),
    getDevice: db.prepare('SELECT * FROM devices WHERE imei = ?'),
    insertDevice: db.prepare(`INSERT INTO devices(imei, label, channel, created_at)
                              VALUES (@imei, @label, @channel, @created_at)`),
    deleteDevice: db.prepare('DELETE FROM devices WHERE imei = ?'),
    touchDevice: db.prepare(`UPDATE devices SET current_ver = @current_ver, last_seen = @ts,
                             last_ip = @ip WHERE imei = @imei`),
    setDeviceStatus: db.prepare(`UPDATE devices SET last_status = @status, last_seen = @ts,
                                 current_ver = COALESCE(@current_ver, current_ver) WHERE imei = @imei`),
    // tokens
    insertToken: db.prepare('INSERT INTO tokens(token, imei, version, expires_at) VALUES (?, ?, ?, ?)'),
    getToken: db.prepare('SELECT * FROM tokens WHERE token = ?'),
    useToken: db.prepare('UPDATE tokens SET used_at = ? WHERE token = ? AND used_at IS NULL'),
    purgeTokens: db.prepare('DELETE FROM tokens WHERE expires_at < ?'),
    // events
    insertEvent: db.prepare('INSERT INTO events(ts, imei, type, version, detail) VALUES (?, ?, ?, ?, ?)'),
    listEvents: db.prepare('SELECT * FROM events ORDER BY id DESC LIMIT ?'),
    listEventsFor: db.prepare('SELECT * FROM events WHERE imei = ? ORDER BY id DESC LIMIT ?'),
  };

  const store = {
    raw: db,
    close: () => db.close(),

    listReleases: () => q.listReleases.all(),
    getRelease: (v) => q.getRelease.get(v) || null,
    addRelease: (r) => q.insertRelease.run({ notes: '', created_at: now(), ...r }),
    releaseUsage: (v) => q.releaseUsage.get({ v }),
    deleteRelease: (v) => q.deleteRelease.run(v).changes > 0,

    listChannels: () => q.listChannels.all(),
    getChannel: (name) => q.getChannel.get(name) || null,
    channelVersion: (name) => (q.getChannel.get(name) || {}).version || null,
    setChannel: (name, version) => q.setChannel.run(version, now(), name).changes > 0,

    listDevices: () => q.listDevices.all(),
    getDevice: (imei) => q.getDevice.get(imei) || null,
    addDevice: ({ imei, label = '', channel = 'stable' }) =>
      q.insertDevice.run({ imei, label, channel, created_at: now() }),
    deleteDevice: (imei) => q.deleteDevice.run(imei).changes > 0,
    touchDevice: (imei, currentVer, ip) =>
      q.touchDevice.run({ imei, current_ver: currentVer, ip: ip || null, ts: now() }),
    setDeviceStatus: (imei, status, currentVer) =>
      q.setDeviceStatus.run({ imei, status, current_ver: currentVer || null, ts: now() }),
    updateDevice: (imei, fields) => {
      const allowed = ['label', 'channel', 'pinned_version', 'check_interval_s', 'enabled'];
      const keys = Object.keys(fields).filter((k) => allowed.includes(k));
      if (!keys.length) return false;
      const sql = `UPDATE devices SET ${keys.map((k) => `${k} = @${k}`).join(', ')} WHERE imei = @imei`;
      return db.prepare(sql).run({ ...fields, imei }).changes > 0;
    },

    issueToken: (imei, version, ttlSec) => {
      q.purgeTokens.run(now());
      const token = crypto.randomBytes(16).toString('hex');
      q.insertToken.run(token, imei, version, now() + ttlSec);
      return token;
    },
    /** Atomically consume a token. Returns the token row or an error code. */
    consumeToken: (token, imei) => {
      const row = q.getToken.get(token);
      if (!row || row.imei !== imei) return { error: 'invalid_token' };
      if (row.used_at) return { error: 'token_already_used' };
      if (row.expires_at < now()) return { error: 'token_expired' };
      if (q.useToken.run(now(), token).changes !== 1) return { error: 'token_already_used' };
      return { row };
    },

    logEvent: (imei, type, version = null, detail = '') =>
      q.insertEvent.run(now(), imei, type, version, String(detail).slice(0, 500)),
    listEvents: (imei, limit = 200) =>
      imei ? q.listEventsFor.all(imei, limit) : q.listEvents.all(limit),
  };
  return store;
}

module.exports = { openDb };
