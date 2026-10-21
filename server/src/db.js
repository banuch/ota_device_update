'use strict';
// =============================================================================
//  db.js  --  SQLite store (better-sqlite3, synchronous)
//
//  releases  one row per uploaded firmware image
//  channels  stable / beta -> release version (nullable)
//  devices   one row per IMEI: channel, optional pin, last seen state
//  tokens    one-time download tokens (device + release bound, TTL)
//  events    append-only update + audit history (actor = who did it)
//  users     dashboard accounts (admin / viewer)
//  sessions  dashboard login sessions (id = sha256 of the cookie value)
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
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass_hash   TEXT NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  INTEGER NOT NULL,
  last_login  INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
INSERT OR IGNORE INTO channels(name, version, updated_at) VALUES ('stable', NULL, 0), ('beta', NULL, 0);
`;

// In-place upgrades for databases created by earlier versions.
function migrate(db) {
  const cols = db.prepare('PRAGMA table_info(events)').all().map((c) => c.name);
  if (!cols.includes('actor')) {
    db.exec("ALTER TABLE events ADD COLUMN actor TEXT NOT NULL DEFAULT 'device'");
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)');
}

/**
 * @param {string} file
 * @param {{clock?: () => number}} [opts]  clock returns ms (tests inject a fake one)
 */
function openDb(file, opts = {}) {
  const clock = opts.clock || Date.now;
  const now = () => Math.floor(clock() / 1000);

  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  migrate(db);

  const q = {
    // releases
    listReleases: db.prepare(`SELECT r.*,
        (SELECT GROUP_CONCAT(name) FROM channels c WHERE c.version = r.version) AS channels,
        (SELECT COUNT(*) FROM devices d WHERE d.pinned_version = r.version) AS pinned_devices,
        (SELECT COUNT(*) FROM devices d WHERE d.current_ver = r.version) AS running_devices
      FROM releases r ORDER BY r.created_at DESC`),
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
    insertEvent: db.prepare('INSERT INTO events(ts, imei, type, version, detail, actor) VALUES (?, ?, ?, ?, ?, ?)'),
    countFailures: db.prepare(`SELECT COUNT(*) AS events, COUNT(DISTINCT imei) AS devices FROM events
                               WHERE type IN ('failed', 'md5_fail') AND ts >= ?`),
    // users
    listUsers: db.prepare(`SELECT id, username, role, enabled, created_at, last_login FROM users
                           ORDER BY username`),
    getUser: db.prepare('SELECT * FROM users WHERE id = ?'),
    getUserByName: db.prepare('SELECT * FROM users WHERE username = ?'),
    insertUser: db.prepare(`INSERT INTO users(username, pass_hash, role, created_at)
                            VALUES (@username, @pass_hash, @role, @created_at)`),
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
    countAdmins: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND enabled = 1"),
    countUsers: db.prepare('SELECT COUNT(*) AS n FROM users'),
    setLastLogin: db.prepare('UPDATE users SET last_login = ? WHERE id = ?'),
    // sessions
    insertSession: db.prepare(`INSERT INTO sessions(id, user_id, created_at, last_seen, ip, user_agent)
                               VALUES (?, ?, ?, ?, ?, ?)`),
    getSession: db.prepare(`SELECT s.*, u.username, u.role, u.enabled FROM sessions s
                            JOIN users u ON u.id = s.user_id WHERE s.id = ?`),
    touchSession: db.prepare('UPDATE sessions SET last_seen = ? WHERE id = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE id = ?'),
    deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE last_seen < ? OR created_at < ?'),
  };

  const store = {
    raw: db,
    now,
    close: () => db.close(),
    transaction: (fn) => db.transaction(fn)(),

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

    logEvent: (imei, type, version = null, detail = '', actor = 'device') =>
      q.insertEvent.run(now(), imei, type, version, String(detail).slice(0, 500), actor),
    /** Filtered, paged history (newest first). beforeId pages backwards. */
    listEvents: ({ imei, type, actor, beforeId, limit = 200 } = {}) => {
      const where = [];
      const args = {};
      if (imei) { where.push('imei = @imei'); args.imei = imei; }
      if (type) { where.push('type = @type'); args.type = type; }
      if (actor) { where.push('actor = @actor'); args.actor = actor; }
      if (beforeId) { where.push('id < @beforeId'); args.beforeId = beforeId; }
      const sql = `SELECT * FROM events ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                   ORDER BY id DESC LIMIT ${Math.max(1, Math.min(Number(limit) || 200, 1000))}`;
      return db.prepare(sql).all(args);
    },
    failuresSince: (ts) => q.countFailures.get(ts),

    listUsers: () => q.listUsers.all(),
    getUser: (id) => q.getUser.get(id) || null,
    getUserByName: (name) => q.getUserByName.get(name) || null,
    addUser: ({ username, passHash, role }) =>
      q.insertUser.run({ username, pass_hash: passHash, role, created_at: now() }).lastInsertRowid,
    updateUser: (id, fields) => {
      const map = { role: 'role', enabled: 'enabled', passHash: 'pass_hash' };
      const keys = Object.keys(fields).filter((k) => map[k]);
      if (!keys.length) return false;
      const sql = `UPDATE users SET ${keys.map((k) => `${map[k]} = @${k}`).join(', ')} WHERE id = @id`;
      return db.prepare(sql).run({ ...fields, id }).changes > 0;
    },
    deleteUser: (id) => q.deleteUser.run(id).changes > 0,
    countEnabledAdmins: () => q.countAdmins.get().n,
    countUsers: () => q.countUsers.get().n,
    setLastLogin: (id) => q.setLastLogin.run(now(), id),

    createSession: (id, userId, ip, ua) =>
      q.insertSession.run(id, userId, now(), now(), ip || null, String(ua || '').slice(0, 200)),
    getSession: (id) => q.getSession.get(id) || null,
    touchSession: (id) => q.touchSession.run(now(), id),
    deleteSession: (id) => q.deleteSession.run(id),
    /** Remove all of a user's sessions except keepId (pass '' to remove all). */
    deleteUserSessions: (userId, keepId = '') => q.deleteUserSessions.run(userId, keepId),
    purgeSessions: (idleSec, maxSec) => q.purgeSessions.run(now() - idleSec, now() - maxSec),
  };
  return store;
}

module.exports = { openDb };
