'use strict';
// Dashboard auth: login/lockout/session expiry/roles/CSRF/users/bulk/stats/migration.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { execFileSync } = require('child_process');
const { hashPassword, verifyPassword, parseCookies, LoginLimiter } = require('../src/auth');
const { parseTrustProxy } = require('../src/config');
const { openDb } = require('../src/db');
const { deviceKey, sign } = require('../src/hmac');

const ADMIN_TOKEN = 'admin-token-for-tests';
const MASTER = 'master-secret-for-tests';
const PW = 'correct-horse-battery';

async function setup(t, { preCreateDb, cfg: extra = {} } = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-auth-'));
  if (preCreateDb) preCreateDb(path.join(dataDir, 'ota.db'));
  const clock = { now: Date.now() };
  const cfg = loadConfig({ dataDir, masterSecret: MASTER, adminToken: ADMIN_TOKEN, clock: () => clock.now, ...extra });
  cfg.dbFile = path.join(dataDir, 'ota.db');
  cfg.firmwareDir = path.join(dataDir, 'firmware');
  const { app, store } = createApp(cfg);
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((r) => server.close(() => { store.close(); fs.rmSync(dataDir, { recursive: true, force: true }); r(); })));

  store.addUser({ username: 'boss', passHash: hashPassword(PW), role: 'admin' });
  store.addUser({ username: 'watcher', passHash: hashPassword(PW), role: 'viewer' });

  // Minimal cookie-jar browser.
  const browser = () => {
    let cookie = '';
    const call = async (method, p, body, { csrf = true, ip } = {}) => {
      const headers = {};
      if (ip) headers['X-Forwarded-For'] = ip;
      if (cookie) headers.Cookie = cookie;
      if (csrf) headers['X-OTA-Console'] = '1';
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      const res = await fetch(base + p, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
      const sc = res.headers.get('set-cookie');
      if (sc) cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
      return { status: res.status, body: await res.json().catch(() => null), setCookie: sc };
    };
    return { call, login: (u, pw = PW, opts) => call('POST', '/auth/login', { username: u, password: pw }, opts),
      cookie: () => cookie };
  };
  const api = async (method, p, body) => {
    const res = await fetch(base + p, { method,
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined });
    return { status: res.status, body: await res.json() };
  };
  return { base, store, clock, browser, api };
}

test('password hashing round-trips and rejects wrong passwords', () => {
  const h = hashPassword('abcdefghij');
  assert.match(h, /^scrypt\$16384\$8\$1\$/);
  assert.ok(verifyPassword('abcdefghij', h));
  assert.ok(!verifyPassword('abcdefghiJ', h));
  assert.notStrictEqual(hashPassword('abcdefghij'), h, 'salted');
});

test('login sets a hardened cookie; me/logout work; logout kills the session', async (t) => {
  const { browser } = await setup(t);
  const b = browser();
  assert.strictEqual((await b.call('GET', '/auth/me')).status, 401);
  const r = await b.login('boss');
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.body, { username: 'boss', role: 'admin' });
  assert.match(r.setCookie, /HttpOnly/);
  assert.match(r.setCookie, /SameSite=Strict/);
  assert.doesNotMatch(r.setCookie, /Secure/, 'plain http -> no Secure flag in auto mode');
  assert.strictEqual((await b.call('GET', '/auth/me')).body.username, 'boss');
  assert.strictEqual((await b.call('GET', '/api/devices')).status, 200);
  const out = await b.call('POST', '/auth/logout');
  assert.match(out.setCookie, /Max-Age=0/);
  assert.strictEqual((await b.call('GET', '/auth/me')).status, 401);
});

test('logout invalidates the cookie server-side', async (t) => {
  const { browser, base } = await setup(t);
  const b = browser();
  await b.login('boss');
  const old = b.cookie();
  await b.call('POST', '/auth/logout');
  const res = await fetch(base + '/api/devices', { headers: { Cookie: old } });
  assert.strictEqual(res.status, 401);
});

test('wrong password -> 401 generic; 5 failures lock the account for 15 min', async (t) => {
  const { browser, clock } = await setup(t);
  const b = browser();
  const unknown = await b.login('nobody', 'whatever-123');
  assert.strictEqual(unknown.status, 401);
  assert.strictEqual(unknown.body.error, 'invalid_credentials');
  for (let i = 0; i < 4; i++) assert.strictEqual((await b.login('boss', 'wrong-password')).status, 401);
  const fifth = await b.login('boss', 'wrong-password');
  assert.strictEqual(fifth.status, 429);
  // Even the right password is refused while locked.
  const locked = await b.login('boss');
  assert.strictEqual(locked.status, 429);
  assert.ok(locked.body.retry_after_s > 800);
  clock.now += 15 * 60 * 1000 + 1000;
  assert.strictEqual((await b.login('boss')).status, 200);
});

test('session expires after 8 h idle and after 24 h absolute', async (t) => {
  const { browser, clock } = await setup(t);
  const b = browser();
  await b.login('boss');
  clock.now += 7 * 3600 * 1000;
  assert.strictEqual((await b.call('GET', '/auth/me')).status, 200, 'activity at 7 h keeps it alive');
  clock.now += 7 * 3600 * 1000;
  assert.strictEqual((await b.call('GET', '/auth/me')).status, 200, '14 h total, but only 7 h idle');
  clock.now += 8 * 3600 * 1000 + 1000;
  assert.strictEqual((await b.call('GET', '/auth/me')).status, 401, '8 h idle -> expired');

  const b2 = browser();
  await b2.login('boss');
  for (let h = 0; h < 24; h += 6) {
    clock.now += 6 * 3600 * 1000;
    if (h < 18) assert.strictEqual((await b2.call('GET', '/auth/me')).status, 200);
  }
  clock.now += 1000;
  assert.strictEqual((await b2.call('GET', '/auth/me')).status, 401, '24 h absolute limit');
});

test('CSRF header required for cookie writes; Bearer token still works without it', async (t) => {
  const { browser, api, store } = await setup(t);
  store.addDevice({ imei: '868123456789012' });
  const b = browser();
  await b.login('boss');
  const noHdr = await b.call('PATCH', '/api/devices/868123456789012', { label: 'x' }, { csrf: false });
  assert.strictEqual(noHdr.status, 403);
  assert.strictEqual(noHdr.body.error, 'csrf_header_missing');
  assert.strictEqual((await b.call('PATCH', '/api/devices/868123456789012', { label: 'x' })).status, 200);
  assert.strictEqual((await api('PATCH', '/api/devices/868123456789012', { label: 'y' })).status, 200);
  // Login itself also needs the header.
  assert.strictEqual((await browser().call('POST', '/auth/login', { username: 'boss', password: PW }, { csrf: false })).status, 403);
});

test('viewer is read-only and never sees device keys or users', async (t) => {
  const { browser, store } = await setup(t);
  store.addDevice({ imei: '868123456789012' });
  const v = browser();
  await v.login('watcher');
  assert.strictEqual((await v.call('GET', '/api/devices')).status, 200);
  assert.strictEqual((await v.call('GET', '/api/stats')).status, 200);
  assert.strictEqual((await v.call('GET', '/api/devices/868123456789012')).status, 200);
  assert.strictEqual((await v.call('PATCH', '/api/devices/868123456789012', { label: 'x' })).status, 403);
  assert.strictEqual((await v.call('PUT', '/api/channels/stable', { version: null })).status, 403);
  assert.strictEqual((await v.call('GET', '/api/devices/868123456789012/key')).status, 403);
  assert.strictEqual((await v.call('GET', '/api/users')).status, 403);
});

test('user management: create, role/enable rules, last-admin protection, audit actor', async (t) => {
  const { browser, store } = await setup(t);
  const a = browser();
  await a.login('boss');
  const me = store.getUserByName('boss');

  assert.strictEqual((await a.call('POST', '/api/users', { username: 'x', password: PW })).status, 400);
  assert.strictEqual((await a.call('POST', '/api/users', { username: 'ops', password: 'short' })).status, 400);
  const created = await a.call('POST', '/api/users', { username: 'ops', password: PW, role: 'viewer' });
  assert.strictEqual(created.status, 201);
  assert.ok(!('pass_hash' in created.body), 'hash never leaves the server');
  assert.strictEqual((await a.call('POST', '/api/users', { username: 'OPS', password: PW })).status, 409, 'case-insensitive');

  // Self-protection.
  assert.strictEqual((await a.call('PATCH', `/api/users/${me.id}`, { role: 'viewer' })).status, 400);
  assert.strictEqual((await a.call('PATCH', `/api/users/${me.id}`, { enabled: false })).status, 400);
  assert.strictEqual((await a.call('DELETE', `/api/users/${me.id}`)).status, 400);

  // Disabling a user ends their session.
  const o = browser();
  assert.strictEqual((await o.login('ops')).status, 200);
  assert.strictEqual((await a.call('PATCH', `/api/users/${created.body.id}`, { enabled: false })).status, 200);
  assert.strictEqual((await o.call('GET', '/auth/me')).status, 401);
  assert.strictEqual((await o.login('ops')).status, 401, 'disabled user cannot log in');

  // Promote ops, then the only other admin path: last-admin rule via a second admin session.
  await a.call('PATCH', `/api/users/${created.body.id}`, { enabled: true, role: 'admin' });
  const o2 = browser();
  await o2.login('ops');
  assert.strictEqual((await o2.call('PATCH', `/api/users/${me.id}`, { role: 'viewer' })).status, 200);
  // Now 'ops' is the only admin: boss (viewer) can't do anything, ops can't demote self.
  assert.strictEqual((await o2.call('PATCH', `/api/users/${created.body.id}`, { role: 'viewer' })).status, 400);
  assert.strictEqual(store.countEnabledAdmins(), 1);

  const actors = store.listEvents({ type: 'user_updated' }).map((e) => e.actor);
  assert.ok(actors.includes('boss') && actors.includes('ops'));
});

test('change own password ends other sessions and needs the current one', async (t) => {
  const { browser } = await setup(t);
  const s1 = browser();
  const s2 = browser();
  await s1.login('boss');
  await s2.login('boss');
  assert.strictEqual((await s1.call('POST', '/auth/password', { current: 'nope-nope-nope', next: 'brand-new-password' })).status, 400);
  assert.strictEqual((await s1.call('POST', '/auth/password', { current: PW, next: 'short' })).status, 400);
  assert.strictEqual((await s1.call('POST', '/auth/password', { current: PW, next: 'brand-new-password' })).status, 200);
  assert.strictEqual((await s1.call('GET', '/auth/me')).status, 200, 'own session survives');
  assert.strictEqual((await s2.call('GET', '/auth/me')).status, 401, 'other session ended');
  assert.strictEqual((await browser().login('boss', 'brand-new-password')).status, 200);
});

test('bulk update, device detail, stats and decorated device list', async (t) => {
  const { browser, store, base } = await setup(t);
  const fw = crypto.randomBytes(70000); fw[0] = 0xe9;
  store.addRelease({ version: '1.1.0', file: 'fw_1.1.0.bin', size: fw.length, md5: 'x'.repeat(32) });
  store.setChannel('stable', '1.1.0');
  for (const i of ['868000000000001', '868000000000002', '868000000000003']) store.addDevice({ imei: i });
  store.touchDevice('868000000000001', '1.0.0', '1.2.3.4');
  store.touchDevice('868000000000002', '1.1.0', '1.2.3.4');
  store.logEvent('868000000000001', 'failed', '1.1.0', 'short download');

  const a = browser();
  await a.login('boss');
  let s = (await a.call('GET', '/api/stats')).body;
  assert.strictEqual(s.devices, 3);
  assert.strictEqual(s.online, 2);
  assert.strictEqual(s.pending, 1);
  assert.deepStrictEqual(s.failed_24h, { events: 1, devices: 1 });
  assert.deepStrictEqual(s.versions.map((v) => v.version).sort(), ['1.0.0', '1.1.0', 'never checked']);

  const list = (await a.call('GET', '/api/devices')).body;
  const d1 = list.find((d) => d.imei === '868000000000001');
  assert.strictEqual(d1.target, '1.1.0');
  assert.strictEqual(d1.online, true);
  assert.strictEqual(list.find((d) => d.imei === '868000000000003').target_reason, 'never_checked');

  assert.strictEqual((await a.call('POST', '/api/devices/bulk', { imeis: ['868000000000001', '999'], set: { enabled: false } })).status, 404);
  assert.strictEqual((await a.call('POST', '/api/devices/bulk', { imeis: ['868000000000001'], set: { pinned_version: '9.9.9' } })).status, 400);
  const bulk = await a.call('POST', '/api/devices/bulk', { imeis: ['868000000000001', '868000000000002'], set: { channel: 'beta', enabled: false } });
  assert.strictEqual(bulk.body.updated, 2);
  s = (await a.call('GET', '/api/stats')).body;
  assert.strictEqual(s.disabled, 2);
  assert.strictEqual(s.pending, 0);

  const detail = (await a.call('GET', '/api/devices/868000000000001')).body;
  assert.strictEqual(detail.channel, 'beta');
  assert.strictEqual(detail.target_reason, 'device_disabled');
  assert.ok(detail.events.some((e) => e.type === 'admin_update' && e.actor === 'boss'));

  // History filters + paging.
  const all = (await a.call('GET', '/api/events?limit=1000')).body;
  const page1 = (await a.call('GET', '/api/events?limit=2')).body;
  const page2 = (await a.call('GET', `/api/events?limit=2&before=${page1[1].id}`)).body;
  assert.strictEqual(page2[0].id, all[2].id);
  assert.ok((await a.call('GET', '/api/events?actor=boss')).body.every((e) => e.actor === 'boss'));
  assert.ok(base);
});

test('device protocol is unaffected by dashboard auth (no cookie, no token)', async (t) => {
  const { base } = await setup(t);
  const imei = '868123456789012';
  const ts = Math.floor(Date.now() / 1000);
  const res = await fetch(base + '/ota/check', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: imei, current_ver: '1.0.0', ts, sig: sign(deviceKey(MASTER, imei), `${imei}|1.0.0|${ts}`) }) });
  assert.strictEqual(res.status, 200);
});

test('old database without events.actor is migrated in place', async (t) => {
  const { store } = await setup(t, {
    preCreateDb: (file) => {
      const db = new Database(file);
      db.exec(`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
               imei TEXT NOT NULL, type TEXT NOT NULL, version TEXT, detail TEXT NOT NULL DEFAULT '');
               INSERT INTO events(ts, imei, type, version, detail) VALUES (1, '868000000000001', 'running', '1.0.0', 'old');`);
      db.close();
    },
  });
  const ev = store.listEvents({ imei: '868000000000001' });
  assert.strictEqual(ev[0].detail, 'old');
  assert.strictEqual(ev[0].actor, 'device');
});

test('undecodable cookies from other apps do not break requests', async (t) => {
  const { base } = await setup(t);
  const res = await fetch(base + '/auth/me', { headers: { Cookie: 'other=%E0%A4%A; ota_sid=x' } });
  assert.strictEqual(res.status, 401);
  assert.deepStrictEqual(parseCookies('a=%zz; b=%20'), { a: '%zz', b: ' ' });
});

test('lockout is per source IP; one IP cannot spray many usernames', async (t) => {
  const { browser, store } = await setup(t, { cfg: { trustProxy: 'loopback' } });
  const b = browser();
  for (let i = 0; i < 5; i++) await b.login('boss', 'wrong-password', { ip: '203.0.113.9' });
  assert.strictEqual((await b.login('boss', PW, { ip: '203.0.113.9' })).status, 429);
  assert.strictEqual((await b.login('boss', PW, { ip: '198.51.100.7' })).status, 200, 'other IP unaffected');

  const failed = store.listEvents({ type: 'login_failed' });
  assert.ok(failed.every((e) => e.actor === '-'), 'typed username is not recorded as the actor');
  assert.match(failed[0].detail, /203\.0\.113\.9/, 'logs the forwarded client IP');

  for (let i = 0; i < 20; i++) await b.login(`user${i}`, 'wrong-password', { ip: '192.0.2.1' });
  const sprayed = await b.login('watcher', PW, { ip: '192.0.2.1' });
  assert.strictEqual(sprayed.status, 429, 'IP budget exhausted across usernames');
});

test('login limiter stays bounded under random usernames', () => {
  let now = 0;
  const l = new LoginLimiter({ maxFails: 5, lockSec: 60, clock: () => now });
  for (let i = 0; i < 30000; i++) { now += 10; l.fail(`u${i}`, `10.0.${i >> 8}.${i & 255}`); }
  assert.ok(l.state.size <= 10000 + 2, `size ${l.state.size}`);
});

test('TRUST_PROXY accepts booleans and hop counts', () => {
  assert.strictEqual(parseTrustProxy('true'), true);
  assert.strictEqual(parseTrustProxy('2'), 2);
  assert.strictEqual(parseTrustProxy('false'), '');
  assert.strictEqual(parseTrustProxy(undefined), '');
  assert.strictEqual(parseTrustProxy('loopback'), 'loopback');
});

test('user:add --reset keeps the existing role unless --role is given', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-cli-'));
  try {
    const store = openDb(path.join(dataDir, 'ota.db'));
    store.addUser({ username: 'boss', passHash: hashPassword(PW), role: 'admin' });
    store.close();
    const tool = path.join(__dirname, '..', 'tools', 'user-add.js');
    const run = (...args) => execFileSync(process.execPath, [tool, ...args],
      { input: 'another-good-password\n', env: { ...process.env, DATA_DIR: dataDir } });
    run('boss', '--reset');
    let db = openDb(path.join(dataDir, 'ota.db'));
    assert.strictEqual(db.getUserByName('boss').role, 'admin');
    db.close();
    run('boss', '--reset', '--role', 'viewer');
    run('newbie');
    db = openDb(path.join(dataDir, 'ota.db'));
    assert.strictEqual(db.getUserByName('boss').role, 'viewer');
    assert.strictEqual(db.getUserByName('newbie').role, 'viewer');
    db.close();
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
