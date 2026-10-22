'use strict';
// End-to-end: admin uploads releases and assigns them, a simulated device
// checks / downloads / reports exactly the way the firmware does.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { loadConfig } = require('../src/config');
const { createApp } = require('../src/app');
const { deviceKey, sign } = require('../src/hmac');

const ADMIN = 'admin-token-for-tests';
const MASTER = 'master-secret-for-tests';
const IMEI_A = '868123456789012';
const IMEI_B = '868123456789029';

function fakeFirmware(tag, size = 4096) {
  const buf = crypto.randomBytes(size);
  buf[0] = 0xe9;
  buf.write(tag, 16);
  return buf;
}

async function setup(t) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-test-'));
  const cfg = loadConfig({ dataDir, masterSecret: MASTER, adminToken: ADMIN, autoRegister: true });
  cfg.dbFile = path.join(dataDir, 'ota.db');
  cfg.firmwareDir = path.join(dataDir, 'firmware');
  const { app, store } = createApp(cfg);
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((r) => server.close(() => { store.close(); fs.rmSync(dataDir, { recursive: true, force: true }); r(); })));

  const admin = async (method, p, body) => {
    const res = await fetch(base + p, {
      method,
      headers: { Authorization: `Bearer ${ADMIN}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, body: await res.json() };
  };
  const uploadRelease = async (version, buf) => {
    const fd = new FormData();
    fd.append('version', version);
    fd.append('file', new Blob([buf]), `fw_${version}.bin`);
    const res = await fetch(base + '/api/releases', { method: 'POST', headers: { Authorization: `Bearer ${ADMIN}` }, body: fd });
    return { status: res.status, body: await res.json() };
  };

  // Simulated device: signs exactly like ota_client.ino.
  const device = (imei) => {
    const key = deviceKey(MASTER, imei);
    let tsBump = 0; // distinct ts per call so the replay guard sees distinct sigs
    const ts = () => Math.floor(Date.now() / 1000) + (tsBump++ % 50);
    return {
      check: async (currentVer) => {
        const t = ts();
        const res = await fetch(base + '/ota/check', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_id: imei, current_ver: currentVer, ts: t, sig: sign(key, `${imei}|${currentVer}|${t}`) }),
        });
        const body = await res.json();
        if (body.update_available) {
          // Same check the firmware does before downloading.
          const want = sign(key, `${imei}|${t}|${body.version}|${body.size}|${body.md5}|${body.download_token}`);
          assert.strictEqual(body.sig, want, 'offer signature must verify with the device key');
        }
        return { status: res.status, body };
      },
      download: async (token) => {
        const res = await fetch(`${base}/ota/firmware?device_id=${imei}&token=${token}`);
        return { status: res.status, headers: res.headers, buf: Buffer.from(await res.arrayBuffer()) };
      },
      report: async (version, status, detail = '') => {
        const t = ts();
        const res = await fetch(base + '/ota/report', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_id: imei, version, status, detail, ts: t, sig: sign(key, `${imei}|${version}|${status}|${t}`) }),
        });
        return { status: res.status, body: await res.json() };
      },
    };
  };
  return { base, admin, uploadRelease, device };
}

test('admin API requires the bearer token', async (t) => {
  const { base } = await setup(t);
  assert.strictEqual((await fetch(base + '/api/devices')).status, 401);
  assert.strictEqual((await fetch(base + '/api/devices', { headers: { Authorization: 'Bearer nope' } })).status, 401);
});

test('release upload validates version, magic byte, duplicates', async (t) => {
  const { uploadRelease } = await setup(t);
  assert.strictEqual((await uploadRelease('1.0', fakeFirmware('x'))).status, 400);
  const notEsp = fakeFirmware('x'); notEsp[0] = 0x00;
  assert.strictEqual((await uploadRelease('1.0.0', notEsp)).status, 400);
  const buf = fakeFirmware('v100');
  const ok = await uploadRelease('1.0.0', buf);
  assert.strictEqual(ok.status, 201);
  assert.strictEqual(ok.body.md5, crypto.createHash('md5').update(buf).digest('hex'));
  assert.strictEqual(ok.body.size, buf.length);
  assert.strictEqual((await uploadRelease('1.0.0', buf)).status, 409);
});

test('full flow: channel upgrade, one-time token, report, per-device pin', async (t) => {
  const { admin, uploadRelease, device } = await setup(t);
  const fw110 = fakeFirmware('v110', 50_000);
  const fw090 = fakeFirmware('v090', 20_000);
  await uploadRelease('1.1.0', fw110);
  await uploadRelease('0.9.0', fw090);

  const a = device(IMEI_A);
  const b = device(IMEI_B);

  // No channel release yet -> no update, device auto-registers.
  let r = await a.check('1.0.0');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body.update_available, false);
  assert.strictEqual(r.body.check_interval_s, 86400);

  // Stable -> 1.1.0: both devices get offered it.
  assert.strictEqual((await admin('PUT', '/api/channels/stable', { version: '1.1.0' })).status, 200);
  r = await a.check('1.0.0');
  assert.strictEqual(r.body.update_available, true);
  assert.strictEqual(r.body.version, '1.1.0');
  assert.strictEqual(r.body.size, fw110.length);

  // Download: exact bytes, Content-Length set, MD5 matches the offer.
  const dl = await a.download(r.body.download_token);
  assert.strictEqual(dl.status, 200);
  assert.strictEqual(dl.headers.get('content-length'), String(fw110.length));
  assert.ok(!dl.headers.get('transfer-encoding'));
  assert.ok(dl.buf.equals(fw110));
  assert.strictEqual(crypto.createHash('md5').update(dl.buf).digest('hex'), r.body.md5);

  // Token is one-time and bound to the device.
  assert.strictEqual((await a.download(r.body.download_token)).status, 410);
  const rb = await b.check('1.0.0');
  assert.strictEqual((await device(IMEI_A).download(rb.body.download_token)).status, 401);

  // Reports: flashed, then running after reboot -> current_ver updated.
  assert.strictEqual((await a.report('1.1.0', 'flashed')).status, 200);
  assert.strictEqual((await a.report('1.1.0', 'running')).status, 200);
  assert.strictEqual((await a.report('1.1.0', 'bogus')).status, 400);
  let dev = (await admin('GET', '/api/devices')).body.find((d) => d.imei === IMEI_A);
  assert.strictEqual(dev.current_ver, '1.1.0');
  assert.strictEqual(dev.last_status, 'running');

  // Up to date now.
  r = await a.check('1.1.0');
  assert.strictEqual(r.body.update_available, false);
  assert.strictEqual(r.body.reason, 'up_to_date');

  // Device-specific: pin A to 0.9.0 (downgrade) with a custom interval; B unaffected.
  r = await admin('PATCH', `/api/devices/${IMEI_A}`, { pinned_version: '0.9.0', check_interval_s: 3600 });
  assert.strictEqual(r.status, 200);
  r = await a.check('1.1.0');
  assert.strictEqual(r.body.version, '0.9.0');
  assert.strictEqual(r.body.reason, 'pinned');
  assert.strictEqual(r.body.check_interval_s, 3600);
  r = await b.check('1.1.0');
  assert.strictEqual(r.body.update_available, false);

  // Pinned release cannot be deleted while in use.
  assert.strictEqual((await admin('DELETE', '/api/releases/0.9.0')).status, 409);

  // Beta channel for B only.
  await uploadRelease('1.2.0', fakeFirmware('v120'));
  await admin('PUT', '/api/channels/beta', { version: '1.2.0' });
  await admin('PATCH', `/api/devices/${IMEI_B}`, { channel: 'beta' });
  assert.strictEqual((await b.check('1.1.0')).body.version, '1.2.0');

  // Disabled device gets no offers.
  await admin('PATCH', `/api/devices/${IMEI_B}`, { enabled: false });
  r = await b.check('1.1.0');
  assert.strictEqual(r.body.update_available, false);
  assert.strictEqual(r.body.reason, 'device_disabled');

  // Provisioning key endpoint matches the derivation.
  r = await admin('GET', `/api/devices/${IMEI_A}/key`);
  assert.strictEqual(r.body.device_key, deviceKey(MASTER, IMEI_A));

  // History recorded.
  const ev = (await admin('GET', `/api/events?imei=${IMEI_A}`)).body.map((e) => e.type);
  for (const type of ['registered', 'offered', 'download_start', 'flashed', 'running']) {
    assert.ok(ev.includes(type), `missing event ${type}`);
  }
});

test('device requests with a wrong key or stale timestamp are rejected', async (t) => {
  const { base } = await setup(t);
  const ts = Math.floor(Date.now() / 1000);
  const post = (body) => fetch(base + '/ota/check', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));

  const wrongKey = sign('not-the-device-key', `${IMEI_A}|1.0.0|${ts}`);
  let r = await post({ device_id: IMEI_A, current_ver: '1.0.0', ts, sig: wrongKey });
  assert.strictEqual(r.status, 401);
  assert.strictEqual(r.body.error, 'bad_signature');

  const old = ts - 3600;
  r = await post({ device_id: IMEI_A, current_ver: '1.0.0', ts: old,
    sig: sign(deviceKey(MASTER, IMEI_A), `${IMEI_A}|1.0.0|${old}`) });
  assert.strictEqual(r.body.error, 'timestamp_out_of_window');

  const bad = await fetch(base + '/ota/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{nope' });
  assert.strictEqual(bad.status, 400);
});

// ── Automatic registration ──────────────────────────────────────────────────
// Simulated device side of register.ino: P-256 pair, ECDH with the server's
// public key, AES-256-GCM decrypt of the delivered key.
function regDevice(base, imei, serverPubHex) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const pub = ecdh.getPublicKey('hex', 'uncompressed');
  return {
    pub,
    fingerprint: crypto.createHash('sha256').update(Buffer.from(pub, 'hex')).digest('hex').slice(0, 8),
    register: async (overrides = {}) => {
      const res = await fetch(base + '/ota/register', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: imei, current_ver: '1.0.0', pub, ...overrides }),
      });
      return { status: res.status, body: await res.json() };
    },
    decrypt: (b) => {
      const z = ecdh.computeSecret(Buffer.from(serverPubHex, 'hex'));
      const k = crypto.createHash('sha256').update(z).update(imei).digest();
      const d = crypto.createDecipheriv('aes-256-gcm', k, Buffer.from(b.iv, 'hex'));
      d.setAAD(Buffer.from(imei));
      d.setAuthTag(Buffer.from(b.tag, 'hex'));
      return Buffer.concat([d.update(Buffer.from(b.ct, 'hex')), d.final()]).toString('utf8');
    },
  };
}

async function regSetup(t, overrides = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ota-reg-'));
  const cfg = loadConfig({ dataDir, masterSecret: MASTER, adminToken: ADMIN, registerGapMs: 0, ...overrides });
  const { app, store, regKey } = createApp(cfg);
  const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise((r) => server.close(() => { store.close(); fs.rmSync(dataDir, { recursive: true, force: true }); r(); })));
  const admin = async (method, p, body) => {
    const res = await fetch(base + p, {
      method,
      headers: { Authorization: `Bearer ${ADMIN}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, body: await res.json() };
  };
  let tsBump = 0; // distinct ts per call so the replay guard sees distinct sigs
  const signedCheck = async (imei, key) => {
    const ts = Math.floor(Date.now() / 1000) + (tsBump++ % 50);
    const res = await fetch(base + '/ota/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: imei, current_ver: '1.0.0', ts, sig: sign(key, `${imei}|1.0.0|${ts}`) }),
    });
    return { status: res.status, body: await res.json() };
  };
  return { base, admin, signedCheck, serverPub: regKey.publicKeyHex(), dataDir };
}

test('registration: pending -> admin approves -> device decrypts its key and checks', async (t) => {
  const { base, admin, signedCheck, serverPub } = await regSetup(t);
  const dev = regDevice(base, IMEI_A, serverPub);

  let r = await dev.register();
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(r.body, { status: 'pending', retry_s: 600 });
  assert.strictEqual((await dev.register()).body.status, 'pending');

  // Waiting device is listed, cannot check yet even with the right key.
  const d = (await admin('GET', `/api/devices/${IMEI_A}`)).body;
  assert.strictEqual(d.reg_state, 'pending');
  assert.strictEqual(d.awaiting_approval, true);
  assert.strictEqual(d.reg_fingerprint, dev.fingerprint);
  assert.ok(!('reg_pub' in d));
  assert.strictEqual((await admin('GET', '/api/stats')).body.awaiting_approval, 1);
  r = await signedCheck(IMEI_A, deviceKey(MASTER, IMEI_A));
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'awaiting_approval');

  // Fingerprint guard, then approve.
  assert.strictEqual((await admin('POST', `/api/devices/${IMEI_A}/approve`, { fingerprint: 'deadbeef' })).status, 409);
  r = await admin('POST', `/api/devices/${IMEI_A}/approve`, { fingerprint: dev.fingerprint });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body.awaiting_approval, false);

  r = await dev.register();
  assert.strictEqual(r.body.status, 'approved');
  assert.ok(!JSON.stringify(r.body).includes(deviceKey(MASTER, IMEI_A)), 'key must not travel in clear');
  const key = dev.decrypt(r.body);
  assert.strictEqual(key, deviceKey(MASTER, IMEI_A));
  assert.strictEqual((await signedCheck(IMEI_A, key)).status, 200);

  // Another key pair cannot read the reply, and a tampered tag fails.
  const other = regDevice(base, IMEI_A, serverPub);
  assert.throws(() => other.decrypt(r.body));
  assert.throws(() => dev.decrypt({ ...r.body, tag: '00'.repeat(16) }));

  const ev = (await admin('GET', `/api/events?imei=${IMEI_A}`)).body.map((e) => e.type);
  for (const type of ['registration_requested', 'registration_approved', 'key_delivered']) {
    assert.ok(ev.includes(type), `missing event ${type}`);
  }
});

test('registration: a new key for an approved device needs approval again', async (t) => {
  const { base, admin, signedCheck, serverPub } = await regSetup(t);
  const first = regDevice(base, IMEI_A, serverPub);
  await first.register();
  await admin('POST', `/api/devices/${IMEI_A}/approve`);
  assert.strictEqual((await first.register()).body.status, 'approved');

  // Someone (or the same unit after an NVS erase) sends another key.
  const second = regDevice(base, IMEI_A, serverPub);
  assert.strictEqual((await second.register()).body.status, 'pending');
  const d = (await admin('GET', `/api/devices/${IMEI_A}`)).body;
  assert.strictEqual(d.awaiting_approval, true);
  assert.strictEqual(d.reg_key_changed, true);
  // The working device is not locked out meanwhile.
  assert.strictEqual((await signedCheck(IMEI_A, deviceKey(MASTER, IMEI_A))).status, 200);
  // A changed key cannot be rejected (that would lock the real device out).
  assert.strictEqual((await admin('POST', `/api/devices/${IMEI_A}/reject`)).status, 409);
  await admin('POST', `/api/devices/${IMEI_A}/approve`);
  assert.strictEqual(second.decrypt((await second.register()).body), deviceKey(MASTER, IMEI_A));
});

test('registration: reject, input validation, throttle', async (t) => {
  const { base, admin, signedCheck, serverPub } = await regSetup(t, { registerGapMs: 60_000 });
  const dev = regDevice(base, IMEI_A, serverPub);
  await dev.register();
  assert.strictEqual((await dev.register()).status, 429);

  assert.strictEqual((await admin('POST', `/api/devices/${IMEI_A}/reject`)).status, 200);
  assert.strictEqual((await signedCheck(IMEI_A, deviceKey(MASTER, IMEI_A))).body.error, 'registration_rejected');

  const b = regDevice(base, IMEI_B, serverPub);
  assert.strictEqual((await b.register({ device_id: '12ab' })).body.error, 'bad_device_id');
  assert.strictEqual((await b.register({ pub: '04' + '11'.repeat(64) })).body.error, 'bad_pub');
  assert.strictEqual((await b.register({ pub: 'zz' })).body.error, 'bad_pub');
  // A device that never asked cannot be approved.
  await admin('POST', '/api/devices', { imei: '868123456789036' });
  assert.strictEqual((await admin('POST', '/api/devices/868123456789036/approve')).status, 409);
});

test('registration: rejected device stays rejected for new requests', async (t) => {
  const { base, admin, serverPub } = await regSetup(t);
  const dev = regDevice(base, IMEI_A, serverPub);
  await dev.register();
  await admin('POST', `/api/devices/${IMEI_A}/reject`);
  const r = await dev.register();
  assert.strictEqual(r.status, 403);
  assert.strictEqual(r.body.error, 'registration_rejected');
  assert.strictEqual((await regDevice(base, IMEI_A, serverPub).register()).status, 403);
});

test('registration modes: auto approves at once, off refuses, queue cap', async (t) => {
  const auto = await regSetup(t, { registrationMode: 'auto' });
  const dev = regDevice(auto.base, IMEI_A, auto.serverPub);
  const r = await dev.register();
  assert.strictEqual(r.body.status, 'approved');
  assert.strictEqual(dev.decrypt(r.body), deviceKey(MASTER, IMEI_A));

  const off = await regSetup(t, { registrationMode: 'off', autoRegister: false });
  const r2 = await regDevice(off.base, IMEI_A, off.serverPub).register();
  assert.strictEqual(r2.status, 403);
  assert.strictEqual(r2.body.error, 'registration_off');

  const capped = await regSetup(t, { registerMaxPending: 1 });
  assert.strictEqual((await regDevice(capped.base, IMEI_A, capped.serverPub).register()).status, 200);
  assert.strictEqual((await regDevice(capped.base, IMEI_B, capped.serverPub).register()).status, 503);
});

test('registration: server key persists across restarts', async (t) => {
  const { serverPub, dataDir } = await regSetup(t);
  const { loadRegKey } = require('../src/regkey');
  assert.strictEqual(loadRegKey(path.join(dataDir, 'server_reg_key.pem')).publicKeyHex(), serverPub);
  assert.match(serverPub, /^04[0-9a-f]{128}$/);
});
