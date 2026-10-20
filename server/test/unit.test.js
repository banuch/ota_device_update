'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { compareVersions, resolveTarget, isValidVersion } = require('../src/resolver');
const { deviceKey, sign, verifyRequest, ReplayGuard } = require('../src/hmac');

test('compareVersions orders numerically, not lexically', () => {
  assert.strictEqual(compareVersions('1.0.10', '1.0.9'), 1);
  assert.strictEqual(compareVersions('1.2.0', '1.10.0'), -1);
  assert.strictEqual(compareVersions('2.0.0', '2.0.0'), 0);
  assert.throws(() => compareVersions('1.0', '1.0.0'));
  assert.ok(!isValidVersion('v1.0.0'));
});

test('resolveTarget: pin wins over channel and allows downgrade', () => {
  const ch = () => '2.0.0';
  assert.deepStrictEqual(resolveTarget({ pinned_version: '1.0.0', channel: 'stable' }, '1.5.0', ch),
    { target: '1.0.0', reason: 'pinned' });
  assert.strictEqual(resolveTarget({ pinned_version: '1.5.0', channel: 'stable' }, '1.5.0', ch).target, null);
});

test('resolveTarget: channel only upgrades', () => {
  const dev = { pinned_version: null, channel: 'stable' };
  assert.strictEqual(resolveTarget(dev, '1.0.0', () => '1.1.0').target, '1.1.0');
  assert.strictEqual(resolveTarget(dev, '1.1.0', () => '1.1.0').target, null);
  assert.strictEqual(resolveTarget(dev, '1.2.0', () => '1.1.0').reason, 'running_newer_than_channel');
  assert.strictEqual(resolveTarget(dev, '1.0.0', () => null).reason, 'channel_has_no_release');
});

test('verifyRequest accepts a valid signature once, rejects replay/skew/tamper', () => {
  const master = 'master-secret-for-tests';
  const imei = '868123456789012';
  const now = 1_800_000_000;
  const key = deviceKey(master, imei);
  assert.match(key, /^[0-9a-f]{64}$/);
  const surface = `${imei}|1.0.0|${now}`;
  const sig = sign(key, surface);
  const guard = new ReplayGuard(300);
  const base = { masterSecret: master, imei, surface, ts: now, sig, windowSec: 300, nowSec: now };

  assert.deepStrictEqual(verifyRequest({ ...base, replayGuard: guard }), { ok: true });
  assert.strictEqual(verifyRequest({ ...base, replayGuard: guard }).error, 'replayed_request');
  assert.strictEqual(verifyRequest({ ...base, nowSec: now + 301 }).error, 'timestamp_out_of_window');
  assert.strictEqual(verifyRequest({ ...base, surface: `${imei}|9.9.9|${now}` }).error, 'bad_signature');
  assert.strictEqual(verifyRequest({ ...base, imei: '12' }).error, 'bad_device_id');
  // A key for another IMEI must not validate.
  const other = sign(deviceKey(master, '868123456789099'), surface);
  assert.strictEqual(verifyRequest({ ...base, sig: other }).error, 'bad_signature');
});
