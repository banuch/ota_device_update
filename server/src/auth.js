'use strict';
// =============================================================================
//  auth.js  --  dashboard authentication
//
//  Passwords   scrypt (N=16384, r=8, p=1, 16-byte salt), stored as
//              "scrypt$16384$8$1$<salt b64>$<hash b64>"
//  Sessions    random 32-byte cookie value "ota_sid"; the DB stores only its
//              sha256. HttpOnly + SameSite=Strict (+ Secure over HTTPS).
//              Ends after SESSION_IDLE_SEC of inactivity or SESSION_MAX_SEC.
//  Lockout     LOGIN_MAX_FAILS failed logins for a username from one IP (or
//              4x that from one IP for any usernames) within LOGIN_LOCK_SEC
//              lock it for LOGIN_LOCK_SEC.
//  CSRF        cookie-authenticated writes must carry "X-OTA-Console: 1"
//              (a custom header cross-site pages cannot send).
//  API key     "Authorization: Bearer <ADMIN_TOKEN>" = admin, actor "api-token".
// =============================================================================
const crypto = require('crypto');
const { safeEqualHex } = require('./hmac');

const COOKIE = 'ota_sid';
const CSRF_HEADER = 'x-ota-console';
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const USERNAME_RE = /^[A-Za-z0-9._-]{3,32}$/;
const MIN_PASSWORD = 10;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT.keylen,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltB64, hashB64] = parts;
  const want = Buffer.from(hashB64, 'base64');
  const got = crypto.scryptSync(String(password), Buffer.from(saltB64, 'base64'), want.length,
    { N: Number(N), r: Number(r), p: Number(p) });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// A fixed dummy hash so unknown usernames cost the same time as real ones.
const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString('hex'));

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD) return `password must be at least ${MIN_PASSWORD} characters`;
  if (pw.length > 200) return 'password too long';
  return null;
}

function validateUsername(name) {
  return USERNAME_RE.test(String(name || '')) ? null : 'username must be 3-32 chars: letters, digits . _ -';
}

// Failures are counted per (ip, username) and per ip. Keying on the username
// alone would let anyone lock a real admin out; the per-ip budget stops one
// source from spraying passwords across many usernames.
const IP_FAIL_FACTOR = 4;
const LIMITER_MAX_KEYS = 10000;

class LoginLimiter {
  constructor({ maxFails, lockSec, clock }) {
    this.maxFails = maxFails;
    this.lockMs = lockSec * 1000;
    this.clock = clock;
    this.state = new Map(); // key -> {fails:[ms...], lockedUntil}
  }
  keys(username, ip) {
    const addr = String(ip || '-');
    return [[`u:${addr}|${String(username || '').toLowerCase()}`, this.maxFails],
      [`ip:${addr}`, this.maxFails * IP_FAIL_FACTOR]];
  }
  lockedFor(username, ip) {
    const now = this.clock();
    let left = 0;
    for (const [k] of this.keys(username, ip)) {
      const s = this.state.get(k);
      if (s && s.lockedUntil > now) left = Math.max(left, s.lockedUntil - now);
    }
    return left > 0 ? Math.ceil(left / 1000) : 0;
  }
  fail(username, ip) {
    const now = this.clock();
    for (const [k, max] of this.keys(username, ip)) {
      const s = this.state.get(k) || { fails: [], lockedUntil: 0 };
      s.fails = s.fails.filter((t) => now - t < this.lockMs);
      s.fails.push(now);
      if (s.fails.length >= max) {
        s.lockedUntil = now + this.lockMs;
        s.fails = [];
      }
      this.state.set(k, s);
    }
    if (this.state.size > LIMITER_MAX_KEYS) this.prune(now);
    return this.lockedFor(username, ip) > 0;
  }
  success(username, ip) { this.state.delete(this.keys(username, ip)[0][0]); }
  /** Drops expired entries; if still near the cap, the oldest ones (with headroom so this stays rare). */
  prune(now) {
    for (const [k, s] of this.state) {
      if (s.lockedUntil <= now && s.fails.every((t) => now - t >= this.lockMs)) this.state.delete(k);
    }
    for (const k of this.state.keys()) {
      if (this.state.size <= LIMITER_MAX_KEYS * 0.9) break;
      this.state.delete(k);
    }
  }
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const raw = part.slice(eq + 1).trim();
    // Other apps on the same host can set cookies we cannot decode; keep them raw.
    try { out[part.slice(0, eq).trim()] = decodeURIComponent(raw); } catch { out[part.slice(0, eq).trim()] = raw; }
  }
  return out;
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function createAuth({ store, cfg }) {
  const clock = cfg.clock || Date.now;
  const limiter = new LoginLimiter({ maxFails: cfg.loginMaxFails, lockSec: cfg.loginLockSec, clock });

  const cookieAttrs = (req, maxAge) => {
    const secure = cfg.cookieSecure === 'always' || (cfg.cookieSecure === 'auto' && req.secure);
    return `Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
  };

  function startSession(req, res, user) {
    const token = crypto.randomBytes(32).toString('base64url');
    store.purgeSessions(cfg.sessionIdleSec, cfg.sessionMaxSec);
    store.createSession(sha256(token), user.id, req.ip, req.get('user-agent'));
    store.setLastLogin(user.id);
    res.setHeader('Set-Cookie', `${COOKIE}=${token}; ${cookieAttrs(req, cfg.sessionMaxSec)}`);
  }

  function endSession(req, res) {
    if (req.sessionId) store.deleteSession(req.sessionId);
    res.setHeader('Set-Cookie', `${COOKIE}=; ${cookieAttrs(req, 0)}`);
  }

  /** Resolves the cookie into req.user / req.sessionId (does not reject). */
  function sessionMiddleware(req, res, next) {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (!token) return next();
    const id = sha256(token);
    const s = store.getSession(id);
    const now = store.now();
    if (!s || !s.enabled || now - s.last_seen > cfg.sessionIdleSec || now - s.created_at > cfg.sessionMaxSec) {
      if (s) store.deleteSession(id);
      return next();
    }
    if (now - s.last_seen >= 60) store.touchSession(id); // sliding idle window, throttled
    req.sessionId = id;
    req.user = { id: s.user_id, username: s.username, role: s.role };
    next();
  }

  function bearerIsAdmin(req) {
    const h = req.get('authorization') || '';
    if (!h.startsWith('Bearer ')) return false;
    // Hash both sides so the comparison is constant-length.
    return safeEqualHex(sha256(cfg.adminToken), sha256(h.slice(7)));
  }

  /** Guard for /api: Bearer token or a session; viewers are read-only. */
  function requireApi(req, res, next) {
    if (bearerIsAdmin(req)) {
      req.actor = { username: 'api-token', role: 'admin' };
      return next();
    }
    if (!req.user) return res.status(401).json({ error: 'unauthorized' });
    const write = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    if (write && req.get(CSRF_HEADER) !== '1') return res.status(403).json({ error: 'csrf_header_missing' });
    if (write && req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden_viewer' });
    req.actor = req.user;
    next();
  }

  function requireAdmin(req, res, next) {
    if (!req.actor || req.actor.role !== 'admin') return res.status(403).json({ error: 'admin_only' });
    next();
  }

  return { limiter, startSession, endSession, sessionMiddleware, requireApi, requireAdmin, CSRF_HEADER };
}

module.exports = {
  createAuth, hashPassword, verifyPassword, validatePassword, validateUsername,
  DUMMY_HASH, LoginLimiter, parseCookies, MIN_PASSWORD,
};
