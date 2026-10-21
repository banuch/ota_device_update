'use strict';
// =============================================================================
//  routes/auth.js  --  dashboard login session
//
//    POST /auth/login     {username, password}   -> {username, role} + cookie
//    POST /auth/logout                           -> {ok}
//    GET  /auth/me                               -> {username, role} | 401
//    POST /auth/password  {current, next}        -> {ok}  (ends other sessions)
//
//  All POSTs require the X-OTA-Console: 1 header (CSRF guard).
// =============================================================================
const express = require('express');
const { verifyPassword, hashPassword, validatePassword, DUMMY_HASH } = require('../auth');

function authRoutes({ store, auth }) {
  const r = express.Router();
  r.use(express.json({ limit: '4kb' }));

  r.use((req, res, next) => {
    if (req.method === 'POST' && req.get(auth.CSRF_HEADER) !== '1') {
      return res.status(403).json({ error: 'csrf_header_missing' });
    }
    next();
  });

  r.post('/login', (req, res) => {
    const username = String((req.body && req.body.username) || '').trim();
    const password = String((req.body && req.body.password) || '');
    const locked = auth.limiter.lockedFor(username, req.ip);
    if (locked) return res.status(429).json({ error: 'locked', retry_after_s: locked });

    const user = username ? store.getUserByName(username) : null;
    // Always run scrypt so response time does not reveal whether the user exists.
    const ok = verifyPassword(password, user ? user.pass_hash : DUMMY_HASH) && user && user.enabled;
    if (!ok) {
      const nowLocked = auth.limiter.fail(username, req.ip);
      // actor stays '-': the typed username is unauthenticated input, not who acted.
      store.logEvent('-', 'login_failed', null, `user '${username.slice(0, 32)}' from ${req.ip}`, '-');
      return res.status(nowLocked ? 429 : 401).json(nowLocked
        ? { error: 'locked', retry_after_s: auth.limiter.lockedFor(username, req.ip) }
        : { error: 'invalid_credentials' });
    }
    auth.limiter.success(username, req.ip);
    auth.startSession(req, res, user);
    store.logEvent('-', 'login', null, `from ${req.ip}`, user.username);
    res.json({ username: user.username, role: user.role });
  });

  r.post('/logout', (req, res) => {
    if (req.user) store.logEvent('-', 'logout', null, '', req.user.username);
    auth.endSession(req, res);
    res.json({ ok: true });
  });

  r.get('/me', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' });
    res.json({ username: req.user.username, role: req.user.role });
  });

  r.post('/password', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'unauthorized' });
    const { current, next } = req.body || {};
    const user = store.getUser(req.user.id);
    if (!user || !verifyPassword(String(current || ''), user.pass_hash)) {
      return res.status(400).json({ error: 'current password is wrong' });
    }
    const err = validatePassword(next);
    if (err) return res.status(400).json({ error: err });
    store.updateUser(user.id, { passHash: hashPassword(next) });
    store.deleteUserSessions(user.id, req.sessionId);
    store.logEvent('-', 'password_changed', null, 'own password', user.username);
    res.json({ ok: true });
  });

  return r;
}

module.exports = { authRoutes };
