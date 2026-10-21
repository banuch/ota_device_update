'use strict';
// =============================================================================
//  routes/users.js  --  dashboard account management (admin only)
//
//    GET    /api/users
//    POST   /api/users        {username, password, role}
//    PATCH  /api/users/:id    {role?, enabled?, password?}
//    DELETE /api/users/:id
//
//  Rules: you cannot change your own role/enabled flag or delete yourself,
//  and there must always be at least one enabled admin. Disabling a user or
//  resetting their password ends their sessions.
// =============================================================================
const express = require('express');
const { hashPassword, validatePassword, validateUsername } = require('../auth');

const ROLES = new Set(['admin', 'viewer']);

function userRoutes({ store, auth }) {
  const r = express.Router();
  r.use(express.json({ limit: '4kb' }));
  r.use(auth.requireAdmin);

  const bad = (res, error, status = 400) => res.status(status).json({ error });
  const actorName = (req) => req.actor.username;
  const isSelf = (req, user) => req.actor.id === user.id;

  r.get('/', (req, res) => res.json(store.listUsers()));

  r.post('/', (req, res) => {
    const { username, password, role = 'viewer' } = req.body || {};
    const uErr = validateUsername(username);
    if (uErr) return bad(res, uErr);
    const pErr = validatePassword(password);
    if (pErr) return bad(res, pErr);
    if (!ROLES.has(role)) return bad(res, 'role must be admin or viewer');
    if (store.getUserByName(username)) return bad(res, 'username already exists', 409);
    const id = store.addUser({ username, passHash: hashPassword(password), role });
    store.logEvent('-', 'user_added', null, `${username} (${role})`, actorName(req));
    res.status(201).json(store.listUsers().find((u) => u.id === Number(id)));
  });

  r.patch('/:id', (req, res) => {
    const user = store.getUser(Number(req.params.id));
    if (!user) return bad(res, 'not found', 404);
    const b = req.body || {};
    const fields = {};
    const notes = [];

    if ('role' in b) {
      if (!ROLES.has(b.role)) return bad(res, 'role must be admin or viewer');
      if (b.role !== user.role) {
        if (isSelf(req, user)) return bad(res, 'you cannot change your own role');
        fields.role = b.role;
        notes.push(`role=${b.role}`);
      }
    }
    if ('enabled' in b) {
      const en = b.enabled ? 1 : 0;
      if (en !== user.enabled) {
        if (isSelf(req, user)) return bad(res, 'you cannot disable yourself');
        fields.enabled = en;
        notes.push(en ? 'enabled' : 'disabled');
      }
    }
    if ('password' in b) {
      const pErr = validatePassword(b.password);
      if (pErr) return bad(res, pErr);
      fields.passHash = hashPassword(b.password);
      notes.push('password reset');
    }
    if (!Object.keys(fields).length) return res.json(store.listUsers().find((u) => u.id === user.id));

    const losesAdmin = user.role === 'admin' && user.enabled &&
      (fields.role === 'viewer' || fields.enabled === 0);
    if (losesAdmin && store.countEnabledAdmins() <= 1) return bad(res, 'at least one enabled admin is required', 409);

    store.updateUser(user.id, fields);
    if (fields.enabled === 0 || fields.passHash || fields.role) {
      store.deleteUserSessions(user.id, isSelf(req, user) ? req.sessionId || '' : '');
    }
    store.logEvent('-', 'user_updated', null, `${user.username}: ${notes.join(', ')}`, actorName(req));
    res.json(store.listUsers().find((u) => u.id === user.id));
  });

  r.delete('/:id', (req, res) => {
    const user = store.getUser(Number(req.params.id));
    if (!user) return bad(res, 'not found', 404);
    if (isSelf(req, user)) return bad(res, 'you cannot delete yourself');
    if (user.role === 'admin' && user.enabled && store.countEnabledAdmins() <= 1) {
      return bad(res, 'at least one enabled admin is required', 409);
    }
    store.deleteUser(user.id); // sessions cascade
    store.logEvent('-', 'user_deleted', null, user.username, actorName(req));
    res.json({ ok: true });
  });

  return r;
}

module.exports = { userRoutes };
