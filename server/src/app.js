'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const { openDb } = require('./db');
const { ReplayGuard } = require('./hmac');
const { createAuth } = require('./auth');
const { deviceRoutes } = require('./routes/device');
const { adminRoutes } = require('./routes/admin');
const { authRoutes } = require('./routes/auth');
const { userRoutes } = require('./routes/users');

function createApp(cfg) {
  fs.mkdirSync(cfg.firmwareDir, { recursive: true });
  const store = openDb(cfg.dbFile, { clock: cfg.clock });
  const replayGuard = new ReplayGuard(cfg.tsWindowSec);
  const auth = createAuth({ store, cfg });

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  if (cfg.trustProxy) app.set('trust proxy', cfg.trustProxy);

  app.use((req, res, next) => {
    const t0 = Date.now();
    const urlPath = req.originalUrl.split('?')[0]; // never log the download token
    res.on('finish', () => {
      if (urlPath.startsWith('/ota/') && !process.env.OTA_QUIET) {
        console.log(`${new Date().toISOString()} ${req.socket.remoteAddress} ${req.method} ` +
          `${urlPath} ${res.statusCode} ${Date.now() - t0}ms`);
      }
    });
    next();
  });

  app.get('/health', (req, res) => res.json({ ok: true }));
  app.use('/ota', deviceRoutes({ store, cfg, replayGuard }));

  // Dashboard: session cookie -> req.user for everything below.
  app.use(auth.sessionMiddleware);
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
  });
  app.use('/auth', authRoutes({ store, auth }));
  app.use('/api/users', auth.requireApi, userRoutes({ store, auth }));
  app.use('/api', adminRoutes({ store, cfg, auth }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'not_found' }));
  app.use('/', express.static(path.join(__dirname, '..', 'public'), {
    setHeaders: (res) => res.setHeader('Cache-Control', 'no-cache'),
  }));

  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json' });
    console.error(err);
    res.status(500).json({ error: 'internal_error' });
  });

  return { app, store, auth };
}

module.exports = { createApp };
