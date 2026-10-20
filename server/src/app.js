'use strict';
const express = require('express');
const fs = require('fs');
const path = require('path');
const { openDb } = require('./db');
const { ReplayGuard } = require('./hmac');
const { deviceRoutes } = require('./routes/device');
const { adminRoutes } = require('./routes/admin');

function createApp(cfg) {
  fs.mkdirSync(cfg.firmwareDir, { recursive: true });
  const store = openDb(cfg.dbFile);
  const replayGuard = new ReplayGuard(cfg.tsWindowSec);

  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);

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
  app.use('/api', adminRoutes({ store, cfg }));
  app.use('/', express.static(path.join(__dirname, '..', 'public')));

  app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json' });
    console.error(err);
    res.status(500).json({ error: 'internal_error' });
  });

  return { app, store };
}

module.exports = { createApp };
