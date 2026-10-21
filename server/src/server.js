'use strict';
const { loadConfig, assertConfig } = require('./config');
const { createApp } = require('./app');

const cfg = loadConfig();
try {
  assertConfig(cfg);
} catch (e) {
  console.error(e.message);
  process.exit(1);
}

const { app, store } = createApp(cfg);
const server = app.listen(cfg.port, () => {
  console.log(`[OTA] server listening on :${cfg.port}`);
  console.log(`[OTA] data dir: ${cfg.dataDir}`);
  console.log(`[OTA] admin dashboard: http://localhost:${cfg.port}/`);
  if (store.countUsers() === 0) {
    console.warn('[OTA] WARNING: no dashboard users yet. Create the first admin with:');
    console.warn('[OTA]   npm run user:add -- <username> --role admin');
  }
});
// Cellular links are slow: give a full firmware download plenty of time.
server.setTimeout(15 * 60 * 1000);

const shutdown = () => {
  server.close(() => {
    store.close();
    process.exit(0);
  });
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
