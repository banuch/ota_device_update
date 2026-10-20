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
