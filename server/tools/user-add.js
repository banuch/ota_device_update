#!/usr/bin/env node
'use strict';
// Create a dashboard user, or reset an existing one (e.g. a locked-out admin).
//
//   npm run user:add -- <username> [--role admin|viewer] [--reset]
//
// Prompts for the password (hidden). For scripts, pipe it in:
//   echo "the-password" | npm run user:add -- ops --role viewer
//
// --reset  existing user: set the new password and role, re-enable the
//          account, and end all of its sessions.
// Safe to run while the server is up (SQLite WAL).
const readline = require('readline');
const { loadConfig } = require('../src/config');
const { openDb } = require('../src/db');
const { hashPassword, validatePassword, validateUsername } = require('../src/auth');

function parseArgs(argv) {
  const out = { role: 'viewer', reset: false, username: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--role') out.role = argv[++i];
    else if (a === '--reset') out.reset = true;
    else if (!a.startsWith('--') && !out.username) out.username = a;
    else throw new Error(`unknown argument: ${a}`);
  }
  return out;
}

function ask(question, hidden) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: !!process.stdin.isTTY });
    if (hidden && process.stdin.isTTY) {
      rl._writeToOutput = (s) => { if (s.includes(question)) rl.output.write(s); };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden && process.stdin.isTTY) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { return fail(e.message); }
  if (!args.username) return fail('usage: npm run user:add -- <username> [--role admin|viewer] [--reset]');
  const uErr = validateUsername(args.username);
  if (uErr) return fail(uErr);
  if (!['admin', 'viewer'].includes(args.role)) return fail('--role must be admin or viewer');

  const cfg = loadConfig();
  require('fs').mkdirSync(cfg.dataDir, { recursive: true });
  const store = openDb(cfg.dbFile);
  const existing = store.getUserByName(args.username);
  if (existing && !args.reset) return fail(`user '${existing.username}' exists (use --reset to set a new password)`);

  const pw = await ask(`Password for ${args.username}: `, true);
  const pErr = validatePassword(pw);
  if (pErr) return fail(pErr);
  if (process.stdin.isTTY) {
    const again = await ask('Repeat password: ', true);
    if (again !== pw) return fail('passwords do not match');
  }

  if (existing) {
    store.updateUser(existing.id, { passHash: hashPassword(pw), role: args.role, enabled: 1 });
    store.deleteUserSessions(existing.id, '');
    store.logEvent('-', 'user_updated', null, `${existing.username}: reset via CLI (${args.role})`, 'cli');
    console.log(`Reset '${existing.username}' (${args.role}); its sessions were ended.`);
  } else {
    store.addUser({ username: args.username, passHash: hashPassword(pw), role: args.role });
    store.logEvent('-', 'user_added', null, `${args.username} (${args.role}) via CLI`, 'cli');
    console.log(`Created ${args.role} '${args.username}'.`);
  }
  store.close();
}

function fail(msg) {
  console.error(msg);
  process.exitCode = 1;
}

main();
