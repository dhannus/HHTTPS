#!/usr/bin/env node
// scripts/migrate.js — apply the SQL migration chain in a fixed order with a
// ledger (`schema_migrations`), so a fresh installation ends up with the same
// schema the server expects at boot (AP6-01, Review 2026-09).
//
//   node scripts/migrate.js              apply everything not yet in the ledger
//   node scripts/migrate.js --dry-run    list pending files, change nothing
//   node scripts/migrate.js --baseline   mark every file as applied WITHOUT
//                                        running it (existing installations
//                                        whose schema was migrated by hand)
//
// Connection: DB_HOST / DB_PORT / DB_NAME / DB_USER / DB_PASSWORD (same as
// server.js; .env is loaded). Each file runs as ONE multi-statement query over
// the simple protocol (the files use DO $$ blocks and their own BEGIN/COMMIT),
// followed by the ledger insert. A failing file stops the run; nothing after
// it is applied.
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { MIGRATIONS } from '../db.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const SQL_DIR = path.join(here, '..', 'sql');

// The apply order is NOT defined here: `MIGRATIONS` in db.js is the single
// registry (AP6-40, #160), so the boot-DDL safety net and this runner can
// never drift apart. Entries marked `boot` there are the files a running
// server applies itself; this runner always applies the WHOLE file.
export const MIGRATION_ORDER = MIGRATIONS.map(m => m.file);

export async function migrate({ client, mode = 'apply', log = console } = {}) {
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  const { rows } = await client.query(`SELECT name FROM schema_migrations`);
  const done = new Set(rows.map(r => r.name));
  const pending = MIGRATION_ORDER.filter(f => !done.has(f));
  for (const f of MIGRATION_ORDER) {
    if (!fs.existsSync(path.join(SQL_DIR, f))) throw new Error(`migration file missing: sql/${f}`);
  }
  if (mode === 'dry-run') {
    log.log(pending.length ? `pending:\n  ${pending.join('\n  ')}` : 'nothing pending');
    return { applied: [], pending };
  }
  const applied = [];
  for (const f of pending) {
    if (mode === 'apply') {
      const text = fs.readFileSync(path.join(SQL_DIR, f), 'utf8');
      log.log(`applying sql/${f} …`);
      await client.query(text);
    } else {
      log.log(`baseline: marking sql/${f} as applied`);
    }
    await client.query(`INSERT INTO schema_migrations (name) VALUES ($1) ON CONFLICT DO NOTHING`, [f]);
    applied.push(f);
  }
  log.log(applied.length ? `done: ${applied.length} file(s) ${mode === 'apply' ? 'applied' : 'baselined'}` : 'nothing to do');
  return { applied, pending: [] };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const mode = process.argv.includes('--dry-run') ? 'dry-run'
             : process.argv.includes('--baseline') ? 'baseline' : 'apply';
  const client = new pg.Client({
    host:     process.env.DB_HOST     || 'localhost',
    port:     parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME     || 'hhttps',
    user:     process.env.DB_USER     || 'hhttps',
    password: process.env.DB_PASSWORD,
  });
  try {
    await client.connect();
    await migrate({ client, mode });
  } catch (e) {
    console.error(`[migrate] ${e.message}`);
    process.exitCode = 1;
  } finally {
    await client.end().catch(() => {});
  }
}
