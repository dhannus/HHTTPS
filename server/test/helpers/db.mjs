// Direct SQL access to the same Postgres the harnessed server uses, for
// assertions and cleanup in integration tests.
//
// W-27: the test-DB configuration lives HERE only — helpers/server.mjs
// (child-process env) and the db-phase8 test (db.js in-process) import it.
import pg from 'pg';

export const TEST_DB = Object.freeze({
  host:     process.env.TEST_PG_HOST || '',
  user:     'hhttps',
  database: 'hhttps',
  password: 'x',
});

/** Pepper the harnessed server runs with (helpers/server.mjs testEnv). */
export const TEST_PEPPER = 'test-pepper';
/** EUDI verifier secret the harnessed server runs with. */
export const TEST_EUDI_SECRET = 'test-secret';

let pool = null;

function getPool() {
  if (!pool) {
    if (!TEST_DB.host) throw new Error('db helper: TEST_PG_HOST is not set');
    pool = new pg.Pool({ ...TEST_DB, max: 2 });
  }
  return pool;
}

export async function sql(text, params = []) {
  const { rows } = await getPool().query(text, params);
  return rows;
}

export async function closeDb() {
  if (pool) { await pool.end(); pool = null; }
}
