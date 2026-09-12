// Direct SQL access to the same Postgres the harnessed server uses, for
// assertions and cleanup in integration tests.
import pg from 'pg';

let pool = null;

function getPool() {
  if (!pool) {
    if (!process.env.TEST_PG_HOST) throw new Error('db helper: TEST_PG_HOST is not set');
    pool = new pg.Pool({
      host: process.env.TEST_PG_HOST,
      user: 'hhttps',
      database: 'hhttps',
      password: 'x',
      max: 2,
    });
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
