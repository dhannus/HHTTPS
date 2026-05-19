/**
 * Privacy Pass DB migrations
 *
 * Inline-versioniert. Die Migrations laufen idempotent bei jedem Server-Start
 * über initPrivacyPass(). Das vermeidet alle Probleme mit externen SQL-Dateien,
 * die deploy-Skripte gelegentlich nicht mitkopieren.
 */

const MIGRATIONS = [
  {
    name: 'pp_issuance_log_v1',
    sql: `
      CREATE TABLE IF NOT EXISTS pp_issuance_log (
        id              BIGSERIAL PRIMARY KEY,
        credential_id   TEXT NOT NULL,
        role            TEXT NOT NULL,
        token_count     INT NOT NULL CHECK (token_count > 0),
        issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS pp_issuance_log_credential_at_idx
        ON pp_issuance_log (credential_id, issued_at DESC);
      CREATE INDEX IF NOT EXISTS pp_issuance_log_role_at_idx
        ON pp_issuance_log (role, issued_at DESC);
    `,
  },
  // Future migrations append here.
];

export async function runMigrations() {
  const db = await import('../db.js');
  const pool = db.pool();

  let applied = 0;
  let failed  = 0;
  for (const m of MIGRATIONS) {
    try {
      await pool.query(m.sql);
      applied++;
    } catch (err) {
      failed++;
      console.error(`   [PRIVACY-PASS] migration ${m.name} failed:`, err.message);
    }
  }

  if (failed === 0) {
    console.log(`   [PRIVACY-PASS] ${applied} migration(s) applied`);
  } else {
    console.warn(`   [PRIVACY-PASS] ${applied} migration(s) applied, ${failed} failed`);
  }
}
