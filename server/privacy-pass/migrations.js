/**
 * Privacy Pass DB migrations
 *
 * Inline-versioniert. Die Migrations laufen idempotent bei jedem Server-Start
 * über initPrivacyPass(). Das vermeidet alle Probleme mit externen SQL-Dateien,
 * die deploy-Skripte gelegentlich nicht mitkopieren.
 *
 * Append-only: neue Migrationen am Ende der MIGRATIONS-Liste hinzufügen.
 * Bestehende Migrationen niemals umschreiben — sie laufen idempotent (IF NOT
 * EXISTS) und werden bei jedem Start erneut ausgeführt.
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

  // ── Attribute verifications: which credentials have completed which role-
  //    specific verifications, with what trust level. Email is stored as a
  //    SHA-256 hash only — we never store the plaintext address here.
  {
    name: 'pp_attribute_verifications_v1',
    sql: `
      CREATE TABLE IF NOT EXISTS pp_attribute_verifications (
        id                  BIGSERIAL PRIMARY KEY,
        credential_id       TEXT NOT NULL,
        role                TEXT NOT NULL,
        method              TEXT NOT NULL,
        email_hash          TEXT,
        email_domain        TEXT,
        attribute_data      JSONB,
        trust_score         INT NOT NULL DEFAULT 0,
        verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at          TIMESTAMPTZ,
        UNIQUE (credential_id, role, method)
      );
      CREATE INDEX IF NOT EXISTS pp_attr_credential_role_idx
        ON pp_attribute_verifications (credential_id, role)
        WHERE revoked_at IS NULL;
      CREATE INDEX IF NOT EXISTS pp_attr_email_hash_idx
        ON pp_attribute_verifications (email_hash)
        WHERE revoked_at IS NULL;
    `,
  },

  // ── Pending email verifications. The user enters an email on the wallet
  //    page; we send a link with a token; clicking the link converts a
  //    pp_email_pending row into a pp_attribute_verifications row.
  {
    name: 'pp_email_pending_v1',
    sql: `
      CREATE TABLE IF NOT EXISTS pp_email_pending (
        token_hash      TEXT PRIMARY KEY,
        credential_id   TEXT NOT NULL,
        role            TEXT NOT NULL,
        email_hash      TEXT NOT NULL,
        email_domain    TEXT NOT NULL,
        method          TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMPTZ NOT NULL
      );
      CREATE INDEX IF NOT EXISTS pp_email_pending_expires_idx
        ON pp_email_pending (expires_at);
    `,
  },

  // ── Recovery codes: 10 single-use codes per user_id, generated at first
  //    onboarding. We store only SHA-256 hashes of each code.
  {
    name: 'pp_recovery_codes_v1',
    sql: `
      CREATE TABLE IF NOT EXISTS pp_recovery_codes (
        code_hash       TEXT PRIMARY KEY,
        user_id         TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        used_at         TIMESTAMPTZ,
        used_from_ip    TEXT
      );
      CREATE INDEX IF NOT EXISTS pp_recovery_codes_user_idx
        ON pp_recovery_codes (user_id)
        WHERE used_at IS NULL;
    `,
  },
];

export async function runMigrations() {
  const db   = await import('../db.js');
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
