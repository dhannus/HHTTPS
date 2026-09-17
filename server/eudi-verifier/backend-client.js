// server/eudi-verifier/backend-client.js
//
// Thin client for EUDIPLO (OpenWallet Foundation), the verifier component we
// switched to for the German SPRIND EUDI sandbox wallet. It REPLACES the old
// EU Verifier Endpoint backend (Docker, :8080) but keeps the EXACT same export
// surface, so eudi-verifier/index.js needs no changes:
//
//   initTransaction(minAge)          → { transaction_id, nonce, uri, crossDeviceUri }
//   buildWalletLink(tx)              → openid4vp:// URL (already built by EUDIPLO)
//   pollWalletResponse(id, code)     → { status:'pending' } | { status:'done', walletResponse } | { status:'failed', reason }
//   extractAgeClaims(walletResponse) → { age_over_14?, age_over_16?, age_over_18? }
//   config                           → { BACKEND, AV_DOCTYPE, AUTH_SCHEME }
//
// EUDIPLO does ALL the OpenID4VP 1.0 / DCQL / mso_mdoc / SessionTranscript /
// JWE work and signs the request object with our German-Registrar access cert.
// We only speak HTTP/JSON. Token, offer and config-create are proven manually
// against the running instance.
//
// EUDIPLO API surface used (all under the /api prefix):
//   POST   /api/oauth2/token          { client_id, client_secret } → { access_token, expires_in }
//   POST   /api/verifier/config       { id, dcql_query, ... }      → stored config (201)
//   PATCH  /api/verifier/config/{id}  { description, dcql_query }  → updated config
//   POST   /api/verifier/offer        { response_type:'uri', requestId } → { uri, crossDeviceUri, session }
//   GET    /api/verifier/session/{id} → session/result with the disclosed claims
//          (path pinnable via EUDIPLO_SESSION_PATH; legacy candidates are probed
//           once per process — see pollWalletResponse / AP4-38)
//   POST   /api/issuer/config, POST /api/issuer/offer → iamhmn-card issuance
//
// Every environment variable this module reads is documented in .env.example
// under "EUDI / EUDIPLO" (AP4-52 #245).

// EUDIPLO base URL — INCLUDES the /api prefix (confirmed: 404 on /oauth2/token,
// 201 on /api/oauth2/token). EUDIPLO runs on the same box on :3002; talk to it
// internally, not through nginx /eudiplo/ (that path is for the wallet).
const BACKEND       = process.env.EUDIPLO_BASE_URL    || 'http://127.0.0.1:3002/api';
const CLIENT_ID     = process.env.EUDIPLO_CLIENT_ID   || 'hhttps';
const CLIENT_SECRET = process.env.EUDIPLO_CLIENT_SECRET || '';

// Doctype to request. The SPRIND sandbox wallet presented PID, so PID is the
// default here (the old EU AV app used eu.europa.ec.av.1). Configurable so the
// doctype can change without code. For mdoc, the namespace equals the doctype.
const AV_DOCTYPE    = process.env.EUDI_AV_DOCTYPE     || 'eu.europa.ec.eudi.pid.1';

// Kept only for /age/health display: EUDIPLO already returns the full
// openid4vp:// URL in the offer, so we never assemble the scheme ourselves.
const AUTH_SCHEME   = process.env.EUDI_AUTH_SCHEME    || 'openid4vp://';

// Verifier-config id prefix. We map each HHTTPS age threshold to one EUDIPLO
// verifier config: age-over-14 / age-over-16 / age-over-18. (age-over-18 was
// created manually during bring-up; the others are created on first request.)
const CONFIG_PREFIX = process.env.EUDIPLO_CONFIG_PREFIX || 'age-over-';

// eID identity verification (v0.5): a SEPARATE, orthogonal PID presentation that
// proves "this holder presented a valid state PID" → the +40 `eudi` method. We
// request a single NON-identifying PID attribute purely to trigger a validated
// presentation; the value is never read or stored (zero-PII). The proof is the
// validated presentation itself. Both the config id and the claim are env-tunable.
// TODO(#248): confirm on the live German sandbox which minimal PID claim is
// actually disclosed, then pin EUDI_EID_CLAIM to it. Not blocking: success
// depends on the EUDIPLO session reaching a POSITIVE terminal state (AP4-24),
// never on the claim's value.
const EID_CONFIG_ID = process.env.EUDIPLO_EID_CONFIG_ID || 'eid-identity';
const EID_CLAIM     = process.env.EUDI_EID_CLAIM        || 'issuing_country';

// AP4-28 (#189): EUDI_DEBUG is a development aid only — ignored in production,
// and even then it logs status/keys, never the wallet response body.
const DEBUG = process.env.EUDI_DEBUG === '1' && process.env.NODE_ENV !== 'production';

// AP4-39 (#222): every upstream call is bounded — a hung EUDIPLO must not pin a
// polled or login-critical request for undici's ~300 s default.
const FETCH_TIMEOUT_MS = Number(process.env.EUDIPLO_FETCH_TIMEOUT_MS) || 8000;
const withTimeout = (init = {}) =>
  (init.signal ? init : Object.assign({}, init, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) }));

// ── Token (client-credentials, cached, re-auth on expiry) ────────────────────

let tokenCache = { value: null, expiresAt: 0 };

async function getToken() {
  const now = Date.now();
  if (tokenCache.value && now < tokenCache.expiresAt - 60_000) return tokenCache.value;
  if (!CLIENT_SECRET) throw new Error('EUDIPLO_CLIENT_SECRET not configured');

  const r = await fetch(`${BACKEND}/oauth2/token`, withTimeout({
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET })
  }));
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EUDIPLO token failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json();
  tokenCache = {
    value: data.access_token,
    expiresAt: now + (Number(data.expires_in) || 86400) * 1000
  };
  return tokenCache.value;
}

/** Drop the cached client-credentials token (AP4-10: a 401/403 means it is no longer valid upstream). */
export function resetTokenCache() {
  tokenCache = { value: null, expiresAt: 0 };
}

async function authedOnce(path, init) {
  const token = await getToken();
  const headers = Object.assign({ Accept: 'application/json' }, init.headers, {
    Authorization: `Bearer ${token}`
  });
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  return fetch(`${BACKEND}${path}`, withTimeout(Object.assign({}, init, { headers })));
}

// AP4-10 (#102): the token cache is only time-based; when EUDIPLO answers
// 401/403 (token revoked / secret rotated / instance restarted) invalidate it
// and retry exactly once with a fresh token.
async function authed(path, init = {}) {
  const r = await authedOnce(path, init);
  if (r.status !== 401 && r.status !== 403) return r;
  resetTokenCache();
  return authedOnce(path, init);
}

// ── Verifier config (one per age threshold, created on demand) ───────────────

// AP4-18 (Review 2026-09): PID issuer trust. EUDIPLO validates the issuer
// chain ONLY when the DCQL credential query carries `trusted_authorities`
// (see the AV section below) — the PID queries never did. The PID trust list
// (EUDIPLO-hosted LoTE with the PID issuer CAs, e.g. the German Registrar /
// national PID providers) is configured by the operator:
//   EUDI_PID_TRUST_LIST=<TENANT_URL>/trust-list/pid-trusted-list   (recommended)
//   EUDI_PID_TRUST_LIST=off                                        (explicitly skip)
// Unset → the queries are sent WITHOUT trust binding (EUDIPLO accepts any
// issuer) and the server logs a loud warning at boot. Activation is an
// operator step because it needs the LoTE installed in EUDIPLO first.
const PID_TRUST_LIST_URL = process.env.EUDI_PID_TRUST_LIST || '';
export function pidTrustBinding() {
  if (!PID_TRUST_LIST_URL || PID_TRUST_LIST_URL === 'off') return null;
  return [{ type: 'etsi_tl', values: [PID_TRUST_LIST_URL] }];
}
export function warnIfPidTrustUnbound(log = console) {
  if (pidTrustBinding()) return false;
  log.warn('[EUDI] EUDI_PID_TRUST_LIST is not set — PID presentations (age via PID, eID) are accepted from ANY issuer (AP4-18). Set EUDI_PID_TRUST_LIST to the EUDIPLO-hosted PID trust list before go-live.');
  return true;
}

// DCQL in the OpenID4VP 1.0 `path` form [namespace, element] — the form EUDIPLO
// expects and that matched the German wallet (confirmed for age_over_18).
export function buildDcqlQuery(minAge) {
  const credential = {
    id: 'pid',
    format: 'mso_mdoc',
    meta: { doctype_value: AV_DOCTYPE },
    claims: [{ path: [AV_DOCTYPE, `age_over_${minAge}`] }]
  };
  const trusted = pidTrustBinding();
  if (trusted) credential.trusted_authorities = trusted;
  return { credentials: [credential] };
}

// Track configs we've ensured this process lifetime to avoid re-POSTing.
const ensuredConfigs = new Set();

// AP4-51 (#242): EUDIPLO signals "this id already exists" as a 409 or as a
// 400/422 whose body says so — one place that decides it, for verifier AND
// issuer configs.
function looksLikeDuplicate(status, text) {
  return status === 409 || /exist|duplicate|already/i.test(text || '');
}

/**
 * AP4-51 (#242) / AP4-15: ONE way to bring a verifier config into its desired
 * shape. The three call sites used to differ in how they handled a conflict —
 * PID and eID silently reused whatever was stored, only AV patched it.
 *
 * EUDIPLO PERSISTS configs: a config created by an older deploy keeps its old
 * DCQL forever. That is how the `trusted_authorities` binding (AP4-18) silently
 * went missing from live requests. Therefore an existing config is always
 * PATCHed to the current description + DCQL, and a failed PATCH is an error —
 * a stale query means "issuer trust is not validated", which must not pass
 * unnoticed.
 *
 * @param {object}  cfg
 * @param {string}  cfg.id           verifier-config id
 * @param {string}  cfg.description  human-readable description
 * @param {object}  cfg.dcqlQuery    the DCQL query to store
 * @param {string}  cfg.label        error-message prefix ('' | 'AV ' | 'eid ')
 * @returns {Promise<string>} the config id (= EUDIPLO's requestId)
 */
async function ensureConfig({ id, description, dcqlQuery, label = '' }) {
  if (ensuredConfigs.has(id)) return id;

  const r = await authed('/verifier/config', {
    method: 'POST',
    body: JSON.stringify({ id, description, dcql_query: dcqlQuery })
  });
  if (r.ok) { ensuredConfigs.add(id); return id; }

  const text = await r.text().catch(() => '');
  if (!looksLikeDuplicate(r.status, text))
    throw new Error(`EUDIPLO ${label}config create failed (${r.status}): ${text.slice(0, 200)}`);

  const u = await authed(`/verifier/config/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify({ description, dcql_query: dcqlQuery })
  });
  if (!u.ok) {
    const utext = await u.text().catch(() => '');
    throw new Error(`EUDIPLO ${label}config update failed (${u.status}): ${utext.slice(0, 200)}`);
  }
  ensuredConfigs.add(id);
  return id;
}

/**
 * AP4-51 (#242): the three init*Transaction functions differed only in which
 * config they ensure and in their error text. One offer call for all of them.
 * @returns {Promise<{transaction_id:string, nonce:null, uri:string, crossDeviceUri:string}>}
 *          the transaction shape index.js expects. EUDIPLO's `session` IS our
 *          transaction id, and it returns the wallet-ready openid4vp:// URL, so
 *          there is no client_id / request_uri assembly on our side. The OID4VP
 *          nonce is managed inside EUDIPLO (hence `nonce: null`).
 */
async function createOffer(requestId, label = '') {
  const r = await authed('/verifier/offer', {
    method: 'POST',
    body: JSON.stringify({ response_type: 'uri', requestId })
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EUDIPLO ${label}offer failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json(); // { uri, crossDeviceUri, session }
  return {
    transaction_id: data.session,
    nonce: null,
    uri: data.uri,
    crossDeviceUri: data.crossDeviceUri
  };
}

// ── 1. Init transaction = create an EUDIPLO presentation offer ───────────────

/** Age via PID: ensure the `age-over-{minAge}` verifier config, then offer. */
export async function initTransaction(minAge) {
  const requestId = await ensureConfig({
    id:          `${CONFIG_PREFIX}${minAge}`,
    description: `HHTTPS age verification (>=${minAge})`,
    dcqlQuery:   buildDcqlQuery(minAge)
  });
  return createOffer(requestId);
}

// ── 1a. AV Profile transaction (EU Age Verification attestation, DIRECT) ─────
//
// DIRECT acceptance of the EU AV Profile Proof of Age attestation (doctype
// eu.europa.ec.av.1) — the attestation the EU Age Verification App ("mini
// wallet", announced 2026-04-15) carries. Unlike the PID age path above, this
// does NOT require any prior HHTTPS session: the attestation IS the entry point.
// Same OpenID4VP/mso_mdoc rails, different doctype and namespace (for mdoc the
// namespace equals the doctype). EUDIPLO does presentation validation exactly
// as for PID.
//
// TODO(#248) before go-live: EUDIPLO must know the AV trust anchors (Commission
// AV Trusted List / eIDAS Dashboard) to validate eu.europa.ec.av.1 signatures.
// The binding itself is enforced below via `trusted_authorities`; what is still
// unverified end-to-end is the anchor set inside EUDIPLO. Testing needs the EU
// AV demo app (the SPRIND sandbox wallet presents PID, not AV).
const AV_PROFILE_DOCTYPE = process.env.EUDI_AV_PROFILE_DOCTYPE  || 'eu.europa.ec.av.1';
const AV_CONFIG_PREFIX   = process.env.EUDIPLO_AV_CONFIG_PREFIX || 'av-age-over-';

// Trust list for DIRECT AV acceptance. EUDIPLO validates issuer trust ONLY when
// the DCQL credential query carries `trusted_authorities` (type `etsi_tl`,
// values = URLs of signed LoTE JWTs) — WITHOUT it, trust validation is SKIPPED
// (confirmed in EUDIPLO docs/source). We therefore always attach our own
// EUDIPLO-hosted LoTE (id `av-trusted-list`), populated from the EU AV Trusted
// List by scripts/install-av-trustlist.sh. `<TENANT_URL>` is resolved by
// EUDIPLO at runtime to `${PUBLIC_URL}/issuers/${tenantId}`.
// Escape hatch for local development WITHOUT trust validation:
//   EUDI_AV_TRUST_LIST=off   (never use in production — fail-open)
// AP4-35: `off` is a DEVELOPMENT escape hatch. In production it is ignored (the
// default LoTE is used) and the attempt is logged loudly — a fail-open trust
// setting must not be one environment variable away from a live deployment.
const AV_TRUST_LIST_DEFAULT = '<TENANT_URL>/trust-list/av-trusted-list';
const AV_TRUST_LIST_URL = (() => {
  const configured = process.env.EUDI_AV_TRUST_LIST || AV_TRUST_LIST_DEFAULT;
  if (configured !== 'off') return configured;
  if (process.env.NODE_ENV === 'production') {
    console.error('[EUDI] EUDI_AV_TRUST_LIST=off is FAIL-OPEN and is IGNORED in production (AP4-35) — ' +
                  `falling back to ${AV_TRUST_LIST_DEFAULT}. Unset the variable to silence this.`);
    return AV_TRUST_LIST_DEFAULT;
  }
  console.warn('[EUDI] EUDI_AV_TRUST_LIST=off — AV attestations are accepted from ANY issuer (development only).');
  return 'off';
})();

function buildAvDcqlQuery(minAge) {
  const credential = {
    id: 'proof_of_age',
    format: 'mso_mdoc',
    meta: { doctype_value: AV_PROFILE_DOCTYPE },
    claims: [{ path: [AV_PROFILE_DOCTYPE, `age_over_${minAge}`] }]
  };
  if (AV_TRUST_LIST_URL !== 'off') {
    credential.trusted_authorities = [
      { type: 'etsi_tl', values: [AV_TRUST_LIST_URL] }
    ];
  }
  return { credentials: [credential] };
}

// Init a DIRECT AV Profile presentation. Same offer mechanism and return shape
// as initTransaction; poll with the SAME pollWalletResponse / extractAgeClaims
// (the defensive age_over_* scan is doctype-agnostic by design).
export async function initAvTransaction(minAge) {
  const requestId = await ensureConfig({
    id:          `${AV_CONFIG_PREFIX}${minAge}`,
    description: `HHTTPS direct AV attestation (EU AV Profile, >=${minAge})`,
    dcqlQuery:   buildAvDcqlQuery(minAge),
    label:       'AV '
  });
  return createOffer(requestId, 'AV ');
}

// ── 1b. eID identity transaction (orthogonal PID presentation) ───────────────

// DCQL requesting one NON-identifying PID attribute, purely to obtain a validated
// PID presentation. The value is never read (zero-PII) — see EID_CLAIM note above.
export function buildPidDcqlQuery() {
  const credential = {
    id: 'pid',
    format: 'mso_mdoc',
    meta: { doctype_value: AV_DOCTYPE },
    claims: [{ path: [AV_DOCTYPE, EID_CLAIM] }]
  };
  const trusted = pidTrustBinding();
  if (trusted) credential.trusted_authorities = trusted;   // AP4-18
  return { credentials: [credential] };
}

// Init an eID identity presentation. Same offer mechanism as initTransaction;
// poll the result with the SAME pollWalletResponse (a POSITIVE terminal session
// = a valid PID presentation). Returns the index.js-compatible transaction shape.
export async function initEidTransaction() {
  const requestId = await ensureConfig({
    id:          EID_CONFIG_ID,
    description: 'HHTTPS EUDI identity (PID presentation)',
    dcqlQuery:   buildPidDcqlQuery(),
    label:       'eid '
  });
  return createOffer(requestId, 'eid ');
}

// ── 2. Wallet link ───────────────────────────────────────────────────────────

// EUDIPLO already returns the wallet-ready openid4vp:// URL (client_id +
// request_uri embedded, request object signed with the German-Registrar cert).
// `uri` works same- and cross-device; `crossDeviceUri` is the no-redirect
// variant if you ever want to split the two surfaces. index.js uses one string.
export function buildWalletLink(tx) {
  return (tx && (tx.uri || tx.crossDeviceUri)) || null;
}

// ── 3. Poll the EUDIPLO session for the wallet's response ────────────────────

// The session/result endpoint path. Set EUDIPLO_SESSION_PATH to pin it
// explicitly (recommended for production); otherwise the documented EUDIPLO
// path `/verifier/session/{id}` is the default candidate and the legacy
// alternatives are probed ONCE (AP4-38 #217): the path is resolved on the
// first poll that answers 2xx, or — when the first candidate answers 404 —
// taken as resolved-and-pending (a session that is not yet known upstream
// looks identical to a wrong path, and re-probing three URLs every 2.5 s
// per client is what the autodiscovery used to do).
const SESSION_PATHS = (process.env.EUDIPLO_SESSION_PATH
  ? [process.env.EUDIPLO_SESSION_PATH]
  : ['/verifier/session/{id}', '/session/{id}', '/presentations/{id}']);
let resolvedSessionPath = process.env.EUDIPLO_SESSION_PATH || null;

// AP4-24 (#166): only documented POSITIVE terminal states count as "presentation
// valid". `submitted` (wallet posted, not yet validated) is NOT one of them.
const TERMINAL = ['verified', 'completed', 'success', 'valid', 'done'];
// AP4-09 (#92): negative terminal states — surfaced as { status:'failed' } so
// the browser stops polling instead of waiting for the 10-min TTL.
const FAILED = ['failed', 'rejected', 'expired', 'error', 'cancelled', 'canceled',
                'declined', 'denied', 'aborted', 'invalid'];

function sessionStatus(body) {
  if (!body || typeof body !== 'object') return '';
  return String(body.status || body.state || '').toLowerCase();
}

// Done = an explicit positive terminal status. A body without a status field is
// only "done" when it carries VERIFIED disclosure data (the EUDIPLO session
// result fields, never an arbitrary nested age_over_* key — AP4-24).
const DISCLOSURE_FIELDS = ['credentials', 'verifiedCredentials', 'presentation', 'claims', 'disclosed'];
export function sessionLooksDone(body) {
  if (!body || typeof body !== 'object') return false;
  const status = sessionStatus(body);
  if (TERMINAL.includes(status)) return true;
  if (status) return false;                              // explicit non-terminal status
  if (body.error || body.errorCode) return false;
  return DISCLOSURE_FIELDS.some(f => body[f] && typeof body[f] === 'object'
                                     && Object.keys(extractAgeClaims(body[f])).length > 0);
}

export function sessionLooksFailed(body) {
  if (!body || typeof body !== 'object') return null;
  const status = sessionStatus(body);
  if (FAILED.includes(status)) return status;
  if (body.error || body.errorCode) return String(body.error || body.errorCode).slice(0, 80);
  return null;
}

async function fetchSession(sessionId, tpl) {
  const r = await authed(tpl.replace('{id}', encodeURIComponent(sessionId)), { method: 'GET' });
  const raw = await r.text().catch(() => '');
  let body = null;
  try { body = raw && raw.trim().length ? JSON.parse(raw) : null; } catch { body = null; }
  return { ok: r.ok, status: r.status, body, raw };
}

// Transactions that were seen by the session endpoint at least once: a later
// 404 for them means the session is gone upstream (expired/cleaned) → failed,
// not "pending forever" (AP4-09).
const seenSessions = new Set();
export function forgetSession(transactionId) { seenSessions.delete(transactionId); }

export async function pollWalletResponse(transactionId) {
  const tag = String(transactionId).slice(0, 8);

  // Resolve the session endpoint once (first 2xx wins, else first candidate on
  // 404), then reuse it for the process lifetime.
  if (!resolvedSessionPath) {
    let firstStatus = null;
    for (const tpl of SESSION_PATHS) {
      const res = await fetchSession(transactionId, tpl);
      if (DEBUG) console.log(`[EUDI-DEBUG] probe ${tpl} tx=${tag}… HTTP ${res.status} bodyLen=${res.raw.length}`);
      if (firstStatus === null) firstStatus = res.status;
      if (res.ok) { resolvedSessionPath = tpl; break; }
    }
    if (!resolvedSessionPath && firstStatus === 404) resolvedSessionPath = SESSION_PATHS[0];
    if (!resolvedSessionPath) return { status: 'pending' }; // nothing answered; retry next poll
  }

  const res = await fetchSession(transactionId, resolvedSessionPath);
  if (DEBUG) {
    // AP4-28: status + top-level keys only — never the wallet response body.
    console.log(`[EUDI-DEBUG] poll tx=${tag}… HTTP ${res.status} keys=${JSON.stringify(Object.keys(res.body || {}))} status=${sessionStatus(res.body)}`);
  }

  if (res.status === 404) {
    if (seenSessions.has(transactionId)) {
      seenSessions.delete(transactionId);
      return { status: 'failed', reason: 'session_gone' };
    }
    return { status: 'pending' };
  }
  if (!res.ok) throw new Error(`EUDIPLO session poll failed (${res.status}): ${res.raw.slice(0, 200)}`);
  seenSessions.add(transactionId);

  const failedReason = sessionLooksFailed(res.body);
  if (failedReason) {
    seenSessions.delete(transactionId);
    return { status: 'failed', reason: failedReason };
  }
  if (sessionLooksDone(res.body)) {
    seenSessions.delete(transactionId);
    if (DEBUG) console.log(`[EUDI-DEBUG] tx=${tag}… → DONE, keys=${JSON.stringify(Object.keys(res.body || {}))}`);
    return { status: 'done', walletResponse: res.body };
  }
  return { status: 'pending' };
}

// ── 4. Extract disclosed age_over_NN booleans (unchanged) ────────────────────

// Defensive recursive scan for any age_over_* keys, so a PID-vs-AV doctype
// difference still yields the booleans. Returns { age_over_14?, age_over_16?,
// age_over_18? } with only present ones set; ageGroupFromEudiClaims maps the rest.
// AP4-24 (#166): the claims the bridge acts on come from the session result's
// disclosure fields (the data EUDIPLO validated). Only when the backend reports
// an explicit positive terminal status and none of the known disclosure fields
// is present do we fall back to the whole body.
// TODO(#248): pin DISCLOSURE_FIELDS to the field EUDIPLO actually uses once it
// is confirmed on the live instance; the fallback exists only because the
// naming is instance-specific.
export function extractVerifiedAgeClaims(sessionBody) {
  if (!sessionBody || typeof sessionBody !== 'object') return {};
  for (const f of DISCLOSURE_FIELDS) {
    if (sessionBody[f] && typeof sessionBody[f] === 'object') {
      const found = extractAgeClaims(sessionBody[f]);
      if (Object.keys(found).length) return found;
    }
  }
  return TERMINAL.includes(sessionStatus(sessionBody)) ? extractAgeClaims(sessionBody) : {};
}

export function extractAgeClaims(walletResponse) {
  const out = {};
  const scan = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [k, v] of Object.entries(obj)) {
      if (/^age_over_\d+$/.test(k)) {
        out[k] = v === true;
      } else if (typeof v === 'object') {
        scan(v);
      }
    }
  };
  scan(walletResponse);
  return out;
}

// ── iamhmn-card ISSUANCE (OID4VCI) ───────────────────────────────────────────
//
// HHTTPS as an ISSUER: we mint our own attestation — the "iamhmn-card" — INTO the
// user's wallet via EUDIPLO's issuer offer. This is the "create a role yourself"
// path proven manually at the hackathon, now as code. The card carries the role
// the user defined plus its honest RAL (0 self-declared / 1 document-checked).
// Later the card is presented back (OID4VP) and read like any other attestation.
//
// Proven flow (hackathon):
//   POST /api/issuer/offer
//     { response_type:'uri', flow:'pre_authorized_code',
//       credentialConfigurationIds:['iamhmn-card'],
//       claims:{ 'iamhmn-card':{ type:'inline', claims:{ …string-valued… } } } }
//   → { uri, crossDeviceUri }
// Notes baked in: NO tx_code (Android-friendly); inline claims are STRING-typed
// (mdoc); the EUDIPLO issuer config for 'iamhmn-card' must have
// refreshTokenEnabled:false and ECDH-ES response encryption (server-side config).

const CARD_CONFIG_ID = process.env.EUDIPLO_CARD_CONFIG_ID || 'iamhmn-card';
let cardConfigEnsured = false;

// Best-effort: ensure the ISSUER config exists with the hackathon-proven flags.
// Unlike the verifier configs (ensureConfig above) there is no DCQL to keep in
// sync, so an existing config is simply accepted — many instances provision it
// out-of-band. A network error is tolerated for the same reason.
export async function ensureIamhmnCardConfig() {
  if (cardConfigEnsured) return CARD_CONFIG_ID;
  const r = await authed('/issuer/config', {
    method: 'POST',
    body: JSON.stringify({
      id: CARD_CONFIG_ID,
      description: 'iamhmn human/role card (HHTTPS-issued EAA)',
      refreshTokenEnabled: false        // hackathon fix: avoid session.consumed on retry
    })
  }).catch(() => null);
  if (r && r.ok) { cardConfigEnsured = true; return CARD_CONFIG_ID; }
  const text = r ? await r.text().catch(() => '') : '';
  if (!r || looksLikeDuplicate(r.status, text)) {
    cardConfigEnsured = true;            // assume pre-provisioned / present
    return CARD_CONFIG_ID;
  }
  throw new Error(`EUDIPLO card-config failed (${r.status}): ${text.slice(0, 200)}`);
}

// Coerce every inline claim value to a string (mdoc inline claims are strings).
function stringifyClaims(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (v === undefined || v === null) continue;
    out[k] = typeof v === 'string' ? v : String(v);
  }
  return out;
}

/**
 * Issue an iamhmn-card offer. Returns the wallet-ready offer URI.
 * @param {object} claims  inline card claims, e.g.
 *   { userId, role, roleLabel, isco08, escoUri, ral, human, method, trustScore }
 * @returns {Promise<{ uri:string, crossDeviceUri?:string, session?:string }>}
 */
export async function issueIamhmnCard(claims) {
  await ensureIamhmnCardConfig();
  const r = await authed('/issuer/offer', {
    method: 'POST',
    body: JSON.stringify({
      response_type: 'uri',
      flow: 'pre_authorized_code',                 // no tx_code → Android-friendly
      credentialConfigurationIds: [CARD_CONFIG_ID],
      claims: { [CARD_CONFIG_ID]: { type: 'inline', claims: stringifyClaims(claims) } }
    })
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EUDIPLO card offer failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json();   // { uri, crossDeviceUri, session }
  return { uri: data.uri, crossDeviceUri: data.crossDeviceUri || null, session: data.session || null };
}

export const config = { BACKEND, AV_DOCTYPE, AV_PROFILE_DOCTYPE, AUTH_SCHEME, CARD_CONFIG_ID };
