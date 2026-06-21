// server/eudi-verifier/backend-client.js
//
// Thin client for EUDIPLO (OpenWallet Foundation), the verifier component we
// switched to for the German SPRIND EUDI sandbox wallet. It REPLACES the old
// EU Verifier Endpoint backend (Docker, :8080) but keeps the EXACT same export
// surface, so eudi-verifier/index.js needs no changes:
//
//   initTransaction(minAge)          → { transaction_id, nonce, uri, crossDeviceUri }
//   buildWalletLink(tx)              → openid4vp:// URL (already built by EUDIPLO)
//   pollWalletResponse(id, code)     → { status:'pending' } | { status:'done', walletResponse }
//   extractAgeClaims(walletResponse) → { age_over_14?, age_over_16?, age_over_18? }
//   config                           → { BACKEND, AV_DOCTYPE, AUTH_SCHEME }
//
// EUDIPLO does ALL the OpenID4VP 1.0 / DCQL / mso_mdoc / SessionTranscript /
// JWE work and signs the request object with our German-Registrar access cert.
// We only speak HTTP/JSON. The calls below (token, offer, config-create) are the
// ones proven manually against the running instance; the two behaviours we could
// NOT verify end-to-end are marked **CONFIRM** with the exact check to run.
//
// EUDIPLO API surface used (all under the /api prefix):
//   POST /api/oauth2/token      { client_id, client_secret } → { access_token, expires_in }
//   POST /api/verifier/config   { id, dcql_query, ... }       → stored config (201)
//   POST /api/verifier/offer    { response_type:'uri', requestId } → { uri, crossDeviceUri, session }
//   GET  /api/<session-path>    (CONFIRM) → session/result with disclosed claims

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
// **CONFIRM**: the exact minimal claim the German sandbox discloses — success
// relies on the EUDIPLO session reaching a terminal state, not on the value.
const EID_CONFIG_ID = process.env.EUDIPLO_EID_CONFIG_ID || 'eid-identity';
const EID_CLAIM     = process.env.EUDI_EID_CLAIM        || 'issuing_country';

const DEBUG = process.env.EUDI_DEBUG === '1';

// ── Token (client-credentials, cached, re-auth on expiry) ────────────────────

let tokenCache = { value: null, expiresAt: 0 };

async function getToken() {
  const now = Date.now();
  if (tokenCache.value && now < tokenCache.expiresAt - 60_000) return tokenCache.value;
  if (!CLIENT_SECRET) throw new Error('EUDIPLO_CLIENT_SECRET not configured');

  const r = await fetch(`${BACKEND}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET })
  });
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

async function authed(path, init = {}) {
  const token = await getToken();
  const headers = Object.assign({ Accept: 'application/json' }, init.headers, {
    Authorization: `Bearer ${token}`
  });
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  return fetch(`${BACKEND}${path}`, Object.assign({}, init, { headers }));
}

// ── Verifier config (one per age threshold, created on demand) ───────────────

// DCQL in the OpenID4VP 1.0 `path` form [namespace, element] — the form EUDIPLO
// expects and that matched the German wallet (confirmed for age_over_18).
function buildDcqlQuery(minAge) {
  return {
    credentials: [
      {
        id: 'pid',
        format: 'mso_mdoc',
        meta: { doctype_value: AV_DOCTYPE },
        claims: [{ path: [AV_DOCTYPE, `age_over_${minAge}`] }]
      }
    ]
  };
}

// Track configs we've ensured this process lifetime to avoid re-POSTing.
const ensuredConfigs = new Set();

// Ensure the verifier config `age-over-{minAge}` exists; return its id.
// **CONFIRM**: re-creating an existing config wasn't tested — does EUDIPLO 409
// or overwrite? We tolerate a conflict (treat "already exists" as success). If
// your instance returns something else on duplicate, tighten the check below.
async function ensureVerifierConfig(minAge) {
  const id = `${CONFIG_PREFIX}${minAge}`;
  if (ensuredConfigs.has(id)) return id;

  const r = await authed('/verifier/config', {
    method: 'POST',
    body: JSON.stringify({
      id,
      description: `HHTTPS age verification (>=${minAge})`,
      dcql_query: buildDcqlQuery(minAge)
    })
  });

  if (r.ok) {
    ensuredConfigs.add(id);
    return id;
  }
  // Tolerate "already exists": HTTP 409, or a 400/422 whose body mentions it.
  const text = await r.text().catch(() => '');
  if (r.status === 409 || /exist|duplicate|already/i.test(text)) {
    ensuredConfigs.add(id);
    return id;
  }
  throw new Error(`EUDIPLO config create failed (${r.status}): ${text.slice(0, 200)}`);
}

// ── 1. Init transaction = create an EUDIPLO presentation offer ───────────────

// Returns the shape index.js expects. EUDIPLO's `session` is our transaction id;
// it returns the full wallet-ready openid4vp:// URL, so there is no client_id /
// request_uri assembly on our side. The OID4VP nonce is managed inside EUDIPLO.
export async function initTransaction(minAge) {
  const requestId = await ensureVerifierConfig(minAge);

  const r = await authed('/verifier/offer', {
    method: 'POST',
    body: JSON.stringify({ response_type: 'uri', requestId })
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EUDIPLO offer failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json(); // { uri, crossDeviceUri, session }
  return {
    transaction_id: data.session,
    nonce: null,
    uri: data.uri,
    crossDeviceUri: data.crossDeviceUri
  };
}

// ── 1b. eID identity transaction (orthogonal PID presentation) ───────────────

// DCQL requesting one NON-identifying PID attribute, purely to obtain a validated
// PID presentation. The value is never read (zero-PII) — see EID_CLAIM note above.
function buildPidDcqlQuery() {
  return {
    credentials: [
      {
        id: 'pid',
        format: 'mso_mdoc',
        meta: { doctype_value: AV_DOCTYPE },
        claims: [{ path: [AV_DOCTYPE, EID_CLAIM] }]
      }
    ]
  };
}

async function ensureEidConfig() {
  const id = EID_CONFIG_ID;
  if (ensuredConfigs.has(id)) return id;
  const r = await authed('/verifier/config', {
    method: 'POST',
    body: JSON.stringify({
      id,
      description: 'HHTTPS EUDI identity (PID presentation)',
      dcql_query: buildPidDcqlQuery()
    })
  });
  if (r.ok) { ensuredConfigs.add(id); return id; }
  const text = await r.text().catch(() => '');
  if (r.status === 409 || /exist|duplicate|already/i.test(text)) { ensuredConfigs.add(id); return id; }
  throw new Error(`EUDIPLO eid config create failed (${r.status}): ${text.slice(0, 200)}`);
}

// Init an eID identity presentation. Same offer mechanism as initTransaction;
// poll the result with the SAME pollWalletResponse (a terminal session = a valid
// PID presentation). Returns the index.js-compatible transaction shape.
export async function initEidTransaction() {
  const requestId = await ensureEidConfig();
  const r = await authed('/verifier/offer', {
    method: 'POST',
    body: JSON.stringify({ response_type: 'uri', requestId })
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EUDIPLO eid offer failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json(); // { uri, crossDeviceUri, session }
  return {
    transaction_id: data.session,
    nonce: null,
    uri: data.uri,
    crossDeviceUri: data.crossDeviceUri
  };
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

// **CONFIRM**: the session/result endpoint path. We auto-discover it across the
// candidates below on the first poll and cache the one that answers; set
// EUDIPLO_SESSION_PATH to pin it explicitly. Run the check in the chat to lock
// this. While the wallet hasn't responded the session reports a non-terminal
// status (no age claims yet) → 'pending'.
const SESSION_PATHS = (process.env.EUDIPLO_SESSION_PATH
  ? [process.env.EUDIPLO_SESSION_PATH]
  : ['/verifier/session/{id}', '/session/{id}', '/presentations/{id}']);
let resolvedSessionPath = process.env.EUDIPLO_SESSION_PATH || null;

const TERMINAL = ['verified', 'completed', 'success', 'valid', 'done', 'submitted'];

// Done = explicit terminal status OR disclosed age_over_* claims present.
function sessionLooksDone(body) {
  if (!body || typeof body !== 'object') return false;
  const status = String(body.status || body.state || '').toLowerCase();
  if (TERMINAL.includes(status)) return true;
  return Object.keys(extractAgeClaims(body)).length > 0;
}

async function fetchSession(sessionId, tpl) {
  const r = await authed(tpl.replace('{id}', encodeURIComponent(sessionId)), { method: 'GET' });
  const raw = await r.text().catch(() => '');
  let body = null;
  try { body = raw && raw.trim().length ? JSON.parse(raw) : null; } catch { body = null; }
  return { ok: r.ok, status: r.status, body, raw };
}

export async function pollWalletResponse(transactionId, _responseCode) {
  const tag = String(transactionId).slice(0, 8);

  // Resolve the session endpoint once (first 2xx wins), then reuse it.
  if (!resolvedSessionPath) {
    for (const tpl of SESSION_PATHS) {
      const res = await fetchSession(transactionId, tpl);
      if (DEBUG) console.log(`[EUDI-DEBUG] probe ${tpl} tx=${tag}… HTTP ${res.status} bodyLen=${res.raw.length}`);
      if (res.ok) { resolvedSessionPath = tpl; break; }
    }
    if (!resolvedSessionPath) return { status: 'pending' }; // no path answered yet; retry next poll
  }

  const res = await fetchSession(transactionId, resolvedSessionPath);
  if (DEBUG) {
    console.log(`[EUDI-DEBUG] poll tx=${tag}… HTTP ${res.status} bodyLen=${res.raw.length} body=${res.raw.slice(0, 500)}`);
  }

  if (res.status === 404) return { status: 'pending' };
  if (!res.ok) throw new Error(`EUDIPLO session poll failed (${res.status}): ${res.raw.slice(0, 200)}`);

  if (sessionLooksDone(res.body)) {
    if (DEBUG) console.log(`[EUDI-DEBUG] tx=${tag}… → DONE, keys=${JSON.stringify(Object.keys(res.body || {}))}`);
    return { status: 'done', walletResponse: res.body };
  }
  return { status: 'pending' };
}

// ── 4. Extract disclosed age_over_NN booleans (unchanged) ────────────────────

// Defensive recursive scan for any age_over_* keys, so a PID-vs-AV doctype
// difference still yields the booleans. Returns { age_over_14?, age_over_16?,
// age_over_18? } with only present ones set; ageGroupFromEudiClaims maps the rest.
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

export const config = { BACKEND, AV_DOCTYPE, AUTH_SCHEME };
