// server/eudi-verifier/backend-client.js
//
// Thin client for the official EU Verifier Endpoint backend (Docker, :8080).
// Wraps exactly two real endpoints (verified against the repo README):
//
//   POST /ui/presentations               → initialise a transaction
//   GET  /ui/presentations/{id}          → poll for the wallet's response
//
// This module does NOT parse mdoc/vp_token or do any crypto — the EU backend
// does all of that. We only send a DCQL age query and read back the validated
// age_over_NN booleans.

import crypto from 'crypto';

const BACKEND = process.env.EUDI_BACKEND_URL || 'http://127.0.0.1:8080';

// Which credential + doctype to request. The EU Age-Verification app issues
// `eu.europa.ec.av.1`; a generic EUDI wallet with PID uses
// `eu.europa.ec.eudi.pid.1`. Both carry age_over_NN claims — only the doctype
// string differs. Configurable so the hackathon sandbox can switch without code.
const AV_DOCTYPE = process.env.EUDI_AV_DOCTYPE || 'eu.europa.ec.av.1';

// Scheme used inside the QR / deep-link. The AV profile uses custom schemes;
// `openid4vp://` is the interoperable default. Configurable for the sandbox.
const AUTH_SCHEME = process.env.EUDI_AUTH_SCHEME || 'openid4vp://';

// Build the DCQL query asking for the minimal age_over_NN boolean(s).
// `minAge` is one of 14 | 16 | 18 (the thresholds HHTTPS cares about).
function buildDcqlQuery(minAge) {
  const claimName = `age_over_${minAge}`;
  return {
    credentials: [
      {
        id: 'proof_of_age',
        format: 'mso_mdoc',
        meta: { doctype_value: AV_DOCTYPE },
        claims: [{ path: [AV_DOCTYPE, claimName] }]
      }
    ]
  };
}

// Initialise a presentation transaction. Returns the backend's JSON:
//   { transaction_id, client_id, request_uri, request_uri_method }
// We build the wallet-facing openid4vp:// link from request_uri + client_id.
export async function initTransaction(minAge) {
  const nonce = crypto.randomUUID();
  const body = {
    dcql_query: buildDcqlQuery(minAge),
    nonce,
    jar_mode: 'by_reference',
    request_uri_method: 'post',
    response_mode: 'direct_post',
    profile: 'openid4vp'
  };

  const r = await fetch(`${BACKEND}/ui/presentations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body)
  });

  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EU backend init failed (${r.status}): ${text.slice(0, 200)}`);
  }
  const data = await r.json();
  return { ...data, nonce };
}

// Build the openid4vp:// URL the wallet consumes (same string for QR + deep-link).
// Per OpenID4VP, the wallet receives client_id + request_uri.
export function buildWalletLink({ client_id, request_uri, request_uri_method }) {
  const params = new URLSearchParams({
    client_id,
    request_uri
  });
  if (request_uri_method) params.set('request_uri_method', request_uri_method);
  return `${AUTH_SCHEME}?${params.toString()}`;
}

// Poll the backend for the wallet's response. The EU backend returns:
//   - 404 / empty while the wallet hasn't responded yet (still pending)
//   - 200 + JSON containing the validated presentation once the wallet posted
//
// We return { status: 'pending' } or { status: 'done', walletResponse }.
export async function pollWalletResponse(transactionId, responseCode) {
  const url = new URL(`${BACKEND}/ui/presentations/${encodeURIComponent(transactionId)}`);
  if (responseCode) url.searchParams.set('response_code', responseCode);

  const r = await fetch(url, { headers: { Accept: 'application/json' } });

  // EU backend state machine: GET /ui/presentations/{id} only returns the wallet
  // response once the presentation reaches the `Submitted` state (wallet has
  // posted vp_token). While still in `Requested` or `RequestObjectRetrieved`
  // (wallet hasn't scanned/answered yet), the backend responds with HTTP 400
  // and an empty body — this is its convention for "still pending", NOT a real
  // error. We therefore treat 404 AND 400-with-empty-body as pending. A 400
  // WITH content remains a real error so genuine backend problems still surface.
  if (r.status === 404) return { status: 'pending' };
  if (r.status === 400) {
    const text = await r.text().catch(() => '');
    if (!text || text.trim().length === 0) return { status: 'pending' };
    throw new Error(`EU backend rejected poll (400): ${text.slice(0, 200)}`);
  }
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`EU backend poll failed (${r.status}): ${text.slice(0, 200)}`);
  }

  const body = await r.json().catch(() => null);
  // A 200 with an empty/again-pending body can also mean "not yet"; treat the
  // presence of presentation data as the done signal.
  if (!body || (Array.isArray(body) && body.length === 0)) {
    return { status: 'pending' };
  }
  return { status: 'done', walletResponse: body };
}

// Extract the disclosed age_over_NN booleans from the backend's wallet response.
// The validated attributes appear under the doctype namespace. We defensively
// scan for any age_over_* keys so a PID-vs-AV doctype mismatch still yields the
// booleans. Returns { age_over_14?, age_over_16?, age_over_18? } (only present
// ones are set true; absent/false → not proven, handled by ageGroupFromEudiClaims).
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
