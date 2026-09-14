// server/eudi-verifier/errors.js
//
// Typed error for a non-OK answer of an internal HHTTPS endpoint
// (/hhttps/age/upgrade, /hhttps/age/direct, /hhttps/eid/upgrade) and the pure
// mapping of any status-handler error to the HTTP answer the browser gets (#26).
//
// Business errors of the backend (4xx, e.g. the e-mail gate
// 403 email_verification_required) are passed through with their status and
// `error` code; everything else (backend 5xx, EU verifier unreachable, missing
// config) stays a 502 so the frontend can tell "fix your input" from "try later".

export class BackendError extends Error {
  /**
   * @param {string} endpoint  short name, e.g. 'age/upgrade'
   * @param {number} status    HTTP status the backend answered
   * @param {object} body      parsed JSON body (may be {})
   */
  constructor(endpoint, status, body = {}) {
    super(`${endpoint} failed (${status}): ${body?.error || ''}`);
    this.name = 'BackendError';
    this.endpoint = endpoint;
    this.status = status;
    this.body = body || {};
  }
}

/** Map a status-handler error to `{ httpStatus, body }` for `res.status().json()`. */
export function mapBackendError(err) {
  const message = err?.message || String(err);
  if (err instanceof BackendError) {
    const passThrough = err.status >= 400 && err.status < 500;
    const body = { status: 'error' };
    if (err.body.error) body.error = err.body.error;
    body.detail = err.body.detail || message;
    return { httpStatus: passThrough ? err.status : 502, body };
  }
  return { httpStatus: 502, body: { status: 'error', detail: message } };
}
