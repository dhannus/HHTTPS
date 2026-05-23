/**
 * HHTTPS Client SDK — JavaScript / Node.js / Browser
 * iamhmn Initiative · github.com/dhannus/HHTTPS
 *
 * Two verification paths:
 *
 *   1. verifyLocal(token) — RECOMMENDED for servers.
 *      Fetches the issuer JWKS once (cached 1h) and verifies the token's
 *      ES256 signature locally. No per-request network call to the issuer.
 *      This is the federated, offline-verifiable path the protocol is built on.
 *
 *   2. check(token) — convenience path.
 *      Calls the issuer's /hhttps/check endpoint. Useful when you also want
 *      the issuer's live revocation status and enriched role metadata in one
 *      call, at the cost of a network round-trip per check.
 *
 * Usage (Node.js, local verification):
 *   import { HHTPPSClient } from './sdk/client.js';
 *   const hhttps = new HHTPPSClient('https://hhttps.org');
 *   const result = await hhttps.verifyLocal(token);
 *   if (result.human && result.trustScore >= 80) { ... }
 *
 * Usage (Node.js, remote check):
 *   const result = await hhttps.check(token);
 *
 * Local verification uses the Web Crypto API (globalThis.crypto.subtle),
 * available in Node 16+ and all modern browsers. No external dependency.
 */

export class HHTPPSClient {
  /**
   * @param {string} serverUrl  — Base URL of the HHTTPS issuer
   * @param {object} options
   * @param {number} options.timeout      — Request timeout in ms (default 8000)
   * @param {boolean} options.cache       — Cache discovery + JWKS (default true)
   * @param {number} options.jwksMaxAgeMs — JWKS cache TTL in ms (default 3600000)
   */
  constructor(serverUrl, options = {}) {
    this.serverUrl    = serverUrl.replace(/\/$/, '');
    this.timeout      = options.timeout || 8000;
    this._cache       = options.cache !== false;
    this.jwksMaxAgeMs = options.jwksMaxAgeMs || 3600_000;
    this._discovery   = null;
    this._jwks        = null;   // { keys: [...] }
    this._jwksAt      = 0;      // epoch ms of last JWKS fetch
    this._keyCache    = new Map(); // kid -> CryptoKey
  }

  // ── Discovery ───────────────────────────────────────────────────────────────

  async discover() {
    if (this._cache && this._discovery) return this._discovery;
    const res = await this._fetch('/.well-known/hhttps-configuration');
    this._discovery = res;
    return res;
  }

  // ── Local verification (no per-request issuer call) ──────────────────────────

  /**
   * Fetch and cache the issuer JWKS (RFC 7517). Re-fetched after jwksMaxAgeMs.
   * Honours the configured jwks_uri from discovery when available, else the
   * conventional /.well-known/jwks.json path.
   */
  async getJwks() {
    const fresh = this._jwks && (Date.now() - this._jwksAt) < this.jwksMaxAgeMs;
    if (this._cache && fresh) return this._jwks;

    let path = '/.well-known/jwks.json';
    try {
      const disc = await this.discover();
      if (disc?.jwks_uri) path = disc.jwks_uri;
    } catch { /* fall back to conventional path */ }

    const jwks = path.startsWith('http')
      ? await this._fetchAbsolute(path)
      : await this._fetch(path);

    this._jwks   = jwks;
    this._jwksAt = Date.now();
    this._keyCache.clear();
    return jwks;
  }

  /**
   * Verify a token's ES256 signature locally against the issuer JWKS.
   * Does NOT contact the issuer per call (JWKS is cached). Checks signature,
   * `exp`, and (when present) `nbf`. Selects the key by the token header `kid`.
   *
   * For high-trust use cases that must also honour revocation, additionally
   * call isRevoked(result.jti) — local signature verification alone cannot see
   * a revocation that happened after issuance.
   *
   * @param {string} token — HHTTPS JWT
   * @returns {Promise<object>} normalized result (see _normalizeClaims)
   */
  async verifyLocal(token) {
    if (!token) return this._unverified();

    const parts = token.split('.');
    if (parts.length !== 3) return { ...this._unverified(), status: 'invalid' };

    let header, payload;
    try {
      header  = JSON.parse(this._b64urlToString(parts[0]));
      payload = JSON.parse(this._b64urlToString(parts[1]));
    } catch {
      return { ...this._unverified(), status: 'invalid' };
    }

    if (header.alg !== 'ES256') {
      return { ...this._unverified(), status: 'invalid', error: 'unexpected alg' };
    }

    // Resolve the verifying key by kid
    const key = await this._resolveKey(header.kid);
    if (!key) return { ...this._unverified(), status: 'invalid', error: 'unknown kid' };

    // Verify signature (ES256 = ECDSA P-256 + SHA-256, raw r||s of 64 bytes)
    const signingInput = new TextEncoder().encode(parts[0] + '.' + parts[1]);
    const sig          = this._b64urlToBytes(parts[2]);
    const subtle       = globalThis.crypto.subtle;

    let ok = false;
    try {
      ok = await subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, key, sig, signingInput
      );
    } catch {
      ok = false;
    }
    if (!ok) return { ...this._unverified(), status: 'invalid', error: 'bad signature' };

    // Standard time checks
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && now >= payload.exp) {
      return { ...this._unverified(), status: 'expired' };
    }
    if (typeof payload.nbf === 'number' && now < payload.nbf) {
      return { ...this._unverified(), status: 'not-yet-valid' };
    }

    return this._normalizeClaims(payload);
  }

  // ── Core: remote check (issuer round-trip, live revocation + metadata) ───────

  /**
   * Check a token against the issuer: is it human? What role? Live status.
   * @param {string} token  — HHTTPS JWT
   */
  async check(token) {
    if (!token) return this._unverified();
    const res = await this._fetch('/hhttps/check', {
      method:  'POST',
      headers: { 'HHTTPS-Token': token }
    });
    return this._normalizeCheckResult(res);
  }

  /**
   * Quick header-only check (no body parsing) — for middleware use.
   * Returns the HHTTPS-* response headers directly.
   */
  async checkHeaders(token) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.serverUrl}/hhttps/check`, {
        method: 'POST', signal: controller.signal,
        headers: token ? { 'HHTTPS-Token': token } : {}
      });
      return {
        human:      res.headers.get('HHTTPS-Human') === 'true',
        status:     res.headers.get('HHTTPS-Status'),
        actorType:  res.headers.get('HHTTPS-Actor-Type'),
        role:       res.headers.get('HHTTPS-Role'),
        roleLabel:  res.headers.get('HHTTPS-Role-Label'),
        roleLevel:  res.headers.get('HHTTPS-Role-Level'),
        trustScore: parseInt(res.headers.get('HHTTPS-Trust-Score') || '0'),
        method:     res.headers.get('HHTTPS-Method'),
        issuer:     res.headers.get('HHTTPS-Issuer')
      };
    } finally { clearTimeout(timer); }
  }

  // ── Token lifecycle ──────────────────────────────────────────────────────────

  /** Validate a token and get full claims (remote) */
  async validate(token) {
    return this._fetch('/hhttps/validate', { method: 'POST', body: { token } });
  }

  /** Revoke a token immediately */
  async revoke(token) {
    return this._fetch('/hhttps/revoke', { method: 'POST', body: { token } });
  }

  /** Check if a specific JTI has been revoked */
  async isRevoked(jti) {
    const res = await this._fetch(`/hhttps/revoke/status?jti=${encodeURIComponent(jti)}`);
    return res.revoked;
  }

  /** Refresh an access token using a refresh token (no biometric needed) */
  async refresh(refreshToken) {
    return this._fetch('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  }

  // ── Roles ────────────────────────────────────────────────────────────────────

  /** Get all available roles and verification levels */
  async getRoles() {
    return this._fetch('/hhttps/roles');
  }

  // ── Machine Tokens ────────────────────────────────────────────────────────────

  /** Register a machine operator */
  async registerMachine({ operatorName, operatorUrl, purpose, contactEmail }) {
    return this._fetch('/hhttps/machine/register', {
      method: 'POST', body: { operatorName, operatorUrl, purpose, contactEmail }
    });
  }

  /** Issue a machine token */
  async getMachineToken({ operatorId, apiKey }) {
    return this._fetch('/hhttps/machine/token', {
      method: 'POST', body: { operatorId, apiKey }
    });
  }

  // ── Stats ─────────────────────────────────────────────────────────────────────

  async getStats() { return this._fetch('/hhttps/stats'); }

  // ── Middleware helpers ────────────────────────────────────────────────────────

  /**
   * Express middleware factory. Attaches the hhttps result to req.hhttps.
   *
   * By default uses LOCAL verification (verifyLocal) — no per-request issuer
   * call. Set { mode: 'remote' } to use the issuer /hhttps/check endpoint
   * instead (adds live revocation + richer role metadata, at a round-trip).
   *
   * @example
   *   app.use(hhttps.middleware({ minTrust: 80, allowedRoles: ['journalist'] }));
   *   app.get('/api', (req, res) => {
   *     if (!req.hhttps.human) return res.status(401).json({ error: 'humans only' });
   *     res.json({ role: req.hhttps.role });
   *   });
   */
  middleware({ required = false, minTrust = 0, allowedRoles = null, mode = 'local' } = {}) {
    const client = this;
    return async (req, res, next) => {
      const token = req.headers['hhttps-token'] ||
                    req.headers['authorization']?.replace('Bearer ', '');
      if (token) {
        req.hhttps = mode === 'remote'
          ? await client.check(token).catch(() => client._unverified())
          : await client.verifyLocal(token).catch(() => client._unverified());
      } else {
        req.hhttps = client._unverified();
      }

      if (required && !req.hhttps.human) {
        return res.status(401).json({ error: 'HHTTPS-Verifikation erforderlich.',
                                      authEndpoint: `${client.serverUrl}/hhttps/webauthn/auth/start` });
      }
      if (minTrust && req.hhttps.trustScore < minTrust) {
        return res.status(403).json({ error: `Mindest-Trust-Score ${minTrust} erforderlich.`,
                                      current: req.hhttps.trustScore });
      }
      if (allowedRoles && !allowedRoles.includes(req.hhttps.role)) {
        return res.status(403).json({ error: `Rolle nicht berechtigt. Erlaubt: ${allowedRoles.join(', ')}` });
      }
      next();
    };
  }

  // ── Internal helpers ──────────────────────────────────────────────────────────

  _unverified() {
    return { human: false, actorType: 'unknown', status: 'unverified',
             role: null, roleLabel: null, trustScore: 0, privileges: [] };
  }

  /** Normalize raw JWT claims (from verifyLocal) into the SDK result shape. */
  _normalizeClaims(p) {
    const isMachine = p.sub === 'machine' || p.human === false;
    return {
      human:      p.human === true,
      actorType:  p.actorType || (isMachine ? 'bot' : 'human'),
      status:     'verified',
      role:       p.role || null,
      roleLabel:  p.role_label || null,
      roleIcon:   p.role_icon || null,
      roleLevel:  p.roleLevel || null,
      trustScore: typeof p.trustScore === 'number' ? p.trustScore : 0,
      method:     p.method || null,
      jti:        p.jti || null,
      issuer:     p.iss || null,
      hhttpsIssuer: p.hhttps_iss || null,
      issuedAt:   p.iat ? new Date(p.iat * 1000).toISOString() : null,
      expiresAt:  p.exp ? new Date(p.exp * 1000).toISOString() : null,
      machine:    isMachine
        ? { operatorId: p.operatorId || null, operatorName: p.operatorName || null,
            purpose: p.purpose || null }
        : null,
      claims:     p
    };
  }

  _normalizeCheckResult(res) {
    if (!res?.hhttps) return this._unverified();
    return {
      human:      res.hhttps.human      || false,
      actorType:  res.hhttps.actorType  || 'unknown',
      status:     res.hhttps.status     || 'unverified',
      trustScore: res.hhttps.trustScore || 0,
      method:     res.hhttps.method     || null,
      issuedAt:   res.hhttps.issuedAt   || null,
      expiresAt:  res.hhttps.expiresAt  || null,
      issuer:     res.hhttps.issuer     || null,
      role:       res.role?.id          || null,
      roleLabel:  res.role?.label       || null,
      roleIcon:   res.role?.icon        || null,
      roleLevel:  res.role?.level       || null,
      levelLabel: res.role?.levelLabel  || null,
      privileges: res.role?.privileges  || [],
      userStory:  res.role?.userStory   || null,
      machine:    res.machine           || null
    };
  }

  /** Resolve and cache a CryptoKey for the given kid from the JWKS. */
  async _resolveKey(kid) {
    if (kid && this._keyCache.has(kid)) return this._keyCache.get(kid);

    const jwks = await this.getJwks();
    const keys = jwks?.keys || [];
    // Prefer exact kid match; if token carries no kid, fall back to the first key.
    const jwk = (kid ? keys.find(k => k.kid === kid) : keys[0]) || keys[0];
    if (!jwk) return null;

    const key = await globalThis.crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    if (jwk.kid) this._keyCache.set(jwk.kid, key);
    return key;
  }

  _b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = (typeof atob === 'function')
      ? atob(s)
      : Buffer.from(s, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  _b64urlToString(s) {
    return new TextDecoder().decode(this._b64urlToBytes(s));
  }

  async _fetch(path, options = {}) {
    return this._fetchAbsolute(`${this.serverUrl}${path}`, options);
  }

  async _fetchAbsolute(url, options = {}) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(url, {
        method:  options.method || 'GET',
        signal:  controller.signal,
        headers: { 'Content-Type': 'application/json', ...options.headers },
        body:    options.body ? JSON.stringify(options.body) : undefined
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally { clearTimeout(timer); }
  }
}

// CommonJS compat (for require())
if (typeof module !== 'undefined') module.exports = { HHTPPSClient };
