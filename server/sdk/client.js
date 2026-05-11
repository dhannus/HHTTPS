/**
 * HHTTPS Client SDK — JavaScript / Node.js / Browser
 * HumanProof Initiative · github.com/dhannus/HumanProof
 *
 * Usage (Node.js):
 *   import { HHTPPSClient } from './sdk/client.js';
 *   const hhttps = new HHTPPSClient('https://hhttps.funnysearch.eu');
 *   const result = await hhttps.check(token);
 *
 * Usage (Browser — inline verification):
 *   <script src="sdk/client.js"></script>
 *   const hhttps = new HHTPPSClient('https://hhttps.funnysearch.eu');
 */

export class HHTPPSClient {
  /**
   * @param {string} serverUrl  — Base URL of the HHTTPS server
   * @param {object} options
   * @param {number} options.timeout  — Request timeout in ms (default 8000)
   * @param {boolean} options.cache   — Cache discovery config (default true)
   */
  constructor(serverUrl, options = {}) {
    this.serverUrl   = serverUrl.replace(/\/$/, '');
    this.timeout     = options.timeout || 8000;
    this._cache      = options.cache !== false;
    this._discovery  = null;
  }

  // ── Discovery ───────────────────────────────────────────────────────────────

  async discover() {
    if (this._cache && this._discovery) return this._discovery;
    const res = await this._fetch('/.well-known/hhttps-configuration');
    this._discovery = res;
    return res;
  }

  // ── Core: check if token is human + get role ─────────────────────────────────

  /**
   * Check a token: is it human? What role?
   * @param {string} token  — HHTTPS JWT
   * @returns {{ human, actorType, role, roleLabel, trustScore, privileges, status }}
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
      clearTimeout(timer);
      return {
        human:      res.headers.get('HHTTPS-Human') === 'true',
        status:     res.headers.get('HHTTPS-Status'),
        actorType:  res.headers.get('HHTTPS-Actor-Type'),
        role:       res.headers.get('HHTTPS-Role'),
        trustScore: parseInt(res.headers.get('HHTTPS-Trust-Score') || '0'),
        method:     res.headers.get('HHTTPS-Method')
      };
    } finally { clearTimeout(timer); }
  }

  // ── Token lifecycle ──────────────────────────────────────────────────────────

  /** Validate a token and get full claims */
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
   * Express middleware factory.
   * Attaches hhttps result to req.hhttps.
   *
   * @example
   *   app.use(hhttps.middleware());
   *   app.get('/api', (req, res) => {
   *     if (!req.hhttps.human) return res.status(401).json({ error: 'humans only' });
   *     res.json({ role: req.hhttps.role });
   *   });
   */
  middleware({ required = false, minTrust = 0, allowedRoles = null } = {}) {
    const client = this;
    return async (req, res, next) => {
      const token = req.headers['hhttps-token'] || req.headers['authorization']?.replace('Bearer ', '');
      req.hhttps = token ? await client.check(token).catch(() => client._unverified()) : client._unverified();

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

  async _fetch(path, options = {}) {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.serverUrl}${path}`, {
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
