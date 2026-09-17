// Test double for the EUDIPLO backend (server/eudi-verifier/backend-client.js)
// and for the internal HHTTPS endpoints the eudi-verifier calls back into.
//
// Both are plain http servers on a free port; every request is recorded on the
// returned `state` object so a test can assert how often something was called.
//
//   const eudiplo = await startEudiploStub();
//   process.env.EUDIPLO_BASE_URL = eudiplo.url;      // includes the /api prefix
//   const bc = await import('../../eudi-verifier/backend-client.js?v=1');
//   … await eudiplo.stop();
import http from 'node:http';

function listen(server) {
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve({ _raw: raw }); } });
  });
}

const send = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body ?? {}));
};

/** EUDIPLO stub. `state` is mutable: tests steer the session answer through it. */
export async function startEudiploStub() {
  const state = {
    tokenCalls: 0,
    sessionGets: 0,          // GETs on ANY of the session-path candidates
    offerCalls: 0,
    issuerOffers: [],        // request bodies of POST /issuer/offer
    lastAuthorization: null,
    /** token values that must be answered with 401 (AP4-10 cache invalidation) */
    rejectTokens: new Set(),
    /** answer of GET <session-path>: { status, body } */
    session: { status: 200, body: { status: 'pending' } },
    /** when true the session endpoint never answers (AP4-39 timeout) */
    hangSession: false,
    /** when true only the FIRST candidate path answers 2xx */
    onlyFirstPath: false,
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const p = url.pathname.replace(/^\/api/, '');
    state.lastAuthorization = req.headers.authorization || null;

    if (req.method === 'POST' && p === '/oauth2/token') {
      state.tokenCalls += 1;
      await readBody(req);
      return send(res, 201, { access_token: `tok-${state.tokenCalls}`, expires_in: 3600 });
    }

    // Every other route is bearer-authenticated; a rejected token yields 401.
    const bearer = String(req.headers.authorization || '').replace(/^Bearer /, '');
    if (state.rejectTokens.has(bearer)) return send(res, 401, { error: 'invalid_token' });

    if (req.method === 'POST' && p === '/verifier/config') { await readBody(req); return send(res, 201, {}); }
    if (req.method === 'PATCH' && p.startsWith('/verifier/config/')) { await readBody(req); return send(res, 200, {}); }
    if (req.method === 'POST' && p === '/verifier/offer') {
      state.offerCalls += 1;
      await readBody(req);
      return send(res, 201, { session: `sess-${state.offerCalls}`, uri: 'openid4vp://offer', crossDeviceUri: 'openid4vp://offer' });
    }
    if (req.method === 'POST' && p === '/issuer/config') { await readBody(req); return send(res, 201, {}); }
    if (req.method === 'POST' && p === '/issuer/offer') {
      state.issuerOffers.push(await readBody(req));
      return send(res, 201, { uri: 'openid-credential-offer://card', crossDeviceUri: 'openid-credential-offer://card', session: 'issue-1' });
    }

    const isSessionPath = req.method === 'GET' &&
      (/^\/verifier\/session\//.test(p) || /^\/session\//.test(p) || /^\/presentations\//.test(p));
    if (isSessionPath) {
      state.sessionGets += 1;
      if (state.hangSession) return;                               // never answers
      if (state.onlyFirstPath && !/^\/verifier\/session\//.test(p)) return send(res, 404, {});
      return send(res, state.session.status, state.session.body);
    }
    return send(res, 404, { error: 'not_found', path: p });
  });

  const port = await listen(server);
  return {
    url: `http://127.0.0.1:${port}/api`,
    state,
    stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

/** Stub of the internal HHTTPS endpoints (/hhttps/age/upgrade, /hhttps/eid/upgrade). */
export async function startInternalStub({ delayMs = 0 } = {}) {
  const state = { calls: [] };
  const server = http.createServer(async (req, res) => {
    const body = await readBody(req);
    state.calls.push({ path: req.url, body });
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    return send(res, 200, {
      hhttps: { version: '0.5.0', token: 'stub.token.value', refreshToken: 'stub.refresh', trustScore: 20, verifiedMethods: ['email'] },
      ageGroup: { id: 'adult', label: 'Adult', verified: true, method: 'eudi-wallet' },
      eudi: { verified: true, method: 'eudi-eid' },
    });
  });
  const port = await listen(server);
  return { url: `http://127.0.0.1:${port}`, state,
    stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}
