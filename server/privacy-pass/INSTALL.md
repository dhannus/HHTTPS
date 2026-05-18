# Installing the Privacy Pass module

Three small steps to activate the additive Privacy Pass layer in your existing HHTTPS server. None of the existing routes, modules, or behaviors change.

## 1. Install the dependency

From `server/`:

```bash
npm install @cloudflare/voprf-ts
```

This adds VOPRF cryptography. It's a Cloudflare-maintained TypeScript library and ships with no runtime peer dependencies.

## 2. Mount the module in `server.js`

You need to add exactly three things to `server/server.js`:

### a) Add the import (alongside the other top-level imports)

```javascript
import {
  initPrivacyPass,
  privacyPassRouter,
  privacyPassWellKnownRouter
} from './privacy-pass/index.js';
```

### b) Initialise the module in the bootstrap section

Find the place where you call `loadOrCreateKeys()` (around the `// ─── Bootstrap ───` section near the top, or wherever you start the server). Add:

```javascript
await initPrivacyPass();
```

If your bootstrap is inside an async function (or top-level await is enabled — your `"type": "module"` setup supports it), this works directly. Otherwise, wrap your `app.listen(...)` in an async IIFE.

### c) Mount the routers (alongside your other `app.use(...)` calls)

Place these somewhere after your other route registrations but before the 404 fallback:

```javascript
app.use(privacyPassWellKnownRouter);
app.use('/privacy-pass', privacyPassRouter);
```

The well-known router intentionally registers its own `/.well-known/...` path so it lives at the URL root — same convention as your existing `/.well-known/hhttps-configuration`.

## 3. Verify it's running

Start the server and check three URLs:

```bash
# Privacy Pass issuer directory (per RFC 9578)
curl -s https://hhttps.org/.well-known/private-token-issuer-directory | jq .

# Developer-friendly keys listing
curl -s https://hhttps.org/privacy-pass/keys | jq .

# Token request endpoint (will return 501 until VOPRF is wired up)
curl -i -X POST https://hhttps.org/privacy-pass/token-request \
     -H 'Content-Type: application/private-token-request' \
     --data-binary @/dev/null
```

Expected:

- Discovery returns a valid Privacy Pass directory document with token-type 2.
- Keys endpoint returns the same key information in JSON.
- Token request returns HTTP 501 with `{ "error": "not_implemented" }` — that's the expected state until VOPRF cryptography is implemented.

## What this module does NOT do yet

- **Real VOPRF blind evaluation.** Issuance returns 501. The protocol structure, key management, and discovery are complete; the cryptographic primitive call is marked `TODO` in `issuer.js` and `verifier.js` with the exact library API to use.
- **Replay protection.** Add `jti`-style nonce tracking via `db.js` once issuance is live.
- **Key rotation.** Manual for now. Rotate by deleting `privacy-pass/keys/` and restarting.
- **Oblivious HTTP for issuance.** Future work per RFC 9458.

## Rolling back

If something goes wrong, removing the three additions to `server.js` (import, init, mount) fully disables the module. The `privacy-pass/` directory has no effect on the rest of the codebase as long as it isn't imported.

## Verifying isolation

Run this quick check after install:

```bash
grep -rn "privacy-pass" server.js auth.js keys.js roles.js webhooks.js email.js db.js 2>/dev/null
```

The only matches should be the three additions in `server.js`. Nothing else in the existing codebase references the new module — that's the additive guarantee.
