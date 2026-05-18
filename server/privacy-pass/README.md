# Privacy Pass Module (additive)

This module adds an [RFC 9576–9578](https://datatracker.ietf.org/wg/privacypass/about/) compliant Privacy Pass issuer to the HHTTPS server **without touching any existing functionality**.

## Why additive

The HHTTPS Role Layer (Identity API in `../server.js`) and the Privacy Pass Layer are kept fully separate:

- **Different key material.** HHTTPS uses ES256 (P-256) for JWT signing in `../keys/`. Privacy Pass uses VOPRF P-384/SHA-384 for blind token issuance in `./keys/`. No overlap.
- **Different endpoints.** All Privacy Pass routes live under `/privacy-pass/*` plus the standardized `/.well-known/private-token-issuer-directory`. No collision with existing `/hhttps/*` routes.
- **Different threat model.** Privacy Pass tokens are anonymous and unlinkable per RFC 9576. HHTTPS Role tokens are pseudonymous and bound to WebAuthn. This separation is preserved.

## Status

| Component | Status |
|---|---|
| Issuer directory (`.well-known/private-token-issuer-directory`) | Implemented |
| Key generation and persistence (P-384) | Implemented |
| Token request handling (RFC 9578 §6) | **TODO** — needs VOPRF library integration |
| Token verification | **TODO** — needs VOPRF library integration |
| OHTTP issuance (RFC 9458) | Future work |

Run the server now and the discovery and key endpoints work. Issuance returns `501 Not Implemented` until the VOPRF cryptography is wired up.

## Integration with server.js

Two lines added to `../server.js` at the end of the route definitions (see `INSTALL.md`). No other changes to existing code.

## Dependencies

Requires `@cloudflare/voprf-ts` from npm. Install with:

```bash
cd ../
npm install @cloudflare/voprf-ts
```

## References

- [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576) — Privacy Pass Architecture
- [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577) — HTTP Authentication Scheme
- [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578) — Issuance Protocols
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497) — OPRFs Using Prime-Order Groups
