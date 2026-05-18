# Privacy Pass Module (additive)

This module adds an [RFC 9576–9578](https://datatracker.ietf.org/wg/privacypass/about/) compliant Privacy Pass issuer and verifier to the HHTTPS server **without touching any existing functionality**.

## Why additive

The HHTTPS Role Layer (Identity API in `../server.js`) and the Privacy Pass Layer are kept fully separate:

- **Different key material.** HHTTPS uses ES256 (P-256) for JWT signing in `../keys/`. Privacy Pass uses VOPRF P-384/SHA-384 for blind token issuance in `./keys/`. No overlap.
- **Different endpoints.** All Privacy Pass routes live under `/privacy-pass/*` plus the standardized `/.well-known/private-token-issuer-directory`. No collision with existing `/hhttps/*` routes.
- **Different threat model.** Privacy Pass tokens are anonymous and unlinkable per RFC 9576. HHTTPS Role tokens are pseudonymous and bound to WebAuthn. This separation is preserved.

## Status

| Component | Status |
|---|---|
| Issuer directory (`.well-known/private-token-issuer-directory`) | ✅ Implemented |
| Key generation and persistence (VOPRF P-384/SHA-384) | ✅ Implemented |
| Token request handling (RFC 9578 §6, Token Type 0x0002) | ✅ Implemented |
| Token verification with DLEQ proof and constant-time comparison | ✅ Implemented |
| End-to-end roundtrip test (client blind → issue → finalize → verify) | ✅ Passing |
| Replay protection (`jti`-like nonce tracking) | Pending |
| OHTTP issuance (RFC 9458) for additional privacy | Future work |
| Token Type 0x0001 (Blind RSA, publicly verifiable) for federation | Future work |

## Wire format

Token Type 0x0002 follows RFC 9578 §6:

```
TokenRequest  (52 bytes)  = token_type(2) || truncated_key_id(1) || blinded_msg(49)
TokenResponse (145 bytes) = evaluated_msg(49) || evaluated_proof(96)
Token         (146 bytes) = token_type(2) || nonce(32) || challenge_digest(32) || token_key_id(32) || authenticator(48)
```

The library [`@cloudflare/voprf-ts`](https://github.com/cloudflare/voprf-ts) provides the underlying VOPRF P-384/SHA-384 implementation; this module bridges between the library's serialization format and the Privacy Pass wire format.

## Integration with server.js

Two lines added to `../server.js` at the end of the route definitions (see `INSTALL.md`). No other changes to existing code.

## Dependencies

- `@cloudflare/voprf-ts ^1.0.0` (added to `../package.json` automatically by the deploy script)

## References

- [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576) — Privacy Pass Architecture
- [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577) — HTTP Authentication Scheme
- [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578) — Issuance Protocols
- [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497) — OPRFs Using Prime-Order Groups
