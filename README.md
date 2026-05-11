<div align="center">

# HumanProof — HHTTPS Protocol

**The missing protocol for human identity on the web.**

[![Version](https://img.shields.io/badge/protocol-v0.4.1-C97D5B?style=flat-square)](https://hhttps.org)
[![License](https://img.shields.io/badge/license-EUPL--1.2-A8B89E?style=flat-square)](https://eupl.eu/1.2/en/)
[![Status](https://img.shields.io/badge/status-production-889982?style=flat-square)](https://hhttps.org/hhttps/info)
[![Roles](https://img.shields.io/badge/roles-15-F2B894?style=flat-square)](#roles)

[**hhttps.org**](https://hhttps.org) · [**iamhmn.org**](https://iamhmn.org) · [**Spec**](https://hhttps.org/spec) · [**Issues**](https://github.com/dhannus/HumanProof/issues)

</div>

---

HHTTPS extends HTTP/HTTPS with a **cryptographic proof-of-personhood layer**. It allows web servers to verify that an HTTP request was initiated by a real human — without storing personally identifiable information.

```
HTTP   →  HTTPS   →  HHTTPS
1991      1994       2026
data      crypto     human
```

This repo contains the reference implementation: server, browser extension, SDKs, and the open specification.

## Why HHTTPS?

In 2026, you can't tell whether the entity on the other end of a digital interaction is a human, a bot, or an AI deepfake. CAPTCHA is broken. Real-name policies break privacy. Crypto-based "proof of personhood" requires KYC and/or expensive on-chain operations.

**HHTTPS solves this with W3C standards already in your browser:**
- WebAuthn (Touch ID, Face ID, YubiKey, Windows Hello, Passkeys) for human-presence verification
- ES256-signed JWTs (RFC 7519) carry role + trust score, **no PII**
- JWKS (RFC 7517) lets any server verify tokens locally — no central authority

The protocol is **open**, **GDPR-compliant by design**, and runs on infrastructure you already trust.

## Quick Start

### Run a local HHTTPS server (5 minutes)

```bash
git clone https://github.com/dhannus/HumanProof.git
cd HumanProof/server

# Install PostgreSQL (Ubuntu/Debian)
bash scripts/install-pg.sh

# Install Node deps
npm install

# Start
npm start
```

Server runs on `http://localhost:3000`. Open it in your browser to register a passkey and get your first HHTTPS token.

### Verify HHTTPS tokens in your app (5 lines)

```js
import jwt        from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const jwks = jwksClient({
  jwksUri: 'https://hhttps.org/.well-known/jwks.json',
  cache: true, cacheMaxAge: 3600000
});

function getKey(header, cb) {
  jwks.getSigningKey(header.kid, (err, key) => cb(err, key?.getPublicKey()));
}

// In your route handler:
const token = req.headers['hhttps-token'];
jwt.verify(token, getKey, { algorithms: ['ES256'] }, (err, decoded) => {
  if (err)                       return res.status(401).send();
  if (decoded.trustScore < 60)   return res.status(403).send();
  if (decoded.role !== 'doctor') return res.status(403).send();
  // ✓ Verified human, role validated
  next();
});
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│  iamhmn.org    ⤍ Marketing landing (DE/EN)      │
└──────────────┬───────────────────────────────────┘
               │ "Verify now →"
               ↓
┌──────────────────────────────────────────────────┐
│  hhttps.org    ⤍ Identity issuer + dashboard    │
│                                                  │
│   /.well-known/hhttps-configuration              │
│   /.well-known/jwks.json                         │
│   /hhttps/check                                  │
│   /hhttps/webauthn/{register,auth}/{start,fin}   │
│   /hhttps/role/declare                           │
│   /hhttps/token/refresh                          │
│   /hhttps/revoke                                 │
└──────────────────────────────────────────────────┘
               ↑                              ↑
               │ JWKS cache                   │
   ┌───────────┴────────┐         ┌───────────┴────────┐
   │  3rd-party site    │         │  3rd-party site    │
   │  validates tokens  │         │  validates tokens  │
   │  (no API call!)    │         │  (no API call!)    │
   └────────────────────┘         └────────────────────┘
```

Tokens are signed by the issuer (`hhttps.org`) and verified by **any third-party server** using only the public JWKS. No API calls, no rate limits, no central bottleneck — verification scales linearly with consumers.

## Roles

15 societal roles, each with verification methods and trust scores:

| Role | Icon | Verification | Trust |
|---|:---:|---|:---:|
| Citizen | 🧑 | WebAuthn baseline | 60 |
| Journalist | 📰 | Press card / editorial email | up to 85 |
| Student | 🎓 | Education email / matriculation | up to 85 |
| Teacher | 👨‍🏫 | School email / teacher ID | up to 86 |
| Researcher | 🔬 | ORCID / university email | up to 88 |
| Creative professional | 🎭 | Association membership (VDS, BFFS, etc.) | up to 85 |
| Developer | 💻 | GitHub / domain email | up to 72 |
| Medical professional | 🩺 | Approbation number | up to 93 |
| Caregiver | 🤝 | Pflegekammer registration | up to 90 |
| Attorney | ⚖️ | Bar association (RAK) | up to 92 |
| Notary | 📜 | Notarkammer registration | up to 95 |
| Civil servant | 🏛️ | Official email / service ID | up to 90 |
| Politician | 🗳️ | Bundestag verification | up to 98 |
| Business | 🏢 | Domain / Handelsregister | up to 92 |
| Skilled tradesperson | 🔧 | Handwerksrolle / master cert. | up to 90 |

See [`server/roles.js`](server/roles.js) for the full mapping.

## Repository Structure

```
HumanProof/
├── server/                 # HHTTPS reference server (Node.js + PostgreSQL)
│   ├── server.js          # Express app, all endpoints
│   ├── db.js              # PostgreSQL data access layer
│   ├── roles.js           # 15 role definitions + trust mapping
│   ├── email.js           # Email verification (DB-backed)
│   ├── keys.js            # ES256 key management + JWKS
│   ├── webhooks.js        # Webhook subscriber system
│   ├── sql/schema.sql     # 12-table DB schema
│   ├── scripts/           # install-pg.sh, migrate.sh
│   ├── public/            # WebAuthn registration UI
│   └── package.json
│
├── extension/              # Chrome/Firefox/Edge browser extension
│   ├── manifest.json      # Manifest V3
│   ├── background.js      # Service worker, token refresh, JWKS cache
│   ├── content.js         # Header reader, page indicator
│   ├── popup.html, popup.js
│   ├── icons/
│   └── INSTALL.md
│
├── sdk/
│   ├── js/                # JavaScript SDK (Express middleware, vanilla client)
│   ├── python/            # Python SDK (Flask, Django, FastAPI)
│   ├── php/               # PHP SDK (Laravel middleware)
│   └── go/                # Go SDK (planned)
│
├── examples/               # Integration examples
│   ├── express-comments/  # Comment system gated by HHTTPS
│   ├── django-medical/    # Medical Q&A requiring doctor role
│   ├── flask-petition/    # Online petition with HHTTPS
│   └── laravel-school/    # School chat with teacher verification
│
├── docs/
│   ├── spec.md            # Full HHTTPS protocol specification
│   ├── integration-guide.md
│   ├── security.md
│   ├── threat-model.md
│   └── governance.md
│
├── sites/                  # Static marketing sites
│   ├── iamhmn/            # iamhmn.org (warm pastel)
│   └── hhttps/            # hhttps.org/spec (light, technical)
│
└── rfc/                    # IETF Internet-Draft
    └── draft-hannuschka-hhttps-00.txt
```

## Try It Live

- **Marketing**: [iamhmn.org](https://iamhmn.org) — what HHTTPS does, in 90 seconds
- **Verify yourself**: [hhttps.org](https://hhttps.org) — register a passkey and get your first token
- **Spec**: [hhttps.org/spec](https://hhttps.org/spec) — protocol specification
- **Discovery**: [hhttps.org/.well-known/hhttps-configuration](https://hhttps.org/.well-known/hhttps-configuration)
- **Public key**: [hhttps.org/.well-known/jwks.json](https://hhttps.org/.well-known/jwks.json)
- **Stats**: [hhttps.org/hhttps/info](https://hhttps.org/hhttps/info)

## Trust & Credibility

This is a **civic-tech initiative**, not a venture-backed crypto play.

- ✓ Open source (EUPL-1.2)
- ✓ No VC funding, no token, no IPO ambitions
- ✓ Outreach to all 5 factions of the 21st German Bundestag (digital policy spokespersons)
- ✓ Research engagement with TUM, TU Darmstadt/ATHENE, DFKI, HPI, TU Berlin, CISPA
- ✓ Civil society partners: VDS, BFFS, Synchronverband Die Gilde, BSD
- ✓ GDPR & eIDAS compliant by design
- ✓ Servers in the EU; no US cloud lock-in
- ✓ IETF Internet-Draft in preparation

## Contributing

Pull requests welcome. For major changes (protocol-level), please open an issue first to discuss. The specification undergoes a 30-day public discussion period before each minor version bump.

```bash
git clone https://github.com/dhannus/HumanProof.git
cd HumanProof
# Server work:
cd server && npm install && npm run dev
# Extension work:
cd extension && # load unpacked in Chrome
# Site work:
cd sites/iamhmn && python3 -m http.server 8000
```

See [`docs/governance.md`](docs/governance.md) for the contribution and decision-making process.

## Roadmap

- [x] **v0.1** — In-memory prototype, single-role
- [x] **v0.2** — WebAuthn registration, multi-device passkeys
- [x] **v0.3** — 8-role identity API, trust scores
- [x] **v0.4** — JWKS, refresh tokens, machine tokens, revocation
- [x] **v0.4.1** — PostgreSQL persistence, 15 roles, production hardening *(current)*
- [ ] **v0.5** — Transparency log of issued/revoked token hashes
- [ ] **v0.6** — Federation: multiple cooperating issuers
- [ ] **v0.7** — Selective disclosure (zero-knowledge attribute proofs)
- [ ] **v1.0** — IETF RFC submission

## License

[EUPL-1.2](https://eupl.eu/1.2/en/) — European Union Public Licence. OSI-approved, GPLv3-compatible, GDPR-aligned.

## Contact

**Daniel Hannuschka** · daniel.hannuschka@tweakz.de · [tweakz.de](https://tweakz.de)

Press, institutional partnerships, and policy-level inquiries explicitly welcomed.

---

<div align="center">
<sub>Made with care in 🇩🇪 · Open Source · No surveillance · No tracking · No tokens (the financial kind)</sub>
</div>
