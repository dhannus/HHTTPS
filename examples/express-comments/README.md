# Express + HHTTPS — Comment system example

A minimal Express app showing HHTTPS-gated comments.

## Run
```bash
npm install
node server.js
```

## Endpoints
| Path | Auth | Notes |
|---|---|---|
| GET  /comments              | none           | List all comments |
| POST /comment               | optional       | Anyone can post; verified humans get a badge |
| POST /comment/verified-only | trust ≥ 60     | Only verified humans |
| POST /article               | role=journalist, trust ≥ 80 | Press-only |
| POST /medical-advice        | role=medical_professional, trust ≥ 90 | Doctors only |

Get a token at https://hhttps.org and pass it as `HHTTPS-Token: <token>` header.
