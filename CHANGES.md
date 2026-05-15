# Sync changes — Phase 3a + 2.5 integration

This sync brings the GitHub repo to the production state (May 2026, Phase 3a complete).

## Files replaced

### Extension (v1.2.0 → v1.4.3)
- `extension/manifest.json` — version bump, iframe support (`all_frames`, `match_about_blank`)
- `extension/background.js` — slug-based signatures, batch verification
- `extension/content-universal.js` — inline seal renderer, iframe-aware DOM scanning
- `extension/content-issuer.js` — identity sync on hhttps.org
- `extension/popup.html` + `popup.js` — updated UI
- `extension/icons/*` — new state icons (verified, unverified, supported, neutral)
- `extension/INSTALL.md` — updated

### Server (Phase 2.5 + Phase 3a OAuth)
- `server/server.js` (2218 lines) — adds:
  - POST `/hhttps/signatures` (create slug-based signature)
  - GET `/hhttps/s/:slug` (verify signature)
  - POST `/hhttps/signatures/batch` (batch verify)
  - POST `/hhttps/signatures/:slug/revoke`
  - GET `/.well-known/openid-configuration` (OIDC discovery)
  - GET `/hhttps/oauth/authorize` (consent page)
  - POST `/hhttps/oauth/approve`
  - POST `/hhttps/oauth/token`
  - GET `/hhttps/oauth/userinfo`
  - POST `/hhttps/oauth/revoke`
  - Helper functions: pairwise subject IDs, slug generation, text hashing, domain normalization
- `server/db.js` — adds `signatures`, `oauthClients`, `authCodes`, `connectedPlatforms` modules
- `server/public/index.html` — adds `?returnTo=` banner + post-login toast + Connected Platforms section + OAuth API demo with 3 tabs
- `server/sql/migration-phase-2.5.sql` — signatures table with ownership grants
- `server/sql/migration-phase-3a.sql` — oauth_clients, authorization_codes, connected_platforms tables

### Sites
- `sites/iamhmn.html` — adds new "Platforms" section with hero SVG, ask.iamhmn.org showcase card, DE/EN translations
- `sites/hhttps.html` — NEW reference copy of the issuer UI (identical to server/public/index.html)
- `sites/spec.html` — unchanged

### Docs
- `docs/IMAGES_CHECKLIST.md` — NEW (which screenshots are still optional to add)

### Root
- `README.md` — updated to point to dhannus/HHTTPS (was HumanProof) in 4 URLs

## Files NOT changed
- `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `LICENSE`, `SECURITY.md`
- `server/email.js`, `server/keys.js`, `server/roles.js`, `server/webhooks.js`, `server/package.json`, `server/.env.example`
- `server/sdk/`, `server/scripts/`
- `examples/` (all sub-projects untouched)
- `scripts/`
- `docs/architecture.md`, `docs/governance.md`, `docs/oauth-integration.md`, `docs/roadmap.md`, `docs/security.md`, `docs/spec.md`, `docs/threat-model.md`
- `docs/integration-guide.md`
- `docs/protocol/*.md`
- `docs/images/*.svg`

## Deploy steps after sync

```bash
# 1. Unzip and replace
cd ~/HHTTPS  # your local clone
# Copy all files from HHTTPS-sync over the existing repo (preserves untouched files)
rsync -av --exclude='.git' /path/to/HHTTPS-sync/ ./

# 2. Stage and commit
git add .
git status  # review
git commit -m "Phase 3a complete: OAuth provider, slug-based signatures, extension v1.4.3, redirect fix"
git push
```

## After push verification

Check on GitHub:
- Languages bar should show: HTML, JavaScript, Shell, Python, SQL
- README still renders with hero illustration
- 1 new file in docs/: IMAGES_CHECKLIST.md
- sites/iamhmn.html grew (+386 lines)
- sites/hhttps.html is NEW
- server/server.js much bigger (+~1500 lines)
- server/sql/ has 3 migration files
