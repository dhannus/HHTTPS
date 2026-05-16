# Phase 3b — Developer Self-Service Registration

This sync brings the repo up to date with Phase 3b backend changes deployed on
production (May 2026).

## Files in this sync

```
server/
├── server.js                          ← UPDATED (Phase 3b endpoints + dotenv import)
├── db.js                              ← UPDATED (admins, clientStats, adminActions modules)
├── email.js                           ← UPDATED (Brevo-ready, Reply-To, Phase 3b templates)
└── sql/
    ├── migration-phase-3b.sql         ← NEW (Phase 3b tables + admin flag)
    └── migration-phase-3b.1.sql       ← NEW (domain_email_match column)
```

## What's new

### Database
- New table `admins` — membership-style admin privileges
- New table `client_stats_daily` — privacy-preserving per-day login counts (no user IDs)
- New table `admin_actions` — append-only audit log of admin actions
- Extended `oauth_clients` with verification workflow:
  - `verification_status` (state machine)
  - `email_token`, `email_verified_at`, `dns_token`, `dns_verified_at`
  - `domain_email_match`, `impressum_url`
  - `submitted_for_review_at`, `reviewed_at`, `rejection_reason`

### API endpoints (15 new)

Developer self-service (`/hhttps/developers/*`):
- `POST   /clients` — register new platform (rate-limited 3/day/user)
- `GET    /clients` — list own platforms
- `GET    /clients/:id` — detail
- `PATCH  /clients/:id` — update metadata or contact email
- `DELETE /clients/:id` — delete draft
- `GET    /confirm-email?token=...` — email confirmation handler (HTML response)
- `POST   /clients/:id/dns-check` — verify TXT record at _hhttps-verify.{apex}
- `POST   /clients/:id/submit-review` — submit to admin queue (with hard-checks)
- `GET    /clients/:id/stats` — owner's per-platform login stats

Admin (`/hhttps/admin/*` — requires admin membership):
- `GET  /clients/pending` — admin queue (developer-role sorted first)
- `GET  /clients` — all clients with status filter
- `POST /clients/:id/approve` — verify (auto-sends notification email)
- `POST /clients/:id/reject` — reject with reason
- `POST /clients/:id/suspend` — suspend with reason
- `GET  /stats` — system overview

### State machine for `oauth_clients.verification_status`

```
draft → email_pending → unverified → pending_review → verified
                                                    ↘ rejected
                            ↑
                            └── (after email change, reverts)
```

Hard requirements for `verified` (enforced in submit-for-review):
1. Email confirmed (user clicked confirmation link)
2. Email domain matches platform apex domain (Apex-Match)
3. DNS TXT record verified at `_hhttps-verify.{apex}`
4. Impressum URL set
5. Admin approval

### Email (Brevo integration)

- Three new templates: platform registration, verified notification, rejected notification
- Optional `Reply-To` header via `SMTP_REPLY_TO` env (for non-receivable noreply addresses)
- Branding cleanup: HumanProof → HHTTPS Project, GitHub URL updated

## Deploy steps (already done on production May 2026)

```bash
# 1. Apply migrations
sudo -u postgres psql -d hhttps -f /var/www/hhttps/sql/migration-phase-3b.sql
sudo -u postgres psql -d hhttps -f /var/www/hhttps/sql/migration-phase-3b.1.sql

# 2. Bootstrap yourself as admin
sudo -u postgres psql -d hhttps -c "
  INSERT INTO admins (user_id, note) 
  VALUES ('<your-user-id>', 'Project operator');
"

# 3. Install dotenv (for .env auto-loading)
cd /var/www/hhttps && npm install dotenv

# 4. Update .env with SMTP credentials (Brevo example)
# SMTP_HOST=smtp-relay.brevo.com
# SMTP_PORT=587
# SMTP_USER=<your-brevo-account-email>
# SMTP_PASS=<your-brevo-smtp-key>
# SMTP_FROM=noreply@hhttps.org
# SMTP_FROM_NAME=HHTTPS Issuer
# SMTP_REPLY_TO=info@yourdomain.example  # optional, for non-receivable noreply

# 5. Restart PM2 (full stop/start, not reload, to pick up new env via dotenv)
sudo pm2 stop hhttps-v4
sudo pm2 delete hhttps-v4
cd /var/www/hhttps
sudo pm2 start server.js --name hhttps-v4
sudo pm2 save
```

## Brevo Setup Gotchas

For others setting up email later:
1. Add domain (`hhttps.org`) in Brevo → get 3 DNS TXT records
2. Add those TXT records at your DNS host (does NOT change MX records)
3. Generate SMTP key in Brevo → SMTP & API → SMTP
4. **Authorize your VPS IP in Brevo** → Senders & IP → Authorized IPs
   (Without this, SMTP-AUTH succeeds but mails are silently dropped)
5. Verify by sending a test mail — check Brevo Statistics → Email logs

## What's next (Phase 3b UI)

Phase 3b backend is complete. The UI for /developers landing, dashboard,
register form, and admin queue is the next deliverable. Backend endpoints
above are sufficient to drive that UI entirely from the browser.
