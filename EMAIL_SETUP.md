# HHTTPS v4.1 — E-Mail-Setup

E-Mail wird in HHTTPS für **zwei unterschiedliche Zwecke** verwendet:

1. **Nutzer-Verifikation** — eine Person bestätigt eine E-Mail-Domain, um ihren Trust Score zu erhöhen (z. B. von 60 auf 75 bei einer Uni-Domain).
2. **Plattform-Verifikation** — ein:e Entwickler:in registriert eine Plattform; HHTTPS schickt einen Bestätigungslink an die `contact_email` und informiert anschließend bei Genehmigung / Ablehnung.

Beide laufen über denselben SMTP-Transporter in [`email.js`](email.js). Production-Setup: Brevo (vorher Sendinblue), kostenlos bis 300 E-Mails/Tag.

---

## Umgebungsvariablen (`.env`)

Produktions-Setup auf `hhttps.org`:

```bash
# ─── HHTTPS Basis ─────────────────────────────────────────────────
PORT=3000
RP_ID=hhttps.org
ORIGIN=https://hhttps.org
BASE_URL=https://hhttps.org
JWT_SECRET=<openssl rand -hex 64>   # einmal generieren, sicher speichern

# ─── Datenbank ────────────────────────────────────────────────────
DB_HOST=localhost
DB_PORT=5432
DB_NAME=hhttps
DB_USER=hhttps
DB_PASS=<db-password>

# ─── SMTP via Brevo (Production) ──────────────────────────────────
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USER=<brevo-account>@smtp-brevo.com
SMTP_PASS=<brevo-smtp-key>
SMTP_FROM=noreply@hhttps.org
SMTP_FROM_NAME=HHTTPS Open Issuer
SMTP_REPLY_TO=info@tweakz.de
```

> ⚠️ `.env` darf niemals ins Git-Repo. Sie ist in `.gitignore`. Backups verschlüsseln.

### Alternative Provider

Sollte Brevo ausfallen oder ein Wechsel nötig sein:

| Provider | SMTP-Host | Port | Hinweise |
|---|---|---|---|
| **Brevo** *(aktuell)* | `smtp-relay.brevo.com` | 587 | 300 Mails/Tag kostenlos |
| Mailgun | `smtp.mailgun.org` | 587 | Eigene Domain via TXT verifizieren |
| Strato | `smtp.strato.de` | 465 | TLS direkt (SSL), nicht STARTTLS |
| System-Postfix | – | – | `sudo apt install postfix`; nodemailer fällt automatisch auf `sendmail` zurück, wenn `SMTP_HOST` leer ist |

---

## Brevo einrichten

1. Account auf [brevo.com](https://brevo.com) erstellen, Domain `hhttps.org` verifizieren (DKIM + SPF + DMARC TXT-Records).
2. Im Dashboard → **SMTP & API → SMTP** einen Schlüssel generieren.
3. Im Brevo-Account die Absender-Adresse `noreply@hhttps.org` validieren (Mail-Verifizierungslink).
4. SMTP-Credentials in die `.env` eintragen (siehe oben).
5. `pm2 reload hhttps-v4 --update-env` — `dotenv/config` wird beim Start in `server.js` geladen, damit die neuen Werte aktiv werden.

Test-Send:

```bash
TOKEN="<dein-hhttps-token>"
curl -X POST https://hhttps.org/hhttps/developers/clients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SMTP Test",
    "homepage_url": "https://example.org",
    "redirect_uris": ["https://example.org/cb"],
    "contact_email": "deine@adresse.de",
    "impressum_url": "https://example.org/impressum"
  }'
# Posteingang prüfen → Brevo-Mail sollte ankommen.
```

---

## Domain-Klassifizierung (Nutzer-Verifikation)

Eine privatperson kann ihre E-Mail-Domain bestätigen, um ihren Trust Score zu erhöhen. Die Klassifizierung läuft in [`email.js → classifyDomain()`](email.js):

| Domain-Typ | Beispiele | Level | Trust-Bonus |
|---|---|---|---|
| Parlament / Bundesbehörden | `bundestag.de`, `bundesregierung.de`, `bmi.bund.de` | `official-email` | 90 |
| Universitäten / Hochschulen | `lmu.de`, `tu-berlin.de`, `kit.edu`, `.uni-*`, `.fh-*` | `email-verified` | 75 |
| Presse / Medien | `spiegel.de`, `ard.de`, `dpa.com`, `tagesspiegel.de` | `email-verified` | 72 |
| Verbände (Kreativ) | `bffs.de`, `sprecherverband.de`, `gema.de` | `email-verified` | 78 |
| Generische Provider | `gmail.com`, `web.de`, eigene Domains | `email-verified` | 65 |

Anpassung der Regeln: `DOMAIN_RULES` in `email.js` editieren, `pm2 reload hhttps-v4`.

---

## API-Endpoints

### Nutzer-Verifikation (Trust Score)

```
POST /hhttps/email/send
  body: { sessionId, email, role }
  → versendet Verifikations-Mail (15 Min Gültigkeit)

GET  /hhttps/email/verify?token=<raw>&session=<sid>
  → bestätigt Token, upgradet Session, redirect auf /email-verify.html

POST /hhttps/email/status
  body: { sessionId }
  → liefert aktuellen Verifikationsstand der Session
```

### Plattform-Lifecycle-Mails (Developer + Admin)

Diese Mails werden **automatisch** vom Server ausgelöst — keine eigenen API-Calls nötig, außer dem Resend-Endpoint:

| Auslöser | Empfänger | Mail-Funktion in `email.js` |
|---|---|---|
| `POST /hhttps/developers/clients` (Plattform-Registrierung) | Plattform-Kontakt | `sendPlatformRegistrationEmail` (kind: `registration`) |
| `PATCH /clients/:id` mit geänderter `contact_email` | Neue Kontakt-Adresse | `sendPlatformRegistrationEmail` (kind: `email_change`) |
| `POST /clients/:id/resend-email` | Plattform-Kontakt | `sendPlatformRegistrationEmail` (kind: `resend`) |
| `POST /hhttps/admin/clients/:id/approve` | Plattform-Kontakt | `sendPlatformVerifiedEmail` |
| `POST /hhttps/admin/clients/:id/reject` | Plattform-Kontakt | `sendPlatformRejectedEmail` |

#### Manueller Resend-Aufruf

```
POST /hhttps/developers/clients/:id/resend-email
Authorization: Bearer <dein-hhttps-token>

→ 200 { success: true, sent_to: "<masked@email>" }      bei Erfolg
→ 409 { error: "wrong_state" }                          falls Email schon bestätigt
→ 500 { error: "send_failed", message: "<smtp error>" } falls SMTP-Problem
```

Nur möglich, solange `verification_status === 'email_pending'`. Generiert einen frischen Token (48 h Gültigkeit) und sendet eine neue Brevo-Mail.

---

## Datenschutz-Design

- **Nutzer-Verifikation:** Die E-Mail-Adresse wird **nicht** in der DB gespeichert. Persistiert wird nur: SHA-256 Hash der Domain + verschlüsselter Token mit 15 Minuten TTL. Im JWT landet nur `{ domain, level, trustScore }`, niemals die E-Mail selbst.
- **Plattform-Verifikation:** Hier muss die Kontakt-E-Mail gespeichert werden, weil sie für spätere Lifecycle-Mails (approve, reject, suspend) gebraucht wird. Sie steht in der Spalte `oauth_clients.contact_email` und wird nur intern bzw. an den Plattform-Owner ausgeliefert.
- Tokens (`email_token`, `dns_token`) werden bei erfolgreicher Verifikation auf `NULL` gesetzt — kein „leak after verify".
- DSGVO Art. 6 Abs. 1 lit. b (Vertrag) + Art. 6 Abs. 1 lit. f (berechtigtes Interesse Plattform-Sicherheit) als Rechtsgrundlage.

---

## Troubleshooting

**„email send failed: Cannot read properties of undefined (reading 'split')"** in `pm2 logs hhttps-v4`:
→ Bedeutet, dass `SMTP_USER` zur Laufzeit `undefined` ist. Ursache: `dotenv` wird nicht geladen.
Fix: oberste Zeile in `server.js` muss `import 'dotenv/config';` sein. Dann `pm2 delete hhttps-v4 && pm2 start server.js --name hhttps-v4 && pm2 save`.

**Brevo-Mail kommt im Spam an / wird gar nicht zugestellt:**
→ DKIM und SPF im Brevo-Dashboard prüfen (alle drei TXT-Records für `hhttps.org` müssen grün sein). Bei eigener Domain: DMARC zusätzlich anlegen (`v=DMARC1; p=quarantine; rua=mailto:postmaster@hhttps.org`).

**Bestätigungslink verläuft auf 404:**
→ Sollte mit v4.1 behoben sein (`${BASE_URL}/developers/` mit trailing slash, vorher ohne). Falls noch alt: `email.js` aus dem Repo-Stand v4.1 neu deployen.

---

*HHTTPS Project · daniel.hannuschka@tweakz.de · [github.com/dhannus/HHTTPS](https://github.com/dhannus/HHTTPS)*
