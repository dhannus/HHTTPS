# HHTTPS v3.1 — E-Mail-Verifikation Setup

## Wie es funktioniert

1. Nutzer führt WebAuthn durch (Fingerabdruck/PIN)
2. Nutzer wählt Rolle (Journalist, Student, etc.)
3. Nutzer gibt E-Mail-Adresse ein
4. Server erkennt Domain automatisch und klassifiziert sie
5. Server sendet Verifikationslink per E-Mail (gültig 15 Min)
6. Nutzer klickt Link → Domain wird bestätigt → Trust Score steigt
7. Nutzer stellt HHTTPS-Token aus (mit erhöhtem Trust Score)

**Dev Mode:** Ohne SMTP-Konfiguration wird der Verifikationslink
in der Server-Konsole ausgegeben und automatisch im Browser getestet.

---

## Umgebungsvariablen (.env)

```bash
# ─── HHTTPS Basis ──────────────────────────────────────────────
PORT=3000
RP_ID=hhttps.org
ORIGIN=https://hhttps.org
BASE_URL=https://hhttps.org
JWT_SECRET=$(openssl rand -hex 64)   # einmal generieren, sicher speichern!

# ─── E-Mail (Option A: SMTP) ────────────────────────────────────
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your-password
SMTP_FROM=noreply@hhttps.org

# ─── E-Mail (Option B: Brevo/Sendinblue — kostenlos bis 300/Tag) ─
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your-brevo-api-key

# ─── E-Mail (Option C: Mailgun) ────────────────────────────────
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@mg.yourdomain.com
SMTP_PASS=your-mailgun-api-key

# ─── E-Mail (Option D: Eigener Postfix auf dem VPS) ────────────
# Kein SMTP_HOST nötig — nodemailer nutzt system sendmail
# sudo apt install postfix  (wähle "Internet Site", dann deine Domain)
```

---

## Empfohlener Provider: Brevo (ehemals Sendinblue)

Brevo ist kostenlos bis 300 E-Mails/Tag — ideal für die Demo.

1. Account auf brevo.com erstellen
2. SMTP & API → SMTP-Schlüssel generieren
3. .env befüllen (Option B oben)

---

## Deployment

```bash
# .env anlegen
cat > .env << 'EOF'
PORT=3000
RP_ID=hhttps.org
ORIGIN=https://hhttps.org
BASE_URL=https://hhttps.org
JWT_SECRET=HIER_LANGEN_ZUFALLSWERT_EINTRAGEN
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_USER=deine@email.com
SMTP_PASS=dein-brevo-key
SMTP_FROM=noreply@hhttps.org
EOF

# dotenv laden (server.js bereits ESM, dotenv muss manuell geladen werden)
npm install dotenv
node -e "import('./server.js')"

# oder mit pm2:
pm2 start server.js --name hhttps-v3 \
  --env production \
  --env PORT=3000
pm2 save
```

---

## Automatische Domain-Klassifizierung

| Domain-Typ | Beispiele | Level | Trust Score |
|---|---|---|---|
| Parlament/Regierung | bundestag.de, bundesregierung.de | official-email | 90 |
| Universität | lmu.de, tu-berlin.de, kit.edu | email-verified | 75 |
| Medien | spiegel.de, ard.de, dpa.com | email-verified | 72 |
| Verbände | sprecherverband.de, bffs.de | email-verified | 78 |
| Sonstige | gmail.com, web.de, ... | email-verified | 65 |

---

## API-Endpunkte (neu in v3.1)

```
POST /hhttps/email/send
  Body: { sessionId, email, role }
  → sendet Verifikations-E-Mail (oder gibt Link im Dev-Mode aus)

GET  /hhttps/email/verify?token=<raw>&session=<sid>
  → bestätigt Token, upgradet Session, redirect zu /email-verify.html

POST /hhttps/email/status
  Body: { sessionId }
  → gibt aktuellen E-Mail-Verifikationsstatus der Session zurück

POST /hhttps/role/declare/v2
  Body: { sessionId, role, verificationMethod?, verificationData? }
  → wie /role/declare, nutzt aber automatisch E-Mail-Verifikation aus Session
```

---

## Datenschutz-Design

- E-Mail-Adresse wird nach dem Senden NICHT gespeichert
- Gespeichert wird nur: SHA-256 Hash der Domain + verschlüsselter Token
- Nach 15 Min wird alles automatisch gelöscht
- In der JWT-Payload steht nur: domain, level, trustScore — niemals die E-Mail

---

Initiative HumanProof · daniel.hannuschka@tweakz.de · github.com/dhannus/HumanProof
