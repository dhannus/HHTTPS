# HHTTPS — Projekt-Review REPORT

**Basis:** `main` @ `bf0a82b` (2026-09-15) · **Review-Branch:** `claude/kind-pasteur-kweqf1` · **Datum:** 2026-09-17
**Verfahren:** Songbird-Review-Agentenpaket v2 — Review-Lead → 8 Arbeitspakete × 4 Reviewer (Korrektheit, Sicherheit, Performance, Wartbarkeit) → Verifikator je AP (jedes Finding am Code geprüft, Repro gegen Test-Server/Test-DB) → Report.
**Artefakte:** `00-inventar.md` (Bestandsaufnahme, AP-Schnitt), `01-automatische-checks.md` (Gates), `ap/APx-{K,S,P,W}.md` (Rohbefunde), `ap/APx-verifikation.md` (verifizierte Findings mit Beleg, Urteil, Empfehlung — **maßgeblich**).

## 1. Management-Summary

Die deterministischen Gates sind grün (203/203 Unit+Integration, 7/7 e2e, ESLint 0 Fehler), und die im Feature „email-anchored-identity“ gehärteten Pfade (E-Mail-Anker, Consent, OAuth-Parameter) halten dem Review stand. Das Gesamtbild außerhalb dieser Pfade ist jedoch **nicht produktionsreif**: Von 443 gemeldeten Befunden wurden **370 bestätigt** (2 verworfen, 71 als Duplikate zusammengeführt), darunter **7 kritische (S1)** und **30 hohe (S2)**.

Die kritischen Befunde verteilen sich auf drei Cluster:

1. **Privacy-Pass-Modul (AP7) ist als Vertrauensanker unbrauchbar.** Der öffentliche `token-request` stellt Rollen-Tokens ohne Session/Eligibility/Quota aus (AP7-20), die Domain-Regexe der Rollenanforderungen sind unverankert (AP7-05), und ein frei wählbares `method` macht per E-Mail-Klick aus einer Adresse eine „Approbations-/Kammerprüfung“ (AP7-04). Gleichzeitig ist der reguläre Ausgabepfad `/privacy-pass/issue` seit v0.5 dauerhaft 403 (AP7-01). Empfehlung: Modul bis zur Sanierung **abschalten oder aus dem Mount nehmen**.
2. **E-Mail-Vertrauen ist manipulierbar.** Ein Adressformat mit Kommentar-Klammer wird an eine fremde Domain zugestellt, aber als `official-email` (+40 Trust) gewertet (AP3-13, S1); `classifyDomain` matcht ohne Label-Grenze (AP3-02, S2). Damit erreicht ein Angreifer „Verified human“ mit Behördenbonus ohne Passkey.
3. **Zwei Produktionsfehler im Kernflow und ein XSS auf der IdP-Origin.** Der Standard-Sign-in (E-Mail → Passkey → Token) endet in 403, weil `auth/finish` die gemergte Verifikation nicht persistiert (AP3-01, S1); `email-verify.html` ist tot, aber ausgeliefert und per URL-Parameter XSS-fähig, bei Tokens in `localStorage` (AP8-15, S1). Die EUDI-PID-Abfragen laufen laut Code-Vertrag ohne Aussteller-Vertrauenskette (AP4-18, S1 mit Vorbehalt „Live-Nachweis ausstehend“).

Die S2-Befunde sind überwiegend **Autorisierungs- und Lifecycle-Lücken**: Widerruf erreicht Refresh-Tokens nicht (AP2-01, AP4-03), Refresh-Tokens gelten als Portal-/Admin-Credential (AP5-01), Webhook-Routen sind unauthentifiziert und liefern HMAC-Secrets (AP5-16/AP1-22, SSRF AP1-21), Claim-Transplantation in `age/upgrade`/`eid/upgrade` (AP4-20), `documentProvided:true` erzeugt RAL-1-Karten ohne Nachweis (AP4-21), frische Installation bootet nicht (AP6-01), `make-admin.sh --grant-recent` mit TOCTOU (AP6-13).

Querschnittlich: **keine Cleanup-Jobs** für `authorization_codes`, `email_verifications(used)`, `revoked_tokens`, Privacy-Pass-Tabellen (Klartext-E-Mails unbefristet), **CI ohne Test-/Lint-/Audit-Gate**, `nodemailer@6` mit erreichbaren Advisories (via AP3-13), hoher Duplikationsgrad (Sign-in-Flow 3×, Apex/Redirect-Helfer 2×, Rollenkataloge 3–4×) und ~15 % toter Code (workload-identity.js, demo.js, email-verify.html, email-patch.js, roles.eaa.js).

## 2. Statistik

| | gemeldet | bestätigt | verworfen | zusammengeführt |
|---|---|---|---|---|
| Gesamt | **443** | **370** | 2 | 71 |

Verworfen: AP2-12 (Refresh-Token an `/approve` ohne beobachtbare Folge), AP6-27 (Projekt-Kontaktadresse ist bewusst öffentlich).

### Statistik je Modul

| AP | Modul | S1 | S2 | S3 | S4 | Σ |
|---|---|---|---|---|---|---|
| AP1 | Kern, Middleware, Signaturen, Rollenmodell, Schlüssel | 0 | 2 | 25 | 29 | 56 |
| AP2 | OAuth 2.1 / OIDC + Consent | 0 | 2 | 14 | 13 | 29 |
| AP3 | Identität, Session, E-Mail-Anker, WebAuthn, GitHub | 2 | 2 | 18 | 18 | 40 |
| AP4 | Rollen-/Alters-/eID-Verifikation, Karten, Revoke, EUDI | 1 | 6 | 27 | 17 | 51 |
| AP5 | Maschinen, PoP, Webhooks, Developer-Portal, Admin | 0 | 4 | 18 | 22 | 44 |
| AP6 | Persistenz, Migrationen, Betrieb, CI | 0 | 3 | 21 | 27 | 51 |
| AP7 | Privacy Pass + SDK | 3 | 6 | 22 | 20 | 51 |
| AP8 | Frontend, Sites, Browser-Extension | 1 | 5 | 26 | 16 | 48 |
| **Σ** | | **7** | **30** | **171** | **162** | **370** |

### Statistik je Dimension (Primärdimension)

| Dimension | S1 | S2 | S3 | S4 | Σ |
|---|---|---|---|---|---|
| Korrektheit | 1 | 14 | 58 | 42 | 115 |
| Sicherheit | 6 | 13 | 35 | 28 | 82 |
| Performance | 0 | 3 | 24 | 30 | 57 |
| Wartbarkeit | 0 | 0 | 53 | 62 | 115 |

## 3. Top-Risiken (S1 und S2)

### S1 — Critical

#### AP3-01 [Korrektheit] `server/server.js:L2571-2592`
**Passkey-Login verwirft die gemergte E-Mail-/GitHub-Verifikation: `db.sessions.create` persistiert `priorMerge` nicht**

- **Auswirkung:** Der Standard-Sign-in-Flow der Seite (E-Mail → Passkey → Token) endet in 403. Passkey ist für Nutzer der Sign-in-Seite faktisch unbenutzbar; dieselbe Lücke gilt für eine vorher abgeschlossene GitHub-Verifikation (`githubVerified` geht ebenfalls verloren). `merged:true` in der Antwort (L2598) ist falsch.
- **Empfehlung:** Nach dem INSERT `await db.sessions.update(sid, priorMerge)` (die `allowedColumns` in `sessions.update` L171-195 decken alle Merge-Felder ab) oder `sessions.create` um die E-Mail-/GitHub-Spalten erweitern; `sessions.delete` implementieren (AP3-26) und die Vorgänger-Session erst NACH erfolgreichem Anlegen löschen. Test: E-Mail-verifizierte Session → Passkey → `role/declare` 200 mit `email_verified:true` und `passkey_verified:true` (E2E: `#issueBtn` klicken, siehe AP3-10).

#### AP3-13 [Sicherheit] `server/server.js:L2852-2854`
**E-Mail-Regex und nodemailer-Adressparser interpretieren die Adresse unterschiedlich: `x@evil.com(bundestag.de` wird an evil.com zugestellt, aber als `official-email` (+40) klassifiziert**

- **Auswirkung:** Kostenlose Erlangung der höchsten E-Mail-Assurance-Stufe (Behörde) und des „Verified human“-Bands ohne Passkey; Assurance-Modell für Behörden/Hochschulen/Presse ist nicht belastbar.
- **Empfehlung:** Strikte ASCII-Validierung (`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`, max. 254 Zeichen) VOR `classifyDomain` und `sendMail`; zusätzlich `addressparser(email)[0].address === email` erzwingen (sonst 400); nodemailer ≥ 9.1.0 (GHSA-cc9r-2j5m-2m83, GHSA-mm7p-fcc7-pg87, GHSA-wmmp-3585-3rmp); Label-Grenzen-Fix aus AP3-02 zusätzlich nötig.

#### AP4-18 [Sicherheit] `server/eudi-verifier/backend-client.js:L98-109, L278-289`
**PID-DCQL-Queries (Alter via PID, eID-Identität) ohne `trusted_authorities`; laut Backend-Vertrag im Code prüft EUDIPLO dann keine Aussteller-Vertrauenskette**

- **Auswirkung:** `age_verified:true` (Methode `eudi-wallet`) und `eudi_verified:true` (+40 Trust) mit einem selbst signierten mdoc `eu.europa.ec.eudi.pid.1` aus einem Test-Issuer. Die Ausnutzung setzt ein Wallet voraus, das ein fremd signiertes PID-mdoc präsentiert (Sandbox-/Referenz-Wallets erlauben das). Ob EUDIPLO in der Live-Konfiguration nicht doch einen globalen Trust-Anchor besitzt, ist aus dem Repo nicht belegbar — im Zweifel gilt der eigene, ausdrücklich als bestätigt markierte Vertrag.
- **Empfehlung:** (1) Einmalige Live-Prüfung: `GET /api/verifier/config/age-over-18` und `eid-identity` auf `trusted_authorities` prüfen; Test-Präsentation mit nicht gelisteter Issuer-CA. (2) `trusted_authorities` (etsi_tl, PID-Trust-List/LoTE) in `buildDcqlQuery`/`buildPidDcqlQuery` setzen, Configs per PATCH aktualisieren (AP4-15), fail-closed ohne Trust-List. (3) Fehlendes `install-av-trustlist.sh` einchecken oder Kommentar korrigieren.

#### AP7-04 [Sicherheit/Korrektheit] `server/privacy-pass/verifications-api.js:L61,L70,L95-101,L156-159`
**Frei wählbares `method` in `/email/start` wird per E-Mail-Klick als erfüllte Registerprüfung (`approbation-id`, `bar-association-id`, `notary-chamber-id`) gespeichert**

- **Auswirkung:** Die Register-Gates der höchsten Vertrauensstufe sind wirkungslos; der gespeicherte Zustand ist falsch (Methode ≠ durchgeführte Prüfung). Aktuell nur deshalb nicht in Rollen-Tokens umsetzbar, weil `/issue` an AP7-01 scheitert — `/token-request` (AP7-20) liefert die Tokens ohnehin.
- **Empfehlung:** `method` serverseitig auf E-Mail-basierte Methoden (`email-verified`, ggf. `school-email`, `medical-email`, `lawyer-email`, `official-email`) beschränken, Fremdwerte 400; `recordVerification` den Score über `resolveVerification()` ermitteln lassen.

#### AP7-05 [Sicherheit/Korrektheit] `server/privacy-pass/role-requirements.js:L61,L69,L75,L89,L97,L151-158`
**Domain-Regexe sind unverankerte Substring-Muster; Fremddomains erfüllen strikte Rollen**

- **Auswirkung:** Für `civil_servant`/`politician` (required nur `email-verified`, L86-101) erhält jeder Inhaber einer Domain mit passendem Teilstring nach Klick auf seinen eigenen Link die strikte Rolle; mit AP7-04 gilt das auch für `medical_professional`/`lawyer`.
- **Empfehlung:** Alle Alternativen mit `(^\|\.)…$` verankern, generische Wortlisten (`verwaltung`, `zoll`, `drk`, `anwalt`, `klinik…`, `medi-`) streichen oder als explizite Allowlist offizieller Domains führen; strikte Rollen nur über Registerprüfung/EUDI-Attestierung; Unit-Tests mit Positiv-/Negativ-Domains je Rolle.

#### AP7-20 [Sicherheit] `server/privacy-pass/issuer.js:L82-98, index.js:L61-65`
**Öffentlicher `/privacy-pass/token-request` stellt Rollen-Tokens ohne Session, Eligibility oder Quota aus**

- **Auswirkung:** Jeder kann unbegrenzt gültige, unlinkbare Tokens für jede Rolle minten; die gesamte Gate-Logik in issuance.js/verifications*.js ist umgehbar; `/verify`/`/redeem` bestätigen die Tokens.
- **Empfehlung:** Anonymen Endpunkt auf den `default`-Issuer beschränken (oder entfernen) und auch dort Autorisierung verlangen; Rollenschlüssel nur über `/issue` nach Eligibility-/Quota-Prüfung evaluieren.

#### AP8-15 [Sicherheit] `server/public/email-verify.html:L69, L96-97, L111`
**DOM-XSS auf der IdP-Origin: URL-Parameter `domain`, `level`, `reason` landen ungeprüft in `innerHTML`**

- **Auswirkung:** Skriptausführung auf `hhttps.org`. Dort liegen Access- **und Refresh-Token** in `localStorage['hhttps_identity']` (index.html L791, hhttps.html L1577) sowie `hhttps_uid`. `connect-src 'self'` blockiert `fetch` zu Fremd-Origins, nicht aber `location = 'https://evil/?'+localStorage…` (kein `navigate-to`). Mit dem Access-Token lassen sich Signaturen im Namen des Opfers erzeugen (`/hhttps/signatures` liest `hhttps-token`-Header, server.js L1077); mit dem Refresh-Token 7 Tage lang neue Access-Tokens (stateless `/hhttps/token/refresh`). Angriff = Link an ein angemeldetes Opfer, keine Interaktion außer Klick. S1 bleibt gerechtfertigt, weil es sich um reflektiertes XSS auf der Identitäts-Origin mit direktem Token-Diebstahl handelt; mildernd nur, dass die Seite ein Legacy-Artefakt ist.
- **Empfehlung:** Datei löschen (der Server steuert sie nie an, AP8-10). Zusätzlich `unsafe-inline` in `script-src`/`script-src-attr` durch Nonces ersetzen — die `onclick=`-Handler in index.html sind der einzige Grund für `script-src-attr 'unsafe-inline'` (Kommentar server.js L390–391).

### S2 — High

#### AP1-21 [Sicherheit] `server/webhooks.js:L17-18`
**Webhook-URL nur syntaktisch geprüft: SSRF gegen interne Netze**

- **Auswirkung:** Blinder SSRF-POST an `127.0.0.1:*`, `169.254.169.254`, den eudi-verifier-Backend-Port etc.; Port-Scan-Orakel über die Liste.
- **Empfehlung:** In `registerWebhook` nur `https:` (Dev: `http:`), Host nach DNS-Auflösung gegen private/Loopback/Link-Local/ULA prüfen, `redirect: 'error'` im `fetch`; Registrierung an Auth binden (AP5).

#### AP1-22 [Sicherheit] `server/webhooks.js:L41-43`
**`listWebhooks()` liefert das HMAC-Secret jedes Webhooks zurück**

- **Auswirkung:** Jeder Leser der Liste erhält URL + Secret aller Webhooks und kann gültig signierte `token.issued`-Events fälschen; ids aus der Liste erlauben `DELETE /hhttps/webhooks/:id`.
- **Empfehlung:** `listWebhooks` ohne `secret` (nur `secret_hint`), Secrets gehasht/verschlüsselt speichern; Route-Auth in AP5.

#### AP2-01 [Korrektheit] `server/server.js:L1652-1690, L1950-1959; server/db.js:L1270-1306`
**Plattform-Widerruf erreicht den OAuth-Refresh-Grant nicht; Refresh-Kette läuft nach „Verbindung trennen“ unbegrenzt weiter**

- **Auswirkung:** Nach dem vom Nutzer erklärten Widerruf kann die Plattform beliebig lange (bei Nutzung mindestens alle 30 Tage: unbegrenzt) frische Access-Tokens inkl. `email`, `preferred_username`, `verified_methods`, Rolle/Trust beziehen; Rollenentzug/Methodenwegfall bei HHTTPS wird nie propagiert („stale attestation“). Die Zusage im Consent-Footer („jederzeit widerrufen“) ist faktisch nicht eingelöst; UI-Zustand („my logins“) und Token-Zustand widersprechen sich.
- **Empfehlung:** Im Refresh-Grant `connectedPlatforms.getPairwiseId(rd.ouid, client_id)` (bzw. `revoked_at IS NULL`) prüfen → sonst `invalid_grant`; in `/oauth/revoke` alle OAuth-Refresh-jtis des Paars (user, client) löschen (`client_id`-Spalte auf `refresh_tokens`); absolute Maximallebensdauer der Refresh-Kette; Claims beim Refresh gegen aktuellen Nutzerzustand neu bilden. Test: revoke → refresh_token grant → `invalid_grant`.

#### AP2-23 [Performance] `server/server.js:L1601-1623, L714-724; server/db.js:L1245-1266, L1339-1347; server/sql/schema.sql:L192-206`
**`authorization_codes` wird bei jeder Autorisierung befüllt, aber nie bereinigt; der vorhandene Cleanup ist nirgends eingehängt**

- **Auswirkung:** Tabelle + PK-Index + `idx_authcodes_expires` wachsen linear mit allen jemals gestarteten Logins (inkl. abgebrochener); Autovacuum/Backups werden stetig teurer. Nie eingelöste Codes behalten `email` im Klartext unbegrenzt (die Wipe-Logik in `claim()` greift nur beim Einlösen) — das widerspricht der Datenminimierungs-Zusage und rechtfertigt S2.
- **Empfehlung:** `db.authCodes.cleanup()` in das 5-Minuten-Intervall (server.js L714-724) aufnehmen oder `DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'` in `cleanup_expired()` ergänzen; Ergebnis in die `[CLEANUP]`-Ausgabe zählen.

#### AP3-02 [Korrektheit/Sicherheit] `server/email.js:L99-115`
**`classifyDomain` prüft Domain-Suffixe ohne Label-Grenze; Fremddomains erhalten `official-email`/`school-email` und bis zu +40 Trust**

- **Auswirkung:** Mit einer frei registrierbaren Lookalike-Domain (`notbundestag.de`) oder einer eigenen Subdomain (`*.uni-*.`) erhält man dauerhaft Behörden-/Hochschul-Assurance, den Header `HHTTPS-Domain-Verified: true` und die Human-Schwelle ohne zweiten Faktor.
- **Empfehlung:** `domain === d \|\| domain.endsWith('.' + d)`; Präfixregeln auf Label-Anfang (`/(^\|\.)(uni\|tu\|hs\|fh\|hochschule)-[a-z0-9-]+\.(de\|edu)$/` o. ä.) beschränken, Liste deduplizieren; Unit-Tests für die Grenzfälle (siehe AP3-41).

#### AP3-15 [Sicherheit] `server/email.js:L445-448`
**`setupUrl` wird unescaped in ein `href`-Attribut der Registrierungsmail eingesetzt → HTML-Injection in Mails von noreply@hhttps.org an frei wählbare Empfänger**

- **Auswirkung:** Phishing-Relay mit vertrauenswürdigem Absender und SPF-Domain hhttps.org.
- **Empfehlung:** `escapeHtml` für jede interpolierte URL (auch `ctaUrl`); `setupUrl` serverseitig aus `https://<apex>` + festem Pfad bilden statt aus der Roh-URL; `homepage_url` auf `new URL(u).origin === u` (ohne Pfad) prüfen.

#### AP4-01 [Korrektheit] `server/server.js:L3719-3741, L3744-3763`
**`/hhttps/validate` und `/hhttps/protected` bestätigen Maschinen- und Refresh-Tokens als `human:true · actorType:'human'`**

- **Auswirkung:** Die zentrale Zusicherung der Validierungs-API („human-verified“) ist über registrierte Bot-Operatoren und über 7-Tage-Refresh-Tokens fälschbar; SDKs (`server/sdk/client.js` L191, `client.py` L214) und die Spec (`sites/spec.html` L758) verweisen genau auf diesen Endpunkt.
- **Empfehlung:** In beiden Handlern `d.sub === 'human-verified'` verlangen (sonst 401 bzw. `human:false, actorType:d.actorType` aus dem Token spiegeln); `checkTokenValid` um `{ allowRefresh:false }` ergänzen; `human`/`actorType` nie hart setzen.

#### AP4-02 [Korrektheit] `server/server.js:L3341-3362`
**`/hhttps/age/upgrade` reissued Tokens ohne `pseudonym` und ohne `*_verified`-Flags; Alter überlebt den Refresh nicht**

- **Auswirkung:** Nach EUDI-Altersverifikation verliert die Identität Pseudonym und Methodenflags (OAuth `preferred_username`, Consent), nach ≤1 h ist das verifizierte Alter weg bei inkonsistentem `verified_methods`.
- **Empfehlung:** `...tokenSurface(session, v)` wie in `/hhttps/eid/upgrade` (L3555); `pseudonym: session.pseudonym \|\| null` an `issueRefreshToken`; Age-Claims in Refresh-Token und `/hhttps/token/refresh` übernehmen; Integrationstest für den 200-Pfad (Vorlage: gate.test.mjs L108–125).

#### AP4-03 [Korrektheit] `server/server.js:L3678-3707`
**`/hhttps/revoke` widerruft nur das übergebene Access-Token; der Refresh-Token bleibt gültig, Antwort meldet vollständigen Widerruf**

- **Auswirkung:** Ein Angreifer mit Refresh-Token (gleicher Speicherort) holt sich bis zu 7 Tage neue Access-Tokens, obwohl der Nutzer widerrufen hat.
- **Empfehlung:** Beim Revoke alle `refresh_tokens` des `userId` löschen und deren `jti` in `revoked_tokens` eintragen (Index `refresh_tokens_user_id_idx` existiert, schema.sql L92), oder Refresh-`jti` als Claim ins Access-Token schreiben und paarweise widerrufen.

#### AP4-20 [Sicherheit] `server/server.js:L3314-3322, L3520-3530`
**`currentToken` in `/hhttps/age/upgrade` und `/hhttps/eid/upgrade` wird nicht an `session.userId` gebunden**

- **Auswirkung:** Claim-Transplantation über Nutzergrenzen; mit einem geleakten (auch widerrufenen, noch nicht abgelaufenen) Fremdtoken.
- **Empfehlung:** `prev.userId === session.userId` und `checkTokenValid` statt `verifyToken`; sonst `currentToken` ignorieren und warnen.

#### AP4-21 [Sicherheit] `server/server.js:L3598-3667`
**Client-Flag `documentProvided:true` erzeugt ohne Nachweis eine Karte mit `verificationStatus:'verified'`, `method:'document-checked'`, RAL 1 — auch für geschützte Berufe**

- **Auswirkung:** Jede Session erhält eine signierte Berufsattestation „Arzt · RAL1 · verified · document-checked“; Relying Parties können Pilot- von Echtbetrieb nicht unterscheiden.
- **Empfehlung:** Bis zum realen Dokumenten-Review: `documentProvided` serverseitig ignorieren (reserved → 400) oder ehrlich labeln (`self-asserted-document`, RAL0); geschützte Berufe nur per externer (Q)EAA.

#### AP4-23 [Sicherheit] `server/eudi-verifier/docker/docker-compose.yaml:L34, L36`
**Keystore-Passwörter des RP-Signaturschlüssels im Klartext im Repository (bekanntes Issue #32)**

- **Auswirkung:** Mit Keystore-Zugriff Impersonation des Verifiers (`x509_san_dns:hhttps.org`) gegenüber Wallets.
- **Empfehlung:** Wie in #32: `${VAR}` aus gitignored `.env`, Passwort rotieren, History bereinigen; Datei entfernen.

#### AP5-01 [Korrektheit] `server/server.js:L3970-3982`
**`authenticatedUser` akzeptiert Refresh-Tokens (7 Tage) als Portal-/Admin-Credential**

- **Auswirkung:** Ein Refresh-Token (REFRESH_TTL = 7 d, L94) ist ein 7-Tage-Bearer für `/hhttps/whoami`, alle `/hhttps/developers/*`- und `/hhttps/admin/*`-Routen. Revocation des Access-Tokens schützt diese Endpunkte nicht. Hinweis: AP1-S meldet dieselbe Ursache (L702-711) für `/hhttps/check`, `/sign-text`, `/signatures`; Ursache ist `checkTokenValid`, die Auswirkung auf Portal/Admin gehört zu AP5.
- **Empfehlung:** In `authenticatedUser` nach `checkTokenValid`: `if (d.sub === 'refresh') throw new Error('refresh token not accepted as bearer')` — oder `checkTokenValid(token, { allowRefresh })` mit Default `false`, nur `/hhttps/token/refresh` setzt `true`. Gemeinsam mit dem AP1-Fix umsetzen.

#### AP5-02 [Korrektheit] `server/server.js:L4331-4348 + server/db.js:L927-944 / L902-913`
**E-Mail-Wechsel bei `verified`-Client führt in einen unbestätigbaren Zustand**

- **Auswirkung:** Owner kann die Plattform nach Mail-Wechsel nie wieder verifizieren; Bestätigungsseite lügt; `verified = TRUE` und `verification_status = 'unverified'` stehen inkonsistent nebeneinander und das Vertrauenssiegel bleibt im Consent-Screen sichtbar.
- **Empfehlung:** `updateContactEmail` immer auf `'email_pending'` setzen und `verified = FALSE` mitschreiben; `confirmEmail` per `WHERE email_verified_at IS NULL` mit `RETURNING`/`rowCount` arbeiten lassen und die Erfolgsseite nur bei `rowCount === 1` rendern.

#### AP5-16 [Sicherheit] `server/server.js:L3889-3911`
**Webhook-Registrierung, -Auflistung und -Löschung vollständig unauthentifiziert; GET liefert alle HMAC-Secrets**

- **Auswirkung:** Jeder kann alle Webhook-URLs fremder Betreiber inkl. HMAC-Secret lesen (→ gültig signierte gefälschte `token.issued/revoked`-Events), fremde Webhooks löschen (DoS für Integrationen) und beliebige eigene Webhooks anlegen, die bei jedem Token-Ereignis beliefert werden.
- **Empfehlung:** Routen mit `requireUser`/`requireAdmin` schützen, Webhooks an Owner-ID binden, `list`/`delete` darauf filtern; Secret nur einmal bei Registrierung ausgeben, in der Liste nie mehr.

#### AP5-17 [Sicherheit] `server/wp-plugin-registration.js:L81-88, L103-107`
**Rate-Limit der Plugin-Registrierung per `X-Forwarded-For` umgehbar; In-Memory-Map wächst unbegrenzt**

- **Auswirkung:** 5/h-Limit ist wirkungslos → Mail-Bombing/Phishing mit Issuer-Absender, unbegrenzte `oauth_clients`-Zeilen, plus Heap-Wachstum der pm2-Instanz durch einen Map-Eintrag pro erfundenem XFF-Wert (OOM-Restart).
- **Empfehlung:** `req.ip` bzw. den vorhandenen `express-rate-limit`-Limiter (`limit.email` oder `rl(5, 3600_000)`) verwenden; `regHits` entfernen.

#### AP6-01 [Korrektheit] `server/db.js:L432-439, server/scripts/install-pg.sh:L72-82, scripts/deploy-all.sh:L145-152`
**Installationsskripte spielen nur schema.sql ein; Boot-DDL setzt `authorization_codes` voraus → frische Installation bootet nicht**

- **Auswirkung:** Jede Neuinstallation nach Skript/README (und jede nach `install-pg.sh` aufgesetzte Testumgebung) endet mit „Boot schema migration failed“; die Fehlermeldung nennt die fehlenden Vor-Migrationen nicht. Die Produktionsinstanz ist nicht betroffen (bereits migriert), daher S2 statt S1. Kein Test deckt den Pfad ab (`db-phase8.test.mjs` läuft nur gegen eine voll migrierte DB).
- **Empfehlung:** Einen Migrationslauf (`server/scripts/migrate.js`, den `package.json:L9` bereits referenziert) mit Ledger `schema_migrations` und fester Reihenfolge (schema → 2.5 → 3a → 3b → 3b.1 → 4 → 5 → 6 → 7 → portal → 8 → 4b → 3a1) einführen und aus `install-pg.sh`/`deploy-all.sh` aufrufen; alternativ die Basismigrationen mit Applied-Checks in `BOOT_DDL_FILES` aufnehmen. Integrationstest „schema.sql only → ensureBootSchema()“ ergänzen.

#### AP6-02 [Korrektheit] `server/db.js:L1264-1267`
**`authCodes.cleanup()` wird nirgends aufgerufen; abgelaufene, nie eingelöste Codes (inkl. Klartext-E-Mail) bleiben unbegrenzt liegen**

- **Auswirkung:** `authorization_codes` und `idx_authcodes_expires` wachsen linear mit den Logins; nicht eingelöste Codes behalten `email`, `pseudonym`, `user_id`, `state`/`nonce` (bis 2 KB) dauerhaft. Die Zusicherung AK-17/D5 (Klartext-E-Mail ≤ 7 Tage) gilt für abgebrochene Flows nicht.
- **Empfehlung:** In `cleanupExpired()` `DELETE FROM authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'` ergänzen (bzw. `authCodes.cleanup()` aufrufen) und das Ergebnis in die `[CLEANUP]`-Ausgabe (server.js:L714-724) aufnehmen; optional `email` bereits bei Ablauf nullen.

#### AP6-13 [Sicherheit] `server/scripts/make-admin.sh:L146-157`
**`--grant-recent` vergibt Admin-Rechte an „wer auch immer zuletzt ein Token bekam“ (TOCTOU auf öffentlichem Dienst)**

- **Auswirkung:** Ein fremder Nutzer, der sich zwischen Operator-Login und Skriptlauf anmeldet, erhält vollen Admin-Zugriff (Client-Freigabe/Sperre, Audit-Log). Rein zeitlicher Zufall genügt.
- **Empfehlung:** `--grant-recent` entfernen oder ermittelte `user_id` (+ `method`, `issued_at`) anzeigen und per `read` bestätigen lassen; bevorzugt nur `--grant <USER_ID>` mit ID aus `/hhttps/whoami`.

#### AP7-01 [Korrektheit] `server/privacy-pass/issuance.js:L77-82`
**`/privacy-pass/issue` verlangt `session.role === role`, aber kein Server-Pfad setzt `sessions.role` → Token-Ausgabe über die Wallet dauerhaft 403**

- **Auswirkung:** Schritte 4/5 der Wallet (Tokens holen/einlösen) sind für alle Nutzer funktionsunfähig; `/eligibility` und `/email/start` (L75 toleriert `null`) melden vorher „alles erfüllt“. Sicherheitsseitig fail-closed — daher kein S1.
- **Empfehlung:** Rollenbindung neu definieren (Rolle aus verifiziertem Access-Token/EUDI-EAA ableiten oder `session.role`-Vergleich durch reine `eligibilityFor`-Prüfung ersetzen). Vor dem Entfernen des Checks zwingend AP7-04/05/20 beheben, sonst wird die dort beschriebene Gate-Umgehung sofort scharf. Integrationstest `role → /issue → 200` ergänzen (AP7-13).

#### AP7-02 [Korrektheit/Sicherheit] `server/privacy-pass/issuance.js:L98-110,L145,L164-183`
**Quota-Prüfung ist Check-then-Act ohne Transaktion/Lock; parallele Requests umgehen 10 Tokens/24h**

- **Auswirkung:** Die Sybil-Schranke (Kopfkommentar L13-15) ist mit N parallelen Requests auf N×10 dehnbar; die Tokens sind unlinkbar und nicht widerrufbar.
- **Empfehlung:** Zählen und Loggen in einer Transaktion mit `pg_advisory_xact_lock(hashtext(credential_id))` (oder `SELECT … FOR UPDATE` auf einer Quota-Zeile) kapseln; Log vor der Evaluation schreiben und bei Fehler zurückrollen.

#### AP7-03 [Korrektheit] `server/privacy-pass/public/wallet.html:L1025-1067`
**Recovery-Flow verbrennt den Einmal-Code, registriert aber keinen Schlüssel am wiederhergestellten Account**

- **Auswirkung:** Pro Versuch ein Code weniger, Meldung „Registrierung fehlgeschlagen“, kein neuer Schlüssel; nach 10 Versuchen ist Recovery endgültig unmöglich. Siehe auch AP7-30 (Endpunkt-Seite).
- **Empfehlung:** `/recovery/use` muss eine kurzlebige Session mit dem wiederhergestellten `userId` und Registrierungserlaubnis anlegen und deren `sessionId` zurückgeben; alternativ Code erst nach erfolgreichem `register/finish` verbrauchen.

#### AP7-24 [Sicherheit] `server/privacy-pass/verifications-api.js:L59-67,L136-167; server/email.js:L845`
**Bestätigungslink schließt die Verifikation für den *Anfragenden* ab, ohne Bindung an die klickende Person**

- **Auswirkung:** Klickt der Inhaber von `x@bund.de`/`x@bundestag.de` den legitimen Link, ist das Angreifer-Credential für `civil_servant`/`politician` freigeschaltet (nur `email-verified` erforderlich).
- **Empfehlung:** Abschluss an die anfragende Session binden (Code-Eingabe in der Wallet wie `/hhttps/email/confirm-code`) und Mailtext anpassen.

#### AP7-25 [Sicherheit] `server/privacy-pass/verifications-api.js:L164,L172,L199; verifications.js:L21-24`
**HTML-Injection in `renderEmailResult` (E-Mail-Domain und `err.message` unescaped)**

- **Auswirkung:** Stored XSS auf der Wallet-Origin (IndexedDB-Tokens, `hhttps_uid`, Identity-Cookie-Requests).
- **Empfehlung:** `esc()` für alle interpolierten Werte, `err.message` nie ins HTML, Adresse strikt als Einzeladresse validieren.

#### AP7-26 [Sicherheit/Performance] `server/privacy-pass/verifications-api.js:L59-132`
**`/email/start` ohne eigenes Rate-Limit: Mailversand an beliebige Dritte, DB-Insert pro Aufruf**

- **Auswirkung:** Bis zu ~18.000 Mails/h pro IP mit hhttps.org-Absender; SMTP-/Event-Loop-Last; Reputationsschaden.
- **Empfehlung:** `limit.email`-äquivalenten Limiter vor die Route; zusätzlich pro Session/Credential und Empfänger-Hash begrenzen; alte Pending-Zeilen desselben Credentials löschen.

#### AP8-01 [Korrektheit] `sites/hhttps.html:L1839-1896`
**Nach erfolgreichem `/hhttps/role/declare` wirft die aktive `doDeclarRole`-Implementierung immer einen TypeError (`d.role` ist seit v0.5 `null`)**

- **Auswirkung:** Interaktiver Demo-Flow der Landing-Page endet immer mit „Fehler: Cannot read properties of null“, obwohl Access+Refresh-Token ausgestellt wurden; jeder Retry stellt weitere Tokens aus. (Einschränkung: die Seite wird laut AP8-40 nicht deployt — der Fehler ist aber im Repo-Stand reproduzierbar und die Seite wird aktiv getestet/gepflegt.)
- **Empfehlung:** `d.role?.…` bzw. auf `d.verification.emailVerified` / `d.hhttps.verifiedMethods` umstellen; tote Original-Implementierung (AP8-41) entfernen.

#### AP8-02 [Korrektheit] `extension/popup.js:L176-184`
**`buildSnippet()` erzeugt für Maschinen-Identitäten und für v0.5-Menschen „… human · Trust 60/100 …“**

- **Auswirkung:** Die Extension produziert einen menschenlesbaren Identitätsclaim „human · Trust 60/100“ für ein Bot-Token (Server: `human:false, trustScore:0`) — Verstoß gegen die Kernregel „nie als Mensch ausgewiesen“. Für v0.5-Menschen-Tokens (`role:null`) wird ebenfalls ein Default statt der echten Werte ausgegeben. Zusammen mit AP8-16 (Snippet enthält das Bearer-Token) besonders unschön.
- **Empfehlung:** `??` statt `\|\|`, `actorType==='bot'` explizit rendern, keinen 60er-Default; besser das Snippet-Feature ganz entfernen (AP8-16).

#### AP8-16 [Sicherheit] `extension/popup.js:L176-184, L275-292`
**„Signatur-Snippet“ kopiert das vollständige Bearer-Token zum öffentlichen Einfügen in die Zwischenablage**

- **Auswirkung:** Jeder Leser des Beitrags besitzt bis zum Ablauf (1 h) ein gültiges Bearer-Token und kann Signatur-Slugs im Namen des Nutzers erzeugen. Das Slug-Verfahren (`#hhttps:s:`) existiert genau, um das zu vermeiden.
- **Empfehlung:** Snippet-Funktion entfernen oder nur serverseitig erzeugte, domain-gebundene Slugs einfügen.

#### AP8-23 [Performance] `extension/content-universal.js:L165-267`
**Pro same-origin-iframe 30 s lang alle 1,5 s Body-Serialisierung + Voll-Scan, ohne Backoff, zusätzlich zu drei weiteren Hooks**

- **Auswirkung:** 30 s CPU-Last pro Frame auf jeder Seite mit erreichbaren iframes (Werbe-iframes sind meist `about:blank` = same-origin).
- **Empfehlung:** Poller nur bei leerem Body und mit Backoff; abbrechen, sobald der Body-Observer aktiv ist; `innerHTML.length` durch `childNodes.length` ersetzen.

#### AP8-24 [Performance] `extension/manifest.json:L40-50 + content-universal.js:L80-121, L165-267`
**Same-origin-iframes werden doppelt verarbeitet (eigene Instanz im Frame + Eltern-Instanz); Verifikations-Requests dupliziert**

- **Auswirkung:** Doppelte DOM-Arbeit und doppelte Server-Requests je Frame; multipliziert mit Verschachtelungstiefe.
- **Empfehlung:** Entweder Eltern-Scanning auf Frames ohne eigene Instanz beschränken oder `all_frames` abschalten; Slug-Cache in den Background verlagern.

## 4. Befunde je Modul (S3 und S4)

Vollständige Begründungen, Belege und Repro-Hinweise stehen in `docs/review/ap/APx-verifikation.md`.

### AP1 — Kern, Middleware, Signaturen, Rollenmodell, Schlüssel

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP1-01 | S4 | K | `server/server.js:L468-478` | `readIdentityCookie` wirft bei fehlerhaft kodiertem Cookie-Wert `URIError` → 500 auf jeder Route |
| AP1-02 | S3 | K | `server/server.js:L799-806` | Async-Handler ohne try/catch: DB-Fehler führt zu hängendem Request statt 5xx (auch L866, L1164-1170, L1266-1276) |
| AP1-03 | S3 | K | `server/server.js:L1039-1045` | `expired`-Zweig in `/hhttps/verify-text` unerreichbar; abgelaufene Textsignaturen liefern 401 `invalid` |
| AP1-04 | S3 | K | `server/webhooks.js:L14-25` | Event-Katalog passt nicht zu den gefeuerten Events |
| AP1-05 | S3 | K | `server/server.js:L379-389` | CORS `exposedHeaders` enthält die v0.5-Methoden-Header nicht |
| AP1-06 | S3 | K | `server/roles.taxonomy.js:L92-127` | Reserved-Erkennung per Substring/Präfix liefert Falsch-Positive und falsche Registry-Keys |
| AP1-07 | S4 | K | `server/server.js:L1089-1141` | Domain ohne Längenprüfung in `bound_domain VARCHAR(120)`; Überlauf endet als 401 mit PG-Fehlertext |
| AP1-08 | S3 | K | `server/server.js:L774-796` | ESCO-Proxy `fetch` ohne Timeout (und ohne eigenes Rate-Limit/Cache) |
| AP1-09 | S3 | K | `server/server.js:L865-1351` | Kern-Endpunkte ohne einen einzigen Test |
| AP1-10 | S4 | K | `server/package.json:L11` | `roles.taxonomy.test.mjs` außerhalb des `npm test`-Globs |
| AP1-11 | S4 | K | `server/server.js:L1331-1341` | `reason` beim Signatur-Revoke ungeprüft in `revoke_reason VARCHAR(120)` |
| AP1-12 | S4 | K | `server/keys.js:L142-150` | `forgetRetiredKey` nicht restart-fest; Rotations-API ohne Aufrufer |
| AP1-13 | S4 | K | `server/server.js:L412-417` | Rate-Limit-Handler meldet `retryAfter` als volles Fenster |
| AP1-14 | S4 | K | `server/server.js:L868` | `Authorization` nur bei exakt `Bearer ` (Groß-/Kleinschreibung) akzeptiert (auch L951, L1078, L1329) |
| AP1-15 | S4 | K | `server/server.js:L333-357` | HTML-Viewer von `sendJson` verwirft den Query-String |
| AP1-16 | S4 | K | `server/server.js:L751` | Discovery meldet `supported_verification` aus dem Legacy-Katalog `VERIFICATION_LEVELS` |
| AP1-17 | S3 | K | `server/server.js:L485-514` | Identity-Cookie-Middleware prüft weder Revocation noch Token-Typ (Negativliste) |
| AP1-18 | S4 | K | `server/server.js:L607-624` | `normalizeApexDomain` behandelt IPv4-Adressen als Domains |
| AP1-19 | S4 | K | `server/webhooks.js:L20-25` | `events` ohne Typprüfung; Deaktivierungsschwelle weicht vom Kommentar ab |
| AP1-20 | S4 | K | `server/roles.i18n.js:L307` | DE-Übersetzung markiert EUDI-Altersnachweis als „Geplant“; `av-app` fehlt |
| AP1-23 | S3 | S | `server/server.js:L702-711 + L880-935` | Refresh-Tokens werden von `/hhttps/check`, `/hhttps/sign-text`, `/hhttps/signatures`, `…/revoke` als Identitäts-Bearer akzeptiert |
| AP1-25 | S3 | S | `server/server.js:L392-403` | CSP erlaubt `'unsafe-inline'` für Skripte und `unpkg.com` als Script-Quelle |
| AP1-26 | S3 | S | `server/server.js:L1180-1185` | First-Seen-Lock einer Signatur von jedem anonymen Aufrufer mit beliebiger Domain setzbar |
| AP1-27 | S4 | S | `server/server.js:L116-155,L325-357` | `sendJson`-Viewer interpoliert `title`, `subtitle`, `req.path` ohne Escaping |
| AP1-28 | S4 | S | `server/server.js:L1266,L1326` | `/hhttps/signatures/batch` und `…/:slug/revoke` ohne endpoint-spezifisches Rate-Limit |
| AP1-29 | S4 | S | `server/server.js:L938,L1002,L1062,L1158,L1352` | Rohe `e.message` aus `checkTokenValid`/DB-Fehlern an den Client |
| AP1-32 | S3 | P | `server/server.js:L435-436` | `/hhttps/info` vom globalen Rate-Limit ausgenommen und führt pro Aufruf sechs `COUNT(*)` ohne Cache aus |
| AP1-33 | S3 | P | `server/server.js:L866` | Jeder `/hhttps/check`-Aufruf schreibt synchron in die Hot-Row `stats.check_calls`, vor jeder Token-Prüfung |
| AP1-34 | S3 | P | `server/server.js:L704 / L714-724` | `revoked_tokens` wird auf jedem Check gelesen, aber nie bereinigt |
| AP1-35 | S3 | P | `server/webhooks.js:L80 / L86` | Jeder Zustellversuch schreibt eine `webhook_deliveries`-Zeile; keine Retention |
| AP1-37 | S4 | P | `server/server.js:L1171-1184` | `/hhttps/s/:slug` macht vier sequentielle DB-Roundtrips, davon zwei Schreibzugriffe pro Lesezugriff |
| AP1-38 | S4 | P | `server/server.js:L702-711` | `checkTokenValid` mit zwei sequentiellen Einzel-Lookups |
| AP1-39 | S4 | P | `server/server.js:L488-513` | Identity-Cookie-Middleware verifiziert ES256 synchron auf jedem Request, auch für statische Assets |
| AP1-40 | S4 | P | `server/server.js:L1109-1113` | Slug-Kollisionsprüfung mit zwei seriellen Queries pro Versuch; `isReservedSlug` kann nie treffen |
| AP1-41 | S4 | P | `server/keys.js:L179-192` | `getJWKS()` exportiert die Key-Objekte bei jedem Aufruf neu |
| AP1-42 | S3 | W | `server/server.js:L109-366` | `sendJson` ist ein 258-Zeilen-Handler mit ~230 Zeilen eingebettetem HTML/CSS/JS |
| AP1-43 | S3 | W | `server/server.js:L867-869, L950-952, L1077-1079, L1328-1330` | Token-Extraktion viermal identisch kopiert; Signer-ID-Kette `d.uid \|\| d.userId \|\| d.sub` doppelt |
| AP1-44 | S3 | W | `server/server.js:L1166, L1275, L1334, L1359` | Slug-Regex viermal dupliziert und inkonsistent zum Generator |
| AP1-45 | S3 | W | `server/server.js:L1219-1257 vs. L1291-1312` | Signatur-Statusauswertung in Einzel- und Batch-Endpunkt doppelt implementiert |
| AP1-46 | S3 | W | `server/server.js:L770-793` | ESCO-Suche dupliziert `resolveEsco`/`ESCO_API`; `resolveEsco` importiert, aber nie verwendet |
| AP1-47 | S4 | W | `server/server.js:L4-22` | Datei-Header beschreibt v4.1 mit „14 roles“ und widerspricht dem aktuellen Modell |
| AP1-48 | S3 | W | `server/server.js:L955, L1082 vs. L1333; L938, L1002, L1062` | Inkonsistente Statuscodes und Fehlerformate zwischen Signatur-Endpunkten |
| AP1-49 | S4 | W | `server/server.js:L324, L486, L551, L732, L808, L874, …` | Protokollversion `'0.5.0'` 27-mal als Literal |
| AP1-50 | S3 | W | `server/roles.js:L208-288` | `VERIFICATION_CHECKS`/`resolveVerification` toter Code; `VERIFICATION_LEVELS` nur noch als Label-Map genutzt |
| AP1-51 | S3 | W | `server/roles.js:L143 vs. server/server.js:L571` | Header `HHTTPS-Age-Verified` hat zwei Eigentümer |
| AP1-52 | S4 | W | `server/roles.i18n.js:L47-239` | 14 Rollen-Übersetzungen für nicht mehr existierende Rollen-IDs |
| AP1-53 | S3 | W | `server/roles.taxonomy.i18n.js:L1-71` | Modul wird nirgends importiert; `kind`-Katalog übersetzt Werte, die `resolveRole` nie erzeugt |
| AP1-54 | S3 | W | `server/roles.eaa.js:L17, L51-59` | Modul ohne Laufzeit-Aufrufer; `setRoleHeaders` verlangt ein nicht exportiertes `hdrSafe` |
| AP1-60 | S4 | W | `server/server.js:L828-855, L728-752` | Handgepflegter Endpunkt-Katalog in `/hhttps/info` und Discovery unvollständig |
| AP1-61 | S4 | W | `server/server.js:L535, L1080` | Funktionsname `setHHTPPS` (Tippfehler), ungenutzter Parameter `token`, still ignoriertes Feld `mode` |
| AP1-62 | S4 | W | `server/server.js:L482-509 vs. L879-886` | Mapping „dekodiertes Token → `setHHTPPS`-Optionen“ doppelt; Cookie-Pfad ohne Methoden-Header |
| AP1-63 | S4 | W | `server/server.js:L959, L1086, L1111, L1119, L1272, L753` | Magic Numbers ohne benannte Konstante |
| AP1-64 | S4 | W | `server/webhooks.js:L18, L21, L64, L73, L76, L89, L95` | Sprachmix in Fehlermeldungen und verstreute Konstanten im Delivery-Pfad |
| AP1-65 | S4 | W | `server/server.js:L39-57, L535, L612, L792, L1080, L1166, L1…` | Gesammelte ESLint-Warnungen im AP1-Bereich |

### AP2 — OAuth 2.1 / OIDC + Consent

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP2-02 | S3 | K | `server/server.js:L1380, L1950-1959, L1579` | Beworbener `revocation_endpoint` ist kein RFC-7009-Endpunkt; für Maschinen-Akteure ist der Disconnect zusätzlich ein No-op |
| AP2-03 | S3 | K | `server/server.js:L1672-1686` | Refresh-Token-Rotation ist ein nicht-atomares Check-then-Act; parallele Refreshs mit demselben Token liefern mehrere gültige neue Refresh-T… |
| AP2-04 | S3 | K | `server/server.js:L1479, L1561, L1661, L1752, L1775` | `/oauth/authorize`, `/oauth/approve` und `/oauth/token` werfen bei Nicht-String-Parametern (`scope[]`, `client_secret`, `code_verifier` als… |
| AP2-06 | S4 | K | `server/server.js:L1552-1575` | `/oauth/approve` erzwingt für Public Clients keinen `code_challenge` (anders als `/oauth/authorize` L1472-1475); Code wird mit `pkce_challe… |
| AP2-07 | S3 | K | `server/server.js:L2179, L2198 (weitere Literale L1987, L211…` | Consent-Skript verweist hart auf `https://hhttps.org` (Relogin, Token-Refresh) statt auf `BASE_URL`/eigene Origin |
| AP2-08 | S3 | K | `server/test/integration/oauth-claims.test.mjs:L78-96, L179-…` | Fehlerpfade von `/oauth/token`, `/oauth/revoke` und die Refresh-Grant-Bindung sind ungetestet |
| AP2-09 | S4 | K | `server/server.js:L1840` | `auth_time` im ID-Token ist der Zeitpunkt des Code-Einlösens, nicht der Authentifizierung |
| AP2-10 | S3 | K | `server/server.js:L1912-1946` | `/oauth/userinfo` akzeptiert jedes serversignierte JWT mit `client_id`-Claim, also auch den 30 Tage gültigen OAuth-Refresh-JWT — selbst nac… |
| AP2-11 | S4 | K | `server/server.js:L1376-1381` | `issuer` aus `RP_ID`, alle Endpunkte aus `BASE_URL`; bei abweichendem `BASE_URL` stimmt die Discovery nicht mit dem Issuer überein |
| AP2-14 | S4 | S | `server/server.js:L1387, L1608, L1774-1778; server/oauth-par…` | PKCE-Methode `plain` wird beworben, akzeptiert und ist Default bei fehlender Methode |
| AP2-15 | S3 | S | `server/server.js:L1412` | Pairwise-HMAC-Schlüssel hat einen öffentlichen, deterministischen Fallback ohne Prod-Guard; `PAIRWISE_SECRET` wird nirgends dokumentiert od… |
| AP2-20 | S4 | S | `server/server.js:L1661-1663, L1752-1755` | Client-Secret-Vergleich nicht zeitkonstant; Secret ungesalzen gehasht; Prüfung doppelt implementiert |
| AP2-21 | S4 | S | `server/server.js:L1672-1686` | Refresh-Rotation ohne Reuse-/Familien-Erkennung |
| AP2-22 | S4 | S | `server/server.js:L2020-2022; L392-398 (CSP)` | Consent-Seite lädt drei Google-Fonts-Familien (render-blockendes Fremd-CSS) auf dem Login-kritischen Pfad |
| AP2-24 | S3 | P | `server/server.js:L1788, L1860-1861, L1866, L1883` | Token-Endpunkt führt nach der Validierung fünf serielle Schreibzugriffe aus, davon zwei auf globale Hot-Rows der `stats`-Tabelle |
| AP2-25 | S4 | P | `server/server.js:L1625-1626; server/db.js:L854-856` | `/approve` schreibt pro Login die `oauth_clients`-Zeile neu (`touchLastUsed`) und eine globale Stats-Hot-Row, seriell vor der Antwort |
| AP2-26 | S4 | P | `server/server.js:L1454, L1556, L1745; server/db.js:L822-831` | `oauthClients.get` (`SELECT *` + 2× `JSON.parse`) läuft dreimal pro Login-Flow ohne Cache |
| AP2-28 | S3 | W | `server/server.js:L1641-1909` | Token-Endpoint ist ein 268-Zeilen-Handler mit zwei komplett inline ausformulierten Grants |
| AP2-29 | S3 | W | `server/server.js:L1697-1727, L1808-1830, L1884-1896` | Access- und Refresh-JWT werden im Code- und im Refresh-Zweig jeweils komplett doppelt zusammengesetzt; `age_group`-Block sechsfach, Bot-Blo… |
| AP2-30 | S3 | W | `server/server.js:L1478-1492 / L1561-1575 und L1659-1665 / L…` | Scope-Validierung in `/authorize` und `/approve` sowie Client-Secret-Prüfung in beiden Grants dupliziert |
| AP2-31 | S3 | W | `server/server.js:L1990-2367; server/test/unit/consent-page.…` | `renderConsentPage` ist ein 378-Zeilen-Template-Literal mit ~150 Zeilen eingebettetem Browser-JS und ~100 Zeilen CSS |
| AP2-33 | S3 | W | `server/server.js:L1534-1563, L1915-1920, L1952-1959, L2267-…` | Fehlerformate/Statuscodes der OAuth-Routen sind untereinander inkonsistent (RFC-Codes vs. Freitext) |
| AP2-34 | S3 | W | `server/server.js:L1718, L1817, L1936 vs. L1391, L1700, L184…` | Claim-Name `trustScore` (camelCase) im Access-Token, `trust_score` (snake_case) in ID-Token, Refresh-JWT, Discovery und `/userinfo` |
| AP2-37 | S4 | W | `server/server.js:L1494-1499, L1527-1529` | Veraltete Kommentare beschreiben den Consent-Flow mit Passkey/Cookie/Extension statt localStorage-Identität |
| AP2-39 | S4 | W | `server/server.js:L2370-2374; server/email.js:L810-818` | `escapeHtml` in zwei Modulen doppelt implementiert — und bereits auseinandergelaufen |
| AP2-40 | S4 | W | `server/server.js:L1978-1988` | `renderOAuthError` ist eine zweite, abweichende Fehlerseite ohne Escaping und mit altem Farbschema |
| AP2-41 | S4 | W | `server/server.js:L1944, L1969, L2314, L2332` | ESLint-Warnungen und toter i18n-Schlüssel im AP (Sammelfinding) |

### AP3 — Identität, Session, E-Mail-Anker, WebAuthn, GitHub

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP3-03 | S3 | K | `server/server.js:L2534-2538` | `auth/finish` liest `response.id` vor dem `try`; fehlendes `response` → unbehandelte Rejection, Request hängt |
| AP3-04 | S3 | K | `server/server.js:L2896-2925` | `/hhttps/email/verify` ohne try/catch; Array-/Objekt-Query-Parameter wirft in `verifyEmailToken` |
| AP3-05 | S3 | K | `server/server.js:L2695,L2736,L2761` | Session-TTL (15 min ab Session-Start) und Code-/Kontext-TTL (15 min ab Versand) sind nicht aufeinander abgestimmt |
| AP3-06 | S4 | K | `server/server.js:L2687-2695,L2728-2736` | `trustScore: 0` wird von `db.sessions.create` zu 60 hochgesetzt |
| AP3-07 | S4 | K | `server/server.js:L468-478` | `readIdentityCookie` ruft `decodeURIComponent` ungeschützt auf; fehlerhaft kodierter Cookie → 500 auf jeder Route |
| AP3-08 | S3 | K | `server/server.js:L485-516` | Identity-Cookie-Middleware prüft nur die Signatur, nicht die Revocation |
| AP3-09 | S3 | K | `server/server.js:L3028-3050` | GitHub-Callback ignoriert `alreadyOwnedBy`: Anchor wird auf zweiten User umgehängt, Session trotzdem verifiziert |
| AP3-10 | S3 | K | `server/test/integration/gate.test.mjs:L154-166, server/test…` | Kein Test deckt die Kette Passkey-Session → `role/declare` ab |
| AP3-11 | S4 | K | `server/identity.js:L118-129, server/server.js:L2809,L2829` | `eudiVerified`/`hasPasskey` werden nie persistiert |
| AP3-12 | S4 | K | `server/server.js:L2658-2674, server/email.js:L86-97` | Kommentare zu `/session/email/start` und zum Trust-Modell widersprechen dem Code |
| AP3-16 | S3 | S | `server/email.js:L498-502, L553-557, L602-606, L725-730, L87…` | Fünf Versandfunktionen fallen ohne Transport still in „Dev-Mode“ und loggen Bestätigungs-Links/Tokens |
| AP3-18 | S3 | S | `server/server.js:L2606-2656` | Refresh-Token: 7-Tage-Bearer ohne Rotation, ohne Reuse-Erkennung, ohne Bindung |
| AP3-19 | S3 | S | `server/server.js:L2940-2951` | 6-stelliger Code ohne Fehlversuchszähler pro Session |
| AP3-20 | S4 | S | `server/server.js:L2453, L2526, L2709, L2750, L2892, L3024` | Interne Fehlermeldungen (`e.message`) gehen 1:1 an den Client |
| AP3-23 | S4 | S | `server/email.js:L842-848, L879` | `roleDisplay(role)` in der Privacy-Pass-Mail nicht HTML-escaped; `roleLabel` fällt auf die rohe `roleId` zurück |
| AP3-24 | S3 | P | `server/email.js:L388-398, server/sql/schema.sql:L203` | Verbrauchte `email_verifications`-Zeilen werden nie gelöscht; Lookups auf `session_id`/`code` ohne Index |
| AP3-25 | S3 | P | `server/email.js:L145-162` | Pro Mail ein neuer SMTP-Transport ohne Timeouts; `/hhttps/email/send` blockiert bis zur SMTP-Antwort |
| AP3-26 | S4 | P | `server/server.js:L2573` | `db.sessions.delete` existiert nicht; die vorherige Session wird beim Passkey-Merge nie gelöscht |
| AP3-27 | S4 | P | `server/server.js:L656-666` | `issueAccessToken` und alle Session-/Verifikations-Pfade schreiben sequentiell auf eine einzige `stats`-Zeile |
| AP3-28 | S4 | P | `server/server.js:L2606-2656` | `/hhttps/token/refresh`: fünf sequentielle DB-Roundtrips ohne eigenes Rate-Limit; `credentials.get` nur für `deviceType` |
| AP3-29 | S4 | P | `server/server.js:L485-516` | Identity-Cookie-Middleware verifiziert das ES256-JWT bei jedem Request, auch für statische Assets |
| AP3-30 | S3 | W | `server/server.js:L2676-2752` | Zwei fast identische Session-Bootstrap-Routen; Frontend nutzt nur `/session/start` |
| AP3-33 | S3 | W | `server/server.js:L2896-2928 vs L2940-2987` | Bestätigungspfad (Token vs. Code) doppelt implementiert, zwei Fehlerformate, Reihenfolge driftet |
| AP3-34 | S3 | W | `server/server.js:L2611-2616` | `/token/refresh` reimplementiert den Refresh-Zweig von `checkTokenValid` |
| AP3-35 | S3 | W | `server/server.js:L2775 vs server/email.js:L391` | Hash-Vertrag „sha256(normalisierte E-Mail)“ zweimal unabhängig definiert |
| AP3-36 | S3 | W | `server/email.js:L53 vs server/server.js:L78` | `BASE_URL` zweimal mit unterschiedlichem Default aus der Umgebung gelesen |
| AP3-37 | S3 | W | `server/server.js:L2413-3093` | Uneinheitliche Fehlerformate, Sprachen und Body-Handling |
| AP3-39 | S4 | W | `server/server.js:L2692,L2733,L2850,L3010` | `session.verified` ist bei jeder Session `true`; die Gates darauf sind wirkungslos |
| AP3-40 | S4 | W | `server/email.js:L1-7 vs L62,L280,L743,L827` | Widersprüchliche „LEGACY“-Marker für den obligatorischen ersten Anmeldeschritt |
| AP3-41 | S3 | W | `server/email.js:L435-741, server/server.js:L3056-3087` | Module ohne Tests: Plattform-/Admin-Mails, `classifyDomain`, GitHub-Return-Seite, `/session/email/start` |
| AP3-42 | S4 | W | `server/server.js:L2451,L2522,L2524,L2590,L2592,L2624,L2695,…` | Magic Numbers für TTLs, Trust-Seeds und Limits |
| AP3-43 | S4 | W | `server/server.js:L2636` | `tokenSurface` wird mit einem Pseudo-Session-Objekt aufgerufen |
| AP3-44 | S4 | W | `server/server.js:L2697,L2738` | `stats.increment('verifications')` beim reinen Session-Bootstrap |
| AP3-45 | S4 | W | `server/server.js:L2779-2790` | JSDoc von `bindSessionToEmailAnchor` hängt an `anchorConflict` |
| AP3-46 | S4 | W | `server/email.js:L810-818 vs server/server.js:L2370-2374` | `escapeHtml` doppelt implementiert |
| AP3-47 | S4 | W | `server/server.js:L535,L612,L2573; server/email.js:L159,L249…` | ESLint-Warnungen im AP3-Bereich (Sammelfinding) |

### AP4 — Rollen-/Alters-/eID-Verifikation, Karten, Revoke, EUDI

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP4-04 | S3 | K | `server/server.js:L3683-3705` | `/hhttps/revoke`: Fehlerpfad mit Nebenwirkungen und irreführender Antwort (Token ohne `jti`, ungültige Signatur) |
| AP4-05 | S3 | K | `server/server.js:L3097-3230, L3709-3715` | `/hhttps/role/declare` ohne try/catch: Fehler lassen die Anfrage ohne Antwort hängen |
| AP4-06 | S3 | K | `server/server.js:L3598-3607` | `/hhttps/role/card` umgeht die E-Mail-Pflicht (AK-13); Kommentar verweist falsch auf `role/declare` |
| AP4-07 | S3 | K | `server/server.js:L3600, L3635-3637` | `documentProvided` nur auf Truthiness geprüft; `human`-Claim der Karte widerspricht dem Zugangs-Gate |
| AP4-08 | S3 | K | `server/eudi-verifier/index.js:L232-267, L327-364, L408-431` | Status-Polling ohne In-Flight-Sperre: parallele Polls lösen den Upgrade mehrfach aus |
| AP4-09 | S3 | K | `server/eudi-verifier/backend-client.js:L352-360, L388-395` | Nur Erfolgs-Status sind terminal; Fehl-/Ablaufzustände und 404 bleiben bis zum 10-min-TTL „pending“ |
| AP4-10 | S3 | K | `server/eudi-verifier/backend-client.js:L61-92` | Token-Cache ohne Invalidierung bei 401 |
| AP4-11 | S3 | K | `server/external-verify.js:L102-116, L211-232` | GitHub-Anker wird bei Kollision unbedingt auf den neuen Nutzer umgebunden; `getUserGithubAnchor` ist tot |
| AP4-12 | S3 | K | `server/test/**` | Keine Tests für `/hhttps/revoke`, `/revoke/status`, `/validate`, `/protected`, `/role/card`, den 200-Pfad von `/age/upgrade`, den `/eudi/*`… |
| AP4-13 | S4 | K | `server/server.js:L3328-3330` | `/hhttps/age/upgrade` stellt bei ausschließlich `false`-Claims `age_verified:true` für `minor_under_14` aus |
| AP4-14 | S4 | K | `server/eudi-verifier/index.js:L238-258` | Zustand `failed` wird beim nächsten Poll nicht kurzgeschlossen; toter `response_code`-Parameter |
| AP4-15 | S4 | K | `server/eudi-verifier/backend-client.js:L118-142, L291-306` | PID-Age- und eID-Config werden bei Konflikt nicht per PATCH aktualisiert (im Gegensatz zur AV-Config) |
| AP4-16 | S4 | K | `server/eudi-verifier/docker/docker-compose.yaml:L1-17, L23` | Compose beschreibt das abgelöste EU-Verifier-Endpoint (:8080), Code spricht EUDIPLO (:3002) |
| AP4-17 | S4 | K | `server/public/iamhmn-card-issuer.js:L130, L133-143` | Suggest-Race und pro `_render()` registrierter globaler Click-Listener |
| AP4-24 | S3 | S | `server/eudi-verifier/backend-client.js:L352-360` | „Präsentation gültig“ heuristisch aus Status-Strings (`submitted`, …) oder bloßem Vorkommen eines `age_over_*`-Schlüssels abgeleitet |
| AP4-25 | S3 | S | `server/server.js:L3697-3703` | Fallback in `/hhttps/revoke` vertraut dem unsignierten JWT-Payload |
| AP4-27 | S3 | S | `server/server.js:L3254, L3409, L3477` | „INTERNAL / 127.0.0.1 only“-Endpunkte ohne Loopback-Prüfung; nginx proxied `location /` vollständig |
| AP4-28 | S3 | S | `server/eudi-verifier/index.js:L251-252, L344-345; server/eu…` | `EUDI_DEBUG=1` schreibt die Wallet-Antwort (bis 1500 Zeichen) ins Server-Log |
| AP4-29 | S3 | S | `server/server.js:L3641-3643` | Ausgestellte iamhmn-Karte enthält die stabile `userId` als Klartext-Claim |
| AP4-31 | S3 | S | `server/server.js:L3124-3127, L3224` | `ageGroup` per Property-Lookup gegen Plain-Object validiert; Prototype-Schlüssel passieren, Tokens werden ausgestellt, Handler stürzt ohne … |
| AP4-32 | S3 | S | `server/eudi-verifier/index.js:L192-211, L232-267` | Cross-Device-Flow ohne Bindung zwischen Session-Inhaber und Wallet-Inhaber |
| AP4-33 | S4 | S | `server/server.js:L3386, L3461, L3581; server/eudi-verifier/…` | Rohe Fehlermeldungen an den Client |
| AP4-34 | S4 | S | `server/eudi-verifier/index.js:L178-188` | `/eudi/age/health` gibt Backend-URL und Konfiguration unauthentifiziert preis |
| AP4-35 | S4 | S | `server/eudi-verifier/backend-client.js:L193-196, L205` | Fail-open-Schalter `EUDI_AV_TRUST_LIST=off` ohne Kopplung an `NODE_ENV` |
| AP4-36 | S4 | S | `server/eudi-verifier/docker/docker-compose.yaml:L13` | Verifier-Image ungepinnt (`:latest`) mit `restart: unless-stopped` |
| AP4-37 | S3 | P | `server/eudi-verifier/index.js:L192-211, L287-311, L376-393` | Unauthentifizierte `/eudi/*/request`-Routen erzeugen pro Aufruf eine EUDIPLO-Session und einen `txStore`-Eintrag ohne Session-Prüfung und R… |
| AP4-38 | S3 | P | `server/eudi-verifier/backend-client.js:L374-381, L388` | Pfad-Autodiscovery wird bei jedem Poll wiederholt, solange kein Kandidat 2xx liefert; 404 im Pending-Zustand verhindert die Auflösung |
| AP4-39 | S3 | P | `server/eudi-verifier/index.js:L93, L129, L154, L243; server…` | `fetch` ohne Timeout auf gepollten und Login-kritischen Pfaden |
| AP4-40 | S3 | P | `server/server.js:L3684-3687, L3700` | `revoked_tokens` wächst unbegrenzt (kein Cleanup, auch abgelaufene Tokens) und wird auf jedem `/hhttps/validate`/`/protected`-Aufruf abgefr… |
| AP4-41 | S4 | P | `server/server.js:L3723, L3753, L3712-3713` | Zwei sequentielle, unabhängige DB-Roundtrips pro Validate-/Status-Aufruf |
| AP4-42 | S4 | P | `server/server.js:L3168-3186, L3341-3371, L3547-3571, L3684-…` | Token-Ausgabe mit vier bis fünf sequentiellen, teils unabhängigen DB-Schreibvorgängen |
| AP4-43 | S4 | P | `server/eudi-verifier/backend-client.js:L63-83, L118-142` | Client-Credentials-Token-Cache und `ensureVerifierConfig` ohne In-Flight-Deduplizierung |
| AP4-45 | S4 | P | `server/eudi-verifier/index.js:L43-61` | `txStore` ist prozesslokal; Betrieb nur mit einer Node-Instanz korrekt; Tokens verbleiben bis 10 min im Speicher |
| AP4-47 | S3 | W | `server/server.js:L3262-3295, L3417-3450, L3484-3506; server…` | HMAC-Assertion-Prüfung dreifach kopiert, Signierseite ebenfalls dreifach |
| AP4-48 | S3 | W | `server/server.js:L3142-3151, L3329-3338, L3535-3544 (+L2822…` | Flag-Bag aus der Session vierfach kopiert; `hasMethod`-Kette in `/role/card` als fünfte Variante |
| AP4-49 | S3 | W | `server/server.js:L3100/L3602 vs. L3300/L3510, L3386/L3461/L…` | Fehlerformate und Statuscodes zwischen den AP4-Routen uneinheitlich |
| AP4-50 | S3 | W | `server/eudi-verifier/index.js:L232-273 vs. L327-370 vs. L40…` | Status-Handler bis auf den Direct-Fallback identisch; drei `call*`-Funktionen mit gleichem Rumpf |
| AP4-51 | S3 | W | `server/eudi-verifier/backend-client.js:L149-167, L255-272, …` | Drei identische Offer-Aufrufe; drei `ensure*Config`-Varianten mit inkonsistentem Konfliktverhalten |
| AP4-52 | S3 | W | `server/eudi-verifier/backend-client.js:L29-57, L183-196, L3…` | 16 EUDI-/EUDIPLO-Umgebungsvariablen, nur eine dokumentiert |
| AP4-54 | S3 | W | `server/eudi-verifier/index.js:L3-14, L34-37; server/server.…` | Veraltete und widersprüchliche Kommentare; offene CONFIRM-Punkte im Code |
| AP4-56 | S4 | W | `server/server.js:L3208, L3230, L3375, L3575, L3659, L3729, …` | Magic Strings/Numbers und Rollen-Ära-Relikte |
| AP4-57 | S4 | W | `server/public/iamhmn-card-issuer.js:L21-23` | `RESERVED_STEMS` und `fold()` duplizieren server/roles.taxonomy.js L92-104 |
| AP4-58 | S4 | W | `server/external-verify.js:L127, L157, L162, L183, L199, L204` | Gemischt deutsch/englische Fehlermeldungen als API-Antwort |
| AP4-59 | S4 | W | `ESLint-Warnungen (gesammelt)` | server/server.js:L3098, L3320, L3531; server/eudi-verifier/index.js:L213; server/eudi-verifier/backend-client.js:L370 |

### AP5 — Maschinen, PoP, Webhooks, Developer-Portal, Admin

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP5-03 | S3 | K | `server/workload-identity.js:L1-260 + server/server.js:L3768…` | Workload-Identity-Modul ist nicht eingebunden; referenzierte Routen existieren nicht |
| AP5-04 | S3 | K | `server/pop-verify.js:L110-115` | Check-then-Act auf der PoP-Nonce, kein atomares Löschen |
| AP5-05 | S3 | K | `server/pop-verify.js:L83, L136 + server/server.js:L4807` | PoP-Pfad nutzt `verifyToken` statt `checkTokenValid`: widerrufene Tokens bestehen den PoP-Nachweis |
| AP5-06 | S3 | K | `server/server.js:L4362-4369 + server/db.js:L1085-1092 vs. d…` | Dashboard bietet „Delete“ für `unverified`, Server antwortet 409 |
| AP5-07 | S3 | K | `server/server.js:L4353-4356 + server/db.js:L946-957` | PATCH kann `description`/`logo_url` nicht leeren; UI meldet „Saved ✓“ |
| AP5-08 | S3 | K | `server/server.js:L4587-4620 (+ Kommentar L3926-3939)` | `reject`/`suspend` ohne Zustandsprüfung; Zustandsmaschine nur im Kommentar und im UI |
| AP5-09 | S3 | K | `server/server.js:L3889-3891, L3906-3910, L4080-4116, L4239-…` | async Handler ohne try/catch: DB-Fehler lassen den Request hängen |
| AP5-10 | S3 | K | `server/server.js:L3768-3833, L3888-3913, L4121-4653 + serve…` | Keine Tests für Portal, Admin, whoami, Webhooks, PoP und Plugin-Registrierung |
| AP5-11 | S3 | K | `server/server.js:L3816-3820` | Ungültiges `publicKeyJwk` wird stillschweigend verworfen |
| AP5-12 | S4 | K | `server/server.js:L3906-3912` | `/hhttps/webhooks/verify` wirft bei Nicht-String-Eingaben (500 statt 400) |
| AP5-13 | S4 | K | `server/server.js:L3893-3904 + server/webhooks.js:L20` | `events` ohne Array-Prüfung → 400 mit interner Fehlermeldung |
| AP5-14 | S4 | K | `server/wp-plugin-registration.js:L116-120 + server/server.j…` | Fehlermeldung „must be a valid HTTPS URL“ deckt sich nicht mit der Prüfung |
| AP5-15 | S4 | K | `server/server.js:L4544` | `days`-Parameter ohne Untergrenze/NaN-Schutz |
| AP5-18 | S3 | S | `server/server.js:L3893-3904 + server/webhooks.js:L17-18, L6…` | Webhook-Ziel-URL ohne Schema-/Host-Restriktion (blindes SSRF) |
| AP5-20 | S3 | S | `server/server.js:L4302-4358` | PATCH in jedem Status erlaubt, auch `pending_review`/`verified` (TOCTOU gegenüber Admin-Review) |
| AP5-21 | S3 | S | `server/server.js:L3970-3982, L4080-4116` | `authenticatedUser` akzeptiert Maschinen-Token; alle Operatoren erhalten `userId: 'machine'` |
| AP5-22 | S4 | S | `server/workload-identity.js:L173, L197` | OIDC-Audience-Prüfung entfällt bei Binding ohne `expected_audience` |
| AP5-23 | S3 | S | `server/server.js:L4125-4126, L4311, L4353-4356` | `logo_url`/`impressum_url` serverseitig nicht validiert |
| AP5-24 | S4 | S | `server/server.js:L4184, L4415, L4513, L4526` | Interne Fehlermeldungen 1:1 an den Client |
| AP5-25 | S4 | S | `server/server.js:L4114-4116` | `/hhttps/whoami` gibt absoluten Server-Dateipfad aus |
| AP5-26 | S4 | S | `server/server.js:L3847` | API-Key-Hash-Vergleich nicht timing-sicher |
| AP5-29 | S3 | P | `server/wp-plugin-registration.js:L102-160 + server/sql/sche…` | Unauthentifizierte Registrierung schreibt pro Request eine Zeile + Mail; abgelaufene `email_pending`-Drafts werden nie gelöscht |
| AP5-30 | S3 | P | `server/server.js:L4735-4744` | Öffentlicher `/hhttps/stats` führt pro Aufruf acht ungecachte Queries aus, inkl. vier `COUNT(*)` und Laden aller Webhook-Zeilen |
| AP5-31 | S3 | P | `server/wp-plugin-registration.js:L215-231 + server/server.j…` | DNS-TXT-Lookups ohne Timeout und ohne Rate-Limit |
| AP5-32 | S4 | P | `server/server.js:L4393-4395` | Dynamischer Import, `new Resolver()` und `setServers()` pro Request |
| AP5-33 | S4 | P | `server/server.js:L3868-3871` | Zwei unabhängige Writes im Token-Pfad sequenziell |
| AP5-34 | S4 | P | `server/server.js:L4622-4636 + developers/admin.html:L261-274` | `/hhttps/admin/clients` `LIMIT 200` ohne Pagination; UI partitioniert clientseitig |
| AP5-35 | S4 | P | `developers/assets/portal.js:L391-401, L621-626` | Admin-Check bei jedem Seitenaufruf über `/hhttps/admin/stats` |
| AP5-36 | S4 | P | `server/workload-identity.js:L125, L158-161` | JWKS-Fetch ohne Timeout; jeder unbekannte `kid` erzwingt sofortigen Re-Fetch |
| AP5-38 | S3 | W | `server/wp-plugin-registration.js:L35-78 vs. server/server.j…` | Vier Helfer-Kopien mit abweichender Semantik |
| AP5-39 | S3 | W | `server/server.js:L4374-4432 + server/wp-plugin-registration…` | DNS-TXT-Prüfung nahezu zeilengleich dupliziert, mit unterschiedlichem Resolver |
| AP5-40 | S4 | W | `server/server.js:L4621-4653` | Roh-SQL und JSON-Parsing im Admin-Handler statt in db.js; kein `is_active`-Filter |
| AP5-43 | S4 | W | `server/server.js:L3774-3911` | Fehlerformat der Machine-/Webhook-Routen (Freitext) weicht vom Portal-Format (snake_case + `message`) ab; `/webhooks/verify` ohne Limiter |
| AP5-44 | S4 | W | `server/server.js:L3823, L3877, L3890, L3899, L4750, L4809 +…` | Magic Strings/Numbers ohne Konstante |
| AP5-45 | S4 | W | `server/server.js:L82-89 vs. server/pop-verify.js:L41-45, L1…` | `jwkThumbprint` doppelt definiert; pop-verify exportiert es bereits |
| AP5-46 | S4 | W | `server/server.js:L2-3, L4806-4807` | Zusatzmodule per Patch-Marker und uneingerückt in `main()` gemountet |
| AP5-47 | S4 | W | `developers/assets/portal.js:L282-287, L411-426, L638-639 + …` | Veraltete v4-Kommentare, ungenutzte Deprecated-Aliase, timing-abhängiger Admin-Hint |
| AP5-48 | S4 | W | `developers/register.html:L337, L346-352 + developers/dashbo…` | Formularfelder ohne Backend-Pendant; Client-Regel „https-only“ strenger als Server |
| AP5-49 | S4 | W | `sites/spec.html:L964-1141, docs/spec.md:L147-157` | Endpunkt-Doku ohne `/hhttps/pop/*`, `/hhttps/plugin/*`, `/hhttps/whoami`, `resend-email` |
| AP5-50 | S4 | W | `server/server.js:L3945, L4054, L4633-4634; server/pop-verif…` | ESLint-Warnungen (Sammelfinding) |

### AP6 — Persistenz, Migrationen, Betrieb, CI

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP6-03 | S3 | K | `server/sql/schema.sql:L203` | `cleanup_expired()` löscht nur `used = FALSE`; eingelöste/invalidierte `email_verifications`-Zeilen werden nie entfernt |
| AP6-04 | S3 | K | `server/db.js:L147-234` | `sessions` hat keine Methode `delete`; `server.js:L2573` ruft `db.sessions.delete(priorId)` im leeren `catch` auf |
| AP6-05 | S4 | K | `server/db.js:L158` | `data.trustScore \|\| 60` überschreibt ein explizites `trustScore: 0` mit 60 |
| AP6-06 | S3 | K | `server/db.js:L372-383` | `email_verifications.code` existiert in keiner SQL-Datei; wird nur per Fire-and-forget beim Modul-Import angelegt |
| AP6-07 | S3 | K | `server/privacy-pass/migrations.js:L117-138` | fehlgeschlagene Privacy-Pass-Migrationen werden nur gezählt, der Server startet trotzdem; Aufruf vor `db.ping()` |
| AP6-08 | S3 | K | `server/scripts/install-pg.sh:L79-81, scripts/deploy-all.sh:…` | stiller Superuser-Fallback macht `postgres` zum Tabellen-Owner; Boot-DDL scheitert mit „must be owner“ |
| AP6-09 | S3 | K | `server/scripts/deploy-phase8.sh:L267` | dokumentierter Rollback-Befehl scheitert am eigenen Preflight |
| AP6-10 | S4 | K | `server/package.json:L9-10` | `npm run migrate` / `npm run db:check` zeigen auf nicht existierende Skripte; kein `engines`-Feld; veraltete Beschreibung |
| AP6-11 | S4 | K | `server/sql/migration-phase-2.5.sql:L85-87, migration-phase-…` | Zähler als Spalten auf der zeilenbasierten `stats`-Tabelle angelegt |
| AP6-12 | S4 | K | `server/scripts/make-admin.sh:L107-109` | `shift 2` ohne zweites Argument beendet das Skript stumm |
| AP6-14 | S3 | S | `server/scripts/make-admin.sh:L156,L167,L174,L179` | `USER_ID` wird unescaped in SQL interpoliert (NOTE wird escaped, USER_ID nicht) |
| AP6-15 | S3 | S | `server/db.js:L861-899, L916-942` | E-Mail-Bestätigungstoken der OAuth-Clients im Klartext gespeichert und nachgeschlagen |
| AP6-16 | S3 | S | `server/db.js:L656-668` | `webhooks.list()` liefert das HMAC-Secret jedes Webhooks an den (unauthentifizierten) Aufrufer |
| AP6-17 | S3 | S | `server/scripts/migrate.sh:L77-84, scripts/deploy-all.sh:L41…` | `.env` wird als Shell gesourct; alle Secrets landen in pm2-Prozessumgebung und `dump.pm2` |
| AP6-18 | S3 | S | `scripts/deploy-all.sh:L269-281, L367-381` | Nginx `add_header` in `location`-Blöcken verwirft die serverweiten Security-Header |
| AP6-19 | S3 | S | `.github/workflows/ci.yml:L1-30, L44, L94-105` | CI ohne Test-/Lint-/Audit-Gate; `npm ci` fällt still auf `npm install` zurück; kein `permissions:`; Actions per Major-Tag; `docs-lint` kann… |
| AP6-20 | S4 | S | `server/scripts/deploy-phase8.sh:L107-111 + scripts/deploy-p…` | lokale Kopie der `docker-compose.yaml` landet im Repo-Arbeitsverzeichnis; `git add -A && git push` würde sie pushen |
| AP6-21 | S4 | S | `server/scripts/deploy-phase8.sh:L168, L192, L216` | `PGPASSWORD` für die gesamte Skriptlaufzeit exportiert |
| AP6-22 | S4 | S | `server/scripts/install-pg.sh:L47, L55; scripts/deploy-all.s…` | DB-Passwort als Kommandozeilenargument an psql |
| AP6-23 | S4 | S | `scripts/deploy-all.sh:L51` | `curl … \| bash` (NodeSource) ohne Prüfsumme/Pinning |
| AP6-24 | S4 | S | `scripts/deploy-privacy-pass.sh:L324-371 (auch scripts/deplo…` | `curl -k` deaktiviert TLS-Verifikation bei den Live-Checks |
| AP6-25 | S4 | S | `scripts/force-verify-client.mjs:L22, L41 + server/scripts/d…` | Prod-fähiges „Verified-Badge erzwingen“-Tool mit Default-Client wird ins Live-/Repo-Verzeichnis kopiert |
| AP6-26 | S4 | S | `scripts/patch-coop-popups.sh:L31-33, L40-110; scripts/patch…` | Live-Patcher für `/var/www/hhttps/server.js`, inhaltlich obsolet oder driftend |
| AP6-28 | S4 | S | `server/db.js:L1213-1233, L1245-1253` | OAuth-Authorization-Codes im Klartext gespeichert |
| AP6-29 | S3 | P | `server/db.js:L90-93, L206-209, L263-266, L291-294, L313-316…` | sechs ungecachte `COUNT(*)` pro Aufruf von `/hhttps/info` (vom App-Rate-Limit ausgenommen) |
| AP6-32 | S3 | P | `server/privacy-pass/migrations.js:L65-77, L106-113, L17-28` | `pp_email_pending`, `pp_redeemed`, `pp_issuance_log` ohne Cleanup |
| AP6-33 | S3 | P | `server/db.js:L30-39` | Pool ohne `statement_timeout`/`query_timeout` |
| AP6-34 | S4 | P | `server/sql/schema.sql:L24, L48, L78, L92, L102, L119` | sechs Indizes ohne Query-Nutzung auf Hot-Insert-Tabellen |
| AP6-35 | S4 | P | `server/sql/schema.sql:L163-174` | `webhook_deliveries` ohne Retention |
| AP6-36 | S4 | P | `server/db.js:L685-699, L701-708` | Webhook-Statistik in 2–3 Roundtrips statt einem Statement |
| AP6-37 | S4 | P | `server/db.js:L372-383 + server/privacy-pass/migrations.js:L…` | DDL bei jedem Prozessstart |
| AP6-38 | S4 | P | `server/scripts/deploy-phase8.sh:L216, scripts/deploy-privac…` | `pm2 restart` im Fork-Modus: Downtime bei jedem Deploy |
| AP6-40 | S3 | W | `server/db.js:L372-383, L432-439; server/privacy-pass/migrat…` | vier konkurrierende Schema-Mechanismen ohne gemeinsames Ledger |
| AP6-42 | S4 | W | `server/db.js:L829-830, L840-841, L896-897, L1052-1053, L106…` | `JSON.parse`-try/catch elfmal kopiert, obwohl `parseJsonArray()` (L577-585) existiert |
| AP6-43 | S3 | W | `server/db.js:L254-257, L280-285, L601-604, L625-631, L656-6…` | Rückgabeformat der Zugriffsobjekte inkonsistent (camelCase-normalisiert vs. rohe snake_case-Rows) |
| AP6-45 | S3 | W | `scripts/deploy-privacy-pass.sh:L132-145, L147-278, L294, L3…` | Deploy-Skript mit wirkungsloser Sync-Logik, veralteten Annahmen und Commit/Push aus dem Deploy |
| AP6-46 | S4 | W | `server/scripts/migrate.sh:L12-14, L24-27, L69, L77` | veraltetes ZIP-basiertes v4.0→v4.1-Migrationsskript |
| AP6-47 | S3 | W | `scripts/deploy-all.sh:L75-101, L120-152` | PostgreSQL-Provisionierung und .env-Schreiben sind eine driftende Kopie von install-pg.sh:L42-70, L84-104 |
| AP6-48 | S3 | W | `server/scripts/deploy-phase8.sh:L59; server/scripts/make-ad…` | vier verschiedene .env-Parser mit unterschiedlicher Semantik |
| AP6-49 | S3 | W | `server/sql/migration-phase-5-external-verify.sql:L22-64 (un…` | Migrationsdateien uneinheitlich bezüglich Ownership/Grants und Ausführungsrolle; Doku widerspricht sich |
| AP6-50 | S4 | W | `server/scripts/make-admin.sh:L16-21, L160-162` | Operator-Hinweis zur Identitätsstabilität ist seit Phase 8 falsch |
| AP6-52 | S4 | W | `server/eslint.config.js:L21` | Browser-Globals für den gesamten Server-Code freigeschaltet |
| AP6-54 | S4 | W | `server/db.js:L1-15, L325, L490` | veralteter/irreführender Modul-Header und Kommentare |
| AP6-55 | S4 | W | `server/db.js:L112, L148, L326, L545, L1211, L701, L36-38` | TTL-/Schwellen-Defaults als Magic Numbers, teils doppelt zu den Aufrufern |
| AP6-56 | S4 | W | `server/sql/schema.sql:L55, L208-209` | veraltete Kommentare im Schema |
| AP6-57 | S4 | W | `scripts/deploy-all.sh:L23-28 (+ deploy-privacy-pass.sh:L43-…` | Farb-/Log-Präambel fünffach kopiert, uneinheitliche Shell-Optionen, deprecated npm-Flag |
| AP6-58 | S4 | W | `scripts/force-verify-client.mjs:L9-11, L20 + server/scripts…` | Skript liegt unter `scripts/`, erwartet aber, aus `server/` zu laufen |
| AP6-60 | S4 | W | `server/db.js:L829, L830, L840, L841, L896, L897, L1052, L10…` | ESLint-Sammelfinding: 11 × `no-unused-vars` (`'e' is defined but never used`) |

### AP7 — Privacy Pass + SDK

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP7-06 | S3 | K | `server/privacy-pass/keys.js:L80,L143-150` | 1-Byte-`truncated_token_key_id` über 16 Issuer: Kollisionen werden weder erkannt noch behandelt; keine Rotation/kein Ablauf |
| AP7-07 | S3 | K | `server/privacy-pass/keys.js:L61,L77-95` | Fehlt eine der drei Key-Dateien, wird stillschweigend ein neues Schlüsselpaar erzeugt und `voprf-private.bin` überschrieben |
| AP7-08 | S3 | K | `server/privacy-pass/demo.js:L20,L29,L49` | Import eines nicht existierenden Exports `parseTokenAndVerify`; Modul bricht beim Laden |
| AP7-09 | S3 | K | `server/privacy-pass/verifications-api.js:L72-74,L95-101,L12…` | `/email/start` und `/recovery/generate` mit Session ohne Credential: 500 mit PG-Fehlermeldung bzw. Codes ohne Passkey |
| AP7-10 | S3 | K | `server/privacy-pass/public/wallet.html:L1320-1352` | `submitAttribute` meldet „im Pilot-Modus akzeptiert“, speichert nichts und feuert einen unsinnigen `/email/start`-Fallback |
| AP7-11 | S3 | K | `server/sdk/client.js:L337-344, server/sdk/client.py:L192-197` | Unbekannter `kid` löst keinen JWKS-Refresh aus, sondern fällt auf `keys[0]` zurück |
| AP7-12 | S3 | K | `server/sdk/client.js:L152-159,L376-390` | `check()` wirft bei ungültigem Token (401) statt `status:'invalid'`; `res.json()` vor `res.ok` |
| AP7-13 | S3 | T | `server/test/e2e/wallet.e2e.test.mjs:L80-131` | Einziger Privacy-Pass-Test deckt nur den Login ab; Issuance/Verify/Redeem/Eligibility/E-Mail-Verify/Recovery ungetestet |
| AP7-14 | S4 | K | `server/privacy-pass/issuance.js:L118,L140,L156-159` | Nicht-String-Elemente in `requests` und ungültige Gruppenelemente führen zu 500 statt 400 |
| AP7-15 | S4 | K | `server/privacy-pass/issuance.js:L101-102,L108` | `Retry-After`/`window_seconds` melden immer das volle 24-h-Fenster |
| AP7-16 | S4 | K | `server/privacy-pass/public/wallet.html:L1363,L1383` | Wallet fordert immer 10 Tokens an, Button nur bei `remaining === 0` gesperrt |
| AP7-17 | S4 | K | `server/privacy-pass/verifications.js:L147-159` | Recovery-Codes: `DELETE` + 10 sequentielle `INSERT`s ohne Transaktion |
| AP7-18 | S4 | K | `server/sdk/client.js:L393-394, server/sdk/client.py:L222,L3…` | Toter CommonJS-Shim; fehlendes URL-Encoding von `jti`; nacktes `except:`; fehlende Feature-Parität |
| AP7-19 | S4 | W | `server/privacy-pass/issuer.js:L9,L16; verifications.js:L11-…` | ungenutzte Importe/Konstanten (ESLint `no-unused-vars`, gesammelt) |
| AP7-27 | S3 | S | `server/privacy-pass/verifications-api.js:L104-105` | Verifikationslink aus `req.protocol`/`Host` (Host-Header-Poisoning) |
| AP7-29 | S3 | S | `server/privacy-pass/verifier-internal.js:L52-71, verifier.j…` | `challenge_digest` wird nie geprüft: keine Origin-/Challenge-Bindung, Replay über `/verify` |
| AP7-30 | S3 | S | `server/privacy-pass/verifications-api.js:L293-314` | `/recovery/use` als unauthentifiziertes Code-Orakel mit spoofbarer IP im Audit-Log, ohne wirksame Recovery-Funktion |
| AP7-31 | S3 | S | `server/privacy-pass/verifications-api.js:L42,L209,L273; iss…` | Session-ID als Bearer-Geheimnis in GET-Query-Strings |
| AP7-32 | S3 | S | `server/privacy-pass/migrations.js:L17-27,L106-112; verifier…` | Rolle und Zeitstempel in `pp_issuance_log`/`pp_redeemed` ermöglichen Korrelation bei kleinen Anonymitätsmengen |
| AP7-33 | S3 | S | `server/privacy-pass/verifications.js:L14-19` | E-Mail-Pseudonymisierung mit öffentlich bekanntem Fallback-Salt |
| AP7-34 | S3 | S | `server/privacy-pass/public/wallet.html:L9; server.js:L396` | WebAuthn-Bibliothek von unpkg.com ohne SRI, synchron im `<head>` |
| AP7-35 | S4 | S | `server/privacy-pass/issuance.js:L158,L207; verifications-ap…` | `err.message` interner Fehler geht an Clients |
| AP7-38 | S3 | P | `server/privacy-pass/migrations.js:L17-27; issuance.js:L164-…` | `pp_issuance_log` wird nie bereinigt |
| AP7-39 | S3 | P | `server/privacy-pass/verifications.js:L90-119; migrations.js…` | `pp_email_pending`: abgelaufene Links werden nie gelöscht, Ablaufindex ungenutzt |
| AP7-41 | S3 | P | `server/server.js:L371; privacy-pass/issuance.js:L30; verifi…` | Router-eigene Body-Limits (32/8/4 kB) sind wirkungslos, es gilt das globale 2-MB-Limit |
| AP7-42 | S4 | P | `server/privacy-pass/verifier.js:L74-78; migrations.js:L106-…` | `pp_redeemed` wächst dauerhaft ohne Rotations-/Zeitgrenze |
| AP7-45 | S4 | P | `server/sdk/client.js:L65-83; client.py:L127-155` | JWKS-Refresh ohne In-Flight-Deduplizierung |
| AP7-46 | S4 | P | `server/privacy-pass/issuer.js:L82-98; verifier-internal.js:…` | Öffentliche VOPRF-Endpunkte nur durch das globale IP-Limit geschützt |
| AP7-49 | S3 | W | `server/privacy-pass/keys.js:L40-44; role-requirements.js:L2…` | Rollenliste an vier Stellen ohne gemeinsame Quelle |
| AP7-50 | S3 | W | `server/privacy-pass/issuance.js:L118-139; issuer.js:L33-47;…` | TokenRequest-Parsing und Truncated-Key-ID dreifach implementiert |
| AP7-51 | S4 | W | `server/privacy-pass/verifier-internal.js:L18-23; issuer.js:…` | VOPRFServer-Cache pro Rolle doppelt |
| AP7-52 | S4 | W | `server/privacy-pass/well-known.js:L28-36; issuer.js:L115-123` | `token-keys`-Liste zweimal erzeugt |
| AP7-53 | S4 | W | `server/privacy-pass/verifications.js:L88,L98,L102; verifica…` | E-Mail-Token-TTL dreimal festverdrahtet |
| AP7-56 | S3 | W | `server/privacy-pass/public/wallet.html:L938-943,L1059-1063,…` | `register/finish`-Aufruf dreimal kopiert mit divergierender Fehlerbehandlung |
| AP7-57 | S3 | W | `server/privacy-pass/README.md:L21-22; INSTALL.md:L61,L71,L7…` | Modul-Doku beschreibt einen veralteten Stand und widerspricht dem Code |
| AP7-58 | S4 | W | `server/privacy-pass/issuance.js:L68,L165,L177,L195; verific…` | `await import('../db.js')` 17-mal statt statischer Import |
| AP7-59 | S4 | W | `server/privacy-pass/verifications-api.js:L84` | Lokale Konstante `req` verschattet das Express-Request-Objekt |
| AP7-60 | S4 | W | `server/privacy-pass/issuance.js:L13,L23-27; wallet.html:L13…` | Kommentar „tune via env“ ohne Konfigurierbarkeit; `DEFAULT_BATCH_SIZE` ungenutzt; Batchgröße doppelt |
| AP7-61 | S4 | W | `server/privacy-pass/verifications-api.js:L177-203; wallet.h…` | HTML-Seite inkl. CSS/Google-Fonts als Template-String im API-Modul; DE/EN hart codiert |
| AP7-62 | S4 | W | `server/privacy-pass/public/wallet.html:L951,L998,L1027,L122…` | Mischung aus `tr()` und hart codierten deutschen Strings |
| AP7-63 | S4 | W | `server/privacy-pass/public/wallet.html:L602-1550` | ~950 Zeilen Anwendungslogik als Inline-`<script type="module">` |
| AP7-64 | S4 | W | `server/sdk/client.js:L30; client.py:L39,L58` | Klassenname `HHTPPSClient`/`HHTPPSResult` ist ein Tippfehler des Produktnamens |

### AP8 — Frontend, Sites, Browser-Extension

| ID | Sev | Dim | Stelle | Befund |
|---|---|---|---|---|
| AP8-03 | S3 | K | `server/public/workload.html:L117, L180, L233, L254` | Seite ruft `/hhttps/machine/workload/{list,bind,unbind}` (und bewirbt `/hhttps/machine/exchange`), die auf dem Server nicht existieren |
| AP8-04 | S3 | K | `extension/background.js:L36-45 + L128-141 + L168-182` | Auto-Refresh wird für frisch eingefangene Identitäten nie geplant (`identity.id` ist `undefined`) |
| AP8-05 | S3 | K | `extension/background.js:L159-165` | Identitäts-ID `issuer#role` kollidiert für alle v0.5-Identitäten; Mensch und Maschine überschreiben sich gegenseitig |
| AP8-06 | S3 | K | `server/public/index.html:L722-727 + L782` | Maschinen-Flow bleibt nach verbrauchtem Code hängen, wenn `machine/register` oder `machine/token` fehlschlagen |
| AP8-07 | S3 | K | `server/public/index.html:L641-646 (pollEudi), L666-671 (pol…` | Terminale Zustände (`failed`, `expired`/404, HTTP≥400) werden ignoriert; feste Kadenz 80×2,5 s ohne Backoff/Abbruch/Doppelstart-Schutz |
| AP8-08 | S3 | K | `sites/hhttps.html:L923 + L1904-1907 + L1468-1479` | Gecachte `hhttps_uid` springt direkt zum Passkey-Login; die entstehende Session ist nicht E-Mail-verifiziert → `role/declare` 403 ohne Rück… |
| AP8-09 | S3 | K | `sites/hhttps.html:L930-946 + L1849-1871` | Seite sendet einen frei gewählten v0.4-Rollenkatalog und publiziert ihn an die Extension, obwohl der Server die Rolle ignoriert |
| AP8-10 | S4 | K | `server/public/email-verify.html:L77-115` | Verwaiste Legacy-Seite mit veraltetem URL-Vertrag; Doku behauptet einen Redirect, den es nicht gibt |
| AP8-11 | S4 | K | `server/public/email-patch.js:L1-2` | Datei besteht nur aus einem Kommentar und verweist auf ein nicht existierendes Build-Skript |
| AP8-12 | S4 | K | `sites/spec.html:L577, L650, L684, L783, L1495-1515 (+ sites…` | Öffentliche Spezifikation dokumentiert v0.4.1, falschen `issuer`-Wert und eine unvollständige Endpunkt-Tabelle |
| AP8-13 | S4 | K | `server/public/index.html:L554-566` | Im `EMAIL_DEV_MODE` liefert `/hhttps/email/send` `devCode`, die Seite zeigt ihn nicht an |
| AP8-14 | S4 | K | `server/public/index.html:L681-694` | GitHub-Popup ohne Fehlerbehandlung; 503 `github_not_configured` endet als rohes JSON im Popup, Hauptseite pollt 200 s stumm |
| AP8-17 | S3 | S | `sites/hhttps.html:L1232-1250 (+ L1611-1625, server/public/i…` | Open Redirect: `?returnTo=<beliebige URL>` leitet eingeloggte Nutzer sofort weiter; in L1247 auch `javascript:` |
| AP8-18 | S3 | S | `server/public/index.html:L1034-1052` | `?login_hint=<E-Mail>` löst beim bloßen Öffnen des Links automatisch einen Code-Versand an die Adresse aus |
| AP8-19 | S3 | S | `extension/popup.js:L222-227 (+ content-universal.js L57-68,…` | Seitengesteuerte `<meta name="hhttps-*">`-Tags werden ungeprüft als „HHTTPS aktiv / verifiziert“ angezeigt |
| AP8-20 | S3 | S | `server/public/index.html:L791 (analog sites/hhttps.html:L15…` | Refresh-Token im `localStorage` der IdP-Origin |
| AP8-21 | S4 | S | `extension/manifest.json:L54, L57` | Nicht genutzte Berechtigungen `activeTab` und `scripting` |
| AP8-22 | S4 | S | `extension/content-universal.js:L113, L177-183, L484` | Debug-`console.log` auf jeder besuchten Seite inkl. iframe-`src`, Body-Länge und Slug-Listen |
| AP8-25 | S3 | P | `extension/content-universal.js:L128-139` | TreeWalker-Filter ruft für jeden Textknoten zwei `closest()` auf, bevor der billige Textcheck greift |
| AP8-26 | S3 | P | `extension/content-universal.js:L700-720` | MutationObserver scannt jeden hinzugefügten Element-Knoten sofort und ungedrosselt inkl. `querySelectorAll('iframe')` |
| AP8-27 | S3 | P | `extension/content-universal.js:L98-117, L462-481` | Batch-Verify ohne Chunking; Server lehnt >100 Slugs mit 400 ab; Fehler werden nicht gecacht → Seals dauerhaft „pending“ |
| AP8-29 | S3 | P | `sites/hhttps.html:L1825-1835 + L1777-1790` | E-Mail-Status-Polling (5 s) wird bei jedem `setStep(3)` neu gestartet ohne das alte Intervall zu löschen und läuft nach erfolgreicher Verif… |
| AP8-30 | S4 | P | `extension/background.js:L245-253, L297, L21-29` | `updateAllBadges` liest für jeden Tab einzeln `chrome.storage.local` |
| AP8-33 | S4 | P | `server/public/index.html:L8, L382-383; sites/hhttps.html:L9` | Render-blockende Drittressourcen (Google Fonts ohne `preconnect` in index.html; zwei unpkg-Skripte synchron) |
| AP8-34 | S3 | W | `server/public/index.html:L384-1058` | Sign-in-Seite ist ein 675-zeiliges Inline-Skript-Monolith, der nur per Regex getestet werden kann |
| AP8-35 | S3 | W | `server/public/index.html:L546-624` | E-Mail-zuerst-Passkey-Flow dreifach implementiert (index.html, sites/hhttps.html, wallet.html) und bereits gedriftet |
| AP8-36 | S3 | W | `server/public/index.html:L786-827` | `hhttps_identity`-Format an vier Stellen ohne gemeinsames Schema, mit abweichender Semantik |
| AP8-37 | S3 | W | `server/public/iamhmn-card-issuer.js:L1-236` | Web-Component ist tot; index.html dupliziert sie inline; Reserved-Liste dreifach mit abweichendem Inhalt |
| AP8-40 | S3 | W | `sites/hhttps.html:L919-1925` | Landing-Page wird von keinem Deploy-Skript ausgeliefert, aber mit Tests und Protokoll-Migrationen aktiv gepflegt; Inhalt veraltet |
| AP8-41 | S3 | W | `sites/hhttps.html:L1498-1571 + L1838-1895` | `doDeclarRole()` wird 270 Zeilen später komplett überschrieben; Original ist toter Code |
| AP8-42 | S3 | W | `sites/iamhmn.html:L3346-3392` | Drei divergierende Rollen-Kataloge im Frontend gegenüber dynamischem Rollenmodell im Server |
| AP8-44 | S3 | W | `extension/background.js:L405-420 + L323-343` | Signatur-Modus-Einstellung wird gespeichert, aber nie gelesen; Popup-Schalter wirkungslos, Kommentar behauptet das Gegenteil |
| AP8-45 | S3 | W | `extension/content-universal.js:L843-876` | Fetch/XHR-Sniffer läuft in der isolierten Content-Script-Welt und sieht keine Seitenrequests; zugehöriges Background-Plumbing ist tot |
| AP8-46 | S3 | W | `extension/INSTALL.md:L1, L43-58` | Nutzer-Doku zu Version, Datenabflüssen und Berechtigungen ist veraltet/falsch |
| AP8-47 | S3 | W | `extension/background.js:L1-420 (+ content-universal.js, pop…` | Browser-Extension hat keinerlei Tests und kein Lint-Gate |
| AP8-48 | S4 | W | `extension/manifest.json:L4` | Versionskennung in sechs Dateien, fünf davon veraltet |
| AP8-49 | S4 | W | `extension/content-universal.js:L341-383, L544` | i18n inkonsistent: hart kodiertes Deutsch neben `chrome.i18n`, Datumsformat fest `de-DE` |
| AP8-50 | S4 | W | `server/public/index.html:L423, L466 (+ L756, L771, L821, L8…` | i18n-Wörterbuch mit ungenutzten Schlüsseln und zweisprachigen Inline-Ternaries; analog sites/hhttps.html |
| AP8-51 | S4 | W | `server/public/index.html:L642-692` | Dreifach kopierte Polling-Schleife mit Magic Numbers; Token-Kürzung und HTML-Escaping mehrfach implementiert |
| AP8-52 | S4 | W | `server/public/index.html:L391 (+ sites/hhttps.html L1081, L…` | Veraltete/irreführende Kommentare und Phase-Marker |
| AP8-53 | S4 | W | `extension/background.js:L34-108, L347-367, L410-420` | Drei getrennte `onMessage`-Listener und sechsfach hart kodierter Issuer |
| AP8-54 | S4 | W | `server/public/.well-known/hhttps-role-assurance.json:L1-107` | Statische Kopie der berechneten Discovery-Antwort |


## 5. Empfohlene Reihenfolge

| Welle | Ziel | Findings |
|---|---|---|
| 0 — sofort (Tage) | Angriffsfläche schließen | AP7-20/-04/-05 (Privacy-Pass-Mount deaktivieren oder Router ohne `token-request` + verankerte Regexe + `method` server-seitig ableiten), AP8-15 (Datei löschen), AP3-13 + AP3-02 (E-Mail strikt parsen: nur `local@domain`, Label-Grenze in `classifyDomain`), AP5-16/AP1-22/AP1-21 (Webhook-Routen hinter `requireUser`, Secret nie zurückgeben, SSRF-Filter), AP4-23 (#32 Rotation) |
| 1 — Kernflow (1 Woche) | Sign-in und Token-Lifecycle korrekt | AP3-01 (priorMerge persistieren), AP2-01 + AP4-03 (Widerruf → Refresh-Kette), AP5-01 (Refresh nie als Auth-Credential; `checkTokenValid` typisieren), AP4-01, AP4-02, AP4-20, AP4-21, AP6-01 (Install-Skripte = Migrationskette), AP6-13 |
| 2 — Betrieb (2 Wochen) | Wachstum und Deployment | Cleanup-Scheduler (AP6-02, AP2-23, AP3-P, AP4-P `revoked_tokens`, AP7-P), CI-Gates `npm test`/`eslint`/`npm audit` (AP6), `nodemailer` ≥ 7 (nach AP3-13-Fix), `/hhttps/info`-Caching (AP1-32), Rate-Limits für Mailversand (AP7-26, AP5-17) |
| 3 — Wartbarkeit (laufend) | Entkopplung | `server.js` in Router-Module schneiden (AP1/AP2/AP3-W), toten Code entfernen, Sign-in-Flow einmal implementieren (AP8-W), Rollenkatalog zentralisieren (AP7-W), ESLint-Warnungen abbauen |

Welle 0 und 1 sind Voraussetzung, bevor Songbird (oder ein anderer OAuth-Client) auf `verified_methods`/`email_verified` vertrauen darf.

## 6. Grenzen des Reviews

- Statisches Review + gezielte Repros gegen lokalen Test-Server/Test-DB; **kein** Penetrationstest gegen Produktion, keine Last-Messung.
- AP4-18 (EUDIPLO `trusted_authorities`) ist am Code-Vertrag belegt; ob das produktive EUDIPLO eine Trust-List außerhalb des Repos hält, konnte nicht geprüft werden (Live-Nachweis ausstehend).
- `sites/*.html` und `developers/*` wurden auf Client-Logik geprüft, nicht auf Layout/Accessibility.
- Externe Dienste (GitHub-OAuth, ESCO, EUDIPLO-Backend, SMTP) wurden nicht angebunden.
- Zeilennummern beziehen sich auf `bf0a82b`; die Verifikatoren haben die Rohbefund-Zeilen korrigiert, wo sie abwichen.

## 7. Nächste Schritte (Prozess)

1. Freigabe dieses Reports durch Daniel.
2. Danach: ein GitHub-Issue pro bestätigtem Finding S1–S3 (Labels `severity:S1..S4`, `dim:korrektheit|sicherheit|performance|wartbarkeit`, `review-2026-09`), S4 gesammelt als ein Issue pro AP; jedes Issue mit Permalink `…/blob/bf0a82b/<datei>#L<von>-L<bis>` und Rückverweis auf `APx-verifikation.md`.
3. Fix-PRs je Welle, jeweils gegen die Issue-Nummern.
