# Spec: E-Mail-verankerte, stabile Identität + Code-Mail (Feature `email-anchored-identity`)

Status: **FREIGEGEBEN durch Daniel** (Gate 1, 2026-09-12). Die EARS-Kriterien unten sind
1:1 aus der freigegebenen Anforderung abgeleitet (Originaltext + Recherche: `requirements.source.md`).
Es wurden keine neuen Anforderungen hinzugefügt.

## 1. Problem & Nutzer

Heute erzeugt jede Anmeldung auf hhttps.org eine neue zufällige `userId`. Damit erhält
dieselbe Person bei jedem Login einen anderen pairwise `sub` — Plattformen (OAuth-Clients wie
ask.iamhmn.org, WordPress-Plugin) erkennen den Benutzer nicht wieder, und ein Passkey ist an
eine Wegwerf-Identität gebunden. Zusätzlich kommen die verifizierten Methoden
(`email_verified`, `github_verified`, `eudi_verified`, Passkey) nicht bei der Plattform an:
weder im ID-Token noch über `/userinfo`. Und der 6-stellige Code in der Verifikations-Mail
wird als `000 000` gerendert, was beim Kopieren scheitert; das Mail-Design entspricht nicht
mehr dem hellen WorldID-angelehnten Look von hhttps.org.

Nutzer: (a) Endnutzer, die hardwareübergreifend immer als dieselbe Person mit demselben
Pseudonym erkannt werden wollen; (b) Plattform-Betreiber, die E-Mail, Pseudonym und
verifizierte Methoden zuverlässig erhalten wollen.

## 2. Scope / Nicht-Ziele

**Scope**
- E-Mail-Verifikation wird Pflicht und ist der stabile Identitätsanker (gleiche E-Mail ⇒ gleiche `userId` ⇒ gleicher pairwise `sub` pro Plattform).
- Pseudonym als Pflichtbestandteil der Identität; automatisch `iamhmn_<zufall>` falls leer; stabil pro Konto.
- Alle anderen Methoden (Passkey, GitHub, EUDI, Alter) sind erst nach E-Mail-Verifikation nutzbar (UI ausgegraut/nicht klickbar; Backend lehnt ab). „Alter“ ist dabei explizit gegated (AK-27/AK-28): der Alters-Bootstrap ohne Session (`/hhttps/age/direct`) entfällt; Altersnachweis nur noch per `/hhttps/age/upgrade` auf einer Session mit bestätigter E-Mail.
- Passkeys werden an die stabile `userId` gebunden (WebAuthn user handle = `userId`).
- Klartext-E-Mail wird serverseitig zwischengespeichert, bis sie an die Plattform übertragen wurde; Übertragung von `email`, `pseudonym` (`preferred_username`) und Methoden-Flags über ID-Token, Access-Token und `/hhttps/oauth/userinfo`.
- Code-Mail: Code ohne Leerzeichen; Eingabe toleriert Leerzeichen; Design an hhttps.org (hell, WorldID-Anlehnung) angepasst.

**Nicht-Ziele**
- Kein Login „nur mit Passkey“ ohne E-Mail (E-Mail ist immer der erste Schritt).
- Keine Konto-Zusammenführung zweier verschiedener E-Mail-Adressen.
- Keine Änderung des pairwise-`sub`-Algorithmus (`HMAC(userId|clientId)` bleibt).
- Keine Änderung der EUDI-Verifier-Interna (nur die Gate-Prüfung im Backend).
- Keine Pseudonym-Eindeutigkeit (zwei Konten dürfen dasselbe Pseudonym haben).

## 3. Akzeptanzkriterien (EARS)

### A. Stabile Identität über E-Mail
- **AK-1** WHEN ein Nutzer einen 6-stelligen Code für E-Mail `E` bestätigt und für `normalize(E)` noch kein Identitätsanker existiert, THE system SHALL einen Anker `HMAC(pepper, normalize(E)) → userId` anlegen und die Session an diese `userId` binden.
- **AK-2** WHEN ein Nutzer in einer neuen Session (anderes Gerät/Browser) dieselbe E-Mail (auch mit anderer Groß-/Kleinschreibung oder Whitespace) bestätigt, THE system SHALL die Session auf die bereits gespeicherte `userId` des Ankers umbinden.
- **AK-3** WHILE zwei Sessions dieselbe `userId` tragen, THE system SHALL beim OAuth-Login derselben Plattform (`client_id`) denselben `sub` ausgeben.
- **AK-4** WHEN eine Session mit bestätigter E-Mail einen Passkey registriert, THE system SHALL den WebAuthn-`user.id` (user handle) gleich der stabilen `userId` der Session setzen und die Credential dieser `userId` zuordnen.
- **AK-5** WHEN ein Passkey, der zu `userId` U gehört, authentifiziert wird, THE system SHALL die resultierende Session an U binden (und nicht an eine neue zufällige Id).

### B. Pseudonym
- **AK-6** WHEN die E-Mail bestätigt wird und der Nutzer ein Pseudonym angegeben hat, THE system SHALL das bereinigte Pseudonym (max. 32 Zeichen, Zeichensatz `[\w\-. äöüÄÖÜß]`) im Anker speichern.
- **AK-7** WHEN die E-Mail bestätigt wird und kein (oder ein nach Bereinigung leeres) Pseudonym angegeben ist, THE system SHALL ein Pseudonym der Form `iamhmn_` + 10 Zeichen `[a-z0-9]` erzeugen und im Anker speichern.
- **AK-8** WHEN ein bestehender Anker bereits ein Pseudonym trägt, THE system SHALL dieses Pseudonym für die Session verwenden (ein bei der erneuten Anmeldung eingegebenes Pseudonym ändert es nicht).
- **AK-9** WHEN ein HHTTPS-Token (`/hhttps/role/declare`, `/hhttps/eid/upgrade`, `/hhttps/token/refresh`) ausgestellt wird, THE system SHALL den Claim `pseudonym` (nicht leer) enthalten.

### C. E-Mail zuerst (Gate)
- **AK-10** IF eine Session ohne bestätigte E-Mail `/hhttps/webauthn/register/start` aufruft, THEN the system SHALL mit HTTP 403 und `error: 'email_verification_required'` antworten.
- **AK-11** IF eine Session ohne bestätigte E-Mail `/hhttps/verify/github/start` aufruft, THEN the system SHALL mit HTTP 403 und `error: 'email_verification_required'` antworten.
- **AK-12** IF für eine Session ohne bestätigte E-Mail `/hhttps/eid/upgrade` aufgerufen wird, THEN the system SHALL mit HTTP 403 und `error: 'email_verification_required'` antworten (und kein Token ausstellen).
- **AK-13** IF eine Session ohne bestätigte E-Mail `/hhttps/role/declare` aufruft, THEN the system SHALL mit HTTP 403 antworten (E-Mail ist Pflichtmethode; Passkey/GitHub/EUDI allein reichen nicht mehr).
- **AK-14** WHILE die E-Mail in der Sign-in-Seite (`server/public/index.html`) noch nicht bestätigt ist, THE system SHALL die Methoden-Buttons Passkey, EUDI, GitHub und Alter als `disabled` (ausgegraut, nicht klickbar) rendern; WHEN die E-Mail bestätigt wurde, THE system SHALL sie aktivieren.
- **AK-15** WHILE die Sign-in-Seite das E-Mail-Panel zeigt, THE system SHALL ein optionales Pseudonym-Eingabefeld anbieten und es beim Senden des Codes (`/hhttps/email/send`, Feld `pseudonym`) mitschicken.
- **AK-27** IF für eine Session ohne bestätigte E-Mail `/hhttps/age/upgrade` aufgerufen wird, THEN the system SHALL mit HTTP 403 und `error: 'email_verification_required'` antworten (kein Token).
- **AK-28** IF `/hhttps/age/direct` (Alters-Bootstrap ohne bestehende Session) aufgerufen wird, THEN the system SHALL mit HTTP 403 und `error: 'email_verification_required'` antworten; ein Altersnachweis ist nur auf einer Session mit bestätigter E-Mail möglich (über `/hhttps/age/upgrade`).

### D. Übertragung an die Plattform (OAuth/OIDC)
- **AK-16** WHEN die E-Mail bestätigt wird, THE system SHALL die Klartext-E-Mail zusammen mit `pseudonym` und `verified_methods` in einem serverseitigen Cache (`identity_claims_cache`, Schlüssel `userId`, Ablauf ≤ 7 Tage) ablegen.
- **AK-17** WHEN eine Plattform mit Scope `email` einen Authorization-Code einlöst, THE system SHALL `email` und `email_verified: true` im ID-Token und in `/hhttps/oauth/userinfo` liefern; die E-Mail-Kopie auf dem Authorization-Code SHALL beim Einlösen gelöscht werden.
- **AK-18** WHEN eine Plattform (beliebiger Scope mit `openid`) einen Authorization-Code einlöst, THE system SHALL im ID-Token, im Access-Token und in `/hhttps/oauth/userinfo` die Claims `verified_methods` (Array), `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified` (Booleans) und `preferred_username` (= Pseudonym) liefern.
- **AK-19** IF eine Plattform Scope `email` anfordert, aber `allowed_scopes` des Clients `email` nicht enthält, THEN the system SHALL wie bei anderen nicht erlaubten Scopes mit `invalid_scope` antworten.
- **AK-20** WHEN `/.well-known/openid-configuration` abgerufen wird, THE system SHALL `email` in `scopes_supported` und `email`, `email_verified`, `passkey_verified`, `github_verified`, `eudi_verified`, `verified_methods`, `preferred_username` in `claims_supported` auflisten.
- **AK-21** WHEN `/hhttps/oauth/approve` mit einem HHTTPS-Token aufgerufen wird, dessen `verified_methods` Passkey enthält, THE system SHALL `passkey_verified: true` bis zur Plattform durchreichen (Ende-zu-Ende: Passkey-Login wird bei der Plattform erkannt).

### E. Code-Mail
- **AK-22** WHEN die Verifikations-Mail erzeugt wird, THE system SHALL den 6-stelligen Code in HTML- und Text-Teil ohne Leerzeichen (`123456`, nicht `123 456`) darstellen.
- **AK-23** WHEN ein Code mit Leerzeichen, Tabs oder Bindestrichen (z. B. `123 456`, ` 123456 `) an `/hhttps/email/confirm-code` gesendet wird, THE system SHALL ihn nach Entfernen dieser Zeichen wie `123456` akzeptieren.
- **AK-24** IF ein Code nach Normalisierung nicht genau 6 Ziffern hat, THEN the system SHALL mit HTTP 400 antworten.
- **AK-25** WHEN die Verifikations-Mail erzeugt wird, THE system SHALL das helle hhttps.org-Design verwenden: Hintergrund `#F9F9F8`, Textfarbe `#0A0A0A`, Schriftstack Inter/Syne (mit System-Fallback), Code in JetBrains Mono/monospace, Pill-Button (`border-radius:999px`, schwarz mit weißer Schrift); keine Cyan-Neon-Farben (`#00e5ff`) im Mail-Body.
- **AK-26** WHEN die Verifikations-Mail erzeugt wird, THE system SHALL im Datenschutzhinweis wahrheitsgemäß angeben, dass die E-Mail-Adresse bis zur Übertragung an die angemeldete Plattform zwischengespeichert wird.

### F. Login-Hint (Songbird)
- **AK-29** WHEN `/hhttps/oauth/authorize` mit `login_hint` und/oder `pseudonym` aufgerufen wird, THE system SHALL beide Werte in die Consent-Seiten-Parameter übernehmen (`login_hint` nur, wenn es syntaktisch eine E-Mail-Adresse ≤ 254 Zeichen ist — normalisiert per `normalizeEmail`; `pseudonym` via `sanitizePseudonym`), sonst SHALL es sie stillschweigend weglassen (kein Fehler, keine leeren Parameter).
- **AK-30** WHEN die Consent-Seite mangels Identität `relogin()` ausführt, THE system SHALL `login_hint` und `pseudonym` zusätzlich als eigene Query-Parameter an die Sign-in-Seite übergeben (`/?returnTo=…&login_hint=…&pseudonym=…`); das Consent-Feld `#pseudoInput` SHALL mit `pseudonym` vorbefüllt sein (per DOM, nicht per HTML-Interpolation).
- **AK-31** WHEN die Sign-in-Seite mit `login_hint` geladen wird, THE system SHALL das E-Mail-Panel öffnen, `#emailInput` (und bei Vorhandensein `#pseudoInput`) vorbefüllen, `/hhttps/email/send` genau einmal automatisch auslösen und das Code-Feld anzeigen; `login_hint`/`pseudonym` SHALL danach per `history.replaceState` aus der URL entfernt werden, `returnTo` bleibt erhalten.
- **AK-32** IF `login_hint` keine gültige E-Mail-Adresse ist oder das automatische Senden fehlschlägt, THEN the sign-in page SHALL das Panel mit vorbefüllten Feldern und einem Hinweis anzeigen, ohne Endlosschleife (kein erneutes Auto-Senden nach Reload, da die Parameter vor dem Senden entfernt werden).

## 4. Beispiele

**Beispiel 1 (AK-1/2/3):** Session S1 bestätigt `Anna@Example.org` → Anker für `anna@example.org`, `userId = U`. Session S2 (anderes Gerät) bestätigt ` anna@example.org ` → S2.userId = U. Beide Logins bei `client_id = ask` liefern `sub = HMAC(U|ask)`.

**Beispiel 2 (AK-7/8):** S1 bestätigt ohne Pseudonym → `iamhmn_k3j9x0q2wz`. S2 bestätigt dieselbe E-Mail mit Pseudonym „Anna“ → Session-Pseudonym bleibt `iamhmn_k3j9x0q2wz`.

**Beispiel 3 (AK-17/18):** Plattform mit Scope `openid email` löst Code ein → `id_token` enthält `email: "anna@example.org"`, `email_verified: true`, `passkey_verified: true` (falls Passkey), `verified_methods: ["email","passkey"]`, `preferred_username: "iamhmn_k3j9x0q2wz"`.

**Beispiel 4 (AK-23/24):** Eingabe `"482 913"` → akzeptiert als `482913`. Eingabe `"48291"` → 400.

## 5. Nicht-funktionale Anforderungen
- **Sicherheit:** E-Mail-Anker als HMAC-SHA256 mit serverseitigem Pepper (`HHTTPS_VERIFICATION_PEPPER`, Fallback mit Warnung); kein Auto-Linking ohne bestätigten Code; Pseudonym gewährt keinerlei Besitz.
- **Kompatibilität:** Bestehende Clients ohne Scope `email` erhalten weiterhin ihre bisherigen Claims plus die neuen Flags; bestehende Endpunkte behalten ihre Antwortform (nur additive Felder).
- **Migration:** Idempotente SQL-Migration (`sql/migration-phase-8-email-anchored-identity.sql`), safe to re-run.
- **Performance:** Anker-Auflösung = 1 indizierter Lookup pro Code-Bestätigung.

## 6. Offene Fragen (nicht blockierend, Annahmen dokumentiert)
- Annahme: „Issuer“ in der Anforderung meint die OAuth-Client-Plattform (ask.iamhmn.org, WordPress-Plugin), an die HHTTPS die Daten liefert.
- Annahme: Bestehende registrierte Clients bekommen `email` per Migration in `allowed_scopes` ergänzt (damit die Übertragung sofort möglich ist). Falls unerwünscht: Migrationsblock entfernen.
- Entscheidung Daniel 2026-09-12 (Abnahme, Lücke B-2): Das E-Mail-Gate wird für die Age-Endpunkte nachgezogen (AK-27, AK-28). Der Direkt-Bootstrap über eine EU-AV-Attestation ohne Session entfällt damit bewusst; wer Alter nachweisen will, bestätigt zuerst die E-Mail.
