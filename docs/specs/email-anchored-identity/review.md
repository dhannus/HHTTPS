# Review-Findings `email-anchored-identity` (Diff main...HEAD, Stand 2ec40c5)

Legende: Schwere laut Reviewer. Status wird vom Verifikator in verifikation.md gesetzt.

## rev-korrektheit
- K-1 | hoch | server.js /email/send + confirm-code/verify | E-Mail-Kontext `email:<sid>` (challenges) wird bei jedem /email/send überschrieben, alte email_verifications-Zeilen bleiben gültig → Code von Adresse A bindet Session an Kontext-Adresse B (fremder Anker). Vorschlag: emailHash der konsumierten Verifikationszeile gegen Kontext prüfen.
- K-2 | hoch | server.js /email/verify | `result.sessionId` wird nicht mit `req.query.session` verglichen → Magic-Link bindet beliebige Session. Vorschlag: session_mismatch-Fehler.
- K-3 | hoch | server.js /webauthn/auth/finish | `userId: stored.userId || cred.userId` — Body-userId aus auth/start gewinnt über cred.userId (AK-5 verletzt). Vorschlag: `userId: cred.userId`, Mismatch → 400/401; priorMerge nur bei prior.userId === cred.userId.
- K-4 | mittel | public/index.html passkeyRun | Wiederkehrender Nutzer: register/start mit excludeCredentials → InvalidStateError → Passkey unbenutzbar. Vorschlag: bei vorhandenen Credentials direkt auth/start.
- K-5 | mittel | server.js confirm-code/bindSessionToEmailAnchor, db.resolveOrCreate | Session bereits verankert/mit Credentials: neue Adresse → user_id UNIQUE-Fehler 500; bestehender anderer Anker → inkonsistente Session (credential von U1, userId U2). Vorschlag: 409 email_already_bound / identity_conflict.
- K-6 | mittel | db.js ensurePhase8Schema, server.js main() | Boot-Migration fire-and-forget, nicht awaited, Fehler verschluckt. Vorschlag: in main() awaiten, bei Fehler exit(1).
- K-7 | niedrig | public/index.html #emailCode maxlength=6 | Einfügen von "123 456" wird auf 6 Zeichen gekürzt → AK-23 im UI nicht erreichbar. Vorschlag: maxlength entfernen, client-seitig normalisieren.
- K-8 | niedrig | server.js /oauth/approve | scope wird nicht gegen client.allowed_scopes geprüft (nur in /authorize). Vorschlag: gleicher Check in approve.
- K-9 | niedrig | public/index.html | Rückkehr vom Magic-Link (`?email_verify=success&session=…`) wird nicht ausgewertet → Methoden bleiben disabled. Vorschlag: URL-Params lesen, sessionId übernehmen, markConfirmed('email').

## rev-sicherheit
- S-1 | kritisch | = K-1 (Anker-Übernahme ohne Code-Besitz des Opfers via zweitem /email/send).
- S-2 | kritisch | = K-3 + zusätzlich: rohe userId ist stabil und wird verteilt (ouid im OAuth-Refresh-JWT, Antworten). Vorschlag: cred.userId erzwingen; priorMerge nur bei gleicher userId.
- S-3 | hoch | = K-2 + Pre-Hijacking per Klick des Opfers; Empfehlung: Link-Pfad ohne Anker-Bindung oder Session-Abgleich + CTA aus Mail entfernen.
- S-4 | hoch | email.js createTransport | Fail-open: ohne SMTP und ohne sendmail liefert /email/send devCode+devToken an den Aufrufer (Produktion!). Vorschlag: Dev-Mode nur bei `EMAIL_DEV_MODE=1` und NODE_ENV!=='production', sonst 503.
- S-5 | mittel | identity.js Pepper-Fallback 'dev-pepper' | In Produktion ohne Pepper ist der Anker wörterbuch-angreifbar; Rotation trennt alle Anker still. Vorschlag: in production ohne Pepper beim Boot werfen (wie external-verify.js).
- S-6 | mittel | = K-5 (Cross-Anker-Merge, credential_id bleibt nach Rebinding).
- S-7 | mittel | email.js renderVerificationEmail, server.js /email/send `role` | `role` aus Body ungeprüft → roleLabel gibt Rohstring → HTML-Injection in Body/Subject der Mail (Phishing vom vertrauenswürdigen Absender). Vorschlag: role whitelisten (ROLES), label/domain escapeHtml.
- S-8 | mittel | Cache 7 Tage nie bei Transfer gelöscht, Klartext auch in challenges; Datenschutzhinweis „bis zur Übertragung“ nicht ganz wahr. Vorschlag: Hinweis „bis zu 7 Tage bzw. bis zur Übertragung“ + D5 dokumentiert challenges-Kontext.
- S-9 | niedrig | OAuth-Refresh-JWT trägt email im Klartext 30 Tage; approve ohne allowed_scopes-Check (= K-8).
- S-10 | niedrig | Migration `allowed_scopes += email` läuft bei jedem Boot (Opt-out wirkungslos). (= W-11)

## rev-performance
- P-1 | mittel | db.js authCodes.claim | 4 Roundtrips + Pool-Client statt einem Statement; Vorschlag: `WITH old AS (SELECT email …) UPDATE … RETURNING a.*, (SELECT email FROM old) AS email_before`.
- P-2 | mittel | db.js ensurePhase8Schema | DDL (ACCESS EXCLUSIVE auf sessions/authorization_codes) + UPDATE oauth_clients + OWNER TO bei jedem Boot; nicht awaited vor listen. Vorschlag: Applied-Check (information_schema) vor Ausführung; awaiten; UPDATE aus Boot-Pfad.
- P-3 | niedrig | confirm-code 6 sequentielle Roundtrips; Vorschlag Promise.all für upsert+delete.
- P-4 | niedrig | sessions.create schreibt pseudonym nicht → Extra-UPDATE an 3 Stellen. Vorschlag: pseudonym in create.
- P-5 | niedrig | approve: Cache-Read auch ohne Scope email/ohne Pseudonym-Bedarf.
- P-6 | niedrig | JWT-Wachstum; *_verified-Flags redundant zu verified_methods.
- P-7 | niedrig | Tests: zufällige Ports (Kollision ~1.5 %), 6 Server-Boots parallel, 8 parallele Migrationen.

## rev-wartbarkeit
- W-1 | hoch | server.js 4× inline Pseudonym-Sanitizing statt sanitizePseudonym.
- W-2 | hoch | Identity-Claims-Aufbau 3× (code-grant, refresh-grant, userinfo). Vorschlag: buildIdentityClaims in identity.js.
- W-3 | mittel | Token-Surface (methodFlags/pseudonym/domain) 3× in role/declare, eid/upgrade, token/refresh.
- W-4 | mittel | = P-4.
- W-5 | niedrig | 15-min-TTL doppelt (email.js / server.js).
- W-6 | niedrig | Test-Helfer (rnd, freshEmail, newSession, decodeJwt, cleanup, PEPPER) je Datei kopiert.
- W-7 | hoch | `pseudo:<code>`-Challenge in approve/token ist tot (Code-Spalte deckt alle Fälle). Vorschlag: entfernen, D3 anpassen.
- W-8 | mittel | /session/email/start toter Duplikat-Endpoint; Kommentar an /session/start widerspricht AK-14.
- W-9 | niedrig | `&pseudonym=` im Magic-Link-Redirect liest niemand.
- W-10 | niedrig | identityAnchors.getByUserId nur in Tests genutzt.
- W-11 | hoch | = P-2/S-10 (Boot-Migration mit Datenupdate, Opt-out wirkungslos).
- W-12 | hoch | .env.example ohne HHTTPS_VERIFICATION_PEPPER (trägt jetzt Identitätsstabilität).
- W-13 | mittel | Kein Lockfile, npm vs pnpm in Doku; README ohne Test-Abschnitt.
- W-14 | mittel | email.js Header „Zero personal data storage“/„legacy flow“ veraltet.
- W-15 | mittel | docs/security.md, docs/spec.md, issueRefreshToken-Kommentar „zero-PII“ unwahr (Cache).
- W-16 | mittel | README/docs/oauth-integration.md: Scope email + neue Claims fehlen.
- W-17 | mittel | CHANGELOG ohne Phase-8-Eintrag (Breaking: register/start braucht sessionId; 403-Gates; Migration; Env).
- W-18 | niedrig | /hhttps/info Endpoint-Katalog veraltet.
- W-19 | mittel | register/start ohne sessionId → 403 email_verification_required statt 400 sessionId required.
- W-20 | niedrig | Cache-TTL fest 7 Tage vs. D5 „= REFRESH_TTL“.
- W-21 | niedrig | Fehlerformate uneinheitlich (email_context_missing/anchor_bind_failed ohne detail).
- W-22 | niedrig | challenges-Tabelle als E-Mail-Kontext zweckentfremdet, nicht in design.md.
- W-23 | mittel | = P-7 (Ports).
- W-24 | mittel | Integrationstests räumen unvollständig auf (email-code feste Adressen; sessions/verifications/challenges/refresh_tokens).
- W-25 | mittel | db-phase8-Test führt Migration gegen geteilte DB aus (Seiteneffekt allowed_scopes aller Clients).
- W-26 | mittel | signin-page.test.mjs koppelt an Formatierung (Regex auf Funktionsrümpfe).
- W-27 | niedrig | Test-DB-Konfig doppelt in helpers.
- W-28 | niedrig | verifyEmailCode normalisiert doppelt.
- W-29 | niedrig | CSS-Klasse .pseudo ohne Regel.
- W-30 | niedrig | Testvoraussetzungen nur in STAND.md.
