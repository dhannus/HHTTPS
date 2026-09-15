# STAND `email-anchored-identity`
- [x] Gate 1: Spec freigegeben (Daniel) — EARS-Fassung in requirements.md
- [x] Plan: design.md, tasks.md
- [x] Build T0–T7 (je ein Commit; Gates grün)
- [x] Review (4 Reviewer, 56 Findings → review.md) → Verifikation (verifikation.md) → Fix-Runde 1 (F-1..F-8 Sicherheit) + Runde 2 (F-9..F-11)
- [x] Testprotokoll (testprotokoll.md): AK-1..AK-26 = 26 PASS / 0 FAIL / 0 OFFEN; 149 Tests (145 pass, 4 todo für Befunde außerhalb der AK-Liste); ESLint 0 Errors
- [x] Abnahme (abnahme.md): **ABGENOMMEN**
- [x] Gate 2: Freigabe Daniel (2026-09-12) → Nach-Task T8 (AK-27/28) umgesetzt, Issues #6–#18 angelegt, PR erstellt (Merge nur durch Daniel)
Bug #7 behoben (im PR). Folgetasks #22, #23, #25, #26, #27 umgesetzt (im PR); offen #20, #21, #24. WebAuthn-User-Handle-Bug (Buffer→String) gefixt. Endstand: 173 Tests + 6 E2E grün, ESLint 0 Errors, CI grün.
Umgebung: lokale Postgres 16 unter /var/lib/pgtest; Testlauf `cd server && TEST_PG_HOST=/var/lib/pgtest npm test && npm run lint`.
Branch: `claude/kind-pasteur-kweqf1` (Umgebungsvorgabe, ersetzt feat/<slug>).

## Session-Protokoll (2026-09-12 bis 2026-09-14)
| Schritt | Ergebnis | Wo nachlesen |
|---|---|---|
| Spec → Plan | requirements.md (AK-1..28), design.md, tasks.md | dieses Verzeichnis |
| Build T0–T8 | Issues #8–#18, je ein Commit | `git log --grep='entwickler'` |
| Review/Verifikation/Fix | 56 Findings, F-1..F-11 | review.md, verifikation.md |
| Test + Abnahme | 28/28 PASS, ABGENOMMEN | testprotokoll.md, abnahme.md |
| Folgetasks im PR | #22 #23 #25 #26 #27, Bug #7 | Issue-Kommentare, CHANGELOG |
| PR #19 | gemerged 2026-09-14 (Merge-Commit 2b1dd61) | GitHub |
| Deploy srv1421412 | Runbook + Skript, PR #28/#29, Symlink-Layout `/var/www/hhttps → /var/www/HHTTPS/server` | docs/deploy/RUNBOOK-srv1421412-phase8.md |
| Nachlauf | #30 (Node nicht als root), #31 (varchar(128), PR #33), #32 (Keystore-Passwort im Compose) | GitHub Issues |
| Offen | #20, #21, #24, #30, #32 | GitHub Issues |
