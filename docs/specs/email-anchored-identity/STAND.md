# STAND `email-anchored-identity`
- [x] Gate 1: Spec freigegeben (Daniel) — EARS-Fassung in requirements.md
- [x] Plan: design.md, tasks.md
- [x] Build T0–T7 (je ein Commit; Gates grün)
- [x] Review (4 Reviewer, 56 Findings → review.md) → Verifikation (verifikation.md) → Fix-Runde 1 (F-1..F-8 Sicherheit) + Runde 2 (F-9..F-11)
- [x] Testprotokoll (testprotokoll.md): AK-1..AK-26 = 26 PASS / 0 FAIL / 0 OFFEN; 149 Tests (145 pass, 4 todo für Befunde außerhalb der AK-Liste); ESLint 0 Errors
- [x] Abnahme (abnahme.md): **ABGENOMMEN**
- [x] Gate 2: Freigabe Daniel (2026-09-12) → Nach-Task T8 (AK-27/28) umgesetzt, Issues #6–#18 angelegt, PR erstellt (Merge nur durch Daniel)
Offen: Bug #7 (machine/register-Crash, separater Fix). Annahme „Issuer = registrierte Plattformen“ von Daniel bestätigt.
Umgebung: lokale Postgres 16 unter /var/lib/pgtest; Testlauf `cd server && TEST_PG_HOST=/var/lib/pgtest npm test && npm run lint`.
Branch: `claude/kind-pasteur-kweqf1` (Umgebungsvorgabe, ersetzt feat/<slug>).
