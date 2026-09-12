# STAND `email-anchored-identity`
- [x] Gate 1: Spec freigegeben (Daniel) — EARS-Fassung in requirements.md
- [x] Plan: design.md, tasks.md
- [x] Build T0–T7 (je ein Commit; Gates grün)
- [x] Review (4 Reviewer, 56 Findings → review.md) → Verifikation (verifikation.md) → Fix-Runde 1 (F-1..F-8 Sicherheit) + Runde 2 (F-9..F-11)
- [x] Testprotokoll (testprotokoll.md): AK-1..AK-26 = 26 PASS / 0 FAIL / 0 OFFEN; 149 Tests (145 pass, 4 todo für Befunde außerhalb der AK-Liste); ESLint 0 Errors
- [x] Abnahme (abnahme.md): **ABGENOMMEN**
- [ ] Gate 2: Daniel sieht Abnahme-Protokoll → MR (GitHub-PR, kein glab) — wartet auf Freigabe
Offene Entscheidungen für Daniel: B-1 (vorbestehender Crash /hhttps/machine/register, außerhalb Scope), B-2 (Age-Pfade ohne E-Mail-Gate: Spec-Entscheidung), Annahmen §6 (Issuer = OAuth-Client; `email`-Scope für Bestandsclients nur per Operator-Migration).
Umgebung: lokale Postgres 16 unter /var/lib/pgtest; Testlauf `cd server && TEST_PG_HOST=/var/lib/pgtest npm test && npm run lint`.
Branch: `claude/kind-pasteur-kweqf1` (Umgebungsvorgabe, ersetzt feat/<slug>).
