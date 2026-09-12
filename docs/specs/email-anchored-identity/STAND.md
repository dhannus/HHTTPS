# STAND `email-anchored-identity`
- [x] Gate 1: Spec freigegeben (Daniel) — EARS-Fassung in requirements.md
- [x] Plan: design.md, tasks.md
- [x] Build T0–T7 (Commits 6c3a390..2ec40c5; Gates: 67 Tests grün, ESLint 0 Errors)
- [ ] Review (rev-korrektheit, rev-sicherheit, rev-performance, rev-wartbarkeit) → Verifikation → Fix
- [ ] Testprotokoll
- [ ] Abnahme
- [ ] Gate 2 / MR
Nächster Schritt: Tester (testprotokoll.md), dann Abnahme.
Umgebung: lokale Postgres 16 unter /var/lib/pgtest (Socket-Dir), DB `hhttps`, User `hhttps`, trust. Testlauf: `cd server && TEST_PG_HOST=/var/lib/pgtest pnpm test && pnpm lint`.
Branch: `claude/kind-pasteur-kweqf1` (Umgebungsvorgabe, ersetzt feat/<slug>).
