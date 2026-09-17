# Projekt-Review 2026-09 — Abschlussbericht

Basis: `main` @ `bf0a82b` · Fix-Wellen: PR #252, #253, #254, #255

## 1. Was geprüft wurde

Vollständiger Review des Repositories nach dem Songbird-Review-Agentenpaket v2: acht Arbeitspakete,
je vier Reviewer (Korrektheit, Sicherheit, Performance, Wartbarkeit), anschließend ein Verifikator je
Paket, der jedes Finding am Code nachgeprüft und, wo möglich, reproduziert hat.

| | |
|---|---|
| Gemeldete Findings | 443 |
| Bestätigt | **370** |
| Verworfen | 2 |
| Als Duplikat zusammengeführt | 71 |
| Davon S1 (kritisch) | 7 |
| Davon S2 (hoch) | 30 |

## 2. Was behoben wurde

| Welle | PR | Findings | Inhalt |
|---|---|---|---|
| 0 | #252 | 38 | Privacy Pass entfernt, strikte E-Mail-Syntax, Domain-Label-Grenzen, Webhooks abgesichert, XSS-Seite gelöscht |
| 1 | #253 | 20 | Sign-in-Kernflow, Token-Lifecycle, Widerruf, Migrationsläufer |
| 2 | #254 | 94 | Betrieb und Härtung, CI-Gates, Abhängigkeiten |
| 3 | #255 | 51 | Wartbarkeit, Modularisierung, CSP ohne `unsafe-inline` |

**Alle 7 S1 und 30 S2 sind erledigt oder bewusst zurückgestellt** (siehe Abschnitt 4).

## 3. Messbare Veränderung

| Kennzahl | vorher | nachher |
|---|---|---|
| Tests (unit + integration) | 203 | 548 |
| E2E-Tests | 7 | 6 |
| ESLint | 0 Fehler, 59 Warnungen | 0 Fehler, 0 Warnungen |
| `npm audit` | 5 (1 high, 3 moderate, 1 low) | 2 (1 moderate, 1 low, beide unerreichbar) |
| CI | nur Syntax-Checks | Tests, Lint, Audit, Shell-Syntax |
| Inline-Skripte in ausgelieferten Seiten | 27 `onclick` + 675-Zeilen-Skript | keine |

## 4. Bewusst offen

| Issue | Grund |
|---|---|
| #133 (PID-Trust-Liste) | Code vorbereitet, Aktivierung nach dem EUDIPLO-Update (Operator) |
| #158, #32 (Keystore-Passwort) | Rotation erfolgt manuell auf dem Server |
| #159 (`login_hint` versendet automatisch) | Gewünschtes Verhalten aus AK-31 (Songbird-Integration) |
| #210 (Cross-Device-Bindung) | Serverseitig allein nicht lösbar, braucht einen Transaktionscode im Wallet-Request |
| #191, #185, #172, #234, #213 | Betreffen Aufrufer über Paketgrenzen oder veröffentlichte Claim-Namen; über eine Refactoring-Welle hinaus |

## 5. Drei Funde, die ohne den Review nicht aufgefallen wären

1. **`POST /hhttps/signatures` war seit v0.5 vollständig kaputt.** Der Handler schrieb eine Rolle in
   eine Pflichtspalte, die Access-Tokens seit v0.5 nicht mehr tragen; der Datenbankfehler kam beim
   Client als 401 an. Kein Nutzer konnte eine Textsignatur anlegen. Gefunden beim Nachrüsten der
   fehlenden Tests, nicht beim Lesen des Codes.
2. **Der Passkey-Login verwarf die E-Mail-Verifikation.** Der Standard-Flow endete in 403. Der
   bestehende E2E-Test war grün, weil er einen Schritt vor dem Fehler aufhörte.
3. **Ein Adressformat mit Kommentar-Klammer** wurde an eine fremde Domain zugestellt, aber als
   Behördenadresse mit +40 Trust bewertet.

## 6. Grenzen

Statischer Review mit gezielten Reproduktionen gegen einen lokalen Testserver und eine Testdatenbank.
Kein Penetrationstest gegen die Produktion, keine Lastmessung. Externe Dienste (GitHub-OAuth, ESCO,
EUDIPLO, SMTP) wurden gestubbt, nicht angebunden. Ob das produktive EUDIPLO eine Trust-List außerhalb
des Repositories hält, konnte nicht geprüft werden.

## 7. Deploy

`docs/deploy/RUNBOOK-review-2026-09.md` (auf den Wellen-Branches) beschreibt je Welle, was sich am
Betrieb ändert, welche Migration wann läuft und was vorher in der `.env` stehen muss. Der wichtigste
Punkt: **`PAIRWISE_SECRET` muss vor dem Neustart gesetzt sein**, sonst startet der Server in
Produktion nicht mehr.

## 8. Empfohlene Merge-Reihenfolge

Die Wellen bauen aufeinander auf. Reihenfolge: #252 → #253 → #254 → #255. Jeder PR hat als Base den
Vorgänger-Branch; nach dem Merge des Vorgängers stellt GitHub die Base automatisch auf `main` um.
Der Review-PR #35 (dieses Verzeichnis) kann unabhängig davon gemergt werden.
