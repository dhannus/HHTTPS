# Cleanup-Bericht — Frontend-Globals + 15-Rollen-Bereinigung

Jede Änderung einzeln, mit Begründung und Abhängigkeitsnachweis. Validierung nach
jedem Schritt: `node --check` + Inline-Script-Syntaxcheck + Modul-Load + Tests.

## A) Frontend (`public/index.html`)

### Entfernt (tot/vestigial — nachgewiesen)
| Symbol | Warum sicher entfernbar |
|---|---|
| `ROLES_LOCAL` (15-Rollen-Objekt, ~17 Zeilen) | Nur noch genutzt von: setLang-Loop + totem `selectRole`/`buildRoleTable` + Null-Anzeige der Override. Alle mitbereinigt. |
| `selectRole(id)` (Funktion) | **Nie aufgerufen** — nur in einem Kommentar erwähnt. Baute `.role-card`/`#rc-…`, die es im v0.5-DOM nicht gibt. |
| `buildRoleTable()` (Funktion + 2 Aufrufe) | `if(!#roleTableFull) return` — Element existiert nicht → immer No-op. |
| `selRole` (Variable + 9 Bezugsstellen) | Nach Entfernen von `selectRole` immer `null`. Server ignoriert `role` in v0.5. Override + E-Mail-Start + Reset entkoppelt. |
| alte `doDeclarRole` (78 Zeilen) | War bereits von `window.doDeclarRole` überschrieben (toter Zwilling). |

### Bewusst BEHALTEN (live — nicht angefasst)
| Symbol | Warum es bleibt |
|---|---|
| `buildRoleGrid()` | Umfunktioniert (kein Grid mehr); initialisiert die **Methoden-Tabs** (github/eudi). Live. |
| `selectVMethod`, `selVMethod`, `vData`, `VMETHOD_LABELS` | Treiben die Verifikationsmethoden-UI (`#veriOpts`/`#veriBox`/`#veriSlot`). Live. |
| `selAgeGroup` + Age-Selector | Orthogonale Altersangabe. Live. |
| `window.doDeclarRole` (Override) | Der einzige Live-Token-Pfad. Nur von `selRole`/`ROLES_LOCAL` **entkoppelt** (Rolle kommt jetzt aus `d.role`/`role_claim`). |

### Korrigiert
- 2 irreführende i18n-Strings „Bitte Rolle wählen" → Token-Wording (DE+EN).
- 1 veralteter Kommentar (`selectRole('developer')` → „GitHub method tab").

**Verifikation:** Inline-Script (115 K) `node --check` OK · keine verwaisten
Referenzen auf entfernte Symbole (nur 1 Kommentar, gefixt).

## B) Backend — 15-Rollen-Bereinigung

### `roles.js`
- `ROLES` von **15 → 1** reduziert: nur noch `citizen` (die Basis-Identität
  „verifizierter Mensch, keine Rolle"). Die 14 Berufe entfernt.
- `citizen` bleibt, weil ~10 Stellen `|| ROLES.citizen` als Default-Fallback
  nutzen — es ist kein Beruf, sondern der „Boden". Berufe sind jetzt ESCO-dynamisch.
- Header-Kommentar entsprechend aktualisiert.

### `server.js`
- **Maschinen-Registrierung** (`/hhttps/machine/register`): die einzige Stelle
  **ohne** Fallback (`if(!ROLES[role])` hätte jeden Bot-Beruf abgelehnt) auf
  `guardReservedRole` + `resolveRole` umgestellt: ein Bot darf eine freie Rolle
  angeben, **außer** einem geschützten Beruf (Arzt/Anwalt/…). Icon → 🤖.
- Alle übrigen 13 `ROLES[d.role]`-Stellen: **unverändert** — sie haben bereits
  `?.` oder `|| ROLES.citizen` und degradieren sauber (Profession-Token →
  Fallback citizen bzw. roh-id). Nachgewiesen: kein direkter `ROLES.<beruf>`-Zugriff.

### `roles.i18n.js` — NICHT geändert (nachweislich sicher)
- `localizeRole('developer')` → `null` (sauberer Guard). `localizeRoles()` →
  nur `citizen`. `roleLabel('developer','de')` → fällt elegant auf den deutschen
  Katalog zurück (`Entwickler`) — die 15 Katalog-Labels bleiben als harmlose
  Legacy-Anzeige. Kein Crash, kein Bruch.

### `email.js` — NICHT geändert
- `ROLES[role]?.icon || ''` — optional + Fallback. Sicher.

### Nicht angefasst: `privacy-pass/keys.js`
- Hat ein **eigenes**, separates `ROLES`-Array (eigener Import). Nichts mit
  `roles.js` zu tun. Bewusst unberührt.

## Verbleibende Kleinigkeit (kein Bruch, optional)
- `/hhttps/roles` und `/hhttps/info` `supported_roles` liefern jetzt nur noch
  `citizen` (statt 15). Korrekt für ESCO-only, aber wenn du willst, zeige ich dort
  künftig die `reserved_registry` + einen Pointer auf `/hhttps/esco/suggest` an —
  sag Bescheid, dann liefere ich den additiven Patch.

## Gesamtvalidierung (Endstand)
```
node --check: roles.js roles.i18n.js email.js server.js
              roles.taxonomy.js roles.eaa.js
              eudi-verifier/backend-client.js eudi-verifier/index.js   → alle ✓
Inline-Script index.html (115 K)                                       → ✓
Modul-Load + degradierte Pfade                                         → ✓
roles.taxonomy.test.mjs                                                → 9/9 ✓
```
