# HHTTPS Browser Extension v1.2.0

Deine HHTTPS-Identität als Browser-Brieftasche. Verifiziert dich automatisch beim Login auf `hhttps.org`, hält deinen Token frisch, zeigt dir deinen verifizierten Status in der Toolbar — egal auf welcher Seite du gerade bist.

## Was sie tut

| Feature | Beschreibung |
|---|---|
| **Identität speichern** | Token + Refresh-Token werden bei deinem ersten Login auf hhttps.org automatisch in der Extension abgelegt |
| **Auto-Refresh** | Der Token wird 5 Min vor Ablauf automatisch erneuert — ohne dass du was tust |
| **Status-Badge** | Grüner Haken auf dem Extension-Icon in der Toolbar zeigt: du bist verifiziert |
| **Identitäts-Tooltip** | Hover über das Icon zeigt deine Rolle + Trust-Score |
| **Mehrere Rollen** | Wenn du dich z.B. als Bürger UND Entwickler registriert hast, kannst du im Popup zwischen ihnen wechseln |
| **Signatur-Snippet** | Ein-Klick-Kopie deiner Identität als Textsignatur — kannst du in Kommentare einfügen |
| **Logout + Revoke** | Token wird beim Server widerrufen, aus dem Browser gelöscht |

## So funktioniert die Auto-Magie

1. Du gehst auf `hhttps.org` und loggst dich mit deinem Passkey ein
2. Du wählst eine Rolle (Bürger / Entwickler / etc.) und bekommst einen Token
3. Die Extension fängt diesen Token automatisch ab (per `postMessage` von hhttps.org)
4. Ab jetzt: jedes Mal wenn du das Extension-Icon anklickst, siehst du dein verifiziertes Profil mit Rollen-Icon, Trust-Score und Token-Status
5. Token wird automatisch erneuert, du musst nichts tun

## Installation

### Chrome / Edge / Brave / Arc / Opera

1. Extension entpacken oder ZIP herunterladen
2. `chrome://extensions` öffnen (Edge: `edge://extensions`, etc.)
3. "Entwicklermodus" oben rechts aktivieren
4. "Entpackte Erweiterung laden" → den `extension/`-Ordner wählen
5. Extension in der Toolbar festpinnen

### Firefox

1. `about:debugging#/runtime/this-firefox` öffnen
2. "Temporäre Erweiterung laden..."
3. Die `manifest.json` aus dem Ordner auswählen

Hinweis: In Firefox muss die Extension nach jedem Neustart neu geladen werden, bis sie via `addons.mozilla.org` verfügbar ist.

## Berechtigungen erklärt

| Permission | Wofür |
|---|---|
| `storage` | Speichert deine Tokens lokal im Browser |
| `activeTab` | Liest den HHTTPS-Status der aktuell aktiven Seite |
| `alarms` | Plant Token-Refresh-Termine 5 Min vor Ablauf |
| `host: hhttps.org` | Auto-Login-Capture nur auf hhttps.org |
| `<all_urls>` (content) | Zeigt HHTTPS-Status auf anderen Seiten an (passive Anzeige) |

**Die Extension sendet KEINE Daten an externe Server außer:**
- `https://hhttps.org/hhttps/token/refresh` (für Auto-Refresh)
- `https://hhttps.org/hhttps/revoke` (wenn du "Logout" klickst)

Keine Telemetrie. Keine Analytics. Kein Tracking.

## Nutzung

### Identität bekommen

1. Klick aufs Extension-Icon → siehst "Nicht eingeloggt" + "Bei hhttps.org einloggen"-Button
2. Button klicken → öffnet hhttps.org in neuem Tab
3. Passkey-Login + Rolle wählen
4. Automatisch zurück zur Extension — fertig, du bist eingeloggt

### Identität nutzen

- **Status anschauen**: Klick aufs Icon zeigt deine Rolle, Trust-Score, Token-Verbleib
- **Token kopieren**: Button "⎘ Token" — für API-Tests in curl/Postman
- **Snippet kopieren**: Button "📋 In Zwischenablage kopieren" — füge deine Identität in einen Forum-Kommentar ein. Andere mit Extension werden in einer späteren Version automatisch ein verifiziertes Siegel sehen (Phase 2).
- **Refresh manuell**: Button "↻ Refresh" — holt neuen Token vom Server
- **Logout**: Button "↪ Logout" — Token wird beim Server widerrufen, lokal gelöscht

### Mehrere Rollen

Wenn du dich als "Entwickler" eingeloggt hast und später nochmal als "Bürger" registrierst (oder ein anderer Mensch sich auf demselben Browser einloggt), siehst du im Popup einen Rollen-Wechsler. Klick auf eine andere Rolle → Extension zeigt dann diese Identität.

## Roadmap

| Phase | Status | Was |
|---|---|---|
| Phase 1 (du bist hier) | ✓ Fertig | Identitäts-Brieftasche, Auto-Capture, Auto-Refresh, Rollen-Switch |
| Phase 2 | Geplant | Inline-Signaturen auf jeder Seite: füge dein Snippet ein, andere mit Extension sehen ein schwebendes Siegel |
| Phase 3 | Geplant | OAuth-Flow: Drittseiten können "Mit HHTTPS einloggen"-Buttons bauen |
| Phase 4 | Geplant | Demo-Plattform `forum.hhttps.org` wo HHTTPS-Login ausprobiert werden kann |

## Entwicklung & Debugging

- **Service Worker Konsole**: `chrome://extensions` → Extension finden → "Service Worker prüfen"
- **Popup-Konsole**: Rechtsklick aufs Popup → "Untersuchen"
- **Content-Script-Konsole**: Auf der jeweiligen Seite DevTools öffnen (F12) → Console
- Logs starten mit `[HHTTPS Extension]` zur leichteren Filterung

## Lizenz

EUPL-1.2 — selbe wie das HHTTPS-Protokoll.
[github.com/dhannus/HumanProof](https://github.com/dhannus/HumanProof)
