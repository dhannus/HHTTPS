# HHTTPS Browser Extension

> Die Versionsnummer steht ausschliesslich in `manifest.json` und wird im Popup
> aus `chrome.runtime.getManifest().version` angezeigt (AP8-48, #249).

Deine HHTTPS-Identität als Browser-Brieftasche. Verifiziert dich automatisch beim Login auf `hhttps.org`, hält deinen Token frisch, zeigt dir deinen verifizierten Status in der Toolbar — egal auf welcher Seite du gerade bist.

## Was sie tut

| Feature | Beschreibung |
|---|---|
| **Identität speichern** | Token + Refresh-Token werden bei deinem ersten Login auf hhttps.org automatisch in der Extension abgelegt |
| **Auto-Refresh** | Der Token wird 5 Min vor Ablauf automatisch erneuert — ohne dass du was tust |
| **Status-Badge** | Grüner Haken auf dem Extension-Icon in der Toolbar zeigt: du bist verifiziert |
| **Identitäts-Tooltip** | Hover über das Icon zeigt deine Rolle + Trust-Score |
| **Mehrere Rollen** | Wenn du dich z.B. als Bürger UND Entwickler registriert hast, kannst du im Popup zwischen ihnen wechseln |
| **Signieren per Rechtsklick** | Ein Kontextmenü-Eintrag in jedem Textfeld fügt eine Signatur (`#hhttps:s:…`) ein — nie den Token selbst. Ob sie nur an die Domain oder zusätzlich an den exakten Text gebunden wird, stellst du im Popup unter „Signatur-Modus" ein |
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
| `storage` | Speichert deine Identitäten (Token, Refresh-Token, Rolle) und die Signatur-Modus-Einstellung lokal im Browser |
| `alarms` | Plant Token-Refresh-Termine 5 Min vor Ablauf |
| `contextMenus` | Der Eintrag „Mit HHTTPS signieren" im Rechtsklick-Menü von Textfeldern |
| `host: hhttps.org` | Auto-Login-Capture und alle Server-Aufrufe (Refresh, Revoke, Signieren, Siegel-Prüfung) |
| `<all_urls>` (content script) | Zeigt HHTTPS-Siegel auf beliebigen Seiten an und fügt Signaturen in Textfelder ein |

## Was die Extension an hhttps.org sendet

Ausschliesslich an `https://hhttps.org` (bzw. an den Issuer, der in deiner
Identität steht) — nirgendwo sonst hin, keine Telemetrie, keine Analytics:

| Wann | Endpunkt | Was geht raus |
|---|---|---|
| automatisch, 5 Min vor Ablauf, und beim Klick auf „↻ Refresh" | `POST /hhttps/token/refresh` | dein Refresh-Token |
| beim Klick auf „↪ Logout" | `POST /hhttps/revoke` | dein Access-Token |
| wenn du im Rechtsklick-Menü signierst | `POST /hhttps/signatures` | **der zu signierende Text**, der Modus und die Domain der Seite, plus dein Token im `HHTTPS-Token`-Header |
| auf **jeder** Seite, auf der HHTTPS-Siegel (`#hhttps:s:…`) vorkommen | `POST /hhttps/signatures/batch` | die gefundenen Siegel-Slugs und der Hostname der Seite |

Zwei Berechtigungen stehen bewusst NICHT mehr in der Liste: `activeTab` und
`scripting` hat die Extension nie genutzt und sie wurden entfernt (AP8-21, #249).

Die letzten beiden Zeilen der Tabelle sind der Grund, warum die frühere Formulierung
„sendet KEINE Daten ausser token/refresh und revoke" falsch war (AP8-46, #243).
Der Seiteninhalt selbst wird nie übertragen — beim Signieren nur der Text, den
du signierst, bei der Prüfung nur Slugs und Hostname.

## Nutzung

### Identität bekommen

1. Klick aufs Extension-Icon → siehst "Nicht eingeloggt" + "Bei hhttps.org einloggen"-Button
2. Button klicken → öffnet hhttps.org in neuem Tab
3. Passkey-Login + Rolle wählen
4. Automatisch zurück zur Extension — fertig, du bist eingeloggt

### Identität nutzen

- **Status anschauen**: Klick aufs Icon zeigt deine Rolle, Trust-Score, Token-Verbleib
- **Token kopieren**: Button "⎘ Token" — für API-Tests in curl/Postman
- **Signieren**: Rechtsklick in ein Textfeld → „Mit HHTTPS signieren". Es wird eine kurze Signatur eingefügt, nie der Bearer-Token (der gehört nur in API-Tests, nicht in öffentliche Beiträge). Der Modus kommt aus dem Popup: 🛡️ Identität (nur Domain, Text darf danach bearbeitet werden) oder 🔒 Text-gebunden (Änderungen am Text machen die Signatur ungültig).
- **Refresh manuell**: Button "↻ Refresh" — holt neuen Token vom Server
- **Logout**: Button "↪ Logout" — Token wird beim Server widerrufen, lokal gelöscht

### Mehrere Rollen

Wenn du dich als "Entwickler" eingeloggt hast und später nochmal als "Bürger" registrierst (oder ein anderer Mensch sich auf demselben Browser einloggt), siehst du im Popup einen Rollen-Wechsler. Klick auf eine andere Rolle → Extension zeigt dann diese Identität.

## Roadmap

| Phase | Status | Was |
|---|---|---|
| Phase 1 (du bist hier) | ✓ Fertig | Identitäts-Brieftasche, Auto-Capture, Auto-Refresh, Rollen-Switch |
| Phase 2 | Geplant | Inline-Signaturen auf jeder Seite: signiere per Kontextmenü, andere mit Extension sehen ein schwebendes Siegel |
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
