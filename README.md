# AutoScylla

Ein **x64dbg-Plugin**, das den Scylla-Workflow (Dump + Import-Reconstruction)
automatisiert und **echte Rückgabewerte** liefert. Der komplette Ablauf
`Modul → OEP → IAT → Imports → Dump → Fix → Rebuild` läuft mit einem Aufruf.

> **Status: M1–M8 umgesetzt und verifiziert** (Stand 2026-11-19).
> Getestet gegen notepad.exe am System-Breakpoint **per TCP und über das
> Plugins-Menü**: `imports=260/0; relocs=4`.
> **UPX-Sample verifiziert:** echte IAT gefunden (`iat=0x8290/44`),
> Import-Directory neu gebaut, `imports=43/0` (statt 13 Stub-Imports),
> Relocs (42) und OEP gesetzt.
>
> **Bekannte Limitierung:** Der UPX-Dump ist analysefähig (REA/Ghidra),
> aber noch **nicht direkt startbar** — der Windows-Loader bricht bei der
> Verarbeitung veralteter Strukturen des gepackten Headers mit `0xC0000005`
> ab, auch wenn Import/Reloc/TLS korrigiert sind.

## Inspiration / Danksagung

Dieses Projekt ist inspiriert von **Scylla** (x64dbg/Scylla, ursprünglich von
**Nico Bendlin / Ahmadmansoor und den Scylla-Mitautoren**), dem bewährten
Import-Reconstructor für x64dbg. AutoScylla ist eine **eigene, unabhängige
Implementierung** in C++ gegen die x64dbg-Plugin-SDK — kein Fork und kein
abgeleiteter Code der Scylla-Sourcen. Ziel ist die Automatisierung des
manuellen Scylla-Workflows mit Rückgabewerten (für MCP/Automatisierung).

Original: https://github.com/x64dbg/Scylla (GPL-3.0) — danke für die Idee und
die jahrelange Vorarbeit bei Import-Reconstruction. AutoScylla steht bewusst
unter **MIT**, um die Integration in eigene Toolchains zu erlauben.

## Features

- **Dump**: liest das komplette gemappte Modul-Image via `DbgMemRead` und
  schreibt eine saubere File-Layout-PE (Sections, Header, Relocs).
- **Import-Reconstruction**: löst jede IAT-Platzhalter-Adresse über
  `LoadLibraryA` + `GetProcAddress` auf (nach-name und nach-Ordinal).
- **IAT-Suche für gepackte Images**: wenn der Header nur wenige Imports liefert
  (UPX-Fall), wird die echte IAT im Speicher gefunden (Pointer-Arrays mit
  Zero-Trennern), jeder Eintrag über die Export-Tabellen der geladenen DLLs in
  `DLL!Funktion` zurückübersetzt und ein **neues Import-Directory** in den Dump
  geschrieben (neue Deskriptoren + INT + Namen, `FirstThunk` = echte IAT).
- **Reloc-Rebuild für gepackte Images**: scannt das Image nach 8-Byte-Pointern
  in den eigenen Bildbereich und erzeugt `IMAGE_REL_BASED_DIR64`-Blöcke.
- **OEP-Setzung**: optionaler `oep`-Parameter (RVA oder VA) setzt
  `AddressOfEntryPoint` im Dump — auch im `Fix Dump...`-Dialog verfügbar.
- **Reloc-Validierung**: zählt wohlgeformte Base-Relocation-Blöcke.
- **Loopback-Control-Server** (M4): JSON-line TCP auf `127.0.0.1:27043`
  mit Token-Schutz — liefert **echte Rückgabewerte**, unabhängig vom
  Debug-State / der Command-Box.
- **Minimales GUI** (M5): `Plugins → AutoScylla` mit `Fix Dump...`,
  `Status...` und `About` — für manuelles Arbeiten ohne Agent/MCP.

## Manuelle Bedienung (GUI)

Im x64dbg-Menü `Plugins → AutoScylla`:

| Eintrag | Funktion |
|---|---|
| **Fix Dump...** | Öffnet einen Dialog: Modulname (z. B. `notepad.exe`) und Ausgabe-Pfad eingeben, mit OK den Fix starten. Das Ergebnis erscheint in einer Message-Box (`base=…;size=…;imports=…/…;relocs=…`). |
| **Status...** | Zeigt Version, Debug-State, `cip` + Modul, Server-Port und die Befehle. |
| **About** | Version, Lizenz und Danksagung an die Scylla-Autoren. |

Der Modulname kann aus dem x64dbg-`Modules`-Tab kopiert werden. Am
System-Breakpoint (cip in `ntdll`) bleibt das Feld bewusst leer — bitte Modul
von Hand angeben.

## Verwendung (MCP / Automatisierung)

Der Server nutzt denselben Token wie `x64dbg-OpenC`:
`%LOCALAPPDATA%\x64dbgMpc\xdbg_mcp.token`. Ohne gültigen Token werden alle
Anfragen abgelehnt (fail-closed).

```text
{"id":"1","token":"<token>","method":"ping"}
→ {"id":"1","ok":true,"result":"pong"}

{"id":"1","token":"<token>","method":"status"}
→ {"id":"1","ok":true,"result":"running=0;cip=0x7FFD...;module=ntdll"}

{"id":"1","token":"<token>","method":"fix","module":"notepad.exe","path":"C:\\out.exe"}
→ {"id":"1","ok":true,"result":"base=0x7FF67C030000;size=229376;imports=260/0;relocs=4"}
```

`fix` akzeptiert:
- `module` — Modulname (bevorzugt! funktioniert auch am System-Breakpoint,
  wo `cip` noch in `ntdll` liegt — nutzt `DbgModBaseFromName`).
- `addr` — alternative explizite Adresse im Zielmodul (optional).
- `path` — Ausgabedatei (optional, Default `C:\Users\Public\autoscylla_dump.exe`).

Ohne `module`/`addr` wird `cip` als Fallback verwendet — dann darf der
Debuggee nicht am System-Breakpoint stehen.

`fix` akzeptiert zusätzlich:
- `oep` — EntryPoint-RVA (z. B. `0x1440`) oder VA; wird in den Dump geschrieben.

**Wichtige Details der Import-Rekonstruktion (PE32+):**
- INT-Einträge sind **8 Byte** (nicht 4) — die oberen 4 Byte dürfen nicht
  aus dem alten IAT übrig bleiben.
- Die Import-Deskriptor-Liste braucht einen **NULL-Terminator**.
- Die IAT eines gepackten Images kann **DLLs mischen** (ntdll/KERNEL32
  nebeneinander) — Deskriptoren müssen an **DLL-Wechseln** getrennt werden,
  sonst sucht der Loader z. B. `GetLastError` in ntdll.
- UPX-Sections sind `EXEC|READ` ohne `WRITE`; im Dump muss `IMAGE_SCN_MEM_WRITE`
  gesetzt sein, damit der Loader die IAT füllen kann.

### x64dbg-Befehle

- `autoscylla_status` — Status
- `autoscylla_fix [path]` — Fix mit `cip`
- `autoscylla` — Alias für `autoscylla_fix`

## Build

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Voraussetzungen:
- MSVC 14.44 (`D:\Tools\MSVC\VC\Tools\MSVC\14.44.35207`)
- Windows SDK 10.0.22621
- x64dbg Plugin-SDK (`D:\xdbg\pluginsdk`: `_plugins.h`, `bridgemain.h`, `x64dbg.lib`, `x64bridge.lib`)

Erzeugt: `build\AutoScylla.dp64` → nach `D:\xdbg\release\x64\plugins\` kopieren.

## Wichtige Erkenntnisse

- **`pluginit` muss `init->sdkVersion = PLUG_SDKVERSION` (== 1) setzen.**
  x64dbg prüft das Feld direkt nach dem Aufruf; bei 0 wird das Plugin still
  verworfen und `plugstop` gerufen. Das war die Ursache für anfängliche
  Lade-Probleme.
- **`DbgCmdExecDirect("autoscylla_fix")` ist unzuverlässig** (gab `cmd failed`,
  abhängig vom Debug-State und dem `allow_dangerous`-Gate der Bridge). Deshalb
  der eigene Loopback-Server in M4.
- **System-Breakpoint bewusst beibehalten**: `SystemBreakpoint=1` schützt vor
  Anti-Debug-Code, falls ScyllaHide nicht greift. Durch `module=`-basierte
  Dumps ist das kein Hindernis mehr.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
