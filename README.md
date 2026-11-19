# AutoScylla

Ein **x64dbg-Plugin**, das den Scylla-Workflow (Dump + Import-Reconstruction)
automatisiert und **echte Rückgabewerte** liefert. Der komplette Ablauf
`Modul → OEP → IAT → Imports → Dump → Fix → Rebuild` läuft mit einem Aufruf.

> **Status: M1–M4 umgesetzt und verifiziert** (Stand 2026-11-19).
> Getestet gegen notepad.exe am System-Breakpoint:
> `imports=260/0; relocs=4`, Dump = gültige PE x64 (7 Sections, 28 DLLs).

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
- **Reloc-Validierung**: zählt wohlgeformte Base-Relocation-Blöcke.
- **Loopback-Control-Server** (M4): JSON-line TCP auf `127.0.0.1:27043`
  mit Token-Schutz — liefert **echte Rückgabewerte**, unabhängig vom
  Debug-State / der Command-Box.

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
