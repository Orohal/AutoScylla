# AutoScylla

Ein **x64dbg-Plugin**, das den Scylla-Workflow (Dump + Import-Reconstruction)
automatisiert und **echte Rückgabewerte** liefert. Der komplette Ablauf
`OEP → IAT-Suche → Imports → Dump → Fix → Rebuild` soll mit einem Aufruf laufen.

> **Status: Work in Progress** — M1 (Plugin-Gerüst, geladen & verifiziert) und
> M2 (Dump) sind umgesetzt. IAT-Suche/Fix/Rebuild folgen in M3+.
> Siehe `STRATEGY.md` in `x64dbg-OpenC` für die vollständige Strategie.

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

## Build

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Voraussetzungen:
- MSVC 14.44 (`D:\Tools\MSVC\VC\Tools\MSVC\14.44.35207`)
- Windows SDK 10.0.22621
- x64dbg Plugin-SDK (`D:\xdbg\pluginsdk`: `_plugins.h`, `bridgemain.h`, `x64dbg.lib`, `x64bridge.lib`)

Erzeugt: `build\AutoScylla.dp64`

## Wichtige Erkenntnis (M1)

`pluginit` **muss** `init->sdkVersion = PLUG_SDKVERSION` (== 1) setzen. x64dbg
prüft das Feld direkt nach dem Aufruf; bei 0 wird das Plugin still verworfen
und `plugstop` gerufen. Das war die Ursache für anfängliche Lade-Probleme.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
