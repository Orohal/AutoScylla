$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
New-Item -ItemType Directory -Path 'build' -Force | Out-Null

# MSVC C compiler (C11), x64
$vc   = 'D:\Tools\MSVC\VC\Tools\MSVC\14.44.35207'
$sdk  = 'C:\Program Files (x86)\Windows Kits\10'
$sdkv = '10.0.22621.0'
$sdkInc = 'D:\xdbg\pluginsdk'

$env:INCLUDE = @(
    "$vc\include",
    "$sdk\Include\$sdkv\um",
    "$sdk\Include\$sdkv\shared",
    "$sdk\Include\$sdkv\ucrt",
    $sdkInc
) -join ';'

$env:LIB = @(
    "$vc\lib\x64",
    "$sdk\Lib\$sdkv\um\x64",
    "$sdk\Lib\$sdkv\ucrt\x64",
    $sdkInc
) -join ';'

$cl = "$vc\bin\Hostx64\x64\cl.exe"
$link = "$vc\bin\Hostx64\x64\link.exe"

Write-Host "== Compiling plugin.cpp (C++) =="
& $cl /nologo /EHsc /MD /c /O2 /W3 /D_WIN64 /Fo:build\plugin.obj src\plugin.cpp
if ($LASTEXITCODE -ne 0) { throw "cl failed" }

Write-Host "== Compiling version resource (x64dbg needs .rsrc) =="
$rc = "$sdk\Bin\$sdkv\x64\rc.exe"
& $rc /nologo /fo build\plugin.res src\plugin.rc
if ($LASTEXITCODE -ne 0) { throw "rc failed" }

Write-Host "== Linking AutoScylla.dp64 =="
& $link /nologo /DLL /SUBSYSTEM:CONSOLE /OUT:build\AutoScylla.dp64 build\plugin.obj build\plugin.res x64dbg.lib x64bridge.lib
if ($LASTEXITCODE -ne 0) { throw "link failed" }

"AutoScylla.dp64: $((Get-Item 'build\AutoScylla.dp64').Length) bytes (C++)"
