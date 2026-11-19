/*
 * AutoScylla — x64dbg plugin (C++)
 *
 * Automated dump + import reconstruction. Returns real values via
 * _plugin_logprintf, a status file, a loopback JSON server (M4) and a
 * minimal manual control in the Plugins menu (M5).
 *
 * Build: cl /EHsc /MD /LD ... (see build.ps1)
 */

/* NOTE: do NOT define BUILD_DBG — that switches the SDK headers to x64dbg's
 * internal build (_global.h/jansson). Plugin exports are declared explicitly
 * with __declspec(dllexport) below, so the normal (dllimport) SDK path is right. */

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string>   // pulls in MSVCP140/VCRUNTIME140_1 like x64dbg's own plugins
#include <vector>

#include "_plugins.h"
#include "bridgemain.h"
#include "recon.h"
#include "server.h"

#define PLUGIN_NAME  "AutoScylla"
#define PLUGIN_VER   "0.2.2"
#define STATUS_FILE  "C:\\Users\\Public\\autoscylla_status.txt"

static int g_pluginHandle = 0;
static HINSTANCE g_hDll = nullptr;
// Volatile std::string reference the optimizer cannot remove; forces MSVCP140
// / VCRUNTIME140_1 imports like x64dbg's own plugins.
static std::string g_probe;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Write a one-line status snapshot for the MCP server / external tools. */
static void WriteStatus(const char* state, const char* detail)
{
    FILE* f = NULL;
    fopen_s(&f, STATUS_FILE, "w");
    if (!f) return;
    fprintf(f, "state=%s\n", state ? state : "unknown");
    fprintf(f, "detail=%s\n", detail ? detail : "");
    fprintf(f, "version=%s\n", PLUGIN_VER);
    fclose(f);
}

static void Log(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    _plugin_logprintf("[%s] %s\n", PLUGIN_NAME, buf);
}

/* ------------------------------------------------------------------ */
/* Commands                                                           */
/* ------------------------------------------------------------------ */

static bool CmdStatus(int argc, char** argv)
{
    (void)argc; (void)argv;

    duint cip = 0;
    REGDUMP_AVX512 rd;
    memset(&rd, 0, sizeof(rd));
    bool hasRegs = DbgGetRegDumpEx(&rd, sizeof(rd)) ? true : false;
    if (hasRegs) cip = rd.regcontext.cip;

    char mod[256] = {0};
    bool hasMod = DbgGetModuleAt(cip, mod) ? true : false;
    mod[sizeof(mod)-1] = 0;

    bool running = DbgIsRunning() ? true : false;

    Log("status: running=%s regs=%s cip=0x%llX module=%s",
        running ? "yes" : "no", hasRegs ? "yes" : "no",
        (unsigned long long)cip, hasMod ? mod : "-");

    char detail[512];
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "running=%d;regs=%d;cip=0x%llX;module=%s",
               running ? 1 : 0, hasRegs ? 1 : 0,
               (unsigned long long)cip, hasMod ? mod : "-");
    WriteStatus("ok", detail);
    return true;
}

static bool CmdFix(int argc, char** argv)
{
    duint cip = 0;
    REGDUMP_AVX512 rd;
    memset(&rd, 0, sizeof(rd));
    if (DbgGetRegDumpEx(&rd, sizeof(rd))) cip = rd.regcontext.cip;

    const char* out = (argc > 1 && argv[1]) ? argv[1] : "C:\\Users\\Public\\autoscylla_dump.exe";
    Log("autoscylla_fix: cip=0x%llX out=%s", (unsigned long long)cip, out);

    AutoScyllaResult res;
    bool ok = AutoScylla_DumpAndFix(cip, out, &res);
    WriteStatus(ok ? "fixed" : "error", res.message);
    Log("fix: %s (%s)", ok ? "OK" : "FAILED", res.message);
    return ok;
}

static bool CmdAutoScylla(int argc, char** argv)
{
    return CmdFix(argc, argv);   // "autoscylla" == full workflow (alias)
}

/* ------------------------------------------------------------------ */
/* Manual control: Plugins → AutoScylla (menu + Fix Dump dialog)       */
/* ------------------------------------------------------------------ */

#define MENU_FIX     1
#define MENU_STATUS  2
#define MENU_ABOUT   3

#define IDD_FIX_DIALOG  2000
#define IDC_MODULE      2001
#define IDC_PATH        2002

static int  g_hAutoMenu = 0;
static std::string g_dlgModule;
static std::string g_dlgPath;
static std::string g_dlgResult;

static void SetResultFmt(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    g_dlgResult = buf;
}

/* Prefill with the module at cip, but NOT when parked in ntdll (system BP). */
static void CurrentModuleName(char* out, size_t len)
{
    out[0] = 0;
    duint cip = 0;
    REGDUMP_AVX512 rd;
    memset(&rd, 0, sizeof(rd));
    if (DbgGetRegDumpEx(&rd, sizeof(rd))) cip = rd.regcontext.cip;
    char mod[256] = {0};
    if (DbgGetModuleAt(cip, mod) && mod[0]) {
        if (_stricmp(mod, "ntdll") != 0 &&
            _stricmp(mod, "ntdll.dll") != 0 &&
            _stricmp(mod, "kernelbase") != 0 &&
            _stricmp(mod, "kernelbase.dll") != 0)
            strncpy_s(out, len, mod, _TRUNCATE);
    }
}

static INT_PTR CALLBACK FixDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM)
{
    if (msg == WM_INITDIALOG) {
        SetDlgItemTextA(hDlg, IDC_MODULE, g_dlgModule.c_str());
        SetDlgItemTextA(hDlg, IDC_PATH, g_dlgPath.c_str());
        return TRUE;
    }
    if (msg == WM_COMMAND) {
        switch (LOWORD(wParam)) {
        case IDOK: {
            char mod[256] = {0}, path[MAX_PATH] = {0};
            GetDlgItemTextA(hDlg, IDC_MODULE, mod, sizeof(mod));
            GetDlgItemTextA(hDlg, IDC_PATH, path, sizeof(path));
            if (!mod[0] || !path[0]) {
                MessageBoxA(hDlg, "Bitte Modulname und Ausgabepfad angeben.",
                            PLUGIN_NAME, MB_ICONWARNING);
                return TRUE;
            }
            duint base = DbgModBaseFromName(mod);
            if (!base) {
                SetResultFmt("Modul '%s' nicht gefunden.\n"
                             "Tipp: Modulname aus dem Modules-Tab kopieren "
                             "(z. B. notepad.exe).", mod);
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            AutoScyllaResult res;
            bool ok = AutoScylla_DumpAndFix(base, path, &res);
            WriteStatus(ok ? "fixed" : "error", res.message);
            g_dlgResult = res.message;
            Log("menu fix: %s (%s)", ok ? "OK" : "FAILED", res.message);
            EndDialog(hDlg, ok ? IDOK : IDCANCEL);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
    }
    return FALSE;
}

static void MenuEntry(CBTYPE cbType, void* callbackInfo)
{
    if (cbType != CB_MENUENTRY || !callbackInfo) return;
    int id = ((PLUG_CB_MENUENTRY*)callbackInfo)->hEntry;

    if (id == MENU_FIX) {
        char mod[256] = {0};
        CurrentModuleName(mod, sizeof(mod));
        g_dlgModule = mod;
        g_dlgPath = "C:\\Users\\Public\\autoscylla_dump.exe";
        g_dlgResult.clear();
        HWND parent = GetForegroundWindow();
        INT_PTR r = DialogBoxA(g_hDll, MAKEINTRESOURCE(IDD_FIX_DIALOG),
                               parent, FixDlgProc);
        MessageBoxA(parent, g_dlgResult.c_str(), "AutoScylla - Fix Dump",
                    r == IDOK ? MB_ICONINFORMATION : MB_ICONERROR);
    }
    else if (id == MENU_STATUS) {
        duint cip = 0;
        REGDUMP_AVX512 rd;
        memset(&rd, 0, sizeof(rd));
        if (DbgGetRegDumpEx(&rd, sizeof(rd))) cip = rd.regcontext.cip;
        char m[256] = {0};
        bool hasMod = DbgGetModuleAt(cip, m) ? true : false;
        m[sizeof(m)-1] = 0;
        char buf[512];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "Version: %s\n"
                    "Debuggee: %s\n"
                    "cip: 0x%llX  (%s)\n"
                    "Control-Server: 127.0.0.1:27043 (Token-geschützt)\n"
                    "Befehle: autoscylla_status / autoscylla_fix / autoscylla",
                    PLUGIN_VER, DbgIsRunning() ? "läuft" : "pausiert",
                    (unsigned long long)cip, hasMod ? m : "-");
        MessageBoxA(GetForegroundWindow(), buf, "AutoScylla - Status",
                    MB_ICONINFORMATION);
    }
    else if (id == MENU_ABOUT) {
        MessageBoxA(GetForegroundWindow(),
            "AutoScylla v" PLUGIN_VER "\n\n"
            "Automatisierter Dump + Import-Reconstruction für x64dbg.\n"
            "Eigene Implementierung gegen die x64dbg-Plugin-SDK — kein Fork.\n\n"
            "Inspiriert von Scylla (x64dbg/Scylla, GPL-3.0).\n"
            "Dank an Nico Bendlin, Ahmadmansoor und die Scylla-Mitautoren.\n\n"
            "MIT-Lizenz — https://github.com/Orohal/AutoScylla",
            "AutoScylla - About", MB_ICONINFORMATION);
    }
}

/* ------------------------------------------------------------------ */
/* Plugin lifecycle                                                   */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    g_pluginHandle = init->pluginHandle;
    // CRITICAL: x64dbg validates this against PLUG_SDKVERSION (1) right after
    // pluginit returns. If left at 0 the plugin is rejected and plugstop is
    // called immediately (status file flips to "unloaded"). strings.dp64 sets
    // the exact same value here ([rcx+4] = 1).
    init->sdkVersion = PLUG_SDKVERSION;
    // x64dbg's own plugins use 0x100; the value is informational (strings.dp64
    // uses 1). Either works once sdkVersion is correct.
    init->pluginVersion = 0x100;
    strncpy_s(init->pluginName, sizeof(init->pluginName), PLUGIN_NAME, _TRUNCATE);

    _plugin_registercommand(g_pluginHandle, "autoscylla_status", CmdStatus, false);
    _plugin_registercommand(g_pluginHandle, "autoscylla_fix", CmdFix, false);
    _plugin_registercommand(g_pluginHandle, "autoscylla", CmdAutoScylla, false);
    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, MenuEntry);

    g_probe = PLUGIN_NAME;              // cannot be optimized away
    WriteStatus("loaded", g_probe.c_str());
    Log("loaded v%s — commands: autoscylla_status, autoscylla", PLUGIN_VER);

    if (!AutoScyllaServer_Start())
        Log("WARNING: loopback control server failed to start (port 27043)");
    else
        Log("control server listening on 127.0.0.1:27043");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup)
{
    /* Minimal manual control under "Plugins" — no scripting/MCP needed. */
    /* setup->hMenu IS this plugin's own submenu in "Plugins" — add entries
     * directly, otherwise you get a needless second "AutoScylla" level. */
    g_hAutoMenu = setup->hMenu;
    _plugin_menuaddentry(g_hAutoMenu, MENU_FIX, "&Fix Dump...");
    _plugin_menuaddentry(g_hAutoMenu, MENU_STATUS, "&Status...");
    _plugin_menuaddseparator(g_hAutoMenu);
    _plugin_menuaddentry(g_hAutoMenu, MENU_ABOUT, "&About");
    Log("menu ready (hMenu=%d)", g_hAutoMenu);
}

extern "C" __declspec(dllexport) bool plugstop(void)
{
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_status");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_fix");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla");
    _plugin_unregistercallback(g_pluginHandle, CB_MENUENTRY);
    AutoScyllaServer_Stop();
    WriteStatus("unloaded", "plugin stopped");
    return true;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) g_hDll = (HINSTANCE)h;
    return TRUE;
}
