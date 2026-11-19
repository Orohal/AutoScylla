/*
 * AutoScylla — x64dbg plugin (pure C11)
 *
 * Automated dump + import reconstruction. M1: skeleton + status command.
 * Returns real values via _plugin_logprintf and a status file that the MCP
 * server reads (added in M4).
 *
 * Build: cl /TC /LD ... (see build.ps1)
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
#define PLUGIN_VER   "0.2.0"
#define STATUS_FILE  "C:\\Users\\Public\\autoscylla_status.txt"

static int g_pluginHandle = 0;
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
    (void)setup;
}

extern "C" __declspec(dllexport) bool plugstop(void)
{
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_status");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_fix");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla");
    AutoScyllaServer_Stop();
    WriteStatus("unloaded", "plugin stopped");
    return true;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reserved;
    return TRUE;
}
