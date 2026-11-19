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

#define PLUGIN_NAME  "AutoScylla"
#define PLUGIN_VER   "0.1.0"
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

/* Dump the unpacked in-memory image of the module containing 'addr' into a
 * clean file-layout PE (same proven logic as ProcDumpPE). Returns the output
 * path via the status file so MCP/external tools can read it. */
static bool DumpModuleImage(duint addr, const char* outPath)
{
    duint imageBase = DbgMemFindBaseAddr(addr, nullptr);
    if (!imageBase) { WriteStatus("error", "no module at address"); return false; }

    IMAGE_DOS_HEADER dos;
    if (!DbgMemRead(imageBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        WriteStatus("error", "bad DOS header"); return false;
    }
    IMAGE_NT_HEADERS64 nt;
    if (!DbgMemRead(imageBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        WriteStatus("error", "bad NT header"); return false;
    }

    DWORD sizeOfImage = nt.OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt.OptionalHeader.SizeOfHeaders;
    WORD  numSections = nt.FileHeader.NumberOfSections;
    DWORD fileAlign = nt.OptionalHeader.FileAlignment;
    if (!sizeOfImage || sizeOfImage > 0x40000000) { WriteStatus("error", "bad SizeOfImage"); return false; }

    Log("dump: base=0x%llX sizeOfImage=0x%X sections=%u",
        (unsigned long long)imageBase, sizeOfImage, numSections);

    /* Read the whole mapped image (memory layout). */
    std::vector<BYTE> mem(sizeOfImage, 0);
    if (!DbgMemRead(imageBase, mem.data(), sizeOfImage)) {
        WriteStatus("error", "DbgMemRead whole image failed"); return false;
    }

    /* Build file-layout buffer. */
    std::vector<BYTE> file(sizeOfImage, 0);
    size_t hdrCopy = sizeOfHeaders < mem.size() ? sizeOfHeaders : mem.size();
    memcpy(file.data(), mem.data(), hdrCopy);

    size_t sectOff = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    for (WORD i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER sh;
        if (!DbgMemRead(imageBase + sectOff + i * sizeof(sh), &sh, sizeof(sh))) continue;
        DWORD va = sh.VirtualAddress, raw = sh.PointerToRawData;
        DWORD vsz = sh.Misc.VirtualSize;
        if (!va || !vsz || va >= sizeOfImage) continue;
        DWORD copy = vsz < (sizeOfImage - va) ? vsz : (sizeOfImage - va);
        if (raw + copy > file.size()) copy = (raw < file.size()) ? (DWORD)(file.size() - raw) : 0;
        if (copy) memcpy(file.data() + raw, mem.data() + va, copy);
        sh.SizeOfRawData = ((copy + fileAlign - 1) / fileAlign) * fileAlign;
        memcpy(file.data() + sectOff + i * sizeof(sh), &sh, sizeof(sh));
    }

    HANDLE of = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (of == INVALID_HANDLE_VALUE) { WriteStatus("error", "CreateFile failed"); return false; }
    DWORD written = 0;
    WriteFile(of, file.data(), (DWORD)file.size(), &written, nullptr);
    CloseHandle(of);

    char detail[512];
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
                "dumped=%u;base=0x%llX;sections=%u;path=%s",
                written, (unsigned long long)imageBase, numSections, outPath);
    WriteStatus("dumped", detail);
    Log("dump: wrote %u bytes to %s", written, outPath);
    return true;
}

static bool CmdDump(int argc, char** argv)
{
    duint cip = 0;
    REGDUMP_AVX512 rd;
    memset(&rd, 0, sizeof(rd));
    if (DbgGetRegDumpEx(&rd, sizeof(rd))) cip = rd.regcontext.cip;

    /* Default output path next to the status file; optional argv[1] overrides. */
    const char* out = (argc > 1 && argv[1]) ? argv[1] : "C:\\Users\\Public\\autoscylla_dump.exe";
    return DumpModuleImage(cip, out);
}

static bool CmdAutoScylla(int argc, char** argv)
{
    (void)argc; (void)argv;
    Log("autoscylla: use 'autoscylla_dump' (M2) — full workflow comes in M3+");
    WriteStatus("skeleton", "dump ready; iatsearch/fixdump pending (M3)");
    return true;
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
    _plugin_registercommand(g_pluginHandle, "autoscylla_dump", CmdDump, false);
    _plugin_registercommand(g_pluginHandle, "autoscylla", CmdAutoScylla, false);

    g_probe = PLUGIN_NAME;              // cannot be optimized away
    WriteStatus("loaded", g_probe.c_str());
    Log("loaded v%s — commands: autoscylla_status, autoscylla", PLUGIN_VER);
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup)
{
    (void)setup;
}

extern "C" __declspec(dllexport) bool plugstop(void)
{
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_status");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla_dump");
    _plugin_unregistercommand(g_pluginHandle, "autoscylla");
    WriteStatus("unloaded", "plugin stopped");
    return true;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reserved;
    return TRUE;
}
