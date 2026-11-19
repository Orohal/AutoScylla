/*
 * server.cpp — loopback JSON-line control server for AutoScylla.
 * Lets external tools (MCP) call autoscylla_status / autoscylla_fix and get
 * REAL return values, without depending on x64dbg's command box / debug state.
 *
 * Protocol (one JSON per line):
 *   {"id":"1","token":"<token>","method":"status"}
 *   {"id":"1","token":"<token>","method":"fix","path":"C:\\...\\out.exe"}
 * Response:
 *   {"id":"1","ok":true,"result":"..."}
 *
 * Token: same file as x64dbgMpc (%LOCALAPPDATA%\x64dbgMpc\xdbg_mcp.token)
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>   // must come before Windows.h (avoids winsock.h clash)

#include "server.h"
#include "recon.h"

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

#include "bridgemain.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 27043

static HANDLE       g_thread = nullptr;
static volatile bool g_running = false;
static SOCKET        g_listen = INVALID_SOCKET;

/* Reads the shared token; empty token -> all requests rejected (fail-closed). */
static std::string readToken()
{
    char buf[128]{};
    char path[MAX_PATH]{};
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", path, MAX_PATH);
    std::string p = (n && n < MAX_PATH) ? std::string(path) : std::string();
    p += "\\x64dbgMpc\\xdbg_mcp.token";
    FILE* f = nullptr;
    fopen_s(&f, p.c_str(), "r");
    if (!f) return "";
    size_t got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = 0;
    std::string t(buf);
    while (!t.empty() && (t.back() == '\n' || t.back() == '\r')) t.pop_back();
    return t;
}

/* Minimal JSON string field reader (quoted values only). */
static std::string jsonGet(const std::string& s, const char* key)
{
    std::string pat = "\"";
    pat += key;
    pat += "\"";
    size_t p = s.find(pat);
    if (p == std::string::npos) return "";
    p = s.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p++;
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) p++;
    if (p >= s.size() || s[p] != '"') return "";
    p++;
    std::string out;
    while (p < s.size() && s[p] != '"') {
        if (s[p] == '\\' && p + 1 < s.size()) { p++; out += s[p]; }
        else out += s[p];
        p++;
    }
    return out;
}

static std::string jsonEscape(const std::string& s)
{
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

static std::string reply(const std::string& id, bool ok, const std::string& result)
{
    return "{\"id\":\"" + jsonEscape(id) + "\",\"ok\":" + (ok ? "true" : "false") +
           ",\"result\":\"" + jsonEscape(result) + "\"}";
}

static std::string handle(const std::string& line, const std::string& token)
{
    std::string id = jsonGet(line, "id");
    std::string tok = jsonGet(line, "token");
    if (tok.empty() || tok != token)
        return reply(id, false, "unauthorized");

    std::string method = jsonGet(line, "method");

    if (method == "ping") return reply(id, true, "pong");

    if (method == "status") {
        duint cip = 0;
        REGDUMP_AVX512 rd;
        memset(&rd, 0, sizeof(rd));
        bool regs = DbgGetRegDumpEx(&rd, sizeof(rd)) ? true : false;
        if (regs) cip = rd.regcontext.cip;
        char mod[256]{};
        bool hasMod = DbgGetModuleAt(cip, mod) ? true : false;
        mod[sizeof(mod)-1] = 0;
        char buf[512];
        snprintf(buf, sizeof(buf), "running=%d;cip=0x%llX;module=%s",
                 DbgIsRunning() ? 1 : 0, (unsigned long long)cip,
                 hasMod ? mod : "-");
        return reply(id, true, buf);
    }

    if (method == "fix") {
        std::string path = jsonGet(line, "path");
        if (path.empty()) path = "C:\\Users\\Public\\autoscylla_dump.exe";

        /* Prefer an explicit module name (works even at the system breakpoint
         * where cip still sits in ntdll). Fallback: current instruction ptr. */
        std::string module = jsonGet(line, "module");
        std::string addrStr = jsonGet(line, "addr");
        std::string oepStr = jsonGet(line, "oep");
        duint addr = 0;
        if (!module.empty()) {
            addr = DbgModBaseFromName(module.c_str());
        } else if (!addrStr.empty()) {
            addr = (duint)strtoull(addrStr.c_str(), nullptr, 0);  // hex (0x...) oder decimal
        }
        if (!addr) {
            REGDUMP_AVX512 rd;
            memset(&rd, 0, sizeof(rd));
            if (DbgGetRegDumpEx(&rd, sizeof(rd))) addr = rd.regcontext.cip;
        }

        uint64_t oepRva = 0;
        if (!oepStr.empty()) {
            uint64_t v = strtoull(oepStr.c_str(), nullptr, 0);
            /* Accept an RVA (0x1440) or a full VA (base+0x1440). */
            oepRva = (v >= addr && v < addr + 0x40000000) ? (v - addr) : v;
        }

        AutoScyllaResult res;
        bool ok = AutoScylla_DumpAndFix(addr, path.c_str(), oepRva, &res);
        return reply(id, ok, res.message);
    }

    return reply(id, false, "unknown method");
}

static DWORD WINAPI serverThread(LPVOID)
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    std::string token = readToken();

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) { WSACleanup(); return 1; }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_listen, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR ||
        listen(g_listen, 4) == SOCKET_ERROR) {
        closesocket(g_listen); g_listen = INVALID_SOCKET; WSACleanup(); return 1;
    }
    g_running = true;

    char buf[8192];
    while (g_running) {
        SOCKET c = accept(g_listen, nullptr, nullptr);
        if (c == INVALID_SOCKET) break;
        std::string pending;
        while (g_running) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            pending.append(buf, n);
            if (pending.size() > 256 * 1024) break;
            size_t nl;
            while ((nl = pending.find('\n')) != std::string::npos) {
                std::string line = pending.substr(0, nl);
                pending.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;
                std::string r = handle(line, token) + "\n";
                size_t sent = 0;
                while (sent < r.size()) {
                    int k = send(c, r.data() + sent, (int)(r.size() - sent), 0);
                    if (k <= 0) break;
                    sent += k;
                }
            }
        }
        closesocket(c);
    }
    if (g_listen != INVALID_SOCKET) { closesocket(g_listen); g_listen = INVALID_SOCKET; }
    WSACleanup();
    return 0;
}

bool AutoScyllaServer_Start()
{
    if (g_thread) return true;
    g_thread = CreateThread(nullptr, 0, serverThread, nullptr, 0, nullptr);
    return g_thread != nullptr;
}

void AutoScyllaServer_Stop()
{
    g_running = false;
    if (g_listen != INVALID_SOCKET) {
        closesocket(g_listen);
        g_listen = INVALID_SOCKET;
    }
    if (g_thread) {
        WaitForSingleObject(g_thread, 2000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
}
