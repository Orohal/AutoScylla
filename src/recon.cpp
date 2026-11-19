/*
 * recon.cpp — PE dump + import reconstruction logic for AutoScylla.
 * Ported from the verified ProcDumpPE + ImportRecon tools.
 * Reads the target process via x64dbg's DbgMemRead, writes a clean file-layout
 * PE with resolved IAT entries via GetProcAddress.
 */

#include "recon.h"

#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

#include "bridgemain.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct Section { u32 va, vsz, raw, rawsz; std::string name; };

static u32 rd32(const std::vector<u8>& b, size_t o) {
    return (o + 4 <= b.size()) ? *reinterpret_cast<const u32*>(&b[o]) : 0;
}
static u16 rd16(const std::vector<u8>& b, size_t o) {
    return (o + 2 <= b.size()) ? *reinterpret_cast<const u16*>(&b[o]) : 0;
}
static u64 rd64(const std::vector<u8>& b, size_t o) {
    return (o + 8 <= b.size()) ? *reinterpret_cast<const u64*>(&b[o]) : 0;
}
static void wr64(std::vector<u8>& b, size_t o, u64 v) {
    if (o + 8 <= b.size()) memcpy(&b[o], &v, 8);
}
static void wr32(std::vector<u8>& b, size_t o, u32 v) {
    if (o + 4 <= b.size()) memcpy(&b[o], &v, 4);
}

static bool rva2off(const std::vector<Section>& secs, u32 rva, size_t& out) {
    for (const auto& s : secs) {
        u32 span = s.vsz > s.rawsz ? s.vsz : s.rawsz;
        if (rva >= s.va && rva < s.va + span) {
            out = s.raw + (rva - s.va);
            return out < 0x7FFFFFFFULL;
        }
    }
    if (!secs.empty() && rva < secs[0].va) { out = rva; return true; }
    return false;
}

/* Result codes for the status file. */
static void result(AutoScyllaResult* r, bool ok, const char* msg,
                   int resolved, int failed, int blocks)
{
    if (!r) return;
    r->ok = ok;
    r->resolved = resolved;
    r->failed = failed;
    r->relocBlocks = blocks;
    snprintf(r->message, sizeof(r->message), "%s", msg ? msg : "");
}

bool AutoScylla_DumpAndFix(duint addr, const char* outPath, AutoScyllaResult* res)
{
    if (!outPath || !outPath[0]) { result(res, false, "no output path", 0,0,0); return false; }

    duint imageBase = DbgMemFindBaseAddr(addr, nullptr);
    if (!imageBase) { result(res, false, "no module at address", 0,0,0); return false; }

    IMAGE_DOS_HEADER dos;
    if (!DbgMemRead(imageBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        result(res, false, "bad DOS header", 0,0,0); return false;
    }
    IMAGE_NT_HEADERS64 nt;
    if (!DbgMemRead(imageBase + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
        result(res, false, "bad NT header", 0,0,0); return false;
    }

    u32 sizeOfImage = nt.OptionalHeader.SizeOfImage;
    u32 sizeOfHeaders = nt.OptionalHeader.SizeOfHeaders;
    u16 numSections = nt.FileHeader.NumberOfSections;
    u32 fileAlign = nt.OptionalHeader.FileAlignment;
    if (!sizeOfImage || sizeOfImage > 0x40000000) {
        result(res, false, "bad SizeOfImage", 0,0,0); return false;
    }

    /* Read the whole mapped image and build file layout (ProcDumpPE logic). */
    std::vector<u8> mem(sizeOfImage, 0);
    if (!DbgMemRead(imageBase, mem.data(), sizeOfImage)) {
        result(res, false, "DbgMemRead whole image failed", 0,0,0); return false;
    }
    std::vector<u8> file(sizeOfImage, 0);
    size_t hdrCopy = sizeOfHeaders < mem.size() ? sizeOfHeaders : mem.size();
    memcpy(file.data(), mem.data(), hdrCopy);

    size_t sectOff = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    std::vector<Section> secs;
    for (u16 i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER sh;
        if (!DbgMemRead(imageBase + sectOff + i * sizeof(sh), &sh, sizeof(sh))) continue;
        char name[9]{}; memcpy(name, sh.Name, 8);
        Section s;
        s.name = name;
        s.vsz = sh.Misc.VirtualSize;
        s.va = sh.VirtualAddress;
        s.rawsz = sh.SizeOfRawData;
        s.raw = sh.PointerToRawData;
        secs.push_back(s);

        u32 va = s.va, raw = s.raw, vsz = s.vsz;
        if (!va || !vsz || va >= sizeOfImage) continue;
        u32 copy = vsz < (sizeOfImage - va) ? vsz : (sizeOfImage - va);
        if (raw + copy > file.size()) copy = (raw < file.size()) ? (u32)(file.size() - raw) : 0;
        if (copy) memcpy(file.data() + raw, mem.data() + va, copy);
        sh.SizeOfRawData = ((copy + fileAlign - 1) / fileAlign) * fileAlign;
        memcpy(file.data() + sectOff + i * sizeof(sh), &sh, sizeof(sh));
    }

    /* ---- Import reconstruction (ImportRecon logic) ---- */
    size_t opt = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) - sizeof(IMAGE_NT_HEADERS64); // == pe+24
    size_t pe = dos.e_lfanew;
    opt = pe + 24;
    size_t dd = opt + 112;
    u32 impRva = rd32(file, dd + 1 * 8), impSz = rd32(file, dd + 1 * 8 + 4);
    u32 relRva = rd32(file, dd + 5 * 8), relSz = rd32(file, dd + 5 * 8 + 4);

    int resolved = 0, failed = 0, blocks = 0;
    size_t impOff;
    if (impRva && rva2off(secs, impRva, impOff)) {
        size_t p = impOff;
        for (int di = 0; di < 512; di++) {
            u32 oft = rd32(file, p), nameRva = rd32(file, p + 12), firstThunk = rd32(file, p + 16);
            if (!oft && !nameRva && !firstThunk) break;
            size_t nameOff;
            if (!rva2off(secs, nameRva, nameOff)) { p += 20; continue; }
            std::string dll;
            for (size_t k = nameOff; k < file.size() && file[k]; k++) dll += (char)file[k];
            HMODULE h = LoadLibraryA(dll.c_str());
            if (!h) { failed++; p += 20; continue; }

            size_t oftOff, iatOff;
            bool haveOft = rva2off(secs, oft, oftOff);
            bool haveIat = rva2off(secs, firstThunk, iatOff);
            if (!haveOft || !haveIat) { p += 20; continue; }

            const u64 ordinalFlag = (1ULL << 63);
            for (int ti = 0; ti < 8192; ti++) {
                u64 entry = rd64(file, oftOff + (size_t)ti * 8);
                if (entry == 0) break;
                FARPROC proc = nullptr;
                if (entry & ordinalFlag) {
                    proc = GetProcAddress(h, MAKEINTRESOURCEA((u32)(entry & 0xFFFF)));
                } else {
                    size_t hintOff;
                    u32 nr = (u32)entry;
                    if (rva2off(secs, nr, hintOff) && hintOff + 2 < file.size()) {
                        const char* nm = (const char*)&file[hintOff + 2];
                        proc = GetProcAddress(h, nm);
                    }
                }
                if (proc) { wr64(file, iatOff + (size_t)ti * 8, (u64)proc); resolved++; }
                else failed++;
            }
            p += 20;
        }
    }

    /* Validate relocs (well-formed blocks). */
    if (relRva && relSz) {
        size_t ro;
        if (rva2off(secs, relRva, ro)) {
            size_t end = ro + relSz;
            while (ro + 8 <= end && ro < file.size()) {
                u32 bs = rd32(file, ro + 4);
                if (bs < 8 || bs > 0x1000 || ro + bs > end) break;
                blocks++;
                ro += bs;
            }
        }
    }

    /* Write output. */
    FILE* of = nullptr;
    fopen_s(&of, outPath, "wb");
    if (!of) { result(res, false, "open output failed", resolved, failed, blocks); return false; }
    size_t written = fwrite(file.data(), 1, file.size(), of);
    fclose(of);

    char msg[256];
    snprintf(msg, sizeof(msg), "base=0x%llX;size=%u;imports=%d/%d;relocs=%d",
             (unsigned long long)imageBase, (u32)written, resolved, failed, blocks);
    result(res, written == file.size(), msg, resolved, failed, blocks);
    return written == file.size();
}
