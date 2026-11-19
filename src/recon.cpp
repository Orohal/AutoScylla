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
#include <algorithm>

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

/* UPX (and other packers) rebuild the IAT at runtime and clear the original
 * lookup table (OFT == 0) plus all hint/name strings. The IAT then contains
 * already-resolved absolute addresses. Recover the function name by looking
 * the address up in the containing module's export table.
 * System DLLs are mapped at the same address in every process, so this works
 * from the plugin (x64dbg) process as well. */
static bool NameFromAddress(duint addr, std::string& name)
{
    HMODULE h = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)addr, &h))
        return false;
    auto* dos = (IMAGE_DOS_HEADER*)h;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)h + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress || !ed.Size) return false;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)h + ed.VirtualAddress);
    auto* funcs = (DWORD*)((BYTE*)h + exp->AddressOfFunctions);
    auto* names = (DWORD*)((BYTE*)h + exp->AddressOfNames);
    auto* ords  = (WORD*)((BYTE*)h + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD rva = funcs[ords[i]];
        if (rva && (duint)((BYTE*)h + rva) == addr) {
            name = (char*)((BYTE*)h + names[i]);
            return true;
        }
    }
    return false;
}

/* ---- IAT search + import-directory rebuild (for packed images) ---- */

struct IatSym { duint addr; std::string dll, fn; };
struct IatRun { u32 rva; std::vector<IatSym> syms; };

static std::string BaseNameA(const std::string& p)
{
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? p : p.substr(s + 1);
}

/* Resolve a resolved IAT pointer to DLL + function name. */
static bool ResolveIatEntry(duint addr, std::string& dll, std::string& fn)
{
    HMODULE h = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)addr, &h)) return false;
    char path[MAX_PATH]{};
    GetModuleFileNameA(h, path, MAX_PATH);
    dll = BaseNameA(path);
    fn.clear();

    auto* dos = (IMAGE_DOS_HEADER*)h;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)h + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress || !ed.Size) return false;
    auto* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)h + ed.VirtualAddress);
    auto* funcs = (DWORD*)((BYTE*)h + exp->AddressOfFunctions);
    auto* names = (DWORD*)((BYTE*)h + exp->AddressOfNames);
    auto* ords  = (WORD*)((BYTE*)h + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD rva = funcs[ords[i]];
        if (rva && (duint)((BYTE*)h + rva) == addr) {
            fn = (char*)((BYTE*)h + names[i]);
            return !fn.empty();
        }
    }
    return false;
}

/* Find the most likely real IAT: a region with many consecutive (or
 * zero-separated) 8-byte pointers into loaded DLLs. */
static bool FindRealIat(const std::vector<u8>& mem, u32 imageSize,
                        std::vector<IatRun>& runs, u32& iatRva, u32& iatCount)
{
    u32 limit = imageSize < 0x400000u ? imageSize : 0x400000u;
    auto isPtr = [](u64 v) -> bool {
        return v >= 0x0000700000000000ULL && v <= 0x00007FFFFFFFFFFFULL;
    };
    struct Cand { u32 start, end; int count; };
    std::vector<Cand> cands;
    u32 start = 0, last = 0;
    int cnt = 0;
    for (u32 o = 0x1000; o + 8 <= limit; o += 8) {
        if (!isPtr(rd64(mem, o))) continue;
        if (cnt && (o - last) <= 0x40) {
            cnt++;
        } else {
            if (cnt >= 8) cands.push_back({ start, last + 8, cnt });
            start = o; cnt = 1;
        }
        last = o;
    }
    if (cnt >= 8) cands.push_back({ start, last + 8, cnt });
    if (cands.empty()) return false;

    const Cand* best = &cands[0];
    for (const auto& c : cands) if (c.count > best->count) best = &c;
    iatRva = best->start;
    iatCount = (u32)best->count;

    /* Split into sub-runs at zeroes AND at DLL changes. The IAT of packed
     * images interleaves functions from different DLLs (e.g. ntdll and
     * KERNEL32 side by side); a descriptor must name the DLL of EVERY entry,
     * otherwise the loader looks up "GetLastError" in ntdll and fails. */
    u32 p = best->start;
    while (p + 8 <= best->end) {
        u64 v = rd64(mem, p);
        if (!v) { p += 8; continue; }
        IatRun run;
        run.rva = p;
        std::string runDll;
        while (p + 8 <= best->end && rd64(mem, p)) {
            IatSym s;
            s.addr = (duint)rd64(mem, p);
            if (!ResolveIatEntry(s.addr, s.dll, s.fn)) { p += 8; break; }
            if (!run.syms.empty() && s.dll != runDll) break;   // DLL change
            if (run.syms.empty()) runDll = s.dll;
            run.syms.push_back(s);
            p += 8;
        }
        if (!run.syms.empty()) runs.push_back(run);
    }
    return !runs.empty();
}

/* Write a fresh import directory (descriptors + INT + names) into 'file',
 * reusing the REAL IAT as FirstThunk. Returns number of resolved imports. */
static int RebuildImportDirectory(std::vector<u8>& file,
                                  const std::vector<Section>& secs,
                                  const std::vector<IatRun>& runs,
                                  u32 iatRva, size_t peOff)
{
    size_t need = runs.size() * 20 + 20;   // +20: NULL descriptor
    for (const auto& r : runs) {
        need += r.syms.size() * 8 + 8;          // INT entries + terminator
        for (const auto& s : r.syms) need += s.fn.size() + 3;   // hint + name + NUL
        for (const auto& s : r.syms) {
            bool seen = false;
            for (const auto& t : r.syms) {
                if (&t == &s) break;
                if (t.dll == s.dll) { seen = true; break; }
            }
            if (!seen) need += s.dll.size() + 1;
        }
    }
    if (!need) return 0;

    /* Choose the largest section that does not contain the IAT. */
    const Section* target = nullptr;
    for (const auto& s : secs) {
        if (s.vsz <= need + 0x200) continue;
        if (iatRva >= s.va && iatRva < s.va + s.vsz) continue;  // never overwrite the IAT
        if (!target || s.vsz > target->vsz) target = &s;
    }
    if (!target) return 0;

    u32 cur = target->va + 0x100;
    u32 descRva = cur;
    cur += (u32)runs.size() * 20 + 20;   // +20: terminating NULL descriptor
    std::vector<u32> intRvas(runs.size());
    for (size_t i = 0; i < runs.size(); i++) {
        intRvas[i] = cur;
        cur += (u32)runs[i].syms.size() * 8 + 8;   // +8: NULL terminator
    }
    std::vector<u32> nameRvas;
    for (const auto& r : runs)
        for (const auto& s : r.syms) { nameRvas.push_back(cur); cur += (u32)s.fn.size() + 3; }
    std::vector<u32> dllRvas;
    for (const auto& r : runs) {
        std::string lastDll;
        for (const auto& s : r.syms) {
            if (s.dll == lastDll) { dllRvas.push_back(dllRvas.back()); continue; }
            lastDll = s.dll;
            dllRvas.push_back(cur);
            cur += (u32)s.dll.size() + 1;
        }
    }
    if (cur >= target->va + target->vsz) return 0;

    size_t off;
    auto write = [&](u32 rva, const void* src, size_t n) {
        if (rva2off(secs, rva, off) && off + n <= file.size())
            memcpy(file.data() + off, src, n);
    };
    auto writeStr = [&](u32 rva, u16 hint, const std::string& s) {
        if (!rva2off(secs, rva, off) || off + 2 + s.size() + 1 > file.size()) return;
        memcpy(file.data() + off, &hint, 2);
        memcpy(file.data() + off + 2, s.data(), s.size());
        file[off + 2 + s.size()] = 0;
    };
    /* DLL names are plain C strings — no 2-byte hint! */
    auto writeCStr = [&](u32 rva, const std::string& s) {
        if (!rva2off(secs, rva, off) || off + s.size() + 1 > file.size()) return;
        memcpy(file.data() + off, s.data(), s.size());
        file[off + s.size()] = 0;
    };

    size_t ni = 0, nd = 0;
    for (size_t i = 0; i < runs.size(); i++) {
        const auto& r = runs[i];
        IMAGE_IMPORT_DESCRIPTOR d{};
        d.OriginalFirstThunk = intRvas[i];
        d.Name = dllRvas[ni];
        d.FirstThunk = r.rva;
        write(descRva + (u32)i * 20, &d, 20);
        for (size_t k = 0; k < r.syms.size(); k++) {
            u64 entry = nameRvas[ni];   // PE32+: 64-bit RVA, not 32-bit!
            write(intRvas[i] + (u32)k * 8, &entry, 8);
            writeStr((u32)entry, 0, r.syms[k].fn);
            ni++;
        }
        u64 term = 0;
        write(intRvas[i] + (u32)r.syms.size() * 8, &term, 8);   // INT terminator
        (void)nd;
    }
    /* DLL name strings (unique per symbol index already mapped). */
    size_t di = 0;
    for (const auto& r : runs) {
        std::string lastDll;
        for (const auto& s : r.syms) {
            if (s.dll == lastDll) { di++; continue; }
            lastDll = s.dll;
            writeCStr(dllRvas[di], s.dll);
            di++;
        }
    }

    /* The descriptor array MUST end with an all-zero descriptor — the loader
     * walks until it sees one (the data-directory size is not authoritative). */
    IMAGE_IMPORT_DESCRIPTOR nullDesc{};
    write(descRva + (u32)runs.size() * 20, &nullDesc, sizeof(nullDesc));

    /* Point the PE import data directory at the new descriptors. */
    u32 dd = (u32)peOff + 24 + 112;
    write(dd + 8, &descRva, 4);
    u32 newSize = (u32)(runs.size() + 1) * 20;
    write(dd + 12, &newSize, 4);
    return (int)ni;
}

/* Rebuild base relocations for a packed image: UPX discards the original
 * .reloc table but has already applied relocations to the unpacked data.
 * Scan for 8-byte pointers into the image and emit IMAGE_REL_BASED_DIR64
 * entries. The dump keeps ImageBase = actual load address, so Windows can
 * rebase it later using this table. */
static int RebuildRelocations(std::vector<u8>& file, const std::vector<u8>& mem,
                              const std::vector<Section>& secs,
                              duint imageBase, u32 sizeOfImage, size_t peOff,
                              u32 avoidRva)
{
    struct R { u32 page, off; };
    std::vector<R> rels;
    u64 hi = imageBase + sizeOfImage;
    for (u32 o = 0x200; o + 8 <= sizeOfImage; o += 8) {
        u64 v = rd64(mem, o);
        if (v >= imageBase && v < hi) rels.push_back({ o & ~0xfffu, o & 0xfffu });
    }
    if (rels.empty()) return 0;
    std::sort(rels.begin(), rels.end(), [](const R& a, const R& b) {
        return a.page < b.page || (a.page == b.page && a.off < b.off);
    });

    std::vector<std::vector<u16>> blocks;
    std::vector<u32> pages;
    std::vector<u16> cur;
    u32 curPage = rels[0].page;
    for (const auto& r : rels) {
        if (r.page != curPage || cur.size() * 2 + 10 > 0x1000) {
            blocks.push_back(cur);
            pages.push_back(curPage);
            cur.clear();
            curPage = r.page;
        }
        cur.push_back((u16)(0xA000 | r.off));   // IMAGE_REL_BASED_DIR64 (type 10)
    }
    if (!cur.empty()) { blocks.push_back(cur); pages.push_back(curPage); }

    size_t total = 0;
    for (const auto& b : blocks) total += 8 + b.size() * 2;
    if (!total || total > 0x100000) return 0;

    const Section* target = nullptr;
    for (const auto& s : secs) {
        if (s.vsz <= total + 0x1000 + 0x100) continue;
        if (s.va <= avoidRva && avoidRva < s.va + s.vsz) continue;
        if (!target || s.vsz > target->vsz) target = &s;
    }
    if (!target) return 0;

    u32 firstRva = target->va + 0x1000;   // imports live at +0x100
    u32 rva = firstRva;
    size_t off;
    for (size_t i = 0; i < blocks.size(); i++) {
        if (!rva2off(secs, rva, off) || off + 8 + blocks[i].size() * 2 > file.size())
            return 0;
        u32 page = pages[i], sz = (u32)(8 + blocks[i].size() * 2);
        memcpy(file.data() + off, &page, 4);
        memcpy(file.data() + off + 4, &sz, 4);
        for (size_t k = 0; k < blocks[i].size(); k++)
            memcpy(file.data() + off + 8 + k * 2, &blocks[i][k], 2);
        rva += sz;
    }
    /* No explicit terminator: the Data Directory size bounds the block list.
     * (A zero block written from a 4-byte variable caused a malformed 4th
     *  block and an access violation in the Windows loader.) */

    u32 dd = (u32)peOff + 24 + 112;
    memcpy(file.data() + dd + 40, &firstRva, 4);
    u32 relSz = (u32)total;
    memcpy(file.data() + dd + 44, &relSz, 4);
    return (int)rels.size();
}

bool AutoScylla_DumpAndFix(duint addr, const char* outPath, uint64_t oepRva,
                           AutoScyllaResult* res)
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
    /* Lay out sections sequentially. NEVER trust PointerToRawData from the
     * in-memory header: UPX0 has raw=0 and would overwrite the PE header.
     * We assign fresh aligned raw offsets and write them back into the output
     * section headers so RVAs still map correctly. */
    u32 nextRaw = ((sizeOfHeaders + fileAlign - 1) / fileAlign) * fileAlign;
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

        u32 va = s.va, vsz = s.vsz;
        if (!va || !vsz || va >= sizeOfImage) continue;
        u32 copy = vsz < (sizeOfImage - va) ? vsz : (sizeOfImage - va);
        u32 aligned = ((copy + fileAlign - 1) / fileAlign) * fileAlign;
        u32 raw = nextRaw;
        if ((u64)raw + aligned > file.size()) {
            aligned = copy;
            if ((u64)raw + copy > file.size())
                copy = (raw < file.size()) ? (u32)(file.size() - raw) : 0;
        }
        if (copy) memcpy(file.data() + raw, mem.data() + va, copy);
        sh.PointerToRawData = raw;
        sh.SizeOfRawData = aligned;
        memcpy(file.data() + sectOff + i * sizeof(sh), &sh, sizeof(sh));
        s.raw = raw;
        s.rawsz = aligned;
        secs.back() = s;
        nextRaw = raw + aligned;
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

            size_t iatOff = 0;
            if (!rva2off(secs, firstThunk, iatOff)) { p += 20; continue; }

            /* OFT == 0: the loader consumed the lookup table, the IAT holds
             * resolved absolute addresses (classic UPX case). Recover names
             * from the export tables instead of reading hint/name RVAs. */
            size_t lookupOff = 0;
            bool lookupValid = (oft != 0) && rva2off(secs, oft, lookupOff);
            bool resolvedIat = !lookupValid;

            const u64 ordinalFlag = (1ULL << 63);
            for (int ti = 0; ti < 8192; ti++) {
                u64 entry = rd64(file, (resolvedIat ? iatOff : lookupOff) + (size_t)ti * 8);
                if (entry == 0) break;
                FARPROC proc = nullptr;
                if (resolvedIat) {
                    std::string fn;
                    if (NameFromAddress((duint)entry, fn) && !fn.empty())
                        proc = GetProcAddress(h, fn.c_str());
                    if (!proc) proc = (FARPROC)entry;   // keep the working address
                } else if (entry & ordinalFlag) {
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

    /* Packed images (UPX etc.) keep a stale header import table that points
     * at the stub's imports. If the header yielded almost nothing, locate the
     * REAL IAT in memory and rebuild a proper import directory. */
    std::string note;
    bool iatUsed = false;
    u32 foundIatRva = 0;
    if (resolved < 20 && sizeOfImage > 0x10000) {
        std::vector<IatRun> runs;
        u32 iatRva = 0, iatCount = 0;
        if (FindRealIat(mem, sizeOfImage, runs, iatRva, iatCount)) {
            int n = RebuildImportDirectory(file, secs, runs, iatRva, dos.e_lfanew);
            if (n > resolved) {
                resolved = n;
                failed = 0;
                iatUsed = true;
                foundIatRva = iatRva;
                char b[96];
                snprintf(b, sizeof(b), ";iat=0x%x/%u", iatRva, iatCount);
                note = b;
            }
        }
        /* Packed images also lose their original .reloc table. */
        if (iatUsed) {
            int nr = RebuildRelocations(file, mem, secs, imageBase, sizeOfImage,
                                        dos.e_lfanew, foundIatRva);
            char b[64];
            snprintf(b, sizeof(b), ";relocbuilt=%d", nr);
            note += b;
            blocks = nr ? nr : blocks;

            /* UPX keeps its sections read/execute-only and flips them to
             * writable at runtime via VirtualProtect. A standalone dump must
             * be writable itself, otherwise the loader's IAT writes cause an
             * access violation. */
            for (u16 i = 0; i < numSections; i++) {
                size_t sho = sectOff + (size_t)i * sizeof(IMAGE_SECTION_HEADER);
                u32 ch = rd32(file, sho + 36);
                ch |= 0x80000000u;   // IMAGE_SCN_MEM_WRITE
                wr32(file, sho + 36, ch);
            }
        }
    }

    /* Optional OEP (RVA) — makes a packed-image dump directly executable. */
    if (oepRva && oepRva < sizeOfImage) {
        u32 ep = (u32)oepRva;
        size_t epOff = (size_t)dos.e_lfanew + 24 + 16;
        if (epOff + 4 <= file.size()) memcpy(file.data() + epOff, &ep, 4);
        char b[48];
        snprintf(b, sizeof(b), ";oep=0x%x", ep);
        note += b;
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
    snprintf(msg, sizeof(msg), "base=0x%llX;size=%u;imports=%d/%d;relocs=%d%s",
             (unsigned long long)imageBase, (u32)written, resolved, failed, blocks,
             note.c_str());
    result(res, written == file.size(), msg, resolved, failed, blocks);
    return written == file.size();
}
