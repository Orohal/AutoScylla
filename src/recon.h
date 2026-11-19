#pragma once
#include <cstdint>

#ifdef _WIN64
#include <Windows.h>   // for duint on Windows (via bridgemain.h)
#endif

// x64dbg's duint; bridgemain.h defines it, but forward-safe here.
#ifndef DUINT_DEFINED
typedef uintptr_t duint;
#endif

struct AutoScyllaResult {
    bool  ok = false;
    int   resolved = 0;
    int   failed = 0;
    int   relocBlocks = 0;
    char  message[256] = {};
};

// Dump the module at 'addr' to 'outPath', reconstruct its imports.
// 'oepRva' (0 = keep current EP) is written to AddressOfEntryPoint when set
// — needed to make a packed-image dump directly executable.
bool AutoScylla_DumpAndFix(duint addr, const char* outPath, uint64_t oepRva,
                           AutoScyllaResult* res);
