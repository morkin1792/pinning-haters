// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <link.h>
#include <stdint.h>

// GOT/PLT slot rewriter: the primary hooking primitive. One pointer in a data page changes; the
// provider's .text stays byte-identical to disk. Only .rela.plt is parsed — imported functions get
// R_*_JUMP_SLOT entries there and .rela.plt is never packed by Android's SLEB128 relocation
// encoding, which is why this stays small. If you ever need a data import you need DT_ANDROID_RELA
// decoding; do not add it speculatively.
namespace ph::got {

struct Library {
    uintptr_t bias;
    const ElfW(Phdr)* phdr;
    uint16_t phnum;
    char path[256];
};

// Reads dl_iterate_phdr (never hooks it). `fn` returns true to stop iterating.
void for_each_library(bool (*fn)(const Library&, void*), void* ctx);
// `name` is a basename ("libjavacrypto.so") or a full path; nullptr selects the main executable.
bool find_library(const char* name, Library* out);
// Address of the import slot for `symbol`, or nullptr when no edge exists (same-library call,
// -Bsymbolic, data import, or simply not imported).
void** find_slot(const Library& lib, const char* symbol);
// All of them: the PLT slot first, then .rela.dyn GLOB_DAT/ABS64 slots holding the same symbol.
size_t find_slots(const Library& lib, const char* symbol, void*** out, size_t max);
bool has_edge(const char* library, const char* symbol);
// Returns the original pointer (the recorded one if already hooked with the same replacement),
// nullptr on failure. Page protection is restored immediately after the write.
void* hook(const char* library, const char* symbol, void* replacement);
void* hook_in(const Library& lib, const char* symbol, void* replacement);
// Same contract for an arbitrary pointer slot inside `lib` (RELRO function tables and the like).
void* hook_slot(const Library& lib, void** slot, void* replacement);
bool restore(const char* library, const char* symbol);

const char* basename_of(const char* path);
// Does any readable PT_LOAD segment of `lib` hold `needle` as a substring? memmem over the
// mapped bytes; a 40 MB library costs milliseconds. Used by the runtime markers that identify a
// TLS stack by the strings it carries rather than by a library name.
bool segments_contain(const Library& lib, const char* needle);
// Address of an exported (defined, non-zero) dynamic symbol of `lib`, or 0. Walks .dynsym with the
// symbol count taken from DT_HASH or DT_GNU_HASH; no namespace lookup, so it works on a library
// loaded from a file by the host tests as well as on a live one.
uintptr_t find_export(const Library& lib, const char* name);
// Anything not under a platform partition: /data/app, /data/data, memfd, ...
bool is_app_private(const char* path);

}  // namespace ph::got
