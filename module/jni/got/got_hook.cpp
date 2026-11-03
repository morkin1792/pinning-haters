// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "got_hook.h"

#include <elf.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

namespace ph::got {

namespace {

#if defined(__aarch64__)
constexpr uint32_t JUMP_SLOT = R_AARCH64_JUMP_SLOT;
constexpr uint32_t GLOB_DAT = R_AARCH64_GLOB_DAT;
#elif defined(__x86_64__)
constexpr uint32_t JUMP_SLOT = R_X86_64_JUMP_SLOT;  // host-side unit tests only; x86_64 devices are backlog
constexpr uint32_t GLOB_DAT = R_X86_64_GLOB_DAT;
#else
#error "pinning-haters is ARM64-only"
#endif

struct Record {
    void** slot;
    void* original;
    void* replacement;
};
constexpr size_t MAX_RECORDS = 256;  // 24 bytes each; a large app with several TLS consumers can need dozens
constexpr size_t MAX_SLOTS_PER_SYMBOL = 8;  // PLT slot plus the data slots an obfuscated library keeps
Record g_records[MAX_RECORDS];
size_t g_record_count = 0;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

struct IterCtx {
    bool (*fn)(const Library&, void*);
    void* ctx;
};

// dlpi_subs from the most recent walk: the linker bumps it on every dlclose, so a change means an
// address range may have been freed and reused by a later load.
unsigned long long g_unloads = 0;

int iterate_cb(dl_phdr_info* info, size_t size, void* data) {
    if (size >= offsetof(dl_phdr_info, dlpi_subs) + sizeof(info->dlpi_subs))
        __atomic_store_n(&g_unloads, info->dlpi_subs, __ATOMIC_RELAXED);  // walks run on several threads
    auto* ic = static_cast<IterCtx*>(data);
    Library lib{};
    lib.bias = info->dlpi_addr;
    lib.phdr = info->dlpi_phdr;
    lib.phnum = info->dlpi_phnum;
    snprintf(lib.path, sizeof(lib.path), "%s", info->dlpi_name ? info->dlpi_name : "");
    return ic->fn(lib, ic->ctx) ? 1 : 0;
}

struct FindCtx {
    const char* name;
    Library* out;
    bool found;
};

bool find_cb(const Library& lib, void* data) {
    auto* fc = static_cast<FindCtx*>(data);
    bool match;
    if (!fc->name) match = true;  // the main executable is always reported first
    else if (strchr(fc->name, '/')) match = strcmp(lib.path, fc->name) == 0;
    else match = strcmp(basename_of(lib.path), fc->name) == 0;
    if (match) {
        *fc->out = lib;
        fc->found = true;
    }
    return match;
}

// Protection the page must return to after our write. RELRO is applied after relocation, so it
// overrides the PT_LOAD flags for the GOT.
//
// Exception: bionic's 16 KiB app-compat loader (a 4 KiB-aligned ELF on a 16 KiB-page kernel) maps
// RO+RX+RELRO as one RX region and leaves a RELRO tail that shares a 16 KiB page with .data as RW.
// Restoring plain PROT_READ there would strip X from text or W from data and fault the next access.
int protection_after(const Library& lib, const void* addr) {
    const auto a = reinterpret_cast<uintptr_t>(addr);
    const auto page_size = static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
    bool compat = false;
    if (page_size > 4096)
        for (uint16_t i = 0; i < lib.phnum; i++)
            if (lib.phdr[i].p_type == PT_LOAD && lib.phdr[i].p_align < page_size) compat = true;

    int prot = PROT_READ;
    for (int pass = 0; pass < 2; pass++) {
        for (uint16_t i = 0; i < lib.phnum; i++) {
            const ElfW(Phdr)& p = lib.phdr[i];
            const uintptr_t start = lib.bias + p.p_vaddr;
            if (a < start || a >= start + p.p_memsz) continue;
            if (pass == 0 && p.p_type == PT_LOAD)
                prot = ((p.p_flags & PF_R) ? PROT_READ : 0) | ((p.p_flags & PF_W) ? PROT_WRITE : 0) |
                       ((p.p_flags & PF_X) ? PROT_EXEC : 0);
            if (pass == 1 && p.p_type == PT_GNU_RELRO) {
                if (!compat) {
                    prot = PROT_READ;
                } else {
                    const uintptr_t relro_end = (start + p.p_memsz) & ~(page_size - 1);
                    prot = a < relro_end ? (PROT_READ | PROT_EXEC) : (PROT_READ | PROT_WRITE);
                }
            }
        }
    }
    return prot;
}

Record* record_for(void** slot) {
    for (size_t i = 0; i < g_record_count; i++)
        if (g_records[i].slot == slot) return &g_records[i];
    return nullptr;
}

}  // namespace

const char* basename_of(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

uintptr_t find_export(const Library& lib, const char* name) {
    const ElfW(Dyn)* dyn = nullptr;
    for (uint16_t i = 0; i < lib.phnum; i++)
        if (lib.phdr[i].p_type == PT_DYNAMIC) dyn = reinterpret_cast<const ElfW(Dyn)*>(lib.bias + lib.phdr[i].p_vaddr);
    if (!dyn) return 0;
    uintptr_t symtab = 0, strtab = 0, hash = 0, gnu_hash = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_SYMTAB: symtab = dyn->d_un.d_ptr; break;
            case DT_STRTAB: strtab = dyn->d_un.d_ptr; break;
            case DT_HASH: hash = dyn->d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = dyn->d_un.d_ptr; break;
            default: break;
        }
    }
    if (!symtab || !strtab) return 0;
    auto absolute = [&](uintptr_t p) { return p < lib.bias ? p + lib.bias : p; };
    const auto* syms = reinterpret_cast<const ElfW(Sym)*>(absolute(symtab));
    const auto* strs = reinterpret_cast<const char*>(absolute(strtab));
    size_t nsyms = 0;
    if (hash) {
        nsyms = reinterpret_cast<const uint32_t*>(absolute(hash))[1];  // nchain == number of symbols
    } else if (gnu_hash) {
        // The GNU hash has no symbol count: the highest index reachable from any bucket, plus one.
        const auto* h = reinterpret_cast<const uint32_t*>(absolute(gnu_hash));
        const uint32_t nbuckets = h[0], symoffset = h[1], bloom_size = h[2];
        const uint32_t* buckets = h + 4 + bloom_size * (sizeof(ElfW(Addr)) / sizeof(uint32_t));
        const uint32_t* chains = buckets + nbuckets;
        for (uint32_t b = 0; b < nbuckets; b++) {
            uint32_t idx = buckets[b];
            if (idx < symoffset) continue;
            while (true) {
                if (idx + 1 > nsyms) nsyms = idx + 1;
                if (chains[idx - symoffset] & 1) break;
                idx++;
            }
        }
    } else {
        return 0;
    }
    for (size_t i = 0; i < nsyms; i++) {
        const ElfW(Sym)& sym = syms[i];
        if (sym.st_shndx == SHN_UNDEF || sym.st_value == 0) continue;
        if (strcmp(strs + sym.st_name, name) == 0) return lib.bias + sym.st_value;
    }
    return 0;
}

bool segments_contain(const Library& lib, const char* needle) {
    if (!needle || !*needle) return false;
    const size_t len = strlen(needle);  // substring, not a whole string: the needles are prefixes
    for (uint16_t i = 0; i < lib.phnum; i++) {
        const ElfW(Phdr)& p = lib.phdr[i];
        if (p.p_type != PT_LOAD || !(p.p_flags & PF_R) || p.p_memsz < len) continue;
        if (memmem(reinterpret_cast<const void*>(lib.bias + p.p_vaddr), p.p_memsz, needle, len)) return true;
    }
    return false;
}

// Only what the app itself ships or extracted: APK-embedded and extracted libraries, adoptable
// storage. A deny-list of platform prefixes was the first cut and it counted the host's own
// libraries (/data/adb/modules/.../arm64-v8a.so, libzygisk.so) as app-private, which made the
// static-BoringSSL scan find its own needle strings inside this module and report a phantom
// `pattern_not_found` in every process.
bool is_app_private(const char* path) {
    if (!path || !*path) return false;  // the main executable
    // memfd stays in: packers load app code that way. The host's own memfd-mapped libraries (Magisk's
    // Zygisk) are told apart by load address, not by name; see the hook manager's self check.
    static const char* const kAppPrefixes[] = {"/data/app/", "/data/data/", "/data/user/", "/data/user_de/",
                                               "/mnt/expand/", "/memfd:"};
    for (const char* prefix : kAppPrefixes)
        if (strncmp(path, prefix, strlen(prefix)) == 0) return true;
    return false;
}

void for_each_library(bool (*fn)(const Library&, void*), void* ctx) {
    IterCtx ic{fn, ctx};
    dl_iterate_phdr(iterate_cb, &ic);
}

unsigned long long unload_count() { return __atomic_load_n(&g_unloads, __ATOMIC_RELAXED); }

bool find_library(const char* name, Library* out) {
    FindCtx fc{name, out, false};
    for_each_library(find_cb, &fc);
    return fc.found;
}

// Every slot through which `lib` reaches `symbol`: the .rela.plt JUMP_SLOT first (the call edge),
// then .rela.dyn GLOB_DAT entries for the same symbol — a library that takes the address of a libc
// function keeps that pointer in its GOT too, and a call through it would bypass a PLT-only
// rewrite. ABS64 entries are deliberately left alone: those sit in arbitrary data (an obfuscator's
// call-through tables), and Kony's libkonyjsvm transforms its tables after the linker fills them,
// so a pointer swapped there became garbage and the library crashed in JNI_OnLoad. Only plain
// DT_RELA is read: Android's packed .rela.dyn (DT_ANDROID_RELA) holds no GLOB_DAT for the
// libraries we hook today, and the decoder is not worth carrying speculatively.
size_t find_slots(const Library& lib, const char* symbol, void*** out, size_t max) {
    const ElfW(Dyn)* dyn = nullptr;
    for (uint16_t i = 0; i < lib.phnum; i++)
        if (lib.phdr[i].p_type == PT_DYNAMIC)
            dyn = reinterpret_cast<const ElfW(Dyn)*>(lib.bias + lib.phdr[i].p_vaddr);
    if (!dyn || !max) return 0;

    uintptr_t jmprel = 0, pltrelsz = 0, rela_dyn = 0, relasz = 0, symtab = 0, strtab = 0, pltrel = DT_RELA;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
            case DT_JMPREL: jmprel = dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = dyn->d_un.d_val; break;
            case DT_RELA: rela_dyn = dyn->d_un.d_ptr; break;
            case DT_RELASZ: relasz = dyn->d_un.d_val; break;
            case DT_SYMTAB: symtab = dyn->d_un.d_ptr; break;
            case DT_STRTAB: strtab = dyn->d_un.d_ptr; break;
            case DT_PLTREL: pltrel = dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (!symtab || !strtab || pltrel != DT_RELA) return 0;

    // bionic leaves .dynamic untouched (d_ptr is a link-time vaddr); glibc relocates it in place.
    // The host-side unit tests run on glibc, so accept both.
    auto absolute = [&](uintptr_t p) { return p < lib.bias ? p + lib.bias : p; };
    const auto* syms = reinterpret_cast<const ElfW(Sym)*>(absolute(symtab));
    const auto* strs = reinterpret_cast<const char*>(absolute(strtab));
    size_t found = 0;
    auto scan = [&](uintptr_t table, uintptr_t size, bool plt) {
        if (!table || !size) return;
        const auto* rela = reinterpret_cast<const ElfW(Rela)*>(absolute(table));
        for (size_t i = 0, n = size / sizeof(ElfW(Rela)); i < n && found < max; i++) {
            const uint32_t type = ELF64_R_TYPE(rela[i].r_info);
            if (plt ? type != JUMP_SLOT : type != GLOB_DAT) continue;
            const uint32_t sym = ELF64_R_SYM(rela[i].r_info);
            if (!sym) continue;
            if (strcmp(strs + syms[sym].st_name, symbol) == 0) out[found++] = reinterpret_cast<void**>(lib.bias + rela[i].r_offset);
        }
    };
    scan(jmprel, pltrelsz, true);
    scan(rela_dyn, relasz, false);
    return found;
}

void** find_slot(const Library& lib, const char* symbol) {
    void** slot = nullptr;
    return find_slots(lib, symbol, &slot, 1) ? slot : nullptr;
}

bool has_edge(const char* library, const char* symbol) {
    Library lib;
    return find_library(library, &lib) && find_slot(lib, symbol) != nullptr;
}

void* hook_slot(const Library& lib, void** slot, void* replacement) {
    if (!slot) return nullptr;
    pthread_mutex_lock(&g_lock);
    void* result = nullptr;
    Record* r = record_for(slot);
    // A record whose slot no longer holds its replacement belongs to a library that was unloaded
    // and replaced at the same address; it is rewritten, not trusted.
    if (r && __atomic_load_n(slot, __ATOMIC_ACQUIRE) == r->replacement) {
        // Already ours (re-scan after a deferred load): hand back the real original, do not stack.
        result = r->replacement == replacement ? r->original : nullptr;
    } else if ((r || g_record_count < MAX_RECORDS) && __atomic_load_n(slot, __ATOMIC_ACQUIRE) != nullptr) {
        // A null slot is an unresolved weak import: nothing to wrap, and a replacement would have
        // no original to call.
        const long page_size = sysconf(_SC_PAGESIZE);
        const auto page = reinterpret_cast<uintptr_t>(slot) & ~static_cast<uintptr_t>(page_size - 1);
        const int after = protection_after(lib, slot);
        // In 16 KiB compat mode the slot can share a page with code; dropping PROT_EXEC for the
        // write would fault any thread executing there. Keep it when the page has it, and fall
        // back to RW if the policy refuses RWX.
        const bool writable = ((after & PROT_EXEC) &&
                               mprotect(reinterpret_cast<void*>(page), page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) ||
                              mprotect(reinterpret_cast<void*>(page), page_size, PROT_READ | PROT_WRITE) == 0;
        if (writable) {
            void* original = __atomic_exchange_n(slot, replacement, __ATOMIC_SEQ_CST);
            mprotect(reinterpret_cast<void*>(page), page_size, after);
            if (r)
                *r = {slot, original, replacement};
            else
                g_records[g_record_count++] = {slot, original, replacement};
            result = original;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return result;
}

void* hook_in(const Library& lib, const char* symbol, void* replacement) {
    void** slots[MAX_SLOTS_PER_SYMBOL];
    const size_t n = find_slots(lib, symbol, slots, MAX_SLOTS_PER_SYMBOL);
    if (!n) return nullptr;
    void* original = hook_slot(lib, slots[0], replacement);
    if (!original) return nullptr;
    // Data slots must hold the same resolved address (an ABS64 with an addend would not); any
    // other value is not this function and is left alone.
    for (size_t i = 1; i < n; i++)
        if (*slots[i] == original) hook_slot(lib, slots[i], replacement);
    return original;
}

void* hook(const char* library, const char* symbol, void* replacement) {
    Library lib;
    if (!find_library(library, &lib)) return nullptr;
    return hook_in(lib, symbol, replacement);
}

bool restore(const char* library, const char* symbol) {
    Library lib;
    if (!find_library(library, &lib)) return false;
    void** slots[MAX_SLOTS_PER_SYMBOL];
    const size_t n = find_slots(lib, symbol, slots, MAX_SLOTS_PER_SYMBOL);
    if (!n) return false;

    pthread_mutex_lock(&g_lock);
    bool ok = false;
    for (size_t i = 1; i < n; i++)  // data slots first; the PLT slot decides the return value
        if (Record* r = record_for(slots[i])) {
            const long page_size = sysconf(_SC_PAGESIZE);
            const auto page = reinterpret_cast<uintptr_t>(slots[i]) & ~static_cast<uintptr_t>(page_size - 1);
            if (mprotect(reinterpret_cast<void*>(page), page_size, PROT_READ | PROT_WRITE) == 0) {
                __atomic_store_n(slots[i], r->original, __ATOMIC_SEQ_CST);
                mprotect(reinterpret_cast<void*>(page), page_size, protection_after(lib, slots[i]));
                *r = g_records[--g_record_count];
            }
        }
    void** slot = slots[0];
    if (Record* r = record_for(slot)) {
        const long page_size = sysconf(_SC_PAGESIZE);
        const auto page = reinterpret_cast<uintptr_t>(slot) & ~static_cast<uintptr_t>(page_size - 1);
        if (mprotect(reinterpret_cast<void*>(page), page_size, PROT_READ | PROT_WRITE) == 0) {
            __atomic_store_n(slot, r->original, __ATOMIC_SEQ_CST);
            mprotect(reinterpret_cast<void*>(page), page_size, protection_after(lib, slot));
            *r = g_records[--g_record_count];
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

}  // namespace ph::got
