// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "boringssl_table.h"

#include "openssl_table.h"

#include <elf.h>
#include <link.h>
#include <string.h>

#include "../log/log.h"

namespace ph::boringssl_table {

namespace {

struct Segment {
    uintptr_t start;
    uintptr_t end;
    uint32_t flags;
};

size_t segments_of(const got::Library& lib, Segment* out, size_t max) {
    size_t n = 0;
    for (uint16_t i = 0; i < lib.phnum && n < max; i++) {
        const ElfW(Phdr)& p = lib.phdr[i];
        if (p.p_type != PT_LOAD) continue;
        out[n++] = {lib.bias + p.p_vaddr, lib.bias + p.p_vaddr + p.p_memsz, p.p_flags};
    }
    return n;
}

bool in_exec(const Segment* segs, size_t n, uintptr_t a) {
    for (size_t i = 0; i < n; i++)
        if ((segs[i].flags & PF_X) && a >= segs[i].start && a < segs[i].end) return true;
    return false;
}

// Every occurrence of the NUL-terminated `needle` in the library's readable segments. lld folds
// .rodata into the R+X segment unless told otherwise (Flutter's build does not), so executable
// segments are searched too. memmem keeps a 40 MB libapp.so at a few milliseconds.
size_t find_strings(const Segment* segs, size_t n, const char* needle, uintptr_t* out, size_t max) {
    const size_t len = strlen(needle) + 1;
    size_t found = 0;
    for (size_t i = 0; i < n && found < max; i++) {
        if (!(segs[i].flags & PF_R)) continue;
        const auto* p = reinterpret_cast<const uint8_t*>(segs[i].start);
        size_t left = segs[i].end - segs[i].start;
        while (left >= len && found < max) {
            const auto* hit = static_cast<const uint8_t*>(memmem(p, left, needle, len));
            if (!hit) break;
            out[found++] = reinterpret_cast<uintptr_t>(hit);
            left -= static_cast<size_t>(hit + 1 - p);
            p = hit + 1;
        }
    }
    return found;
}

// Greatest pointer in RELRO (falling back to every writable segment) that lands in executable memory
// at most 4 KiB before `ref`: the start of the function containing `ref`, provided that function is
// in a pointer table at all. The ssl_crypto_x509_* functions sit next to each other and all are in
// the table, so the nearest table target below the reference is ours.
void** table_slot_for(const got::Library& lib, const Segment* segs, size_t nsegs, uintptr_t ref) {
    void** best = nullptr;
    uintptr_t best_value = 0;
    auto scan = [&](uintptr_t start, uintptr_t end) {
        start = (start + 7) & ~uintptr_t{7};
        for (uintptr_t a = start; a + 8 <= end; a += 8) {
            const uintptr_t value = *reinterpret_cast<const uintptr_t*>(a);
            if (value > ref || ref - value > 4096 || !in_exec(segs, nsegs, value)) continue;
            if (value > best_value) {
                best_value = value;
                best = reinterpret_cast<void**>(a);
            }
        }
    };
    for (uint16_t i = 0; i < lib.phnum; i++)
        if (lib.phdr[i].p_type == PT_GNU_RELRO)
            scan(lib.bias + lib.phdr[i].p_vaddr, lib.bias + lib.phdr[i].p_vaddr + lib.phdr[i].p_memsz);
    if (!best)
        for (size_t s = 0; s < nsegs; s++)
            if ((segs[s].flags & PF_W) && !(segs[s].flags & PF_X)) scan(segs[s].start, segs[s].end);
    if (!best) return nullptr;
    // A table of function pointers surrounds the slot (SSL_X509_METHOD has a dozen members).
    int neighbours = 0;
    for (int k = -4; k <= 4; k++) {
        if (k == 0) continue;
        const auto* at = reinterpret_cast<const uintptr_t*>(best) + k;
        // A slot near the edge of a segment must not make us read past it.
        bool readable = false;
        for (size_t s = 0; s < nsegs && !readable; s++)
            readable = (segs[s].flags & PF_R) && reinterpret_cast<uintptr_t>(at) >= segs[s].start &&
                       reinterpret_cast<uintptr_t>(at) + sizeof(*at) <= segs[s].end;
        if (readable && in_exec(segs, nsegs, *at)) neighbours++;
    }
    return neighbours >= 4 ? best : nullptr;
}

// The function opens with `*out_alert = SSL_AD_INTERNAL_ERROR` (80): a `mov wN, #0x50` followed by
// `strb wN, [x2]` within the first instructions. Tie-breaker only; never required.
bool stores_internal_error_alert(uintptr_t fn) {
    const auto* code = reinterpret_cast<const uint32_t*>(fn);
    for (size_t i = 0; i < 24; i++) {
        if ((code[i] & 0xffffffe0u) != 0x52800a00u) continue;  // MOVZ wN, #0x50
        const uint32_t rn = code[i] & 0x1f;
        for (size_t j = i + 1; j < i + 4 && j < 24; j++)
            if (code[j] == (0x39000040u | rn)) return true;  // STRB wN, [x2]
    }
    return false;
}

// One static BoringSSL per library, each with its own original. The replacement has no argument
// that names the library, but its caller (ssl_verify_peer_cert) lives in the same one, so the
// return address picks the entry. Written under the hook manager's lock, read on TLS threads.
struct Hooked {
    uintptr_t start;
    uintptr_t end;
    void** slot;
    void* original;
};
constexpr size_t MAX_HOOKED = 8;
Hooked g_hooked[MAX_HOOKED];
size_t g_hooked_count = 0;  // only ever grows; entries are complete before it does

void library_range(const got::Library& lib, uintptr_t* start, uintptr_t* end) {
    *start = UINTPTR_MAX;
    *end = 0;
    for (uint16_t i = 0; i < lib.phnum; i++) {
        if (lib.phdr[i].p_type != PT_LOAD) continue;
        const uintptr_t s = lib.bias + lib.phdr[i].p_vaddr, e = s + lib.phdr[i].p_memsz;
        if (s < *start) *start = s;
        if (e > *end) *end = e;
    }
}

}  // namespace

bool find_adrp_add_ref(const uint32_t* code, size_t n, uintptr_t code_addr, uintptr_t target, uintptr_t* ref_out) {
    const uintptr_t target_page = target & ~uintptr_t{0xfff};
    const uint32_t target_lo = static_cast<uint32_t>(target & 0xfff);
    for (size_t i = 0; i < n; i++) {
        const uint32_t insn = code[i];
        if ((insn & 0x9f000000u) != 0x90000000u) continue;  // ADRP
        const uintptr_t pc = code_addr + i * 4;
        const uint64_t immlo = (insn >> 29) & 3;
        const uint64_t immhi = (insn >> 5) & 0x7ffff;
        int64_t imm = static_cast<int64_t>((immhi << 2) | immlo);
        if (imm & (1 << 20)) imm -= (1 << 21);  // sign-extend 21 bits
        const uintptr_t page = (pc & ~uintptr_t{0xfff}) + static_cast<uintptr_t>(imm << 12);
        if (page != target_page) continue;
        const uint32_t rd = insn & 0x1f;
        // ADD (immediate, 64-bit, no shift) from the same register within the next few instructions.
        for (size_t j = i + 1; j < n && j <= i + 16; j++) {
            const uint32_t add = code[j];
            if ((add & 0xffc00000u) != 0x91000000u) continue;  // sf=1 op=0 S=0 100010 sh=0
            const uint32_t rn = (add >> 5) & 0x1f;
            const uint32_t imm12 = (add >> 10) & 0xfff;
            if (rn == rd && imm12 == target_lo) {
                *ref_out = code_addr + j * 4;
                return true;
            }
        }
    }
    return false;
}

void** locate_session_verify_slot(const got::Library& lib, bool* has_strings) {
    Segment segs[16];
    const size_t nsegs = segments_of(lib, segs, 16);

    uintptr_t clients[8], servers[8];
    const size_t nc = find_strings(segs, nsegs, "ssl_client", clients, 8);
    const size_t ns = find_strings(segs, nsegs, "ssl_server", servers, 8);
    if (has_strings) *has_strings = nc > 0 && ns > 0;
    if (nc == 0 || ns == 0) return nullptr;

    // Code references to "ssl_client" with one to "ssl_server" nearby. Two functions qualify:
    // libcrypto's X509_VERIFY_PARAM_lookup (a strcmp chain over the purpose names) and ours. Only
    // ours is reached through a pointer table, which is what tells them apart. (OpenSSL, which
    // shares the strings, calls its verifier directly and never survives this filter: correct.)
    void** found = nullptr;
    uintptr_t found_fn = 0;
    int survivors = 0;
    for (size_t s = 0; s < nsegs; s++) {
        if (!(segs[s].flags & PF_X)) continue;
        const auto* code = reinterpret_cast<const uint32_t*>(segs[s].start);
        const size_t n = (segs[s].end - segs[s].start) / 4;
        for (size_t c = 0; c < nc; c++) {
            size_t from = 0;
            uintptr_t ref_client;
            while (from < n && find_adrp_add_ref(code + from, n - from, segs[s].start + from * 4, clients[c], &ref_client)) {
                from = (ref_client - segs[s].start) / 4 + 1;
                const size_t lo = ref_client > segs[s].start + 256 ? (ref_client - 256 - segs[s].start) / 4 : 0;
                const size_t count = n - lo < 128 ? n - lo : 128;
                bool server_nearby = false;
                for (size_t v = 0; v < ns && !server_nearby; v++) {
                    uintptr_t ref_server;
                    server_nearby = find_adrp_add_ref(code + lo, count, segs[s].start + lo * 4, servers[v], &ref_server);
                }
                if (!server_nearby) continue;
                void** slot = table_slot_for(lib, segs, nsegs, ref_client);
                if (!slot || slot == found) continue;
                const auto fn = reinterpret_cast<uintptr_t>(*slot);
                if (found && stores_internal_error_alert(found_fn) && !stores_internal_error_alert(fn)) continue;
                if (found && !stores_internal_error_alert(found_fn) && stores_internal_error_alert(fn)) survivors--;
                found = slot;
                found_fn = fn;
                survivors++;
            }
        }
    }
    if (!found) return nullptr;
    if (survivors != 1) {
        PH_LOGW("[boringssl_table] %d functions in %s look like session_verify_cert_chain; refusing to guess", survivors,
                lib.path);
        return nullptr;
    }
    PH_LOGD("[boringssl_table] %s: session_verify_cert_chain at %p, table slot %p%s", got::basename_of(lib.path),
            reinterpret_cast<void*>(found_fn), static_cast<void*>(found),
            stores_internal_error_alert(found_fn) ? "" : " (no out_alert prologue; version drift?)");
    return found;
}

PatternResult install(const got::Library& lib) {
    uintptr_t start, end;
    library_range(lib, &start, &end);
    void* const ours = reinterpret_cast<void*>(&session_verify_cert_chain);
    for (size_t i = 0; i < g_hooked_count; i++) {
        // Re-scan after a deferred load. An entry left by a library that was unloaded and replaced
        // at the same address does not count: its slot no longer holds our function.
        const Hooked& h = g_hooked[i];
        if (h.start == start && reinterpret_cast<uintptr_t>(h.slot) < end && __atomic_load_n(h.slot, __ATOMIC_ACQUIRE) == ours)
            return PatternResult::APPLIED;
    }
    // OpenSSL carries the same "ssl_client"/"ssl_server" strings and no x509 method table; the
    // SSL_METHOD backend owns it, so it is absent here rather than a second ladder line.
    if (openssl_table::is_openssl(lib)) return PatternResult::ABSENT;
    bool has_strings = false;
    void** slot = locate_session_verify_slot(lib, &has_strings);
    if (!slot) return has_strings ? PatternResult::FAILED : PatternResult::ABSENT;
    if (g_hooked_count >= MAX_HOOKED) {
        PH_LOGW("[boringssl_table] more than %zu static BoringSSL libraries; %s left alone", MAX_HOOKED, lib.path);
        return PatternResult::FAILED;
    }
    // Published before the swap: a handshake that reaches the replacement the moment the pointer
    // changes must already find its original.
    void* const current = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (current == ours) return PatternResult::APPLIED;
    g_hooked[g_hooked_count] = {start, end, slot, current};
    __atomic_store_n(&g_hooked_count, g_hooked_count + 1, __ATOMIC_RELEASE);
    return got::hook_slot(lib, slot, ours) ? PatternResult::APPLIED : PatternResult::FAILED;
}

bool session_verify_cert_chain(void* session, void* hs, uint8_t* out_alert) {
    const auto caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const size_t count = __atomic_load_n(&g_hooked_count, __ATOMIC_ACQUIRE);
    // Newest first: a library loaded where an unloaded one used to be must find its own entry.
    for (size_t i = count; i-- > 0;) {
        if (caller < g_hooked[i].start || caller >= g_hooked[i].end) continue;
        const auto orig = reinterpret_cast<bool (*)(void*, void*, uint8_t*)>(g_hooked[i].original);
        if (!orig(session, hs, out_alert)) PH_LOGD("[boringssl_table] BoringSSL rejected the chain; verdict overridden to ok");
        return true;
    }
    // A caller outside every hooked library should not exist; accept rather than crash the handshake.
    PH_LOGW("[boringssl_table] verify called from %p, outside every hooked library; accepted without the original",
            reinterpret_cast<void*>(caller));
    return true;
}

}  // namespace ph::boringssl_table
