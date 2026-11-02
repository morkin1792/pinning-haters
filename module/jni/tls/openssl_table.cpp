// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "openssl_table.h"

#include <elf.h>
#include <link.h>
#include <string.h>

#include "../log/log.h"

namespace ph::openssl_table {

namespace {

// struct ssl_method_st: int version; unsigned flags; 64-bit mask; then function pointers.
//   1.1.x, 3.0, 3.1: ssl_new, ssl_clear, ssl_free, ssl_accept, ssl_connect      (connect at +48)
//   3.2 and later:   ssl_new, ssl_free, ssl_reset, ssl_init, ssl_clear, ssl_deinit,
//                    ssl_accept, ssl_connect                                     (connect at +72)
// Both members on either side are code, so the layout is taken from the version text, never
// inferred from the table: a wrong guess would swap ssl_clear and report success. TLS_method and
// TLS_client_method carry TLS_ANY_VERSION and a mask of SSL_OP_NO_SSLv3 (1.1.1) or 0 (3.x), which
// is how a decoded address is confirmed to be a table before anything is written near it.
constexpr uint32_t TLS_ANY_VERSION = 0x10000;
constexpr uint64_t SSL_OP_NO_SSLv3 = 0x02000000;
struct Layout {
    size_t accept;
    size_t connect;
};
constexpr Layout LAYOUT_1_1 = {16 + 3 * 8, 16 + 4 * 8};
constexpr Layout LAYOUT_3_2 = {16 + 6 * 8, 16 + 7 * 8};
constexpr int SSL_VERIFY_NONE = 0;
constexpr long X509_V_OK = 0;

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

bool in_segment(const Segment* segs, size_t n, uintptr_t a, uint32_t flag) {
    for (size_t i = 0; i < n; i++)
        if ((segs[i].flags & flag) && a >= segs[i].start && a < segs[i].end) return true;
    return false;
}

// `TLS_client_method` is `return &TLS_client_method_data;`: an ADRP into the page and an ADD of the
// low bits, then RET. Decoded, never executed — the host test runs on x86.
uintptr_t decode_adrp_add(uintptr_t fn) {
    const auto* code = reinterpret_cast<const uint32_t*>(fn);
    for (size_t i = 0; i < 4; i++) {
        const uint32_t insn = code[i];
        if ((insn & 0x9f000000u) != 0x90000000u) continue;  // ADRP
        const uintptr_t pc = fn + i * 4;
        const uint64_t immlo = (insn >> 29) & 3;
        const uint64_t immhi = (insn >> 5) & 0x7ffff;
        int64_t imm = static_cast<int64_t>((immhi << 2) | immlo);
        if (imm & (1 << 20)) imm -= (1 << 21);
        const uintptr_t page = (pc & ~uintptr_t{0xfff}) + static_cast<uintptr_t>(imm << 12);
        const uint32_t rd = insn & 0x1f;
        for (size_t j = i + 1; j < i + 4; j++) {
            const uint32_t add = code[j];
            if ((add & 0xffc00000u) != 0x91000000u) continue;  // ADD (immediate, 64-bit)
            if (((add >> 5) & 0x1f) != rd) continue;
            return page + ((add >> 10) & 0xfff);
        }
    }
    return 0;
}

struct Hooked {
    uintptr_t start;
    uintptr_t end;
    void** slot;
    void* original;
    Exports exports;
};
constexpr size_t MAX_HOOKED = 16;  // two tables per library
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

bool is_openssl(const got::Library& lib) {
    // BoringSSL's OPENSSL_VERSION_TEXT is "OpenSSL 1.1.1 (compatible; BoringSSL)": not ours, and it
    // already has its own backend.
    return (got::segments_contain(lib, "OpenSSL 1.") || got::segments_contain(lib, "OpenSSL 3.")) &&
           !got::segments_contain(lib, "compatible; BoringSSL");
}

namespace {

// "OpenSSL 3.1." does not match "OpenSSL 3.10.", so the list stays right when 3.10 exists.
bool old_layout(const got::Library& lib) {
    return got::segments_contain(lib, "OpenSSL 1.1.") || got::segments_contain(lib, "OpenSSL 3.0.") ||
           got::segments_contain(lib, "OpenSSL 3.1.");
}

void** connect_slot_of(uintptr_t method_fn, const Layout& l, const Segment* segs, size_t nsegs) {
    if (!method_fn) return nullptr;
    const uintptr_t table = decode_adrp_add(method_fn);
    if (!table || !in_segment(segs, nsegs, table, PF_R) || !in_segment(segs, nsegs, table + l.connect + 7, PF_R))
        return nullptr;
    uint32_t version;
    uint64_t mask;
    memcpy(&version, reinterpret_cast<const void*>(table), sizeof(version));
    memcpy(&mask, reinterpret_cast<const void*>(table + 8), sizeof(mask));
    // 1.1.1 masks SSLv3 out of the TLS methods; 3.x, which no longer has SSLv3 at all, leaves 0.
    if (version != TLS_ANY_VERSION || (mask != SSL_OP_NO_SSLv3 && mask != 0)) return nullptr;
    auto** slot = reinterpret_cast<void**>(table + l.connect);
    auto** accept = reinterpret_cast<void**>(table + l.accept);
    // ssl_connect must be code; ssl_accept is ossl_statem_accept or ssl_undefined_function, also code.
    if (!in_segment(segs, nsegs, reinterpret_cast<uintptr_t>(*slot), PF_X) ||
        !in_segment(segs, nsegs, reinterpret_cast<uintptr_t>(*accept), PF_X))
        return nullptr;
    return slot;
}

}  // namespace

size_t locate_connect_slots(const got::Library& lib, bool* has_openssl, Exports* ex, void** out[2]) {
    *has_openssl = is_openssl(lib);
    if (!*has_openssl) return 0;
    ex->set_verify = got::find_export(lib, "SSL_set_verify");
    ex->get_verify_callback = got::find_export(lib, "SSL_get_verify_callback");
    ex->set_verify_result = got::find_export(lib, "SSL_set_verify_result");
    if (!ex->set_verify || !ex->get_verify_callback || !ex->set_verify_result) return 0;
    Segment segs[16];
    const size_t nsegs = segments_of(lib, segs, 16);
    const Layout& layout = old_layout(lib) ? LAYOUT_1_1 : LAYOUT_3_2;
    // Two tables reach a client handshake: TLS_client_method's (curl, most apps) and the generic
    // TLS_method's (gRPC, VPN cores). The SSLv23_* names are 1.1.0's macros made functions.
    const char* const kMethods[2][2] = {{"TLS_client_method", "SSLv23_client_method"}, {"TLS_method", "SSLv23_method"}};
    size_t n = 0;
    for (const auto& names : kMethods) {
        uintptr_t fn = got::find_export(lib, names[0]);
        if (!fn) fn = got::find_export(lib, names[1]);
        if (&names == &kMethods[0]) ex->tls_client_method = fn;
        if (void** slot = connect_slot_of(fn, layout, segs, nsegs)) {
            if (n == 0 || out[0] != slot) out[n++] = slot;
        }
    }
    return n;
}

PatternResult install(const got::Library& lib) {
    uintptr_t start, end;
    library_range(lib, &start, &end);
    void* const ours = reinterpret_cast<void*>(&ssl_connect);
    for (size_t i = 0; i < g_hooked_count; i++) {
        const Hooked& h = g_hooked[i];
        // Re-scan after a deferred load. An entry left by a library that was unloaded and replaced
        // at the same address does not count: its slot no longer holds our wrapper.
        const auto slot_addr = reinterpret_cast<uintptr_t>(h.slot);
        if (h.start == start && slot_addr < end && __atomic_load_n(h.slot, __ATOMIC_ACQUIRE) == ours)
            return PatternResult::APPLIED;
    }
    bool has_openssl = false;
    Exports ex;
    void** slots[2] = {};
    const size_t n = locate_connect_slots(lib, &has_openssl, &ex, slots);
    if (!n) {
        if (has_openssl)
            PH_LOGD("[openssl_table] %s is an OpenSSL without the exports or tables the swap needs (TLS_client_method=%d SSL_set_verify=%d)",
                    lib.path, ex.tls_client_method != 0, ex.set_verify != 0);
        return has_openssl ? PatternResult::FAILED : PatternResult::ABSENT;
    }
    size_t applied = 0;
    void* first_original = nullptr;
    for (size_t k = 0; k < n; k++) {
        if (g_hooked_count >= MAX_HOOKED) {
            PH_LOGW("[openssl_table] more than %zu SSL_METHOD tables; %s left alone", MAX_HOOKED, lib.path);
            break;
        }
        // Published before the swap: a handshake that reaches the wrapper the moment the pointer
        // changes must already find its original.
        void* const current = __atomic_load_n(slots[k], __ATOMIC_ACQUIRE);
        if (current == ours) {
            applied++;
            continue;
        }
        // The wrapper picks its original by library, not by table, so both tables must lead to the
        // same connect function (ossl_statem_connect in every release); anything else is left alone.
        if (first_original && current != first_original) {
            PH_LOGW("[openssl_table] %s: TLS_method and TLS_client_method connect through different functions; only the client table swapped",
                    lib.path);
            break;
        }
        if (!first_original) first_original = current;
        g_hooked[g_hooked_count] = {start, end, slots[k], current, ex};
        __atomic_store_n(&g_hooked_count, g_hooked_count + 1, __ATOMIC_RELEASE);
        if (got::hook_slot(lib, slots[k], ours)) applied++;
    }
    return applied ? PatternResult::APPLIED : PatternResult::FAILED;
}

int ssl_connect(void* ssl) {
    using connect_fn = int (*)(void*);
    using verify_cb = int (*)(int, void*);
    using set_verify_fn = void (*)(void*, int, verify_cb);
    using get_cb_fn = verify_cb (*)(const void*);
    using set_result_fn = void (*)(void*, long);
    const auto caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const size_t count = __atomic_load_n(&g_hooked_count, __ATOMIC_ACQUIRE);
    // Newest first: a library loaded where an unloaded one used to be must find its own entry.
    for (size_t i = count; i-- > 0;) {
        if (caller < g_hooked[i].start || caller >= g_hooked[i].end) continue;
        const Exports& ex = g_hooked[i].exports;
        // Keep the app's callback: with SSL_VERIFY_NONE it still runs for every certificate, only
        // its verdict no longer ends the handshake. That is the wrap, not a replacement.
        const verify_cb cb = reinterpret_cast<get_cb_fn>(ex.get_verify_callback)(ssl);
        reinterpret_cast<set_verify_fn>(ex.set_verify)(ssl, SSL_VERIFY_NONE, cb);
        const int r = reinterpret_cast<connect_fn>(g_hooked[i].original)(ssl);
        if (r == 1) {
            reinterpret_cast<set_result_fn>(ex.set_verify_result)(ssl, X509_V_OK);
            PH_LOGD("[openssl_table] handshake completed with verification relaxed; verify result set to ok");
        }
        return r;
    }
    PH_LOGW("[openssl_table] ssl_connect called from %p, outside every hooked library; failing the handshake",
            reinterpret_cast<void*>(caller));
    return -1;
}

}  // namespace ph::openssl_table
