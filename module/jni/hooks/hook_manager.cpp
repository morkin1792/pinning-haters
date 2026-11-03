// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "hook_manager.h"

#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#include "../got/got_hook.h"
#include "../log/log.h"

#ifndef PH_VERSION
#define PH_VERSION "dev"
#endif

namespace ph {

const char* surface_name(SurfaceId id) {
    switch (id) {
        case SurfaceId::PLATFORM_TLS: return "platform_tls";
        case SurfaceId::JAVA_DEX: return "java_dex";
        case SurfaceId::OKHTTP_PINNER: return "okhttp_pinner";
        case SurfaceId::CERT_TRANSPARENCY: return "certificate_transparency";
        case SurfaceId::CHROMIUM: return "chromium";
        case SurfaceId::HOSTNAME_VERIFIER: return "hostname_verifier";
        case SurfaceId::BUNDLED_TLS: return "bundled_tls";
        case SurfaceId::CRONET: return "cronet";
        case SurfaceId::FLUTTER: return "flutter";
        case SurfaceId::STATIC_BORINGSSL: return "static_boringssl";
        case SurfaceId::STATIC_OPENSSL: return "static_openssl";
        case SurfaceId::DART_PINNING: return "dart_pinning";
        case SurfaceId::UNITY_IL2CPP: return "unity_il2cpp";
        case SurfaceId::XAMARIN_MONO: return "xamarin_mono";
        case SurfaceId::GO_TLS: return "go_tls";
        case SurfaceId::RUST_TLS: return "rust_tls";
        case SurfaceId::AOT: return "aot";
        case SurfaceId::DEFERRED_LOAD: return "deferred_load";
        case SurfaceId::COUNT: break;
    }
    return "?";
}

namespace hooks {

namespace {

constexpr int SURFACES = static_cast<int>(SurfaceId::COUNT);
constexpr size_t MAX_LIBS = 512;
constexpr size_t MAX_TARGETS = 64;

ipc::Decision g_decision{};
bool g_installed = false;

// One snapshot buffer for the whole process (512 × ~280 bytes is too big for a specialize callback's
// stack and far too big for a dlopen hook running on an arbitrary app thread). Guarded by g_lock.
struct LibList {
    got::Library libs[MAX_LIBS];
    size_t count;
    bool truncated;
};
LibList g_libs;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// Libraries already evaluated against the table, by load bias. A later dlopen re-evaluates only
// what is new, so one System.loadLibrary that drags in libcurl → libssl → libcrypto gets all three
// without re-reporting the ones from startup.
uintptr_t g_evaluated[MAX_LIBS];
size_t g_evaluated_count = 0;

bool was_evaluated(uintptr_t bias) {
    for (size_t i = 0; i < g_evaluated_count; i++)
        if (g_evaluated[i] == bias) return true;
    return false;
}

void mark_evaluated(uintptr_t bias) {
    if (g_evaluated_count < MAX_LIBS && !was_evaluated(bias)) g_evaluated[g_evaluated_count++] = bias;
}

const char* style_name(HookStyle s) {
    switch (s) {
        case HookStyle::GOT_IN_CONSUMER: return "got";
        case HookStyle::INLINE_IN_PROVIDER: return "inline";
        case HookStyle::PATTERN: return "pattern";
    }
    return "?";
}

// Which config "surfaces" toggle owns a SurfaceId. 0 = not user-toggleable.
uint8_t surface_bit(SurfaceId s) {
    switch (s) {
        case SurfaceId::PLATFORM_TLS: return SURFACE_PLATFORM_TLS;
        case SurfaceId::JAVA_DEX:
        case SurfaceId::OKHTTP_PINNER:
        case SurfaceId::CERT_TRANSPARENCY:
        case SurfaceId::CHROMIUM:
        case SurfaceId::DART_PINNING:  // the plugin-side Java checks; pure Dart stays a marker
        case SurfaceId::HOSTNAME_VERIFIER: return SURFACE_JAVA_DEX;
        case SurfaceId::BUNDLED_TLS:
        case SurfaceId::CRONET:
        // Flutter's TLS *is* a bundled BoringSSL; only Dart-side pin checks are a foreign-runtime matter.
        case SurfaceId::FLUTTER:
        case SurfaceId::STATIC_BORINGSSL:
        case SurfaceId::STATIC_OPENSSL: return SURFACE_BUNDLED_TLS;
        case SurfaceId::UNITY_IL2CPP:
        case SurfaceId::XAMARIN_MONO: return SURFACE_FOREIGN_RUNTIME;
        default: return 0;
    }
}

const char* native_target_blocked(const NativeTarget& t) {
    if (t.min_tier > g_decision.tier) return "tier";
    if (const uint8_t bit = surface_bit(t.surface); bit && !(g_decision.surfaces & bit)) return "surface_disabled";
    if (t.surface == SurfaceId::AOT && !(g_decision.flags & FLAG_STAT_FALLBACK)) return "aot.stat_hook_fallback=false";
    return nullptr;
}

// The inline backend (shadowhook) is not wired yet; PATTERN entries work when they carry a locator.
// Entries without a backend stay in the table so the coverage ladder can name them.
bool style_available(const NativeTarget& t) {
    return t.style == HookStyle::GOT_IN_CONSUMER || (t.style == HookStyle::PATTERN && t.pattern != nullptr);
}


bool collect_cb(const got::Library& lib, void* ctx) {
    auto* list = static_cast<LibList*>(ctx);
    if (list->count < MAX_LIBS) list->libs[list->count++] = lib;
    else list->truncated = true;
    return false;
}

unsigned long long g_unloads_seen = 0;
time_t g_last_reset = 0;
constexpr time_t RESET_MIN_INTERVAL_S = 5;  // ponytail: a full re-pass at most this often; per-library revalidation if a loader churns

// Snapshot first: hooking inside the dl_iterate_phdr callback would nest the linker's lock.
void snapshot() {
    g_libs.count = 0;
    g_libs.truncated = false;
    got::for_each_library(collect_cb, &g_libs);
    if (g_libs.truncated) PH_LOGW("[init] more than %zu libraries loaded; later ones were not evaluated", MAX_LIBS);
    // The evaluated set is keyed by load bias. A dlclose frees a range the next load can reuse, and
    // a library mapped there would be skipped with its slots never rewritten; any unload since the
    // last walk invalidates the whole set (slot rewrites are idempotent, so a re-pass is only cost).
    // Rate-limited so a loader that opens and closes libraries in a loop costs one re-pass per
    // interval, not one per iteration; coverage catches up at the next load after the interval.
    if (got::unload_count() != g_unloads_seen) {
        timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - g_last_reset >= RESET_MIN_INTERVAL_S) {
            g_last_reset = now.tv_sec;
            g_unloads_seen = got::unload_count();
            g_evaluated_count = 0;
        }
    }
}

bool name_matches(const char* pattern, const char* basename) {
    const size_t n = strlen(pattern);
    if (n && pattern[n - 1] == '*') return strncmp(pattern, basename, n - 1) == 0;
    return strcmp(pattern, basename) == 0;
}

// "liba*|libb.so" → does `basename` match one of the patterns (name_matches semantics)?
bool name_in_list(const char* patterns, const char* basename) {
    const char* p = patterns;
    while (*p) {
        const char* bar = strchr(p, '|');
        const size_t len = bar ? static_cast<size_t>(bar - p) : strlen(p);
        char one[64];
        if (len < sizeof(one)) {
            memcpy(one, p, len);
            one[len] = 0;
            if (name_matches(one, basename)) return true;
        }
        if (!bar) break;
        p = bar + 1;
    }
    return false;
}

// "a.so|b*" → does `basename` name one of the candidates? A trailing '*' is a prefix match, so a
// row can name a vendor's library family (libcashshieldptr*) without knowing each build's suffix.
bool is_candidate(const char* candidates, const char* basename) { return name_in_list(candidates, basename); }

// A wildcard PATTERN entry (any app-private library) stays off libraries that another PATTERN
// entry names explicitly, so libflutter.so reports as `flutter`, not twice.
bool claimed_by_named_pattern_entry(const char* basename) {
    for (size_t i = 0; i < kNativeTargetCount; i++) {
        const NativeTarget& o = kNativeTargets[i];
        if (o.style == HookStyle::PATTERN && o.consumer_library && is_candidate(o.consumer_library, basename)) return true;
    }
    return false;
}

// This module's own load address: a wildcard scan must never treat its own library as app code
// (on Magisk it is a memfd mapping, indistinguishable by name).
uintptr_t self_base() {
    static uintptr_t base = [] {
        Dl_info info{};
        return dladdr(reinterpret_cast<void*>(&self_base), &info) ? reinterpret_cast<uintptr_t>(info.dli_fbase) : 0;
    }();
    return base;
}

bool consumer_matches(const NativeTarget& t, const got::Library& lib) {
    if (t.consumer_library) return is_candidate(t.consumer_library, got::basename_of(lib.path));
    return got::is_app_private(lib.path) && lib.bias != self_base();
}

bool try_hook(const NativeTarget& t, const got::Library& lib) {
    // The original is published before the slot goes live: other threads (ART's, the app's) call
    // through these slots while we install, and a replacement that ran between the slot write and
    // the store would jump through a null original. Bionic binds imports at load, so the slot
    // already holds the provider's address.
    void** slots[1];
    if (got::find_slots(lib, t.symbol, slots, 1) == 0) return false;  // the slot hook_in rewrites first
    void* const current = __atomic_load_n(slots[0], __ATOMIC_ACQUIRE);
    if (!current) return false;  // unresolved weak import: nothing to call through
    if (t.original && current != t.replacement) {
        void* const known = __atomic_load_n(t.original, __ATOMIC_ACQUIRE);
        if (!known) {
            __atomic_store_n(t.original, current, __ATOMIC_RELEASE);
        } else if (known != current) {
            // Two different providers for one symbol (two bundled BoringSSL copies). Calling the
            // first provider with the second's objects would be an ABI mismatch, so leave this one.
            PH_LOGW("[%s] %s in %s resolves to a different provider than the first hooked one; skipped",
                    surface_name(t.surface), t.symbol, lib.path);
            return false;
        }
    }
    void* orig = got::hook_in(lib, t.symbol, t.replacement);
    if (!orig) return false;
    PH_LOGD("[%s] %s slot %s rewritten in %s (%s)", surface_name(t.surface), style_name(t.style), t.symbol, lib.path,
            t.label);
    return true;
}

// Installs `t` into every matching library in libs[0..count). Returns slots rewritten; sets
// *present when a matching consumer was loaded at all (edge or not).
int install_target(const NativeTarget& t, const got::Library* libs, size_t count, bool* present) {
    int hooked = 0;
    for (size_t i = 0; i < count; i++) {
        if (!consumer_matches(t, libs[i])) continue;
        if (t.skip_consumers && name_in_list(t.skip_consumers, got::basename_of(libs[i].path))) continue;
        if (t.style == HookStyle::PATTERN) {
            if (!t.consumer_library && claimed_by_named_pattern_entry(got::basename_of(libs[i].path))) continue;
            switch (t.pattern(libs[i])) {
                case PatternResult::APPLIED:
                    hooked++;
                    *present = true;
                    PH_LOGD("[%s] pattern slot %s rewritten in %s (%s)", surface_name(t.surface), t.symbol, libs[i].path,
                            t.label);
                    break;
                case PatternResult::FAILED: *present = true; break;
                case PatternResult::ABSENT: break;
            }
            continue;
        }
        if (t.consumer_library) *present = true;  // ART/conscrypt consumer is loaded
        if (try_hook(t, libs[i])) {
            hooked++;
            *present = true;
        }
    }
    return hooked;
}

// Presence without hooking, for blocked or backend-less targets. For "any app-private consumer"
// entries only app-private copies count — the conscrypt APEX ships a libssl.so in every process
// and must not read as bundled TLS.
bool probe_present(const NativeTarget& t, const got::Library* libs, size_t count) {
    const char* want = t.consumer_library ? t.consumer_library : t.provider_library;
    for (size_t j = 0; j < count; j++)
        if (is_candidate(want, got::basename_of(libs[j].path)) && (t.consumer_library || got::is_app_private(libs[j].path)))
            return true;
    return false;
}

// `surface_hooked`: some other entry for the same surface already rewrote a slot. Then a missing
// edge is an optional variant (conscrypt imports SSL_set_custom_verify but not the SSL_CTX one),
// not a broken contract, and only shows up in verbose logs.
void report_native(const NativeTarget& t, int hooked, bool present, const char* lib_hint, bool surface_hooked) {
    if (hooked > 0) {
        log::coverage(t.surface, "present=yes reachable=yes applied=%d style=%s target=%s%s%s", hooked,
                      style_name(t.style), t.symbol, lib_hint ? " lib=" : "", lib_hint ? lib_hint : "");
        return;
    }
    if (!present) return;
    if (const char* why = native_target_blocked(t))
        log::coverage(t.surface, "present=yes reachable=no reason=%s required_tier=%s current_tier=%s target=%s", why,
                      tier_name(t.min_tier), tier_name(g_decision.tier), t.symbol);
    else if (!style_available(t))
        log::coverage(t.surface, "present=yes reachable=no reason=backend_unavailable style=%s required_tier=%s target=%s",
                      style_name(t.style), tier_name(t.min_tier), t.symbol);
    else if (t.style == HookStyle::PATTERN)
        // The library carries the strings the locator keys on but the slot could not be pinned: a
        // BoringSSL built differently (or an OpenSSL, which shares the strings and has no table).
        log::coverage(t.surface, "present=yes reachable=no reason=pattern_not_found target=%s%s%s", t.symbol,
                      lib_hint ? " lib=" : "", lib_hint ? lib_hint : "");
    else if (t.consumer_library && !t.required_edge && (surface_hooked || t.optional_edge))
        PH_LOGD("[%s] optional edge %s not imported by %s", surface_name(t.surface), t.symbol, t.consumer_library);
    else if (t.consumer_library)
        // The consumer library is loaded but has no import slot for the symbol: the ELF contract
        // this edge rests on does not hold on this build. docs/android-versions.md wants to know.
        log::coverage(t.surface, "present=yes reachable=no reason=contract_missing target=%s consumer=%s", t.symbol,
                      t.consumer_library);
}

void check_markers(const got::Library* libs, size_t count, bool seen[SURFACES]) {
    for (size_t m = 0; m < kRuntimeMarkerCount; m++) {
        const RuntimeMarker& marker = kRuntimeMarkers[m];
        for (size_t i = 0; i < count; i++) {
            const char* base = got::basename_of(libs[i].path);
            if (marker.needle) {
                // String markers look only at the app's own libraries (never at this module, whose
                // table carries the needles), and name the library they found the string in. Chromium's
                // 100+ MB libraries never carry a Go or Rust stack and are not worth two scans each.
                if (!got::is_app_private(libs[i].path) || libs[i].bias == self_base()) continue;
                if (name_in_list(PH_CHROMIUM_LIBS, base)) continue;
                if (!got::segments_contain(libs[i], marker.needle)) continue;
            } else if (!name_matches(marker.library, base)) {
                continue;
            }
            seen[static_cast<int>(marker.surface)] = true;
            log::coverage(marker.surface, "present=yes reachable=no required_tier=%s current_tier=%s lib=%s note=\"%s\"",
                          tier_name(marker.required_tier), tier_name(g_decision.tier), marker.needle ? base : marker.library,
                          marker.note);
            if (!marker.needle) break;
        }
    }
}

// Evaluates the whole table against libs[0..count). Install first, report second: whether a
// missing edge is a broken contract or an optional variant depends on what else the surface got.
void evaluate(const got::Library* libs, size_t count, bool seen[SURFACES], const char* lib_hint) {
    const size_t targets = kNativeTargetCount <= MAX_TARGETS ? kNativeTargetCount : MAX_TARGETS;
    if (targets < kNativeTargetCount)
        PH_LOGE("[init] %zu native targets exceed MAX_TARGETS=%zu; the rest are skipped", kNativeTargetCount, MAX_TARGETS);
    int hooked[MAX_TARGETS] = {};
    bool present[MAX_TARGETS] = {};
    bool surface_hooked[SURFACES] = {};
    for (size_t i = 0; i < targets; i++) {
        const NativeTarget& t = kNativeTargets[i];
        if (!native_target_blocked(t) && style_available(t)) hooked[i] = install_target(t, libs, count, &present[i]);
        else present[i] = probe_present(t, libs, count);
        if (present[i]) seen[static_cast<int>(t.surface)] = true;
        if (hooked[i] > 0) surface_hooked[static_cast<int>(t.surface)] = true;
    }
    for (size_t i = 0; i < targets; i++)
        report_native(kNativeTargets[i], hooked[i], present[i], lib_hint,
                      lib_hint != nullptr || surface_hooked[static_cast<int>(kNativeTargets[i].surface)]);
    check_markers(libs, count, seen);
}

}  // namespace

Tier current_tier() { return g_decision.tier; }

const char* java_target_blocked(const JavaTarget& t) {
    if (t.min_tier > g_decision.tier) return "tier";
    if (!(g_decision.surfaces & SURFACE_JAVA_DEX)) return "surface_disabled";
    if (t.surface == SurfaceId::HOSTNAME_VERIFIER && !(g_decision.flags & FLAG_RELAX_HOSTNAME))
        return "relax_hostname_verification=false";
    return nullptr;
}

const JavaTarget* first_java_target(SurfaceId surface) {
    for (size_t i = 0; i < kJavaTargetCount; i++)
        if (kJavaTargets[i].surface == surface) return &kJavaTargets[i];
    return &kJavaTargets[0];
}

namespace {

bool g_rescan_pending = false;

void rescan_locked(const char* path) {
    snapshot();
    for (size_t i = 0; i < g_libs.count; i++) {
        const got::Library& lib = g_libs.libs[i];
        if (was_evaluated(lib.bias)) continue;
        mark_evaluated(lib.bias);
        PH_LOGD("[deferred_load] %s (via %s)", lib.path, path ? path : "?");
        bool seen[SURFACES] = {};
        evaluate(&lib, 1, seen, got::basename_of(lib.path));
    }
}

}  // namespace

void install(const ipc::Decision& d) {
    pthread_mutex_lock(&g_lock);
    g_decision = d;
    g_installed = true;
    PH_LOGI("[init] pinning-haters %s api=%u build=%s tier=%s surfaces=0x%02x flags=0x%02x oat_evicted=%u", PH_VERSION,
            d.api_level, d.build, tier_name(d.tier), d.surfaces, d.flags, d.evicted);

    snapshot();
    bool seen[SURFACES] = {};
    evaluate(g_libs.libs, g_libs.count, seen, nullptr);
    for (size_t i = 0; i < g_libs.count; i++) mark_evaluated(g_libs.libs[i].bias);

    if (d.flags & FLAG_SYSTEM_APP)
        log::coverage(SurfaceId::AOT, "present=yes reachable=%s reason=system_app note=\"oat on a read-only partition; "
                                      "nothing evicted, %s\"",
                      (d.flags & FLAG_STAT_FALLBACK) ? "yes" : "no",
                      (d.flags & FLAG_STAT_FALLBACK) ? "relying on the stat fallback" : "enable aot.stat_hook_fallback");

    // One present=no per surface we never saw: expected for most entries in most apps.
    for (int s = 0; s < SURFACES; s++) {
        if (seen[s]) continue;
        const auto id = static_cast<SurfaceId>(s);
        if (id == SurfaceId::OKHTTP_PINNER || id == SurfaceId::CERT_TRANSPARENCY || id == SurfaceId::CHROMIUM ||
            id == SurfaceId::HOSTNAME_VERIFIER)
            continue;  // reported per DEX
        log::coverage(id, "present=no");
    }
    // Loads that gave up waiting for the lock while this ran (see on_library_loaded).
    while (__atomic_exchange_n(&g_rescan_pending, false, __ATOMIC_SEQ_CST)) rescan_locked("during install");
    pthread_mutex_unlock(&g_lock);
}

// After any dlopen: everything that is newly mapped — the named library and its DT_NEEDED
// dependencies alike — gets evaluated once.

// A library constructor can reach a hooked dlopen while its thread holds the linker's lock, and the
// thread holding g_lock may at that moment be inside dl_iterate_phdr waiting for the linker's lock.
// So the lock is only waited on for a bounded time; past that the request is left as pending and
// whichever thread holds g_lock rescans before it lets go.
void on_library_loaded(const char* path) {
    if (!g_installed) return;
    __atomic_store_n(&g_rescan_pending, true, __ATOMIC_SEQ_CST);
    for (;;) {
        // Monotonic: a wall-clock step while a dlopen waits here must not stretch the bound.
        timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_nsec += 200 * 1000 * 1000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
        if (pthread_mutex_clocklock(&g_lock, CLOCK_MONOTONIC, &deadline) != 0) return;  // the holder picks it up
        while (__atomic_exchange_n(&g_rescan_pending, false, __ATOMIC_SEQ_CST)) rescan_locked(path);
        pthread_mutex_unlock(&g_lock);
        // A request that arrived between the last exchange and the unlock would otherwise be lost.
        if (!__atomic_load_n(&g_rescan_pending, __ATOMIC_SEQ_CST)) return;
    }
}

// libdl.so's dlopen and android_dlopen_ext are thin wrappers: `__loader_dlopen(name, flags,
// __builtin_return_address(0))` into the linker, called through libdl's own import slots. Every
// load in the process ends there — libnativeloader's System.loadLibrary, Dart FFI's
// DynamicLibrary.open in libflutter.so, SDK loaders, packers, libc itself — so two slots in one
// system library cover them all, and the caller address is forwarded untouched, so the name is
// resolved in exactly the namespace the real caller would get. The earlier design rewrote `dlopen`
// in every app-private importer instead; protection SDKs verify their own .got.plt against
// .rela.plt, and one of them killed the app when its slot pointed outside libdl (2026-11-03).
void* orig_loader_dlopen = nullptr;
void* orig_loader_android_dlopen_ext = nullptr;

// RTLD_NOLOAD probes and dlopen(NULL) cannot map anything new, and SDKs issue them in bulk.
bool may_have_loaded(const char* path, int flags) { return path != nullptr && !(flags & RTLD_NOLOAD); }

void* loader_dlopen_hook(const char* path, int flags, const void* caller_addr) {
    using fn = void* (*)(const char*, int, const void*);
    void* handle = reinterpret_cast<fn>(orig_loader_dlopen)(path, flags, caller_addr);
    if (handle && may_have_loaded(path, flags)) on_library_loaded(path);
    return handle;
}

void* loader_android_dlopen_ext_hook(const char* path, int flags, const void* extinfo, const void* caller_addr) {
    using fn = void* (*)(const char*, int, const void*, const void*);
    void* handle = reinterpret_cast<fn>(orig_loader_android_dlopen_ext)(path, flags, extinfo, caller_addr);
    if (handle && may_have_loaded(path, flags)) on_library_loaded(path);
    return handle;
}

}  // namespace hooks
}  // namespace ph
