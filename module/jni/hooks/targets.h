// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../ipc.h"

// Hooks are data. A pinning surface is added by appending to kJavaTargets / kNativeTargets in
// targets_java.cpp / targets_native.cpp — never by writing per-target logic in the hook manager.
namespace ph {

// Names appear verbatim in coverage-ladder log lines and in docs/coverage.md.
enum class SurfaceId : uint8_t {
    PLATFORM_TLS,       // conscrypt custom_verify wrap: everything that runs as a TrustManager
    JAVA_DEX,           // the adler32 interception itself (contract present / absent)
    OKHTTP_PINNER,      // okhttp3.CertificatePinner (post-handshake, DEX patch)
    CERT_TRANSPARENCY,  // Certificate Transparency libraries (appmattus/babylon): interceptor, hostname verifier, trust manager
    CHROMIUM,           // WebView / Cronet / HTTP3: Chromium's Java certificate verifier in the provider's DEX
    HOSTNAME_VERIFIER,  // opt-in group, not pinning
    BUNDLED_TLS,        // app-shipped BoringSSL/OpenSSL with exported symbols
    CRONET,             // cronet's bundled BoringSSL consumer
    FLUTTER,            // libflutter.so internal BoringSSL (pattern, balanced)
    STATIC_BORINGSSL,   // symbol-stripped BoringSSL in an app-private library (pattern, balanced)
    STATIC_OPENSSL,     // statically linked OpenSSL in an app-private library (SSL_METHOD table swap, max)
    DART_PINNING,       // Flutter pin plugins: their Android-side check is a DEX target; pure-Dart compares are a marker
    UNITY_IL2CPP,       // C# pinning compiled by IL2CPP (compat, Phase 2)
    XAMARIN_MONO,       // ServerCertificateValidationCallback in Mono assemblies (compat, Phase 2)
    GO_TLS,             // Go crypto/tls statically linked into an app library (gomobile); marker only
    RUST_TLS,           // rustls statically linked into an app library; marker only
    AOT,                // oat eviction / stat fallback
    DEFERRED_LOAD,      // libdl.so's __loader_dlopen / __loader_android_dlopen_ext slots: re-scan after every load
    COUNT
};

const char* surface_name(SurfaceId id);

enum class ReplacementKind : uint8_t {
    RETURN_VOID,
    RETURN_TRUE,
    RETURN_FALSE,
    // For okhttp3.Interceptor.intercept(Chain): the body becomes `return chain.proceed(chain.request())`.
    // The two Chain method ids are resolved from the DEX being patched, so this works for any library
    // that implements pinning or Certificate Transparency as an OkHttp interceptor.
    INTERCEPTOR_PROCEED,
    // `return new <aux_type>()` or `return new <aux_type>(0)` depending on aux_ctor ("()V" or "(I)V").
    // The type and constructor ids are resolved from the DEX being patched. Used where a verifier
    // returns a result object whose "all good" state is a zero status (Chromium's
    // AndroidCertVerifyResult: CertVerifyStatusAndroid.OK == 0).
    RETURN_NEW_INSTANCE,
    // Chromium's @CalledByNative verifier entry point (AndroidNetworkLibrary.verifyServerCertificates,
    // 3 or 5 arguments). The body becomes: addTestRootCertificate(certChain[0]) on the same class,
    // then `return <inner static verifier>(args...)`, where the inner verifier is the only other
    // *static* method in the DEX with the same signature (X509Util.verifyServerCertificates, whatever
    // R8 renamed it to). The chain's own leaf becomes a trust anchor of Chromium's test trust store,
    // so the real verifier succeeds and hands native a non-empty verified chain.
    CHROMIUM_TRUST_LEAF,
};

struct JavaTarget {
    const char* class_descriptor;  // "Lokhttp3/CertificatePinner;"
    const char* method_name;       // "check"
    const char* method_signature;  // "(Ljava/lang/String;Ljava/util/List;)V"
    ReplacementKind replacement;
    Tier min_tier;
    SurfaceId surface;
    const char* label;
    // RETURN_NEW_INSTANCE: the class to construct and its constructor descriptor.
    const char* aux_type = nullptr;
    const char* aux_ctor = nullptr;
};

enum class HookStyle : uint8_t {
    GOT_IN_CONSUMER,     // rewrite the import slot in the calling library; no executable bytes change
    INLINE_IN_PROVIDER,  // shadowhook inline patch of the exporting library (balanced+)
    PATTERN,             // byte-pattern locate an unexported function (balanced+)
};

namespace got {
struct Library;
}

enum class PatternResult { ABSENT, APPLIED, FAILED };

struct NativeTarget {
    const char* provider_library;  // where the symbol is defined; informational for GOT style
    const char* symbol;
    // Library whose GOT slot is rewritten. '|'-separated candidates are tried in order and the
    // first one with the edge wins (that is the ART per-version candidate list). nullptr means
    // "every app-private library that imports the symbol".
    const char* consumer_library;
    void* replacement;
    void** original;  // where the manager stores the original pointer; may be nullptr
    HookStyle style;
    Tier min_tier;
    SurfaceId surface;
    const char* label;
    // PATTERN style only: the backend that locates and rewrites a pointer slot inside one library.
    // The write itself is a data-page pointer swap, exactly like a GOT slot; no executable bytes
    // change. ABSENT: nothing of the kind in this library. FAILED: present, but the slot could not
    // be pinned (the ladder names it). The backend owns the replacement and the per-library
    // originals, which is why `replacement` and `original` stay nullptr on these entries.
    PatternResult (*pattern)(const got::Library& lib) = nullptr;
    // Wildcard PATTERN entries only: `|`-separated basename patterns (trailing `*` allowed) that the
    // scan leaves alone. Chromium's libraries carry the table but verify through a custom-verify
    // callback (and are reached through their Java verifier), so a swap there is risk for nothing.
    const char* skip_consumers = nullptr;
    // GOT_IN_CONSUMER entries whose consumers are third-party libraries: a missing import is the
    // normal case (the SDK simply does not use that libc entry point), not a contract failure.
    bool optional_edge = false;
    // The opposite: this slot is load-bearing on its own, so a missing import is a contract failure
    // even when another row for the same surface was rewritten (the libdl pair: System.loadLibrary
    // only ever reaches the android_dlopen_ext slot).
    bool required_edge = false;
};

// Chromium's libraries carry a BoringSSL table but verify through a custom-verify callback (reached
// through their Java verifier instead), and they are the largest libraries an app maps: the
// wildcard table rows and the string markers both leave them alone.
#define PH_CHROMIUM_LIBS "libwebviewchromium.so|libmonochrome*|libchrome*|libcronet.*|libtrichrome*"

// Presence-only detection for runtimes we cannot reach at the current tier. Costs a string
// compare over loaded library names, never a hook.
struct RuntimeMarker {
    const char* library;  // basename pattern (trailing '*' allowed); display name when `needle` is set
    SurfaceId surface;
    Tier required_tier;
    const char* note;
    // When set, the marker is "some app-private library carries this string" instead of a library
    // name: statically linked stacks (Go's crypto/tls, rustls) live in libraries named after the
    // app, not after the stack. One line per library that carries it.
    const char* needle = nullptr;
};

extern const JavaTarget kJavaTargets[];
extern const size_t kJavaTargetCount;
extern const NativeTarget kNativeTargets[];
extern const size_t kNativeTargetCount;
extern const RuntimeMarker kRuntimeMarkers[];
extern const size_t kRuntimeMarkerCount;

}  // namespace ph
