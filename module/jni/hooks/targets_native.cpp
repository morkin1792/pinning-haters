// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "../art/aot_fallback.h"
#include "../dex/dex_intercept.h"
#include "../tls/boringssl_table.h"
#include "../tls/openssl_table.h"
#include "../tls/tls_hooks.h"
#include "hook_manager.h"
#include "targets.h"

// Categories B and C, plus the ART-side contracts the DEX path rests on. The hook manager installs
// the quietest listed style that resolves and the tier permits; everything else becomes a coverage
// line. '|' in consumer_library is an ordered candidate list — every candidate with the edge is
// hooked, which is how per-Android-version library moves are absorbed without code changes.
namespace ph {

using enum HookStyle;

#define FN(f) reinterpret_cast<void*>(&f)

const NativeTarget kNativeTargets[] = {
    // ---- ART contracts (Phase 0.5). Verified by tools/check_elf_contracts.sh against real libraries. ----
    {"libz.so", "adler32", "libdexfile.so", FN(dexi::adler32_hook), &dexi::orig_adler32, GOT_IN_CONSUMER, Tier::MAX,
     SurfaceId::JAVA_DEX, "DexFileVerifier::CheckHeader checksum: patch-at-verify choke point"},
    // Deferred loads. Every dlopen in the process — System.loadLibrary through libnativeloader,
    // Dart FFI through libflutter.so, SDK loaders, packers, libc — ends in libdl.so's wrappers,
    // which call the linker through libdl's own import slots. Two slots in one system library
    // cover all of them, and no app-private GOT is touched: protection SDKs check their own
    // .got.plt against .rela.plt and kill the app when a slot points outside libdl.
    {"ld-android.so", "__loader_dlopen", "libdl.so", FN(hooks::loader_dlopen_hook), &hooks::orig_loader_dlopen,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::DEFERRED_LOAD, "every dlopen → re-evaluate native targets"},
    {"ld-android.so", "__loader_android_dlopen_ext", "libdl.so", FN(hooks::loader_android_dlopen_ext_hook),
     &hooks::orig_loader_android_dlopen_ext, GOT_IN_CONSUMER, Tier::MAX, SurfaceId::DEFERRED_LOAD,
     "every android_dlopen_ext (System.loadLibrary included) → re-evaluate native targets"},
    // vdex/odex probe fallback (aot.stat_hook_fallback). GOT writes in ART libraries, never libc.
    // API 34 imports: libartbase {stat, open, __open_2, access}, libart {stat, open, access};
    // fstatat/openat are kept as candidates for future ART releases.
    {"libc.so", "stat", "libartbase.so|libart.so|libdexfile.so", FN(aot::stat_hook), &aot::orig_stat, GOT_IN_CONSUMER,
     Tier::MAX, SurfaceId::AOT, "OS::FileExists on oat artifacts → ENOENT"},
    {"libc.so", "fstatat", "libartbase.so|libart.so|libdexfile.so", FN(aot::fstatat_hook), &aot::orig_fstatat,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::AOT, "fstatat on oat artifacts → ENOENT"},
    {"libc.so", "open", "libartbase.so|libart.so|libdexfile.so", FN(aot::open_hook), &aot::orig_open, GOT_IN_CONSUMER,
     Tier::MAX, SurfaceId::AOT, "open on oat artifacts → ENOENT"},
    {"libc.so", "__open_2", "libartbase.so|libart.so|libdexfile.so", FN(aot::open_2_hook), &aot::orig_open_2,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::AOT, "FORTIFY open on oat artifacts → ENOENT"},
    {"libc.so", "openat", "libartbase.so|libart.so|libdexfile.so", FN(aot::openat_hook), &aot::orig_openat,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::AOT, "openat on oat artifacts → ENOENT"},
    {"libc.so", "access", "libartbase.so|libart.so|libdexfile.so", FN(aot::access_hook), &aot::orig_access,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::AOT, "access on oat artifacts → ENOENT"},

    // ---- B1: platform TLS. conscrypt APEX libjavacrypto.so → libssl.so. Wrap, never replace. ----
    {"libssl.so", "SSL_set_custom_verify", "libjavacrypto.so", FN(tls::conscrypt_ssl_set_custom_verify),
     &tls::orig_conscrypt_ssl_set_custom_verify, GOT_IN_CONSUMER, Tier::MAX, SurfaceId::PLATFORM_TLS,
     "conscrypt NativeCrypto.SSL_set_verify → cert_verify_callback (wrapped)"},
    {"libssl.so", "SSL_CTX_set_custom_verify", "libjavacrypto.so", FN(tls::conscrypt_ctx_set_custom_verify),
     &tls::orig_conscrypt_ctx_set_custom_verify, GOT_IN_CONSUMER, Tier::MAX, SurfaceId::PLATFORM_TLS,
     "conscrypt SSL_CTX-level verify callback (wrapped)"},

    // ---- B2: app-bundled BoringSSL/OpenSSL with exported symbols. Slot in the CALLING library
    //      (libcurl, grpc, qt, the app's own code), provider text untouched. nullptr consumer =
    //      every app-private library importing the symbol, now and after each deferred load. ----
    {"libssl.so", "SSL_CTX_set_verify", nullptr, FN(tls::ssl_ctx_set_verify), &tls::orig_ssl_ctx_set_verify,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS, "SSL_CTX_set_verify → SSL_VERIFY_NONE"},
    {"libssl.so", "SSL_set_verify", nullptr, FN(tls::ssl_set_verify), &tls::orig_ssl_set_verify, GOT_IN_CONSUMER,
     Tier::MAX, SurfaceId::BUNDLED_TLS, "SSL_set_verify → SSL_VERIFY_NONE"},
    {"libssl.so", "SSL_CTX_set_custom_verify", nullptr, FN(tls::ssl_ctx_set_custom_verify),
     &tls::orig_ssl_ctx_set_custom_verify, GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS,
     "SSL_CTX_set_custom_verify → always ok"},
    {"libssl.so", "SSL_set_custom_verify", nullptr, FN(tls::ssl_set_custom_verify), &tls::orig_ssl_set_custom_verify,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS, "SSL_set_custom_verify → always ok"},
    {"libssl.so", "SSL_CTX_set_cert_verify_callback", nullptr, FN(tls::ssl_ctx_set_cert_verify_callback),
     &tls::orig_ssl_ctx_set_cert_verify_callback, GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS,
     "SSL_CTX_set_cert_verify_callback → always 1"},
    {"libssl.so", "SSL_get_verify_result", nullptr, FN(tls::ssl_get_verify_result), &tls::orig_ssl_get_verify_result,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS, "SSL_get_verify_result → X509_V_OK"},
    // libssl's own chain verification calls into libcrypto: a cross-library edge inside the bundle.
    {"libcrypto.so", "X509_verify_cert", nullptr, FN(tls::x509_verify_cert), &tls::orig_x509_verify_cert,
     GOT_IN_CONSUMER, Tier::MAX, SurfaceId::BUNDLED_TLS, "X509_verify_cert → 1"},

    // ---- C: no symbol to resolve. The locator finds BoringSSL's ssl_crypto_x509_method table and
    //      the write is a RELRO pointer swap: a data page in an app-private library, the same class
    //      as the bundled-TLS GOT edges above, so it is `max` (owner decision, 2026-10-25). The
    //      named entry claims libflutter.so for the `flutter` ladder line; the wildcard one covers
    //      every other app-private library with a static BoringSSL (WebRTC, OpenTok, curl builds). ----
    {"libflutter.so", "ssl_crypto_x509_session_verify_cert_chain", "libflutter.so", nullptr, nullptr, PATTERN, Tier::MAX,
     SurfaceId::FLUTTER, "Flutter's hidden-visibility BoringSSL chain verification (x509 method table)",
     &boringssl_table::install},
    {"<app-private library>", "ssl_crypto_x509_session_verify_cert_chain", nullptr, nullptr, nullptr, PATTERN, Tier::MAX,
     SurfaceId::STATIC_BORINGSSL, "statically linked BoringSSL in an app-private library (x509 method table)",
     &boringssl_table::install, "libwebviewchromium.so|libmonochrome*|libchrome*|libcronet.*|libtrichrome*"},
    // Statically linked OpenSSL: no x509 method table, but the SSL_METHOD the handshake runs through
    // is a RELRO table too; its ssl_connect member is swapped for a wrapper that relaxes the verify
    // mode around the real connect. Found through the library's exports, so a hidden-visibility
    // build reports pattern_not_found. Same primitive class as the row above.
    {"<app-private library>", "ssl_connect", nullptr, nullptr, nullptr, PATTERN, Tier::MAX, SurfaceId::STATIC_OPENSSL,
     "statically linked OpenSSL in an app-private library (SSL_METHOD table)", &openssl_table::install,
     "libwebviewchromium.so|libmonochrome*|libchrome*|libcronet.*|libtrichrome*|libflutter.so"},
};
const size_t kNativeTargetCount = sizeof(kNativeTargets) / sizeof(kNativeTargets[0]);

#undef FN

// Presence-only. A trailing '*' matches a prefix (versioned library names).
const RuntimeMarker kRuntimeMarkers[] = {
    {"libapp.so", SurfaceId::DART_PINNING, Tier::COMPAT,
     "Dart AOT snapshot; a pure-Dart peerCertificate comparison would live here and is out of reach. Plugin-based checks (http_certificate_pinning, ssl_pinning_plugin) are Java and are patched when present"},
    {"libil2cpp.so", SurfaceId::UNITY_IL2CPP, Tier::COMPAT, "C# CertificateHandler / manual chain walks compiled by IL2CPP"},
    {"libmonosgen-2.0.so", SurfaceId::XAMARIN_MONO, Tier::COMPAT, "ServerCertificateValidationCallback lives in Mono assemblies"},
    {"libcronet.*", SurfaceId::CRONET, Tier::BALANCED, "Cronet statically links BoringSSL; pin APIs are compat/Phase 2"},
    // Stacks that live in a library named after the app, found by a string they always carry.
    {"<app-private library>", SurfaceId::GO_TLS, Tier::COMPAT,
     "Go crypto/tls statically linked (gomobile); verification and any VerifyPeerCertificate pin run inside Go code, no hook reaches them",
     "crypto/tls: "},
    {"<app-private library>", SurfaceId::RUST_TLS, Tier::COMPAT,
     "rustls statically linked; its verifier and any custom ServerCertVerifier run inside Rust code, no hook reaches them",
     "/rustls-"},
};
const size_t kRuntimeMarkerCount = sizeof(kRuntimeMarkers) / sizeof(kRuntimeMarkers[0]);

}  // namespace ph
