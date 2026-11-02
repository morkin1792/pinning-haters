// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "tls_hooks.h"

#include <jni.h>

#include "../art/art_api.h"
#include "../log/log.h"

// The single most valuable hook in the project. libjavacrypto.so calls SSL_set_custom_verify in the
// conscrypt APEX's libssl.so with its cert_verify_callback, which calls up into Java
// (SSLHandshakeCallbacks.verifyCertificateChain → the app's / platform's TrustManager) and returns
// ssl_verify_invalid with a pending CertificateException when that throws. Everything that
// validates through a javax.net.ssl TrustManager — platform trust, Network Security Config pins,
// TrustKit, custom X509TrustManagers, Volley, gRPC-over-OkHttp, Cronet's system-trust path — funnels
// through this one edge.
//
// We WRAP conscrypt's callback instead of replacing it: the real TrustManager still runs with every
// observable side effect, and only its verdict is discarded. Replacing the callback is one line
// simpler and strictly louder ("was my trust manager ever called?" is a cheap check an app can make
// without hunting for hooks). The test app asserts the TrustManager ran.
namespace ph::tls {

void* orig_conscrypt_ssl_set_custom_verify = nullptr;
void* orig_conscrypt_ctx_set_custom_verify = nullptr;

namespace {

custom_verify_cb g_conscrypt_cb = nullptr;

ssl_verify_result_t wrapped_verify(void* ssl, uint8_t* out_alert) {
    custom_verify_cb cb = __atomic_load_n(&g_conscrypt_cb, __ATOMIC_ACQUIRE);
    const ssl_verify_result_t verdict = cb ? cb(ssl, out_alert) : ssl_verify_ok;
    if (verdict != ssl_verify_invalid) return verdict;  // ok, or retry (async): nothing to override
    // The TrustManager threw. The exception is still pending on this (Java) thread; clearing it is
    // all that stands between "handshake failed" and "handshake completed".
    if (JNIEnv* env = art::env(); env && env->ExceptionCheck()) env->ExceptionClear();
    PH_LOGD("[platform_tls] TrustManager rejected the chain; verdict overridden to ok");
    return ssl_verify_ok;
}

void remember(custom_verify_cb cb) {
    custom_verify_cb prev = __atomic_exchange_n(&g_conscrypt_cb, cb, __ATOMIC_ACQ_REL);
    if (prev && prev != cb)
        PH_LOGW("[platform_tls] conscrypt installed a second distinct verify callback (%p, was %p)",
                reinterpret_cast<void*>(cb), reinterpret_cast<void*>(prev));
}

}  // namespace

void conscrypt_ssl_set_custom_verify(void* ssl, int mode, custom_verify_cb cb) {
    auto orig = reinterpret_cast<void (*)(void*, int, custom_verify_cb)>(orig_conscrypt_ssl_set_custom_verify);
    if (!cb) return orig(ssl, mode, cb);
    remember(cb);
    orig(ssl, mode, wrapped_verify);
}

void conscrypt_ctx_set_custom_verify(void* ctx, int mode, custom_verify_cb cb) {
    auto orig = reinterpret_cast<void (*)(void*, int, custom_verify_cb)>(orig_conscrypt_ctx_set_custom_verify);
    if (!cb) return orig(ctx, mode, cb);
    remember(cb);
    orig(ctx, mode, wrapped_verify);
}

}  // namespace ph::tls
