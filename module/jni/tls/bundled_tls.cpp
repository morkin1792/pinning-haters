// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "tls_hooks.h"

#include "../log/log.h"

// App-bundled BoringSSL/OpenSSL. These replace verification outright: unlike conscrypt there is no
// single well-known callback to wrap, and the consumer (libcurl, grpc, cronet, ...) is app code
// that cannot observe the difference from inside the handshake. Installed via the GOT slot of the
// *calling* library, so the provider's text is untouched.
namespace ph::tls {

void* orig_ssl_ctx_set_verify = nullptr;
void* orig_ssl_set_verify = nullptr;
void* orig_ssl_ctx_set_custom_verify = nullptr;
void* orig_ssl_set_custom_verify = nullptr;
void* orig_ssl_ctx_set_cert_verify_callback = nullptr;
void* orig_ssl_get_verify_result = nullptr;
void* orig_x509_verify_cert = nullptr;

namespace {
ssl_verify_result_t always_ok(void*, uint8_t*) { return ssl_verify_ok; }
int always_one(void*, void*) { return 1; }
}  // namespace

void ssl_ctx_set_verify(void* ctx, int, verify_cb) {
    PH_LOGD("[bundled_tls] SSL_CTX_set_verify → SSL_VERIFY_NONE");
    reinterpret_cast<void (*)(void*, int, verify_cb)>(orig_ssl_ctx_set_verify)(ctx, SSL_VERIFY_NONE, nullptr);
}
void ssl_set_verify(void* ssl, int, verify_cb) {
    PH_LOGD("[bundled_tls] SSL_set_verify → SSL_VERIFY_NONE");
    reinterpret_cast<void (*)(void*, int, verify_cb)>(orig_ssl_set_verify)(ssl, SSL_VERIFY_NONE, nullptr);
}
void ssl_ctx_set_custom_verify(void* ctx, int mode, custom_verify_cb) {
    PH_LOGD("[bundled_tls] SSL_CTX_set_custom_verify → always ok");
    reinterpret_cast<void (*)(void*, int, custom_verify_cb)>(orig_ssl_ctx_set_custom_verify)(ctx, mode, always_ok);
}
void ssl_set_custom_verify(void* ssl, int mode, custom_verify_cb) {
    PH_LOGD("[bundled_tls] SSL_set_custom_verify → always ok");
    reinterpret_cast<void (*)(void*, int, custom_verify_cb)>(orig_ssl_set_custom_verify)(ssl, mode, always_ok);
}
void ssl_ctx_set_cert_verify_callback(void* ctx, cert_verify_cb, void* arg) {
    PH_LOGD("[bundled_tls] SSL_CTX_set_cert_verify_callback → always 1");
    reinterpret_cast<void (*)(void*, cert_verify_cb, void*)>(orig_ssl_ctx_set_cert_verify_callback)(ctx, always_one, arg);
}
long ssl_get_verify_result(const void*) {
    return 0;  // X509_V_OK
}
int x509_verify_cert(void*) {
    return 1;
}

}  // namespace ph::tls
