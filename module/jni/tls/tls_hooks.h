// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <stdint.h>

// Replacement functions for the TLS edges in targets_native.cpp. SSL/SSL_CTX/X509_STORE_CTX are
// opaque here; we never dereference them.
namespace ph::tls {

enum ssl_verify_result_t : int { ssl_verify_ok = 0, ssl_verify_invalid = 1, ssl_verify_retry = 2 };
using custom_verify_cb = ssl_verify_result_t (*)(void* ssl, uint8_t* out_alert);
using verify_cb = int (*)(int preverify_ok, void* x509_store_ctx);
using cert_verify_cb = int (*)(void* x509_store_ctx, void* arg);
constexpr int SSL_VERIFY_NONE = 0;

// --- Platform TLS: conscrypt APEX (libjavacrypto.so → libssl.so). WRAP, never replace. ---
extern void* orig_conscrypt_ssl_set_custom_verify;
extern void* orig_conscrypt_ctx_set_custom_verify;
void conscrypt_ssl_set_custom_verify(void* ssl, int mode, custom_verify_cb cb);
void conscrypt_ctx_set_custom_verify(void* ctx, int mode, custom_verify_cb cb);

// --- App-bundled BoringSSL / OpenSSL with exported symbols. ---
extern void* orig_ssl_ctx_set_verify;
extern void* orig_ssl_set_verify;
extern void* orig_ssl_ctx_set_custom_verify;
extern void* orig_ssl_set_custom_verify;
extern void* orig_ssl_ctx_set_cert_verify_callback;
extern void* orig_ssl_get_verify_result;
extern void* orig_x509_verify_cert;
void ssl_ctx_set_verify(void* ctx, int mode, verify_cb cb);
void ssl_set_verify(void* ssl, int mode, verify_cb cb);
void ssl_ctx_set_custom_verify(void* ctx, int mode, custom_verify_cb cb);
void ssl_set_custom_verify(void* ssl, int mode, custom_verify_cb cb);
void ssl_ctx_set_cert_verify_callback(void* ctx, cert_verify_cb cb, void* arg);
long ssl_get_verify_result(const void* ssl);
int x509_verify_cert(void* store_ctx);

}  // namespace ph::tls
