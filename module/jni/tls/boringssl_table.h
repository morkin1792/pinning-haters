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

#include "../got/got_hook.h"
#include "../hooks/targets.h"

// A statically linked BoringSSL has no import slot to rewrite, but a handshake whose verification
// runs through the classic SSL_CTX_set_verify path (dart:io, WebRTC, most libcurl builds against a
// private BoringSSL) always calls ssl->ctx->x509_method->session_verify_cert_chain: one member of
// the const ssl_crypto_x509_method table in .data.rel.ro. Swapping that pointer redirects the check
// without touching an executable byte. The function itself is hidden and nameless; it is found as
// the only code that references the "ssl_client"/"ssl_server" purpose strings
// (X509_STORE_CTX_set_default) *and* is reached through a RELRO pointer table. libflutter.so is the
// canonical case; the same code serves every app-private library.
namespace ph::boringssl_table {

// Address of the session_verify_cert_chain table slot in `lib`, or nullptr. *has_strings (optional)
// reports whether the purpose strings exist at all, which separates "no BoringSSL here" from
// "BoringSSL present but the locator could not pin the slot".
void** locate_session_verify_slot(const got::Library& lib, bool* has_strings = nullptr);

// Locates, swaps, and remembers the original for `lib`. Idempotent per library.
PatternResult install(const got::Library& lib);

// The replacement: runs the original of the library that called us (found from the return
// address, since every static BoringSSL has its own), then returns success. Wrap, not replace:
// Dart's badCertificateCallback and WebRTC's verify callback still fire with their side effects.
bool session_verify_cert_chain(void* session, void* hs, uint8_t* out_alert);

// Exposed for the host-side unit test: does code[0..n) contain an ADRP+ADD pair computing `target`
// (the string address), with the code mapped at `code_addr`? *ref_out = address of the ADD.
bool find_adrp_add_ref(const uint32_t* code, size_t n, uintptr_t code_addr, uintptr_t target, uintptr_t* ref_out);

}  // namespace ph::boringssl_table
