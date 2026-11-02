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

#include "../got/got_hook.h"
#include "../hooks/targets.h"

// Statically linked OpenSSL (1.1.1 and 3.x) in an app-private library, reached without touching a
// byte of code. OpenSSL's chain check is a direct call inside libssl (`ssl_verify_cert_chain` →
// `X509_verify_cert`), so no GOT slot and no x509 method table exist. What does exist is the
// `SSL_METHOD` the handshake runs through: a const struct of function pointers in `.data.rel.ro`
// that `TLS_client_method()` returns a pointer to, and whose `ssl_connect` member every
// `SSL_connect` / `SSL_do_handshake` calls. That member is swapped — a data pointer, the same
// detection class as a GOT slot — for a wrapper that lowers the object's verify mode to
// SSL_VERIFY_NONE (the app's verify callback still runs, its verdict no longer aborts the
// handshake), runs the real connect, and sets the stored verify result to X509_V_OK so a
// `SSL_get_verify_result` check afterwards passes too.
//
// The table is found through the library's own exports (`TLS_client_method` decoded as
// ADRP+ADD, `SSL_set_verify`, `SSL_get_verify_callback`, `SSL_set_verify_result`); a build that
// hides them is reported, not guessed at. BoringSSL is told apart by its version string.
namespace ph::openssl_table {

// Version text says "OpenSSL 1.x"/"OpenSSL 3.x" and not BoringSSL's "(compatible; BoringSSL)".
// Also what tells the BoringSSL backend to leave the library to this one.
bool is_openssl(const got::Library& lib);

struct Exports {
    uintptr_t tls_client_method = 0;
    uintptr_t set_verify = 0;
    uintptr_t get_verify_callback = 0;
    uintptr_t set_verify_result = 0;
};

// The `ssl_connect` slots of the TLS_client_method and TLS_method tables (0, 1 or 2 of them; one
// when both resolve to the same table). *has_openssl says whether the library is an OpenSSL at all
// (version string, not BoringSSL's compatible one), which decides between "absent" and "present
// but not reachable".
size_t locate_connect_slots(const got::Library& lib, bool* has_openssl, Exports* exports, void** out[2]);

PatternResult install(const got::Library& lib);

// The replacement for SSL_METHOD::ssl_connect. Public for the host test.
int ssl_connect(void* ssl);

}  // namespace ph::openssl_table
