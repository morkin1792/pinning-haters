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

// The adler32 GOT edge in libdexfile.so: DexFileVerifier::CheckHeader computes the DEX checksum by
// calling zlib's adler32 across a library boundary. Our replacement computes the checksum of the
// UNPATCHED bytes first, patches the DEX in place, and returns the saved value. The verifier
// compares it against the untouched header field, they match, and verification proceeds over the
// patched bytes. One choke point covers the base APK, splits, DexClassLoader and
// InMemoryDexClassLoader, because all of them are verified — provided no vdex exists to let ART
// skip the verifier, which is what companion-side oat eviction guarantees. Neither works alone.
namespace ph::dexi {

extern void* orig_adler32;
unsigned long adler32_hook(unsigned long adler, const uint8_t* buf, unsigned int len);

}  // namespace ph::dexi
