// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

// Re-maps this module's own pages into anonymous memory so /proc/self/maps no longer names
// /data/adb/modules/pinning_haters/zygisk/arm64-v8a.so. Same addresses, same bytes, same
// protections: every GOT slot that points into us keeps working. Nothing outside our own mapping
// is touched, and no libc hook is involved; the technique is Magisk Zygisk's own remap_all().
// What it does not hide: the host's libzygisk.so (not ours to move) and, when bionic's linker
// loaded us, the soinfo entry that dl_iterate_phdr and dladdr still report.
namespace ph::hide {

// Returns the number of mappings replaced, 0 on failure (logged; the module keeps working).
int remap_self();

}  // namespace ph::hide
