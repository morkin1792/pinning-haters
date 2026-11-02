// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <string.h>
#include <sys/stat.h>

// AOT fallback: GOT hooks on the stat/open family *in ART's own libraries* (never inline in libc)
// that make oat artifacts look absent, so ART opens the APK's DEX and the adler32 interception
// fires. The primary mechanism is companion-side deletion (zero in-process footprint); this covers
// read-only paths, odd install layouts and DEX opened mid-run.
namespace ph::aot {

// <root>/.../oat/<isa>/<name>.{odex,vdex,art} for app and framework-shared-library artifacts, plus
// /data/app/.../*.dm (a DexMetadata file can carry a vdex, which would let ART skip the verifier).
// Boot-image files live under /apex and /system/framework/<isa>/ (no "/oat/") and never match.
inline bool is_oat_artifact(const char* path) {
    if (!path || path[0] != '/') return false;
    static const char* const kRoots[] = {"/data/", "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/oem/"};
    bool rooted = false;
    for (const char* r : kRoots) rooted = rooted || strncmp(path, r, strlen(r)) == 0;
    if (!rooted) return false;
    const size_t n = strlen(path);
    if (n >= 3 && strcmp(path + n - 3, ".dm") == 0) return strncmp(path, "/data/app/", 10) == 0;
    if (n < 5 || !strstr(path, "/oat/")) return false;
    const char* ext = path + n - 5;
    return strcmp(ext, ".odex") == 0 || strcmp(ext, ".vdex") == 0 || strcmp(ext + 1, ".art") == 0;
}

extern void* orig_stat;
extern void* orig_fstatat;
extern void* orig_open;
extern void* orig_openat;
extern void* orig_open_2;
extern void* orig_access;

int stat_hook(const char* path, struct stat* st);
int fstatat_hook(int dirfd, const char* path, struct stat* st, int flags);
int open_hook(const char* path, int flags, ...);
int openat_hook(int dirfd, const char* path, int flags, ...);
int open_2_hook(const char* path, int flags);  // FORTIFY variant of open() without a mode
int access_hook(const char* path, int mode);

}  // namespace ph::aot
