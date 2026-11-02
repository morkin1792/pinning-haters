// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "aot_fallback.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../log/log.h"

namespace ph::aot {

void* orig_stat = nullptr;
void* orig_fstatat = nullptr;
void* orig_open = nullptr;
void* orig_openat = nullptr;
void* orig_open_2 = nullptr;
void* orig_access = nullptr;

namespace {

// Does the APK or jar this artifact was compiled from still carry its DEX? Preopted system and
// product code may have been dex-stripped by the ROM (a known OEM practice): hiding its odex/vdex
// then leaves ART nothing to load, and a framework shared library on the class path
// (org.apache.http.legacy, maps) or a targeted system app fails. Only the central directory is
// read (EOCD at the end of the file, then the directory itself, capped), once per container.
bool container_has_dex(const char* artifact) {
    // <dir>/oat/<isa>/<name>.<ext>  →  <dir>/<name>.apk or <dir>/<name>.jar
    const char* oat = strstr(artifact, "/oat/");
    const char* slash = strrchr(artifact, '/');
    const char* dot = strrchr(artifact, '.');
    if (!oat || !slash || !dot || dot < slash) return false;
    char base[512];
    const int dir_len = static_cast<int>(oat - artifact), name_len = static_cast<int>(dot - slash - 1);

    struct Cached {
        char path[512];
        bool has_dex;
    };
    static Cached cache[32];
    static size_t cached = 0;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    static const char* const kContainers[] = {".apk", ".jar"};
    for (const char* ext : kContainers) {
        if (snprintf(base, sizeof(base), "%.*s/%.*s%s", dir_len, artifact, name_len, slash + 1, ext) >= static_cast<int>(sizeof(base)))
            return false;
        pthread_mutex_lock(&lock);
        for (size_t i = 0; i < cached; i++)
            if (strcmp(cache[i].path, base) == 0) {
                const bool r = cache[i].has_dex;
                pthread_mutex_unlock(&lock);
                return r;
            }
        pthread_mutex_unlock(&lock);
        // Our own libc imports, not ART's hooked slots.
        const int fd = open(base, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        bool has_dex = false;
        const off_t size = lseek(fd, 0, SEEK_END);
        constexpr off_t TAIL = 65536 + 22;  // EOCD plus the longest comment
        const off_t tail_at = size > TAIL ? size - TAIL : 0;
        char* tail = static_cast<char*>(malloc(TAIL));
        const ssize_t got = tail ? pread(fd, tail, static_cast<size_t>(size - tail_at), tail_at) : -1;
        for (ssize_t i = got - 22; i >= 0; i--) {
            if (memcmp(tail + i, "PK\x05\x06", 4) != 0) continue;
            uint32_t cd_size, cd_off;
            memcpy(&cd_size, tail + i + 12, 4);
            memcpy(&cd_off, tail + i + 16, 4);
            constexpr uint32_t CD_CAP = 8u << 20;
            if (cd_size > CD_CAP || off_t{cd_off} + cd_size > size) break;
            if (char* cd = static_cast<char*>(malloc(cd_size ? cd_size : 1))) {
                if (pread(fd, cd, cd_size, cd_off) == static_cast<ssize_t>(cd_size))
                    has_dex = memmem(cd, cd_size, "classes.dex", 11) != nullptr;
                free(cd);
            }
            break;
        }
        free(tail);
        close(fd);
        pthread_mutex_lock(&lock);
        if (cached < sizeof(cache) / sizeof(cache[0])) {
            snprintf(cache[cached].path, sizeof(cache[cached].path), "%s", base);
            cache[cached++].has_dex = has_dex;
        }
        pthread_mutex_unlock(&lock);
        return has_dex;
    }
    return false;  // no container next to it: nothing ART could fall back to
}

bool hide(const char* path) {
    if (!is_oat_artifact(path)) return false;
    // App artifacts under /data always have their APK's DEX to fall back to.
    if (strncmp(path, "/data/", 6) != 0 && !container_has_dex(path)) return false;
    PH_LOGD("[aot] hiding %s", path);
    errno = ENOENT;
    return true;
}

using stat_fn = int (*)(const char*, struct stat*);
using fstatat_fn = int (*)(int, const char*, struct stat*, int);
using open_fn = int (*)(const char*, int, ...);
using openat_fn = int (*)(int, const char*, int, ...);
using access_fn = int (*)(const char*, int);

int mode_arg(int flags, va_list* ap) {
    // O_TMPFILE includes O_DIRECTORY's bit, so a plain O_DIRECTORY open must not read a mode.
    return ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) ? va_arg(*ap, int) : 0;
}

}  // namespace

int stat_hook(const char* path, struct stat* st) {
    return hide(path) ? -1 : reinterpret_cast<stat_fn>(orig_stat)(path, st);
}
int fstatat_hook(int dirfd, const char* path, struct stat* st, int flags) {
    return hide(path) ? -1 : reinterpret_cast<fstatat_fn>(orig_fstatat)(dirfd, path, st, flags);
}
int open_hook(const char* path, int flags, ...) {
    if (hide(path)) return -1;
    va_list ap;
    va_start(ap, flags);
    const int mode = mode_arg(flags, &ap);
    va_end(ap);
    return reinterpret_cast<open_fn>(orig_open)(path, flags, mode);
}
int openat_hook(int dirfd, const char* path, int flags, ...) {
    if (hide(path)) return -1;
    va_list ap;
    va_start(ap, flags);
    const int mode = mode_arg(flags, &ap);
    va_end(ap);
    return reinterpret_cast<openat_fn>(orig_openat)(dirfd, path, flags, mode);
}
int open_2_hook(const char* path, int flags) {
    return hide(path) ? -1 : reinterpret_cast<int (*)(const char*, int)>(orig_open_2)(path, flags);
}
int access_hook(const char* path, int mode) {
    return hide(path) ? -1 : reinterpret_cast<access_fn>(orig_access)(path, mode);
}

}  // namespace ph::aot
