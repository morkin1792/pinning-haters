// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "self_remap.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../log/log.h"

namespace ph::hide {

namespace {

struct Mapping {
    uintptr_t start;
    uintptr_t end;
    int prot;
};

// /proc/self/maps entries whose pathname is ours. The path comes from the entry that contains
// this very function, so no name is assumed: on Magisk the mapping is a memfd with an invented
// name, on Zygisk Next it is the module file. Gap entries (---p) count too: bionic reserves the
// whole span under the library's name and those lines would still give the path away.
int own_mappings(Mapping* out, int max, char* path, size_t path_size, bool* bionic_knows_us, bool* anonymous) {
    const auto here = reinterpret_cast<uintptr_t>(&remap_self);
    Dl_info info{};
    *bionic_knows_us = dladdr(reinterpret_cast<void*>(&remap_self), &info) != 0 && info.dli_fname != nullptr;

    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    // One read: the file is small and a line split across reads is not worth the loop.
    static char buf[256 * 1024];
    ssize_t n = 0, got;
    while (n < static_cast<ssize_t>(sizeof(buf) - 1) && (got = read(fd, buf + n, sizeof(buf) - 1 - n)) > 0) n += got;
    close(fd);
    buf[n] = 0;

    path[0] = 0;
    char ours_dev[16] = {};
    unsigned long ours_inode = 0;
    int count = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (char* line = buf; line && *line;) {
            char* nl = strchr(line, '\n');
            if (nl) *nl = 0;
            uintptr_t start, end;
            char perms[8] = {}, dev[16] = {};
            unsigned long inode = 0;
            int consumed = 0;
            if (sscanf(line, "%lx-%lx %7s %*x %15s %lu%n", &start, &end, perms, dev, &inode, &consumed) == 5) {
                const char* name = line + consumed;
                while (*name == ' ') name++;
                if (pass == 0) {
                    if (here >= start && here < end && !*name) *anonymous = true;  // the host already hid us
                    if (here >= start && here < end && *name) {
                        snprintf(path, path_size, "%s", name);
                        snprintf(ours_dev, sizeof(ours_dev), "%s", dev);
                        ours_inode = inode;
                    }
                } else if (*path && strcmp(name, path) == 0 && inode == ours_inode && strcmp(dev, ours_dev) == 0 &&
                           count < max) {
                    // Name and file identity: Magisk names its memfd like ART's JIT cache, and the
                    // JIT cache's two views must never be replaced with private copies.
                    const int prot = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) |
                                     (perms[2] == 'x' ? PROT_EXEC : 0);
                    out[count++] = {start, end, prot};
                }
            }
            if (nl) *nl = '\n';
            line = nl ? nl + 1 : nullptr;
        }
        if (pass == 0 && !*path) return 0;
    }
    return count;
}

// Raw page copy. Not memcpy: the source is a whole mapping, which is not an object, and a
// sanitizer-instrumented build (the host test) would reject the read against its shadow map.
__attribute__((no_sanitize("address", "undefined"))) void copy_pages(void* dst, uintptr_t src, size_t len) {
    auto* d = static_cast<uintptr_t*>(dst);
    const auto* s = reinterpret_cast<const uintptr_t*>(src);
    for (size_t i = 0; i < len / sizeof(uintptr_t); i++) d[i] = s[i];
}

}  // namespace

int remap_self() {
    Mapping maps[16];
    char path[512];
    bool bionic_knows_us = false, anonymous = false;
    const int count = own_mappings(maps, 16, path, sizeof(path), &bionic_knows_us, &anonymous);
    if (count == 0) {
        // Zygisk Next 1.5 maps modules anonymously itself (measured on Android 16): nothing to do.
        if (anonymous)
            PH_LOGI("[hide] self-remap: this module's code is already in anonymous memory (host-side hiding); nothing to do");
        else
            PH_LOGW("[hide] self-remap: could not find this module's mappings; nothing changed");
        return 0;
    }
    int done = 0;
    for (int i = 0; i < count; i++) {
        const Mapping& m = maps[i];
        const size_t len = m.end - m.start;
        if (m.prot == PROT_NONE) {
            // A reserved gap: an anonymous PROT_NONE mapping in the same place drops the name.
            if (mmap(reinterpret_cast<void*>(m.start), len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) !=
                MAP_FAILED)
                done++;
            continue;
        }
        void* copy = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (copy == MAP_FAILED) break;
        if (m.prot & PROT_READ) copy_pages(copy, m.start, len);
        if (mprotect(copy, len, m.prot) != 0) {
            // execmem denied for RX, or similar: give up on this one, keep the file mapping.
            munmap(copy, len);
            PH_LOGW("[hide] self-remap: mprotect(%d) refused for %zx bytes (errno=%d); mapping kept", m.prot, len, errno);
            continue;
        }
        // Atomic replacement: the new pages land exactly where the old ones were, so code that is
        // executing from this range (this function, for the text segment) continues unaffected.
        if (mremap(copy, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, reinterpret_cast<void*>(m.start)) == MAP_FAILED) {
            munmap(copy, len);
            PH_LOGW("[hide] self-remap: mremap over %lx failed (errno=%d); mapping kept", m.start, errno);
            continue;
        }
        done++;
    }
    PH_LOGI("[hide] self-remap: %d/%d mappings of %s now anonymous; loader=%s", done, count, path,
            bionic_knows_us ? "bionic (dl_iterate_phdr still lists the path)" : "host (not in the linker's list)");
    return done;
}

}  // namespace ph::hide
