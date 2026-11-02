// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "dex_intercept.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>

#include "../hooks/hook_manager.h"
#include "../log/log.h"
#include "dex_patcher.h"

namespace ph::dexi {

void* orig_adler32 = nullptr;

namespace {

using adler32_fn = unsigned long (*)(unsigned long, const uint8_t*, unsigned int);

// DEX files we patched, with the checksum of their original bytes. If anything re-checksums the
// in-memory copy later (DexFile::CalculateChecksum, OatFileAssistant), it keeps seeing the value
// the header claims. Base+size collisions after unmap/remap are theoretically possible and
// harmless: the magic check still runs and a wrong answer only affects a non-verifier caller.
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;  // guards g_seen and g_reported

struct Seen {
    const uint8_t* base;
    size_t size;
    unsigned long checksum;
};
constexpr size_t MAX_SEEN = 64;
Seen g_seen[MAX_SEEN];
size_t g_seen_count = 0;

// Coverage lines are printed once per distinct DEX (header checksum + size). ART re-verifies the
// same DEX at new addresses whenever an app re-opens it (Kony apps do it dozens of times a
// launch); the patches are re-applied each time, the ladder does not need to say so each time.
struct Reported {
    uint32_t checksum;
    size_t size;
};
Reported g_reported[MAX_SEEN];
size_t g_reported_count = 0;

bool first_report(uint32_t checksum, size_t size) {
    pthread_mutex_lock(&g_lock);  // adler32 runs on every thread that opens a DEX
    bool first = true;
    for (size_t i = 0; i < g_reported_count && first; i++)
        if (g_reported[i].checksum == checksum && g_reported[i].size == size) first = false;
    if (first && g_reported_count < MAX_SEEN) g_reported[g_reported_count++] = {checksum, size};
    pthread_mutex_unlock(&g_lock);
    return first;
}

// The header checksum is compared too: after an unmap, a different DEX of the same size can land at
// the same address, and answering with the old value would make ART reject it.
bool seen_lookup(const uint8_t* base, size_t size, unsigned long* out) {
    uint32_t header_checksum;
    memcpy(&header_checksum, base + dex::MAGIC_SIZE, sizeof(header_checksum));
    pthread_mutex_lock(&g_lock);
    bool found = false;
    for (size_t i = 0; i < g_seen_count && !found; i++)
        if (g_seen[i].base == base && g_seen[i].size == size && g_seen[i].checksum == header_checksum) {
            *out = g_seen[i].checksum;
            found = true;
        }
    pthread_mutex_unlock(&g_lock);
    return found;
}

void seen_remember(const uint8_t* base, size_t size, unsigned long checksum) {
    pthread_mutex_lock(&g_lock);
    if (g_seen_count < MAX_SEEN) g_seen[g_seen_count++] = {base, size, checksum};
    pthread_mutex_unlock(&g_lock);
}

// Is [addr, addr+len) mapped? mincore is a syscall, not a file read, and ENOMEM means a hole.
bool region_mapped(const void* addr, size_t len) {
    const long page_size = sysconf(_SC_PAGESIZE);
    auto p = reinterpret_cast<uintptr_t>(addr) & ~static_cast<uintptr_t>(page_size - 1);
    const uintptr_t end = reinterpret_cast<uintptr_t>(addr) + len;
    unsigned char vec[256];
    while (p < end) {
        const size_t chunk = std::min<size_t>(end - p, sizeof(vec) * page_size);
        if (mincore(reinterpret_cast<void*>(p), chunk, vec) != 0) return false;
        p += chunk;
    }
    return true;
}

// Protection of [start, end) if it is covered by private mappings that all share it, else -1. Read
// only when something is about to be patched (a handful of DEX per launch). Shared mappings are
// refused: a write would reach the file. So is a range that spills into a neighbouring mapping,
// which only a corrupt or hostile container header could produce.
int private_protection(uintptr_t start, uintptr_t end) {
    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[4096];
    size_t have = 0;
    int prot = -1;
    uintptr_t covered = start;
    bool done = false;
    while (!done) {
        const ssize_t n = read(fd, buf + have, sizeof(buf) - 1 - have);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        have += static_cast<size_t>(n);
        buf[have] = 0;
        char* line = buf;
        for (char* nl; !done && (nl = strchr(line, '\n')); line = nl + 1) {
            *nl = 0;
            uintptr_t lo, hi;
            char perms[8] = {};
            if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3 || hi <= covered) continue;
            if (lo > covered) {
                done = true;  // a hole, or the range starts in no mapping at all
                break;
            }
            const int p = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) | (perms[2] == 'x' ? PROT_EXEC : 0);
            if (perms[3] != 'p' || (prot >= 0 && p != prot)) {
                prot = -1;
                covered = start;
                done = true;
                break;
            }
            prot = p;
            covered = hi;
            if (covered >= end) done = true;
        }
        have = strlen(line);
        memmove(buf, line, have);
        if (have == sizeof(buf) - 1) have = 0;  // a line longer than the buffer: not a mapping line we need
    }
    close(fd);
    return covered >= end ? prot : -1;
}

// Returns the number of methods patched.
int patch_dex(const uint8_t* dex, size_t size) {
    dex::View v;
    if (!dex::open(dex, size, &v)) {
        PH_LOGD("[java_dex] skipping unparseable DEX (%zu bytes)", size);
        return 0;
    }
    // A v41 container header claims a range beyond the bytes ART handed the verifier. The header is
    // unverified input, so make sure that range is actually mapped before trusting any offset in it.
    if ((v.base != dex || v.size != size) && !region_mapped(v.base, v.size)) {
        PH_LOGW("[java_dex] DEX container header points outside the mapping; not patching");
        return 0;
    }

    // Nothing is touched unless a target class is here: most DEX in a process (and every buffer a
    // packer hands ART) has none, and their pages keep exactly the protection they had.
    bool patchable = false;
    for (size_t i = 0; i < kJavaTargetCount && !patchable; i++)
        patchable = dex::class_present(v, kJavaTargets[i]) && !hooks::java_target_blocked(kJavaTargets[i]);

    // The mapping must be MAP_PRIVATE (file-backed from the APK, or anonymous for an extracted entry),
    // so the write copies on write and touches neither the file nor any other process; the original
    // protection is put back afterwards. No madvise: MADV_DONTNEED zero-fills anonymous pages and
    // would corrupt an extracted DEX.
    const long page_size = sysconf(_SC_PAGESIZE);
    const auto start = reinterpret_cast<uintptr_t>(v.base) & ~static_cast<uintptr_t>(page_size - 1);
    const auto end = (reinterpret_cast<uintptr_t>(v.base) + v.size + page_size - 1) & ~static_cast<uintptr_t>(page_size - 1);
    int prot_before = -1;
    if (patchable) {
        prot_before = private_protection(start, end);
        if (prot_before < 0) {
            PH_LOGW("[java_dex] DEX at %p (%zu bytes) is not one private mapping; not patching", v.base, v.size);
            patchable = false;
        } else if (!(prot_before & PROT_WRITE) &&
                   mprotect(reinterpret_cast<void*>(start), end - start, prot_before | PROT_WRITE) != 0) {
            PH_LOGW("[java_dex] mprotect(RW) failed on DEX at %p (%zu bytes); not patching", v.base, v.size);
            patchable = false;
        }
    }

    int present[static_cast<int>(SurfaceId::COUNT)] = {};
    int applied[static_cast<int>(SurfaceId::COUNT)] = {};
    int blocked[static_cast<int>(SurfaceId::COUNT)] = {};
    int total = 0;
    for (size_t i = 0; i < kJavaTargetCount; i++) {
        const JavaTarget& t = kJavaTargets[i];
        const int s = static_cast<int>(t.surface);
        if (!dex::class_present(v, t)) continue;
        present[s]++;
        if (const char* why = hooks::java_target_blocked(t)) {
            blocked[s]++;
            PH_LOGD("[java_dex] %s present but not patched: %s", t.label, why);
            continue;
        }
        if (!patchable) continue;  // mapping refused above; reported there
        const dex::PatchResult r = dex::patch_target(v, t);
        if (r == dex::PatchResult::OK) {
            applied[s]++;
            total++;
            PH_LOGD("[java_dex] patched %s", t.label);
        } else if (r == dex::PatchResult::METHOD_ABSENT) {
            PH_LOGD("[java_dex] %s: class present, overload absent", t.label);
        } else {
            PH_LOGW("[java_dex] %s: %s", t.label, dex::patch_result_name(r));
        }
    }
    if (patchable && !(prot_before & PROT_WRITE)) mprotect(reinterpret_cast<void*>(start), end - start, prot_before);

    if (!first_report(v.hdr->checksum, size)) {
        PH_LOGD("[java_dex] DEX size=%zu checksum=%08x verified again: %d rows re-applied", size, v.hdr->checksum, total);
        return total;
    }
    for (int s = 0; s < static_cast<int>(SurfaceId::COUNT); s++) {
        if (!present[s]) continue;
        if (blocked[s] == present[s])
            log::coverage(static_cast<SurfaceId>(s), "present=yes reachable=no reason=%s current_tier=%s",
                          hooks::java_target_blocked(*hooks::first_java_target(static_cast<SurfaceId>(s))),
                          tier_name(hooks::current_tier()));
        else
            log::coverage(static_cast<SurfaceId>(s), "present=yes reachable=yes applied=%d/%d dex_size=%zu",
                          applied[s], present[s], size);
    }
    return total;
}

}  // namespace

unsigned long adler32_hook(unsigned long adler, const uint8_t* buf, unsigned int len) {
    const auto orig = reinterpret_cast<adler32_fn>(orig_adler32);
    // Z_NULL seed call, or too short to be a DEX body.
    if (!buf || len < dex::HEADER_SIZE_V35 - dex::NON_SUM) return orig(adler, buf, len);
    // Every adler32 caller in libdexfile passes begin + 12 (everything after magic and checksum), so
    // buf - 12 is inside the same mapping. Anything that is not a DEX header passes straight through.
    const uint8_t* dex = buf - dex::NON_SUM;
    if (memcmp(dex, "dex\n", 4) != 0) return orig(adler, buf, len);
    const size_t size = size_t{len} + dex::NON_SUM;

    unsigned long saved;
    const bool known = seen_lookup(dex, size, &saved);
    const unsigned long now = orig(adler, buf, len);  // must run BEFORE any byte changes
    // Our patched bytes checksum differently from the header: answer with the pristine value. A
    // pristine sum at a known address is a fresh copy of the same DEX mapped where the patched one
    // used to be, and it gets patched like the first.
    if (known && now != saved) return saved;
    if (patch_dex(dex, size) > 0 && !known) seen_remember(dex, size, now);
    return now;
}

}  // namespace ph::dexi
