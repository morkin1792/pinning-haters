// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Wire format between the in-app module and the root companion. Both ends are the same .so built
// from the same tree, so there is no versioning beyond the magic/version sanity check.
namespace ph {

enum class Tier : uint8_t { MAX = 0, BALANCED = 1, COMPAT = 2 };

inline const char* tier_name(Tier t) {
    switch (t) {
        case Tier::MAX: return "max";
        case Tier::BALANCED: return "balanced";
        default: return "compat";
    }
}

// config "surfaces" → Decision::surfaces
enum SurfaceBits : uint8_t {
    SURFACE_PLATFORM_TLS = 1 << 0,
    SURFACE_JAVA_DEX = 1 << 1,
    SURFACE_BUNDLED_TLS = 1 << 2,
    SURFACE_FOREIGN_RUNTIME = 1 << 3,
};

enum FlagBits : uint8_t {
    FLAG_RELAX_HOSTNAME = 1 << 0,
    FLAG_LOG_ENABLED = 1 << 1,
    FLAG_LOG_VERBOSE = 1 << 2,
    FLAG_STAT_FALLBACK = 1 << 3,
    FLAG_SYSTEM_APP = 1 << 4,
    FLAG_SELF_REMAP = 1 << 5,  // hide.self_remap: re-map this module's own pages anonymously after hooking  // no /data/app install dir: oat lives on a read-only partition, nothing to evict
};

namespace ipc {

constexpr uint32_t MAGIC = 0x50484e47;  // "PHNG"
constexpr uint32_t VERSION = 1;

// Sent by preAppSpecialize (still zygote-privileged, but we read nothing from disk there).
struct Request {
    uint32_t magic;
    uint32_t version;
    uint32_t uid;
    uint32_t reserved;
    char package[256];   // basename(app_data_dir)
    char process[256];   // nice_name, for the log only
    char data_dir[256];  // app_data_dir, so the companion can find secondary-dex oat dirs
};

// Companion's answer. Fixed size; everything the app side needs to decide and log.
struct Decision {
    uint32_t magic;
    uint8_t target;    // 0 → DLCLOSE_MODULE_LIBRARY and nothing else happens
    Tier tier;         // effective tier for this package (global ceiling or per-package override)
    uint8_t surfaces;  // SurfaceBits
    uint8_t flags;     // FlagBits
    uint32_t api_level;    // ro.build.version.sdk, read root-side so the app process reads no properties
    uint32_t evicted;      // oat artifacts deleted by the companion before replying
    char build[96];        // manufacturer/release/security_patch for the init log line
};

enum class LogLevel : uint8_t { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

// After the Decision, while the socket stays open, the app side streams log records:
// LogHeader followed by `length` bytes of text (no trailing newline, no timestamp).
struct LogHeader {
    uint16_t length;
    LogLevel level;
    uint8_t pad;
};
constexpr size_t LOG_MAX = 1024;

}  // namespace ipc

inline bool read_all(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        const ssize_t r = read(fd, p, n);
        if (r == 0) return false;
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += r;
        n -= static_cast<size_t>(r);
    }
    return true;
}

inline bool write_all(int fd, const void* buf, size_t n) {
    auto* p = static_cast<const uint8_t*>(buf);
    while (n > 0) {
        // A socket peer that died must not SIGPIPE the companion (or the app); files fall back to write.
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == ENOTSOCK) w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}


// One descriptor over a Unix socket (SCM_RIGHTS) with a one-byte payload.
inline bool send_fd(int sock, int fd) {
    char byte = 'F';
    iovec iov{&byte, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    ssize_t r;
    do r = sendmsg(sock, &msg, MSG_NOSIGNAL); while (r < 0 && errno == EINTR);
    return r == 1;
}

inline int recv_fd(int sock) {
    char byte = 0;
    iovec iov{&byte, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t r;
    do r = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC); while (r < 0 && errno == EINTR);
    if (r != 1) return -1;
    for (cmsghdr* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS && cm->cmsg_len == CMSG_LEN(sizeof(int))) {
            int fd;
            memcpy(&fd, CMSG_DATA(cm), sizeof(int));
            return fd;
        }
    }
    return -1;
}

}  // namespace ph
