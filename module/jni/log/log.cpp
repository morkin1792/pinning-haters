// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "log.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef PH_DEBUG_LOGCAT
#include <android/log.h>
#endif

namespace ph::log {

namespace {
int g_fd = -1;
bool g_enabled = false;
bool g_verbose = false;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

void emit(ipc::LogLevel level, const char* fmt, va_list ap) {
    char buf[sizeof(ipc::LogHeader) + ipc::LOG_MAX];
    char* text = buf + sizeof(ipc::LogHeader);
    int n = vsnprintf(text, ipc::LOG_MAX, fmt, ap);
    if (n < 0) return;
    if (static_cast<size_t>(n) >= ipc::LOG_MAX) n = ipc::LOG_MAX - 1;
#ifdef PH_DEBUG_LOGCAT
    __android_log_print(ANDROID_LOG_INFO, "pinning_haters", "%s", text);
#endif
    if (!g_enabled || g_fd < 0) return;
    if (level == ipc::LogLevel::DEBUG && !g_verbose) return;
    auto* hdr = reinterpret_cast<ipc::LogHeader*>(buf);
    *hdr = {static_cast<uint16_t>(n), level, 0};
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) {
        // The sink is a pipe: a vanished reader would turn the next write into SIGPIPE and kill the
        // app, so look for POLLERR (no readers) first and give up on logging instead.
        pollfd pfd{g_fd, POLLOUT, 0};
        const bool dead = poll(&pfd, 1, 0) < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL));
        // Records are well under PIPE_BUF, so each write lands whole even with concurrent threads.
        if (dead || (::write(g_fd, buf, sizeof(ipc::LogHeader) + n) < 0 && errno != EAGAIN)) {  // EAGAIN: full pipe, drop the record
#ifdef PH_DEBUG_LOGCAT
            __android_log_print(ANDROID_LOG_WARN, "pinning_haters", "[dbg] log write on fd %d failed: dead=%d errno=%d", g_fd, dead, errno);
#endif
            close(g_fd);
            g_fd = -1;
        }
    }
    pthread_mutex_unlock(&g_lock);
}
}  // namespace

void init(int companion_fd, bool enabled, bool verbose) {
    g_fd = companion_fd;
    g_enabled = enabled;
    g_verbose = verbose;
}

void shutdown() {
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) close(g_fd);
    g_fd = -1;
    g_enabled = false;
    pthread_mutex_unlock(&g_lock);
}

bool enabled() { return g_enabled; }
bool verbose() { return g_verbose; }

void write(ipc::LogLevel level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emit(level, fmt, ap);
    va_end(ap);
}

void coverage(SurfaceId surface, const char* fmt, ...) {
    char rest[ipc::LOG_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(rest, sizeof(rest), fmt, ap);
    va_end(ap);
    write(ipc::LogLevel::INFO, "[coverage] surface=%s %s", surface_name(surface), rest);
}

}  // namespace ph::log
