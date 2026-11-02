// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "companion.h"

#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <glob.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

#include "art/aot_fallback.h"
#include "config/config.h"
#include "ipc.h"

// Everything that needs root or touches a file happens here, never in the app process: config,
// log files, oat eviction. The app side sends one Request and gets one Decision.
namespace ph {

namespace {

constexpr time_t LOG_MAX_AGE = 7 * 24 * 3600;
constexpr off_t LOG_MAX_BYTES = 100 * 1024 * 1024;
constexpr uid_t AID_APP_START = 10000;
constexpr off_t LOG_FILE_MAX_BYTES = 16 * 1024 * 1024;  // one launch; the directory cap is LOG_MAX_BYTES
constexpr off_t NOTE_MAX_BYTES = 1024 * 1024;
constexpr int SECONDARY_WALK_CAP = 20000;  // ponytail: entries visited per app data dir; parse package-dex-usage.list if this ever bites

void timestamp(char* out, size_t n) {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    tm t;
    localtime_r(&ts.tv_sec, &t);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%d %H:%M:%S", &t);
    snprintf(out, n, "%s.%03ld", base, ts.tv_nsec / 1000000);
}

// Companion-side notes (config errors, eviction counts) go to a root-only file in the log dir.
void note(const char* fmt, ...) {
    mkdir(config::DIR, 0700);
    mkdir(config::LOG_DIR, 0700);
    const int fd = open((std::string(config::LOG_DIR) + "/companion.log").c_str(),
                        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > NOTE_MAX_BYTES) ftruncate(fd, 0);  // written on every launch with a config warning
    char line[1200], ts[40];
    timestamp(ts, sizeof(ts));
    int n = snprintf(line, sizeof(line), "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(line + n, sizeof(line) - n - 1, fmt, ap);
    va_end(ap);
    if (n > static_cast<int>(sizeof(line)) - 2) n = sizeof(line) - 2;
    line[n++] = '\n';
    write_all(fd, line, n);
    close(fd);
}

std::string prop(const char* name) {
    char v[PROP_VALUE_MAX] = {};
    __system_property_get(name, v);
    return v;
}

bool safe_package_name(const char* p) {
    if (!*p) return false;
    for (; *p; p++)
        if (!(isalnum(static_cast<unsigned char>(*p)) || *p == '.' || *p == '_')) return false;
    return true;
}

bool safe_data_dir(const char* d) {
    return strncmp(d, "/data/", 6) == 0 && !strstr(d, "/../") && !strstr(d, "//");
}

int g_walk_budget;
uint32_t g_walk_removed;
int walk_cb(const char* path, const struct stat*, int type, FTW*) {
    if (--g_walk_budget <= 0) return 1;  // stop
    if (type == FTW_F && aot::is_oat_artifact(path) && unlink(path) == 0) g_walk_removed++;
    return 0;
}

// Delete, not `pm compile --reset`: a verify-filter vdex still carries VerifierDeps, ART skips
// DexFileVerifier, and the adler32 interception never fires. We need no vdex at all.
uint32_t evict_oat(const char* package, const char* data_dir) {
    uint32_t removed = 0;
    if (!safe_package_name(package)) return 0;
    // *.dm: a DexMetadata file may carry a vdex, which would let ART skip the verifier just like
    // base.vdex does. Losing the cloud profile inside it costs the same as losing base.odex.
    const char* patterns[] = {"/data/app/*/%s-*/oat/*/*", "/data/app/%s-*/oat/*/*", "/data/app/*/%s-*/*.dm",
                              "/data/app/%s-*/*.dm"};
    for (const char* pat : patterns) {
        char pattern[512];
        snprintf(pattern, sizeof(pattern), pat, package);
        glob_t g{};
        if (glob(pattern, 0, nullptr, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc; i++)
                if (aot::is_oat_artifact(g.gl_pathv[i]) && unlink(g.gl_pathv[i]) == 0) removed++;
        }
        globfree(&g);
    }
    // Secondary DEX (DexClassLoader, downloaded splits) keep their oat next to the DEX inside the
    // app's data directory.
    // The directory is the app's to write, so the app can swap a subdirectory for a symlink between
    // nftw's lstat and our unlink(path). The walk therefore runs with the owner's filesystem
    // identity (setfsuid is per thread and drops the DAC capabilities): whatever the app redirects
    // us to, the kernel only lets us delete what the app itself could.
    struct stat st;
    if (safe_data_dir(data_dir) && lstat(data_dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid >= AID_APP_START) {
        static pthread_mutex_t walk_lock = PTHREAD_MUTEX_INITIALIZER;  // nftw's callback state is global
        pthread_mutex_lock(&walk_lock);
        g_walk_budget = SECONDARY_WALK_CAP;
        g_walk_removed = 0;
        setfsgid(st.st_gid);
        setfsuid(st.st_uid);
        nftw(data_dir, walk_cb, 16, FTW_PHYS | FTW_MOUNT);
        setfsuid(0);
        setfsgid(0);
        removed += g_walk_removed;
        pthread_mutex_unlock(&walk_lock);
    }
    return removed;
}

// Installed under /data/app at all? System and priv-apps keep their oat on a read-only partition,
// where nothing can be evicted and only the in-process stat fallback can help.
bool installed_in_data(const char* package) {
    if (!safe_package_name(package)) return false;
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "/data/app/*/%s-*", package);
    glob_t g{};
    bool found = glob(pattern, 0, nullptr, &g) == 0 && g.gl_pathc > 0;
    globfree(&g);
    if (found) return true;
    snprintf(pattern, sizeof(pattern), "/data/app/%s-*", package);
    g = {};
    found = glob(pattern, 0, nullptr, &g) == 0 && g.gl_pathc > 0;
    globfree(&g);
    return found;
}

void rotate_logs() {
    DIR* d = opendir(config::LOG_DIR);
    if (!d) return;
    struct Entry {
        std::string path;
        time_t mtime;
        off_t size;
    };
    std::vector<Entry> entries;
    const time_t now = time(nullptr);
    while (dirent* e = readdir(d)) {
        if (e->d_name[0] == '.') continue;
        const std::string path = std::string(config::LOG_DIR) + "/" + e->d_name;
        struct stat st;
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
        if (now - st.st_mtime > LOG_MAX_AGE) {
            unlink(path.c_str());
            continue;
        }
        entries.push_back({path, st.st_mtime, st.st_size});
    }
    closedir(d);
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) { return a.mtime < b.mtime; });
    off_t total = 0;
    for (const Entry& e : entries) total += e.size;
    for (size_t i = 0; i < entries.size() && total > LOG_MAX_BYTES; i++) {
        if (unlink(entries[i].path.c_str()) == 0) total -= entries[i].size;
    }
}

int open_log_file(const char* package) {
    mkdir(config::DIR, 0700);
    mkdir(config::LOG_DIR, 0700);
    time_t now = time(nullptr);
    tm t;
    localtime_r(&now, &t);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &t);
    for (int attempt = 0; attempt < 100; attempt++) {
        char path[600];
        if (attempt == 0) snprintf(path, sizeof(path), "%s/%s-%s.log", config::LOG_DIR, package, stamp);
        else snprintf(path, sizeof(path), "%s/%s-%s-%d.log", config::LOG_DIR, package, stamp, attempt);
        const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd >= 0) return fd;
    }
    return -1;
}

const char* level_name(ipc::LogLevel l) {
    switch (l) {
        case ipc::LogLevel::DEBUG: return "DEBUG";
        case ipc::LogLevel::INFO: return "INFO ";
        case ipc::LogLevel::WARN: return "WARN ";
        case ipc::LogLevel::ERROR: return "ERROR";
    }
    return "?    ";
}

void serve_log(int client, int log_fd) {
    char buf[ipc::LOG_MAX + 128];
    ipc::LogHeader hdr;
    off_t written = 0;
    // The pipe is fed by the app process, so it is bounded here: past the budget records are read
    // and dropped (never stop reading, or the app's next log write would find a full pipe), and a
    // record cannot add lines of its own.
    while (read_all(client, &hdr, sizeof(hdr))) {
        if (hdr.length == 0 || hdr.length >= ipc::LOG_MAX) break;  // protocol violation; stop
        char text[ipc::LOG_MAX];
        if (!read_all(client, text, hdr.length)) break;
        text[hdr.length] = 0;
        if (written > LOG_FILE_MAX_BYTES) continue;
        for (char* c = text; *c; c++)
            if (*c == '\n' || *c == '\r') *c = ' ';
        char ts[40];
        timestamp(ts, sizeof(ts));
        const int n = snprintf(buf, sizeof(buf), "[%s] [%s] %s\n", ts, level_name(hdr.level), text);
        const size_t len = std::min<size_t>(n, sizeof(buf) - 1);
        if (!write_all(log_fd, buf, len)) break;
        written += static_cast<off_t>(len);
        if (written > LOG_FILE_MAX_BYTES) write_all(log_fd, "[companion] log budget reached; further records dropped\n", 56);
    }
}

}  // namespace

void companion_main(int client) {
    ipc::Request req{};
    if (!read_all(client, &req, sizeof(req)) || req.magic != ipc::MAGIC || req.version != ipc::VERSION) {
        close(client);
        return;
    }
    req.package[sizeof(req.package) - 1] = 0;
    req.process[sizeof(req.process) - 1] = 0;
    req.data_dir[sizeof(req.data_dir) - 1] = 0;

    // Re-read on every request: a small file, microseconds, and no stale state to invalidate.
    config::Config cfg;
    config::load(config::FILE, &cfg);
    if (!cfg.error.empty()) note("config: %s", cfg.error.c_str());

    ipc::Decision d{};
    d.magic = ipc::MAGIC;
    config::decide(cfg, req.package, &d);
    d.api_level = static_cast<uint32_t>(atoi(prop("ro.build.version.sdk").c_str()));
    snprintf(d.build, sizeof(d.build), "%s/%s/%s", prop("ro.product.manufacturer").c_str(),
             prop("ro.build.version.release").c_str(), prop("ro.build.version.security_patch").c_str());
    if (d.target && cfg.evict_oat) d.evicted = evict_oat(req.package, req.data_dir);
    if (d.target && !installed_in_data(req.package)) d.flags |= FLAG_SYSTEM_APP;

    const bool ok = write_all(client, &d, sizeof(d));
    if (!ok || !d.target || !(d.flags & FLAG_LOG_ENABLED)) {
        close(client);
        return;
    }

    // The log channel is a pipe the app process created before specialization (zygote-labelled,
    // and therefore still writable by the app domain afterwards); it sends us the read end over
    // the Zygisk socket. The reverse — a socket created here — fails: zygote may not receive a
    // magisk-labelled socket (avc denied { read write } ... tcontext=u:r:magisk:s0 on device).
    int log_source = -1;
    pollfd pfd{client, POLLIN, 0};
    if (poll(&pfd, 1, 3000) > 0) log_source = recv_fd(client);
    close(client);
    if (log_source < 0) {
        note("log channel from %s not established (errno=%d)", req.package, errno);
        return;
    }

    rotate_logs();
    // The Request is a trust boundary: never build a root-owned path from an unvalidated name.
    const int log_fd = open_log_file(safe_package_name(req.package) ? req.package : "unknown");
    if (log_fd >= 0) {
        char line[400];
        const int n = snprintf(line, sizeof(line), "[companion] package=%s process=%s uid=%u oat_evicted=%u\n",
                               req.package, req.process, req.uid, d.evicted);
        write_all(log_fd, line, n);
        serve_log(log_source, log_fd);
        close(log_fd);
    }
    close(log_source);
}

}  // namespace ph
