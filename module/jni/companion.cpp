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
#include <map>
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

// Opt-in per package ("redirect": "<ipv4>:<port>"): the app's TCP 80 and 443 are sent to an interception
// proxy by a firewall rule keyed on its uid. This is the quiet way to steer an app that ignores the
// system proxy (dart:io, most native stacks): nothing changes inside the process, its sockets still
// report the real peer address, and no proxy or VPN shows up in the settings an app can read. The
// in-process alternative, a hook on connect(), is what this replaces.
// UDP 443 goes to a closed local port, so QUIC fails with the errno of a server without HTTP/3 and
// the app falls back to TCP. IPv6 80 and 443 are refused so the app falls back to IPv4.
// ponytail: IPv6 UDP uses REJECT, which the sender sees as EPERM (the errno Android's own firewall
// gives); DNAT to [::1]:9 would look like a closed port but needs ip6 nat, absent on 4.14 kernels.
// ponytail: ports 80 and 443 only; add a port list to the key if an app's API lives elsewhere.
constexpr uid_t AID_APP_END = 19999;
constexpr uid_t AID_USER_OFFSET = 100000;
pthread_mutex_t g_redirect_lock = PTHREAD_MUTEX_INITIALIZER;
// What this companion process installed. The rules themselves live in the kernel until reboot.
std::map<uid_t, std::string> g_redirects;

// Runs a shell script as root and returns what it printed. Reading the answer instead of the exit
// status keeps this independent of the host's SIGCHLD disposition.
std::string run_script(const std::string& script) {
    FILE* p = popen(script.c_str(), "r");
    if (!p) return "";
    char out[64] = {};
    const size_t n = fread(out, 1, sizeof(out) - 1, p);
    pclose(p);
    return std::string(out, n);
}

std::string redirect_install_script(uid_t uid, const std::string& dest) {
    const std::string ip = dest.substr(0, dest.rfind(':'));
    char buf[2000];
    snprintf(buf, sizeof(buf),
             "v4=ok; v6=ok\n"
             "/system/bin/iptables-restore -w --noflush 2>/dev/null <<E || v4=failed\n"
             "*nat\n"
             ":ph_%1$u - [0:0]\n"
             "-A ph_%1$u -p tcp --dport 443 ! -d %2$s -j DNAT --to-destination %3$s\n"
             "-A ph_%1$u -p tcp --dport 80 ! -d %2$s -j DNAT --to-destination %3$s\n"
             "-A ph_%1$u -p udp --dport 443 -j DNAT --to-destination 127.0.0.1:9\n"
             "COMMIT\n"
             "E\n"
             "/system/bin/iptables -w -t nat -C OUTPUT -m owner --uid-owner %1$u -j ph_%1$u 2>/dev/null ||"
             " /system/bin/iptables -w -t nat -I OUTPUT -m owner --uid-owner %1$u -j ph_%1$u 2>/dev/null || v4=failed\n"
             "/system/bin/ip6tables-restore -w --noflush 2>/dev/null <<E || v6=failed\n"
             "*filter\n"
             ":ph_%1$u - [0:0]\n"
             "-A ph_%1$u -p tcp --dport 443 -j REJECT --reject-with tcp-reset\n"
             "-A ph_%1$u -p tcp --dport 80 -j REJECT --reject-with tcp-reset\n"
             "-A ph_%1$u -p udp --dport 443 -j REJECT --reject-with icmp6-port-unreachable\n"
             "COMMIT\n"
             "E\n"
             "/system/bin/ip6tables -w -C OUTPUT -m owner --uid-owner %1$u -j ph_%1$u 2>/dev/null ||"
             " /system/bin/ip6tables -w -I OUTPUT -m owner --uid-owner %1$u -j ph_%1$u 2>/dev/null || v6=failed\n"
             "echo v4=$v4 v6=$v6\n",
             uid, ip.c_str(), dest.c_str());
    return buf;
}

std::string redirect_remove_script(uid_t uid) {
    char buf[700];
    snprintf(buf, sizeof(buf),
             "for t in '/system/bin/iptables -w -t nat' '/system/bin/ip6tables -w'; do\n"
             "$t -D OUTPUT -m owner --uid-owner %1$u -j ph_%1$u; $t -F ph_%1$u; $t -X ph_%1$u\n"
             "done 2>/dev/null\n",
             uid);
    return buf;
}

// Brings the rules for `uid` in line with the config (`dest` empty → none) and returns the state
// for the log. Called for every launch, so the common case, nothing configured and nothing
// installed, must cost a map lookup and no process.
std::string sync_redirect(uid_t uid, const std::string& dest) {
    pthread_mutex_lock(&g_redirect_lock);
    const auto it = g_redirects.find(uid);
    std::string state = dest.empty() ? "off" : dest;
    if (dest.empty()) {
        if (it != g_redirects.end()) {
            run_script(redirect_remove_script(uid));
            g_redirects.erase(it);
            note("redirect: removed for uid %u", uid);
        }
    } else if (uid % AID_USER_OFFSET < AID_APP_START || uid % AID_USER_OFFSET > AID_APP_END) {
        state = "skipped(not an app uid)";
    } else if (it == g_redirects.end() || it->second != dest) {
        const std::string out = run_script(redirect_install_script(uid, dest));
        if (out.find("v4=ok") == std::string::npos) {
            state = "failed";
            note("redirect: installing %s for uid %u failed (%s)", dest.c_str(), uid, out.empty() ? "no answer from sh" : "iptables");
        } else {
            g_redirects[uid] = dest;
            if (out.find("v6=ok") == std::string::npos) {
                state += "(ipv6 not blocked)";
                note("redirect: uid %u to %s, but the IPv6 block failed; IPv6 traffic bypasses the proxy", uid, dest.c_str());
            }
        }
    }
    pthread_mutex_unlock(&g_redirect_lock);
    return state;
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
    // Before the reply: the app must not open its first connection ahead of the rule.
    const auto rule = cfg.packages.find(req.package);
    const std::string redirect = sync_redirect(req.uid, rule == cfg.packages.end() ? "" : rule->second.redirect);

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
        char line[700];
        const int n = snprintf(line, sizeof(line), "[companion] package=%s process=%s uid=%u oat_evicted=%u redirect=%s\n",
                               req.package, req.process, req.uid, d.evicted, redirect.c_str());
        write_all(log_fd, line, n);
        serve_log(log_source, log_fd);
        close(log_fd);
    }
    close(log_source);
}

}  // namespace ph
