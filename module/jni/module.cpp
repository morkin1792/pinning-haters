// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "art/art_api.h"
#include "companion.h"
#include "hide/self_remap.h"
#include "hooks/hook_manager.h"
#include "ipc.h"
#include "log/log.h"
#include "zygisk.hpp"

// Zygisk entry. preAppSpecialize asks the companion whether this package is a target;
// postAppSpecialize installs hooks. Everything else — config, logs, oat eviction — is the
// companion's job, so the target process performs no file operations of ours at all.
namespace {

bool copy_jstring(JNIEnv* env, jstring s, char* out, size_t n) {
    out[0] = 0;
    if (!s) return false;
    const char* chars = env->GetStringUTFChars(s, nullptr);
    if (!chars) return false;
    snprintf(out, n, "%s", chars);
    env->ReleaseStringUTFChars(s, chars);
    return true;
}

class PinningHaters : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        fd_ = -1;
        target_ = false;
        decision_ = {};

        ph::ipc::Request req{};
        req.magic = ph::ipc::MAGIC;
        req.version = ph::ipc::VERSION;
        req.uid = static_cast<uint32_t>(args->uid);
        if (!copy_jstring(env_, args->app_data_dir, req.data_dir, sizeof(req.data_dir))) return unload();
        copy_jstring(env_, args->nice_name, req.process, sizeof(req.process));
        // The data dir names the package reliably; nice_name is whatever android:process says.
        const char* slash = strrchr(req.data_dir, '/');
        snprintf(req.package, sizeof(req.package), "%s", slash ? slash + 1 : req.data_dir);

        const int fd = api_->connectCompanion();
        if (fd < 0) return unload();
        if (!ph::write_all(fd, &req, sizeof(req)) || !ph::read_all(fd, &decision_, sizeof(decision_)) ||
            decision_.magic != ph::ipc::MAGIC || !decision_.target) {
            close(fd);
            return unload();
        }
        target_ = true;
        // Log channel, only when the user asked for logs. SELinux shapes it: this Zygisk socket is
        // zygote-labelled and the app domain may not write to it after specialization; a socket the
        // companion creates is magisk-labelled and zygote may not even receive it (file_receive denied
        // on device). A pipe created here — by the zygote-labelled process — is writable from the
        // app domain afterwards, so we create it and hand the READ end to the companion. The write
        // end is the only descriptor we keep.
        if (decision_.flags & ph::FLAG_LOG_ENABLED) {
            int pipe_fds[2];
            if (pipe2(pipe_fds, O_CLOEXEC) == 0) {
                const bool handed_over = ph::send_fd(fd, pipe_fds[0]);
                close(pipe_fds[0]);
                if (handed_over) {
                    // A stalled companion must cost log records, never an app thread parked in write().
                    fcntl(pipe_fds[1], F_SETFL, O_NONBLOCK);
                    fd_ = pipe_fds[1];
                    api_->exemptFd(fd_);
                } else {
                    close(pipe_fds[1]);
                }
            }
        }
        close(fd);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!target_) return;
        ph::art::init(env_);
        ph::log::init(fd_, (decision_.flags & ph::FLAG_LOG_ENABLED) && fd_ >= 0, decision_.flags & ph::FLAG_LOG_VERBOSE);
        // Re-mapped before the hooks go live: once they are, other threads write this library's data
        // (originals, DEX table), and a write landing between a page's copy and its mremap would be lost.
        if (decision_.flags & ph::FLAG_SELF_REMAP) ph::hide::remap_self();
        ph::hooks::install(decision_);
        // DLCLOSE_MODULE_LIBRARY is never set here: our replacement functions live in this library.
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs*) override { unload(); }

private:
    void unload() { api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); }

    zygisk::Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    int fd_ = -1;  // log channel, or -1
    bool target_ = false;
    ph::ipc::Decision decision_{};
};

}  // namespace

REGISTER_ZYGISK_MODULE(PinningHaters)
REGISTER_ZYGISK_COMPANION(ph::companion_main)
