// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include "../hooks/targets.h"
#include "../ipc.h"

// App-side log sink. Records go down a pipe to the companion on the calling thread; the companion
// adds timestamps and writes /data/adb/pinning_haters/log/<package>-<ts>.log (root, 0600). Nothing
// is written to logcat or /sdcard in release builds: both are readable by the app itself.
namespace ph::log {

void init(int companion_fd, bool enabled, bool verbose);
void shutdown();
bool enabled();
bool verbose();
void write(ipc::LogLevel level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
// "[coverage] surface=<name> <rest>" — the fixed format docs/coverage.md and the WebUI key on.
void coverage(SurfaceId surface, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

}  // namespace ph::log

#define PH_LOGD(...) ::ph::log::write(::ph::ipc::LogLevel::DEBUG, __VA_ARGS__)
#define PH_LOGI(...) ::ph::log::write(::ph::ipc::LogLevel::INFO, __VA_ARGS__)
#define PH_LOGW(...) ::ph::log::write(::ph::ipc::LogLevel::WARN, __VA_ARGS__)
#define PH_LOGE(...) ::ph::log::write(::ph::ipc::LogLevel::ERROR, __VA_ARGS__)
