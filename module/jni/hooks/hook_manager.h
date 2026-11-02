// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include "../ipc.h"
#include "targets.h"

// Tier gate and primitive selection. Walks the data tables, installs the quietest listed style
// that resolves and is permitted by the tier ceiling, and reports the rest through the coverage
// ladder. No per-target logic lives here.
namespace ph::hooks {

void install(const ipc::Decision& decision);
// Called from the android_dlopen_ext GOT hook after a library finished loading.
void on_library_loaded(const char* path);

Tier current_tier();
// nullptr when the target may be patched; otherwise the reason for the coverage line.
const char* java_target_blocked(const JavaTarget& target);
const JavaTarget* first_java_target(SurfaceId surface);

extern void* orig_android_dlopen_ext;
void* android_dlopen_ext_hook(const char* path, int flags, const void* extinfo);
// dlopen / android_dlopen_ext as imported by app-private libraries (Dart FFI's DynamicLibrary.open,
// plugin hosts, SDK loaders): loads that never pass through libnativeloader. The replacements go
// through the linker's __loader_* entry points with the real caller address, because the library
// name is resolved in the caller's namespace and ours is nobody's.
extern void* orig_app_dlopen;
extern void* orig_app_dlopen_ext;
void* app_dlopen_hook(const char* path, int flags);
void* app_dlopen_ext_hook(const char* path, int flags, const void* extinfo);

}  // namespace ph::hooks
