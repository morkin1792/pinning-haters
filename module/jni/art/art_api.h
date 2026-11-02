// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <jni.h>

namespace ph::art {
void init(JNIEnv* env);  // caches the JavaVM from onLoad
JNIEnv* env();           // JNIEnv of the calling thread, or nullptr if it is not attached
}  // namespace ph::art
