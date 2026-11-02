// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "art_api.h"

namespace ph::art {

namespace {
JavaVM* g_vm = nullptr;
}

void init(JNIEnv* env) {
    if (env && !g_vm) env->GetJavaVM(&g_vm);
}

JNIEnv* env() {
    if (!g_vm) return nullptr;
    JNIEnv* e = nullptr;
    return g_vm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6) == JNI_OK ? e : nullptr;
}

}  // namespace ph::art
