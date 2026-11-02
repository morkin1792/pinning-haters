// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

namespace ph {
// Root-side request handler (REGISTER_ZYGISK_COMPANION). Runs in the Zygisk daemon, one call per
// connecting process, possibly on several threads at once.
void companion_main(int client);
}  // namespace ph
