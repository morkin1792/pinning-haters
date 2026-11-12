// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <map>
#include <string>

#include "../ipc.h"

// Companion-side only. The app process never parses config; it receives a Decision.
namespace ph::config {

constexpr const char* DIR = "/data/adb/pinning_haters";
constexpr const char* FILE = "/data/adb/pinning_haters/config.json";
constexpr const char* LOG_DIR = "/data/adb/pinning_haters/log";

struct PackageRule {
    bool has_tier = false;
    Tier tier = Tier::MAX;
    std::string redirect;  // "a.b.c.d:port", validated and normalised; empty → the app's traffic is left alone
};

struct Config {
    Tier stealth = Tier::MAX;
    std::map<std::string, PackageRule> packages;  // empty → the module does nothing. Non-negotiable default.
    bool relax_hostname_verification = false;
    uint8_t surfaces = SURFACE_PLATFORM_TLS | SURFACE_JAVA_DEX | SURFACE_BUNDLED_TLS;
    bool evict_oat = true;
    bool stat_hook_fallback = true;
    bool self_remap = true;
    bool log_enabled = false;
    bool log_verbose = false;
    std::string error;  // set when the file was missing or partly unusable; defaults fill the gaps
};

bool parse_tier(const std::string& s, Tier* out);
// IPv4 literal and port only. The result is written into firewall rules, so nothing else passes.
bool parse_redirect(const std::string& s, std::string* out);
// Tolerant: unknown keys ignored, wrong types fall back to defaults and are noted in `error`.
bool parse(const std::string& json_text, Config* out);
bool load(const char* path, Config* out);
// Fills target/tier/surfaces/flags. api_level, build and evicted are the caller's job.
void decide(const Config& cfg, const char* package, ipc::Decision* out);

}  // namespace ph::config
