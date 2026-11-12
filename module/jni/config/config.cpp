// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "config.h"

#include <arpa/inet.h>

#include <fstream>
#include <sstream>

#include "json.hpp"

namespace ph::config {

using json = nlohmann::json;

namespace {

const json* field(const json& obj, const char* key) {
    if (!obj.is_object()) return nullptr;
    const auto it = obj.find(key);
    return it == obj.end() ? nullptr : &*it;
}

bool get_bool(const json& obj, const char* key, bool def, Config* cfg) {
    const json* v = field(obj, key);
    if (!v) return def;
    if (!v->is_boolean()) {
        cfg->error += std::string("'") + key + "' must be true/false; ";
        return def;
    }
    return v->get<bool>();
}

void set_surface(uint8_t* mask, uint8_t bit, bool on) {
    if (on) *mask |= bit; else *mask &= static_cast<uint8_t>(~bit);
}

}  // namespace

bool parse_tier(const std::string& s, Tier* out) {
    if (s == "max") *out = Tier::MAX;
    else if (s == "balanced") *out = Tier::BALANCED;
    else if (s == "compat") *out = Tier::COMPAT;
    else return false;
    return true;
}

bool parse_redirect(const std::string& s, std::string* out) {
    const size_t colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    in_addr addr;
    if (inet_pton(AF_INET, s.substr(0, colon).c_str(), &addr) != 1) return false;
    const std::string port = s.substr(colon + 1);
    if (port.empty() || port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos) return false;
    const int p = atoi(port.c_str());
    if (p < 1 || p > 65535) return false;
    char ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip))) return false;
    *out = std::string(ip) + ":" + std::to_string(p);
    return true;
}

bool parse(const std::string& text, Config* out) {
    *out = Config{};
    const json root = json::parse(text, nullptr, /*allow_exceptions=*/false, /*ignore_comments=*/true);
    if (root.is_discarded() || !root.is_object()) {
        out->error = "config.json is not a JSON object; using defaults (no packages targeted)";
        return false;
    }
    if (const json* v = field(root, "version"); v && (!v->is_number_integer() || v->get<int>() != 2))
        out->error += "unknown 'version' (expected 2); ";
    if (const json* v = field(root, "stealth")) {
        if (!v->is_string() || !parse_tier(v->get<std::string>(), &out->stealth))
            out->error += "'stealth' must be max|balanced|compat; ";
    }
    if (const json* v = field(root, "packages")) {
        if (!v->is_object()) {
            out->error += "'packages' must be an object keyed by package name; ";
        } else {
            for (const auto& [name, rule] : v->items()) {
                PackageRule r;
                if (const json* t = field(rule, "stealth")) {
                    if (!t->is_string() || !parse_tier(t->get<std::string>(), &r.tier))
                        out->error += "'packages." + name + ".stealth' must be max|balanced|compat; ";
                    else
                        r.has_tier = true;
                }
                if (const json* p = field(rule, "redirect")) {
                    if (!p->is_string() || !parse_redirect(p->get<std::string>(), &r.redirect))
                        out->error += "'packages." + name + ".redirect' must be \"<ipv4>:<port>\"; ";
                }
                out->packages[name] = r;
            }
        }
    }
    out->relax_hostname_verification = get_bool(root, "relax_hostname_verification", false, out);
    if (const json* s = field(root, "surfaces")) {
        set_surface(&out->surfaces, SURFACE_PLATFORM_TLS, get_bool(*s, "platform_tls", true, out));
        set_surface(&out->surfaces, SURFACE_JAVA_DEX, get_bool(*s, "java_dex", true, out));
        set_surface(&out->surfaces, SURFACE_BUNDLED_TLS, get_bool(*s, "bundled_tls", true, out));
        set_surface(&out->surfaces, SURFACE_FOREIGN_RUNTIME, get_bool(*s, "foreign_runtime", false, out));
    }
    if (const json* a = field(root, "aot")) {
        out->evict_oat = get_bool(*a, "evict_oat", true, out);
        out->stat_hook_fallback = get_bool(*a, "stat_hook_fallback", true, out);
    }
    if (const json* h = field(root, "hide")) {
        if (!h->is_object()) out->error += "'hide' must be an object; ";
        else out->self_remap = get_bool(*h, "self_remap", true, out);
    }
    if (const json* l = field(root, "log")) {
        out->log_enabled = get_bool(*l, "enabled", false, out);
        out->log_verbose = get_bool(*l, "verbose", false, out);
    }
    return out->error.empty();
}

bool load(const char* path, Config* out) {
    std::ifstream in(path);
    if (!in) {
        *out = Config{};
        out->error = std::string("cannot read ") + path + "; using defaults (no packages targeted)";
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return parse(ss.str(), out);
}

void decide(const Config& cfg, const char* package, ipc::Decision* d) {
    d->target = 0;
    d->tier = cfg.stealth;
    d->surfaces = cfg.surfaces;
    d->flags = 0;
    if (cfg.relax_hostname_verification) d->flags |= FLAG_RELAX_HOSTNAME;
    if (cfg.log_enabled) d->flags |= FLAG_LOG_ENABLED;
    if (cfg.log_verbose) d->flags |= FLAG_LOG_VERBOSE;
    if (cfg.stat_hook_fallback) d->flags |= FLAG_STAT_FALLBACK;
    if (cfg.self_remap) d->flags |= FLAG_SELF_REMAP;
    const auto it = cfg.packages.find(package);
    if (it == cfg.packages.end()) return;
    d->target = 1;
    if (it->second.has_tier) d->tier = it->second.tier;  // per-package override of the global ceiling
}

}  // namespace ph::config
