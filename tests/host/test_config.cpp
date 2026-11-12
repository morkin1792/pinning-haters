// SPDX-License-Identifier: GPL-3.0-or-later
// Host-side test for the companion's config parser and per-package decision.
#include <stdio.h>
#include <string.h>

#include "config/config.h"

using namespace ph;

static int checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s config.example.json\n", argv[0]);
        return 2;
    }
    config::Config cfg;
    CHECK(config::load(argv[1], &cfg));
    CHECK(cfg.error.empty());
    CHECK(cfg.stealth == Tier::MAX);
    CHECK(cfg.packages.count("com.example.targetapp") == 1);
    CHECK(!cfg.packages["com.example.targetapp"].has_tier);
    CHECK(cfg.packages["com.example.hardened"].has_tier && cfg.packages["com.example.hardened"].tier == Tier::BALANCED);
    CHECK(cfg.packages["com.example.ignoresproxy"].redirect == "192.168.1.10:8081");
    CHECK(cfg.packages["com.example.targetapp"].redirect.empty());
    CHECK(!cfg.relax_hostname_verification);
    CHECK(cfg.surfaces == (SURFACE_PLATFORM_TLS | SURFACE_JAVA_DEX | SURFACE_BUNDLED_TLS));
    CHECK(cfg.evict_oat && cfg.stat_hook_fallback);
    CHECK(!cfg.log_enabled && !cfg.log_verbose);

    ipc::Decision d{};
    config::decide(cfg, "com.example.targetapp", &d);
    CHECK(d.target == 1 && d.tier == Tier::MAX);
    CHECK(d.flags & FLAG_STAT_FALLBACK);
    CHECK(d.flags & FLAG_SELF_REMAP);
    CHECK(!(d.flags & FLAG_LOG_ENABLED));
    config::decide(cfg, "com.example.hardened", &d);
    CHECK(d.target == 1 && d.tier == Tier::BALANCED);
    config::decide(cfg, "com.example.nottargeted", &d);
    CHECK(d.target == 0);

    // Empty object: valid and inert.
    CHECK(config::parse("{}", &cfg));
    CHECK(cfg.packages.empty() && cfg.stealth == Tier::MAX);
    // Garbage: defaults, error, and still inert.
    CHECK(!config::parse("not json", &cfg));
    CHECK(!cfg.error.empty() && cfg.packages.empty());
    CHECK(!config::parse("[1,2]", &cfg));
    CHECK(cfg.packages.empty());
    // Wrong types fall back per field instead of discarding the file.
    CHECK(!config::parse(R"({"version":2,"stealth":"loud","packages":{"a.b":{"stealth":7}},"log":{"enabled":"yes"}})", &cfg));
    CHECK(cfg.stealth == Tier::MAX);
    CHECK(cfg.packages.count("a.b") == 1 && !cfg.packages["a.b"].has_tier);
    CHECK(!cfg.log_enabled);
    CHECK(strstr(cfg.error.c_str(), "stealth") && strstr(cfg.error.c_str(), "enabled"));
    // Per-package override and the global ceiling.
    CHECK(config::parse(R"({"version":2,"stealth":"balanced","packages":{"x":{},"y":{"stealth":"compat"}},
        "relax_hostname_verification":true,"surfaces":{"foreign_runtime":true,"bundled_tls":false},
        "aot":{"stat_hook_fallback":false},"hide":{"self_remap":false},"log":{"enabled":true,"verbose":true}})", &cfg));
    config::decide(cfg, "x", &d);
    CHECK(d.target && d.tier == Tier::BALANCED);
    CHECK(d.flags == (FLAG_RELAX_HOSTNAME | FLAG_LOG_ENABLED | FLAG_LOG_VERBOSE));
    CHECK(d.surfaces == (SURFACE_PLATFORM_TLS | SURFACE_JAVA_DEX | SURFACE_FOREIGN_RUNTIME));
    config::decide(cfg, "y", &d);
    CHECK(d.target && d.tier == Tier::COMPAT);
    // redirect ends up in firewall rules: an IPv4 literal and a port, or nothing.
    std::string r;
    CHECK(config::parse_redirect("10.0.0.2:8080", &r) && r == "10.0.0.2:8080");
    for (const char* bad : {"", "10.0.0.2", "10.0.0.2:", "10.0.0.2:0", "10.0.0.2:65536", "10.0.0.2:80 -j ACCEPT",
                            "proxy.lan:8080", "10.0.0.2;reboot:80", "[::1]:8080", "10.0.0.256:80", "10.0.0.2:-1"})
        CHECK(!config::parse_redirect(bad, &r));
    CHECK(!config::parse(R"({"packages":{"a.b":{"redirect":"proxy.lan:8080"}}})", &cfg));
    CHECK(cfg.packages.count("a.b") == 1 && cfg.packages["a.b"].redirect.empty());
    CHECK(strstr(cfg.error.c_str(), "redirect"));
    // Comments are tolerated (people annotate their config).
    CHECK(config::parse("{\n // targets\n \"packages\": {\"z\": {}}\n}", &cfg));
    CHECK(cfg.packages.count("z") == 1);
    CHECK(!config::load("/nonexistent/config.json", &cfg) && cfg.packages.empty());

    printf("test_config: %d checks passed\n", checks);
    return 0;
}
