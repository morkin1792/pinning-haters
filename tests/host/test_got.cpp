// SPDX-License-Identifier: GPL-3.0-or-later
// Host-side test for the GOT rewriter: rewrites this executable's own import slot for getpid.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include "got/got_hook.h"

using namespace ph;

static pid_t fake_getpid() { return 4242; }

static int checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static bool count_cb(const got::Library&, void* ctx) {
    (*static_cast<int*>(ctx))++;
    return false;
}

int main() {
    const pid_t real = getpid();
    int libs = 0;
    got::for_each_library(count_cb, &libs);
    CHECK(libs >= 2);  // at least this executable and libc

    got::Library self;
    CHECK(got::find_library(nullptr, &self));
    CHECK(got::find_slot(self, "getpid") != nullptr);
    CHECK(got::has_edge(nullptr, "getpid"));
    // String markers, checked on libc rather than on this sanitizer-instrumented binary (ASan's
    // memmem interceptor treats a whole-segment scan over its own redzoned globals as an overflow).
    got::Library libc;
    CHECK(got::find_library("libc.so.6", &libc));
    CHECK(got::segments_contain(libc, "GNU C Library"));
    std::string absent = std::string("pinning_haters_marker_") + "never_in_libc";
    CHECK(!got::segments_contain(libc, absent.c_str()));
    CHECK(!got::segments_contain(libc, ""));  // an empty needle matches nothing, by contract
    CHECK(!got::has_edge(nullptr, "pinning_haters_not_imported"));
    CHECK(!got::has_edge("libdoesnotexist.so", "getpid"));

    void* orig = got::hook(nullptr, "getpid", reinterpret_cast<void*>(&fake_getpid));
    CHECK(orig != nullptr);
    CHECK(getpid() == 4242);                                                     // the call goes through the slot
    CHECK(reinterpret_cast<pid_t (*)()>(orig)() == real);                        // and the original still works
    CHECK(got::hook(nullptr, "getpid", reinterpret_cast<void*>(&fake_getpid)) == orig);  // idempotent, no stacking
    CHECK(got::restore(nullptr, "getpid"));
    CHECK(getpid() == real);
    CHECK(!got::restore(nullptr, "getpid"));  // nothing recorded any more

    CHECK(strcmp(got::basename_of("/apex/com.android.conscrypt/lib64/libjavacrypto.so"), "libjavacrypto.so") == 0);
    CHECK(strcmp(got::basename_of("libfoo.so"), "libfoo.so") == 0);
    CHECK(got::is_app_private("/data/app/~~abc/com.x-1/lib/arm64/libfoo.so"));
    CHECK(got::is_app_private("/data/app/~~abc/com.x-1/base.apk!/lib/arm64-v8a/libfoo.so"));
    CHECK(got::is_app_private("/memfd:jit-cache (deleted)"));
    CHECK(!got::is_app_private("/apex/com.android.art/lib64/libart.so"));
    CHECK(!got::is_app_private("/system/lib64/libc.so"));
    CHECK(!got::is_app_private(""));

    printf("test_got: %d checks passed\n", checks);
    return 0;
}
