// SPDX-License-Identifier: GPL-3.0-or-later
// Host-side test for hide/self_remap: the test binary re-maps its own mappings (the function lives
// in this executable, so "our library" is the executable itself), then checks that /proc/self/maps
// no longer names the file, that code still runs and data survived.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hide/self_remap.h"
#include "log/log.h"

namespace ph::log {
void write(ipc::LogLevel, const char*, ...) {}
}  // namespace ph::log

static int checks = 0;
#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static int g_data = 0x5a5a;                 // .data survives the copy
static const char g_rodata[] = "rodata ok";  // .rodata survives the copy
static int volatile g_bss;                   // .bss too

static int count_named(const char* path) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, path)) n++;
    fclose(f);
    return n;
}

__attribute__((noinline)) static int still_runs(int x) { return x * 3 + g_data; }

int main() {
    char self[1024];
    const ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    CHECK(len > 0);
    self[len] = 0;
    const int before = count_named(self);
    CHECK(before >= 2);  // at least text and data
    g_bss = 7;
    const int done = ph::hide::remap_self();
    CHECK(done >= before);  // every named mapping, gaps included
    CHECK(count_named(self) == 0);
    CHECK(still_runs(2) == 6 + 0x5a5a);
    CHECK(strcmp(g_rodata, "rodata ok") == 0);
    CHECK(g_bss == 7);
    g_data = 1;
    CHECK(still_runs(0) == 1);  // data pages are writable again after the copy
    printf("test_self_remap: %d checks passed (%d mappings re-mapped)\n", checks, done);
    return 0;
}
