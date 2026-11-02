// SPDX-License-Identifier: GPL-3.0-or-later
// Host-side test for the static-BoringSSL table locator: synthetic ADRP+ADD decoding, then (for
// every library given on the command line: libflutter.so builds, WebRTC, OpenTok, …) a file "load" — PT_LOADs copied to their vaddrs,
// R_AARCH64_RELATIVE applied — and a run of the real locator over it.
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "got/got_hook.h"
#include "log/log.h"
#include "tls/boringssl_table.h"
#include "tls/openssl_table.h"

using namespace ph;

// The module's sink is Android-only; the locator only logs.
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

static uint32_t adrp(uint32_t rd, int64_t page_delta) {
    const uint64_t imm = static_cast<uint64_t>(page_delta) & 0x1fffff;
    return 0x90000000u | static_cast<uint32_t>((imm & 3) << 29) | static_cast<uint32_t>(((imm >> 2) & 0x7ffff) << 5) | rd;
}
static uint32_t add_imm(uint32_t rd, uint32_t rn, uint32_t imm12) { return 0x91000000u | (imm12 << 10) | (rn << 5) | rd; }

static int synthetic() {
    const uintptr_t code_addr = 0x7000'0000'1000;
    const uintptr_t target = 0x7000'0012'3456;  // 0x122 pages ahead, low bits 0x456
    const int64_t delta = static_cast<int64_t>((target >> 12) - (code_addr >> 12));
    uint32_t code[8] = {0xd503201f, adrp(8, delta), 0xaa0803e9, add_imm(9, 8, 0x456), 0xd65f03c0, 0, 0, 0};
    uintptr_t ref = 0;
    CHECK(boringssl_table::find_adrp_add_ref(code, 8, code_addr, target, &ref));
    CHECK(ref == code_addr + 3 * 4);
    CHECK(!boringssl_table::find_adrp_add_ref(code, 8, code_addr, target + 1, &ref));   // wrong low bits
    CHECK(!boringssl_table::find_adrp_add_ref(code, 8, code_addr, target + 0x1000, &ref));  // wrong page
    uint32_t other_reg[4] = {adrp(8, delta), add_imm(9, 10, 0x456), 0, 0};
    CHECK(!boringssl_table::find_adrp_add_ref(other_reg, 4, code_addr, target, &ref));   // ADD from another register
    // Negative page delta.
    const uintptr_t low_target = code_addr - 0x5000 + 0x10;
    uint32_t back[2] = {adrp(1, -5), add_imm(1, 1, 0x10)};
    CHECK(boringssl_table::find_adrp_add_ref(back, 2, code_addr, low_target, &ref));
    return 0;
}

// Loads an ELF file the way the dynamic linker would lay it out, enough for read-only scanning.
static int locate_in_file(const char* path, bool expect_found) {
    const int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); return 1; }
    struct stat st{};
    fstat(fd, &st);
    auto* file = static_cast<uint8_t*>(mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
    close(fd);
    CHECK(file != MAP_FAILED);
    const auto* eh = reinterpret_cast<const ElfW(Ehdr)*>(file);
    CHECK(memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0 && eh->e_machine == EM_AARCH64);
    const auto* ph = reinterpret_cast<const ElfW(Phdr)*>(file + eh->e_phoff);
    size_t span = 0;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD && ph[i].p_vaddr + ph[i].p_memsz > span) span = ph[i].p_vaddr + ph[i].p_memsz;
    auto* region = static_cast<uint8_t*>(mmap(nullptr, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    CHECK(region != MAP_FAILED);
    const ElfW(Dyn)* dyn = nullptr;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) memcpy(region + ph[i].p_vaddr, file + ph[i].p_offset, ph[i].p_filesz);
        if (ph[i].p_type == PT_DYNAMIC) dyn = reinterpret_cast<const ElfW(Dyn)*>(region + ph[i].p_vaddr);
    }
    CHECK(dyn != nullptr);
    // R_AARCH64_RELATIVE from whichever encoding the library uses: plain RELA (Flutter), Android
    // packed APS2 (Chromium, large apps), RELR (newer NDK defaults).
    const ElfW(Rela)* rela = nullptr;
    size_t relasz = 0;
    const uint8_t* aps2 = nullptr;
    size_t aps2sz = 0;
    const uint64_t* relr = nullptr;
    size_t relrsz = 0;
    const ElfW(Sym)* syms = nullptr;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_SYMTAB) syms = reinterpret_cast<const ElfW(Sym)*>(region + dyn->d_un.d_ptr);
        if (dyn->d_tag == DT_RELA) rela = reinterpret_cast<const ElfW(Rela)*>(region + dyn->d_un.d_ptr);
        if (dyn->d_tag == DT_RELASZ) relasz = dyn->d_un.d_val;
        if (dyn->d_tag == 0x60000011 /* DT_ANDROID_RELA */) aps2 = region + dyn->d_un.d_ptr;
        if (dyn->d_tag == 0x60000012 /* DT_ANDROID_RELASZ */) aps2sz = dyn->d_un.d_val;
        if (dyn->d_tag == 0x24 /* DT_RELR */ || dyn->d_tag == 0x6fffe000 /* DT_ANDROID_RELR */) relr = reinterpret_cast<const uint64_t*>(region + dyn->d_un.d_ptr);
        if (dyn->d_tag == 0x23 /* DT_RELRSZ */ || dyn->d_tag == 0x6fffe001 /* DT_ANDROID_RELRSZ */) relrsz = dyn->d_un.d_val;
    }
    const auto base = reinterpret_cast<uintptr_t>(region);
    size_t relative = 0;
    auto apply = [&](uint64_t offset, uint64_t info, int64_t addend) {
        const uint32_t type = ELF64_R_TYPE(info);
        if (type == R_AARCH64_RELATIVE) {
            *reinterpret_cast<uintptr_t*>(region + offset) = base + static_cast<uintptr_t>(addend);
            relative++;
        } else if ((type == R_AARCH64_ABS64 || type == R_AARCH64_GLOB_DAT) && syms) {
            // Symbol-based slots (OpenSSL's SSL_METHOD tables are filled this way): S + A for a
            // symbol this library defines, left zero for an undefined one.
            const ElfW(Sym)& sym = syms[ELF64_R_SYM(info)];
            if (sym.st_shndx != SHN_UNDEF && sym.st_value)
                *reinterpret_cast<uintptr_t*>(region + offset) = base + sym.st_value + static_cast<uintptr_t>(addend);
        }
    };
    for (size_t i = 0; rela && i < relasz / sizeof(ElfW(Rela)); i++) apply(rela[i].r_offset, rela[i].r_info, rela[i].r_addend);
    if (aps2 && aps2sz > 4 && memcmp(aps2, "APS2", 4) == 0) {
        const uint8_t* p = aps2 + 4;
        const uint8_t* const end = aps2 + aps2sz;
        auto sleb = [&]() -> int64_t {
            int64_t v = 0;
            unsigned shift = 0;
            uint8_t byte;
            do {
                byte = *p++;
                v |= static_cast<int64_t>(byte & 0x7f) << shift;
                shift += 7;
            } while ((byte & 0x80) && p < end);
            if (shift < 64 && (byte & 0x40)) v |= -(int64_t{1} << shift);
            return v;
        };
        const int64_t count = sleb();
        uint64_t offset = static_cast<uint64_t>(sleb());
        uint64_t info = 0;
        int64_t addend = 0;
        for (int64_t done = 0; done < count && p < end;) {
            const int64_t group_size = sleb();
            const int64_t flags = sleb();
            const bool by_info = flags & 1, by_delta = flags & 2, by_addend = flags & 4, has_addend = flags & 8;
            int64_t group_delta = 0;
            if (by_delta) group_delta = sleb();
            if (by_info) info = static_cast<uint64_t>(sleb());
            if (by_addend && has_addend) addend += sleb();
            else if (!has_addend) addend = 0;
            for (int64_t k = 0; k < group_size; k++, done++) {
                offset += by_delta ? static_cast<uint64_t>(group_delta) : static_cast<uint64_t>(sleb());
                if (!by_info) info = static_cast<uint64_t>(sleb());
                if (has_addend && !by_addend) addend += sleb();
                apply(offset, info, addend);
            }
        }
    }
    if (relr) {
        uint64_t where = 0;
        for (size_t i = 0; i < relrsz / 8; i++) {
            const uint64_t entry = relr[i];
            if ((entry & 1) == 0) {
                where = entry;
                *reinterpret_cast<uintptr_t*>(region + where) += base;
                relative++;
                where += 8;
            } else {
                for (unsigned bit = 1; bit < 64; bit++)
                    if (entry & (uint64_t{1} << bit)) {
                        *reinterpret_cast<uintptr_t*>(region + where + (bit - 1) * 8) += base;
                        relative++;
                    }
                where += 63 * 8;
            }
        }
    }
    CHECK(relative > 1000);

    got::Library lib{};
    lib.bias = reinterpret_cast<uintptr_t>(region);
    lib.phdr = ph;
    lib.phnum = eh->e_phnum;
    snprintf(lib.path, sizeof(lib.path), "%s", path);
    bool has_strings = false;
    void** slot = boringssl_table::locate_session_verify_slot(lib, &has_strings);
    // The OpenSSL backend over the same file: a BoringSSL must read as "not OpenSSL", an OpenSSL
    // with exports must yield its SSL_METHOD ssl_connect slot.
    bool has_openssl = false;
    openssl_table::Exports ex;
    void** connect_slots[2] = {};
    const size_t connect_count = openssl_table::locate_connect_slots(lib, &has_openssl, &ex, connect_slots);
    void** connect_slot = connect_count ? connect_slots[0] : nullptr;
    if (!expect_found) {
        // An OpenSSL build: same purpose strings, no method table. The locator must say so, never guess.
        CHECK(has_strings);
        CHECK(slot == nullptr);
        CHECK(has_openssl);
        CHECK(openssl_table::is_openssl(lib));
        CHECK(boringssl_table::install(lib) == PatternResult::ABSENT);
        if (!connect_slot) {
            // Diagnostics for a locator miss: which exports resolved, what TLS_client_method starts with.
            printf("  exports: TLS_client_method=0x%zx SSL_set_verify=0x%zx SSL_get_verify_callback=0x%zx SSL_set_verify_result=0x%zx\n",
                   ex.tls_client_method ? ex.tls_client_method - lib.bias : 0, ex.set_verify ? ex.set_verify - lib.bias : 0,
                   ex.get_verify_callback ? ex.get_verify_callback - lib.bias : 0, ex.set_verify_result ? ex.set_verify_result - lib.bias : 0);
            if (ex.tls_client_method) {
                const auto* code = reinterpret_cast<const uint32_t*>(ex.tls_client_method);
                printf("  TLS_client_method code: %08x %08x %08x %08x\n", code[0], code[1], code[2], code[3]);
            }
        }
        CHECK(connect_slot != nullptr);
        if (connect_slot) {
            CHECK(ex.set_verify && ex.get_verify_callback && ex.set_verify_result);
            for (size_t k = 0; k < connect_count; k++) {
                const uintptr_t fn = reinterpret_cast<uintptr_t>(*connect_slots[k]) - lib.bias;
                CHECK(fn > 0x1000 && fn < span);
                // Every release connects through one function (ossl_statem_connect) in both tables.
                CHECK(*connect_slots[k] == *connect_slots[0]);
                printf("%s: OpenSSL %s table, ssl_connect slot at 0x%zx -> 0x%zx\n", path, k ? "TLS_method" : "client",
                       reinterpret_cast<uintptr_t>(connect_slots[k]) - lib.bias, fn);
            }
        }
        munmap(region, span);
        munmap(file, st.st_size);
        return 0;
    }
    CHECK(!has_openssl);
    CHECK(!openssl_table::is_openssl(lib));
    CHECK(connect_slot == nullptr);
    CHECK(slot != nullptr);
    const uintptr_t fn = reinterpret_cast<uintptr_t>(*slot) - lib.bias;
    const uintptr_t slot_off = reinterpret_cast<uintptr_t>(slot) - lib.bias;
    // SSL_X509_METHOD: session_verify_cert_chain is the 10th member in current BoringSSL; the slots
    // around it must all be function pointers.
    for (int k = -9; k <= 2; k++) {
        const uintptr_t v = reinterpret_cast<uintptr_t>(slot[k]) - lib.bias;
        CHECK(v > 0x1000 && v < span);
    }
    printf("%s: session_verify_cert_chain at 0x%zx, table slot at 0x%zx (member %d of ssl_crypto_x509_method if it starts at 0x%zx)\n",
           path, fn, slot_off, 9, slot_off - 9 * 8);
    munmap(region, span);
    munmap(file, st.st_size);
    return 0;
}

int main(int argc, char** argv) {
    if (synthetic()) return 1;
    bool expect_found = true;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--absent") == 0) {
            expect_found = false;
            continue;
        }
        if (locate_in_file(argv[i], expect_found)) return 1;
    }
    printf("test_boringssl_table: %d checks passed (%d libraries)\n", checks, argc - 1);
    return 0;
}
