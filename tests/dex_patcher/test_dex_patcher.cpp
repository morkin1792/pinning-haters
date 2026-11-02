// SPDX-License-Identifier: GPL-3.0-or-later
// Host-side unit test for the DEX parser and patcher. Runs on a d8-built fixture; no device needed.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include <vector>

#include "dex/dex_parser.h"
#include "dex/dex_patcher.h"
#include "hooks/targets.h"

using namespace ph;
using namespace ph::dex;

static std::vector<uint8_t> read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror(path);
        exit(2);
    }
    std::vector<uint8_t> data;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.insert(data.end(), buf, buf + n);
    fclose(f);
    return data;
}

static uint32_t header_checksum_of(const std::vector<uint8_t>& dex) {
    return adler32(adler32(0, Z_NULL, 0), dex.data() + NON_SUM, static_cast<uInt>(dex.size() - NON_SUM));
}

// Locates the code item of a target in a (possibly patched) buffer so the test can look at bytes.
static const CodeItem* find_code(const View& v, const JavaTarget& t) {
    const int32_t cs = v.find_string(t.class_descriptor);
    const int32_t ti = v.find_type(static_cast<uint32_t>(cs));
    const ClassDef* cd = v.find_class_def(static_cast<uint32_t>(ti));
    const int32_t ns = v.find_string(t.method_name);
    const CodeItem* found = nullptr;
    for_each_method(v, *cd, [&](const EncodedMethod& m) {
        const MethodId* id = v.method_id(m.method_idx);
        if (id->name_idx == static_cast<uint32_t>(ns) && v.proto_matches(id->proto_idx, t.method_signature)) {
            found = v.at<CodeItem>(m.code_off);
            return false;
        }
        return true;
    });
    return found;
}

static int checks = 0;
#define CHECK(cond)                                                                        \
    do {                                                                                   \
        checks++;                                                                          \
        if (!(cond)) {                                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);               \
            return 1;                                                                      \
        }                                                                                  \
    } while (0)

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s classes.dex patched.dex\n", argv[0]);
        return 2;
    }
    const std::vector<uint8_t> original = read_file(argv[1]);
    std::vector<uint8_t> patched = original;

    View v;
    CHECK(open(patched.data(), patched.size(), &v));
    CHECK(v.version >= 35 && v.version <= 41);
    // d8 wrote a correct checksum, so the adler32 trick has something real to preserve.
    CHECK(header_checksum_of(original) == v.hdr->checksum);

    // 1. The production table against the fixture: every OkHttp overload patches; hostname
    //    targets patch (the gate is the hook manager's job, not the patcher's); Apache is absent.
    int okhttp_ok = 0, hostname_ok = 0, apache_absent = 0;
    for (size_t i = 0; i < kJavaTargetCount; i++) {
        const JavaTarget& t = kJavaTargets[i];
        const bool present = class_present(v, t);
        const PatchResult r = patch_target(v, t);
        if (t.surface == SurfaceId::OKHTTP_PINNER) {
            CHECK(present);
            CHECK(r == PatchResult::OK);
            okhttp_ok++;
        } else if (strstr(t.class_descriptor, "okhttp3/internal/tls")) {
            CHECK(present);
            CHECK(r == PatchResult::OK);
            hostname_ok++;
        } else if (t.surface == SurfaceId::CERT_TRANSPARENCY) {
            CHECK(present == (strstr(t.class_descriptor, "appmattus") != nullptr));
            CHECK(r == (present ? PatchResult::OK : PatchResult::CLASS_ABSENT));
        } else if (t.surface == SurfaceId::BUNDLED_TLS) {
            // bundled Conscrypt rows: only org.conscrypt.ConscryptEngine is in the fixture
            const bool in_fixture = strcmp(t.class_descriptor, "Lorg/conscrypt/ConscryptEngine;") == 0;
            CHECK(present == in_fixture);
            CHECK(r == (in_fixture ? PatchResult::OK : PatchResult::CLASS_ABSENT));
        } else if (t.surface == SurfaceId::DART_PINNING) {
            CHECK(present);
            CHECK(r == PatchResult::OK);
        } else if (t.surface == SurfaceId::CHROMIUM) {
            CHECK(present);  // both rows name AndroidNetworkLibrary
            // the 3-argument overload is absent from the fixture: class present, method absent
            CHECK(r == (strstr(t.method_signature, "[B[B)") ? PatchResult::OK : PatchResult::METHOD_ABSENT));
        } else {
            CHECK(!present);
            CHECK(r == PatchResult::CLASS_ABSENT);
            apache_absent++;
        }
    }
    CHECK(okhttp_ok == 4);
    CHECK(hostname_ok == 2);
    CHECK(apache_absent == 4);

    // 1b. The interceptor pass-through: bytes are the 11-unit template with the DEX's own method ids
    //     and the register that holds `chain`, then nops.
    {
        const JavaTarget* ct = nullptr;
        for (size_t i = 0; i < kJavaTargetCount; i++)
            if (kJavaTargets[i].replacement == ReplacementKind::INTERCEPTOR_PROCEED &&
                strstr(kJavaTargets[i].class_descriptor, "appmattus"))
                ct = &kJavaTargets[i];
        CHECK(ct != nullptr);
        CHECK(class_present(v, *ct));
        View vo0;
        CHECK(open(original.data(), original.size(), &vo0));
        const CodeItem* before = find_code(vo0, *ct);
        CHECK(before && before->ins_size == 2 && before->outs_size >= 2 && before->registers_size > 2);
        CHECK(patch_target(v, *ct) == PatchResult::OK);
        const int32_t req = v.find_method("Lokhttp3/Interceptor$Chain;", "request", "()Lokhttp3/Request;");
        const int32_t pro = v.find_method("Lokhttp3/Interceptor$Chain;", "proceed", "(Lokhttp3/Request;)Lokhttp3/Response;");
        CHECK(req >= 0 && pro >= 0 && req != pro);
        const CodeItem* after = find_code(v, *ct);
        const uint16_t* insns = insns_of(after);
        const uint16_t chain = static_cast<uint16_t>(after->registers_size - after->ins_size + 1);
        const uint16_t expect[INTERCEPTOR_PROCEED_UNITS] = {
            0x0008, chain, 0x0178, static_cast<uint16_t>(req), 0, 0x010c, 0x0278, static_cast<uint16_t>(pro), 0, 0x000c, 0x0011};
        for (size_t u = 0; u < INTERCEPTOR_PROCEED_UNITS; u++) CHECK(insns[u] == expect[u]);
        for (size_t u = INTERCEPTOR_PROCEED_UNITS; u < after->insns_size; u++) CHECK(insns[u] == OP_NOP);
        CHECK(after->insns_size == before->insns_size && after->outs_size == before->outs_size);
        // The resolver must not match a method the DEX merely names differently.
        CHECK(v.find_method("Lokhttp3/Interceptor$Chain;", "proceed", "()Lokhttp3/Response;") < 0);
        CHECK(v.find_method("Lokhttp3/Nope;", "request", "()Lokhttp3/Request;") < 0);
        // A DEX without the Chain methods reports NO_CALLEE rather than writing garbage.
        const JavaTarget bogus{"Lfixture/Extra;", "flag", "(Ljava/lang/String;)Z", ReplacementKind::INTERCEPTOR_PROCEED,
                               Tier::MAX, SurfaceId::CERT_TRANSPARENCY, "test"};
        CHECK(patch_target(v, bogus) != PatchResult::OK);
    }

    // 1c. CHROMIUM_TRUST_LEAF: const/4 v0; aget-object v0, p0, v0; addTestRoot(v0); inner(p0..p4);
    //     move-result-object v0; return-object v0 — with the inner verifier found by proto among
    //     *static* methods only (the fixture has an instance method with the same proto).
    {
        const JavaTarget* cr = nullptr;
        for (size_t i = 0; i < kJavaTargetCount; i++)
            if (kJavaTargets[i].replacement == ReplacementKind::CHROMIUM_TRUST_LEAF && strstr(kJavaTargets[i].method_signature, "[B[B)"))
                cr = &kJavaTargets[i];
        CHECK(cr != nullptr);
        CHECK(class_present(v, *cr));
        View vo0;
        CHECK(open(original.data(), original.size(), &vo0));
        const CodeItem* before = find_code(vo0, *cr);
        CHECK(before && before->ins_size == 5 && before->outs_size >= 5 && before->registers_size >= 6);
        CHECK(patch_target(v, *cr) == PatchResult::OK);
        const int32_t add_root = v.find_method("Lorg/chromium/net/AndroidNetworkLibrary;", "addTestRootCertificate", "([B)V");
        const int32_t inner = v.find_static_method_by_proto(cr->method_signature, "Lorg/chromium/net/AndroidNetworkLibrary;");
        const int32_t x509 = v.find_method("Lorg/chromium/net/X509Util;", "verifyServerCertificates", cr->method_signature);
        const int32_t instance = v.find_method("Lorg/chromium/net/X509Util$CertificateVerifier;", "verifyServerCertificates", cr->method_signature);
        CHECK(add_root >= 0 && inner >= 0 && x509 >= 0 && instance >= 0);
        CHECK(inner == x509 && inner != instance);
        CHECK(v.method_is_static(static_cast<uint32_t>(x509)) && !v.method_is_static(static_cast<uint32_t>(instance)));
        const CodeItem* after = find_code(v, *cr);
        const uint16_t* insns = insns_of(after);
        const uint16_t p0 = static_cast<uint16_t>(after->registers_size - after->ins_size);
        const uint16_t expect[11] = {0x0012, 0x0046, p0, 0x0177, static_cast<uint16_t>(add_root), 0,
                                     0x0577, static_cast<uint16_t>(inner), p0, 0x000c, 0x0011};
        for (size_t u = 0; u < 11; u++) CHECK(insns[u] == expect[u]);
        for (size_t u = 11; u < after->insns_size; u++) CHECK(insns[u] == OP_NOP);

        // The no-free-local shape R8 produces on the real WebView: registers == ins == 5. The last
        // parameter (sctList) is the scratch register and is re-nulled before the inner call.
        alignas(4) uint8_t raw[sizeof(CodeItem) + 2 * 20] = {};
        auto* ci = reinterpret_cast<CodeItem*>(raw);
        ci->registers_size = 5; ci->ins_size = 5; ci->outs_size = 5; ci->insns_size = 20;
        CHECK(patch_code_item_chromium(ci, sizeof(raw), 7, 9, /*last_param_droppable=*/false) == PatchResult::NO_REGISTERS);
        CHECK(patch_code_item_chromium(ci, sizeof(raw), 7, 9, true) == PatchResult::OK);
        const uint16_t expect_b[12] = {0x0412, 0x0446, 0x0400, 0x0177, 7, 4, 0x0412, 0x0577, 9, 0, 0x000c, 0x0011};
        for (size_t u = 0; u < 12; u++) CHECK(insns_of(ci)[u] == expect_b[u]);
        for (size_t u = 12; u < 20; u++) CHECK(insns_of(ci)[u] == OP_NOP);
        // Exactly 12 units with one try block: no tail, the try parks on the first const/4.
        {
            alignas(4) uint8_t tight[sizeof(CodeItem) + 2 * 12 + 8 + 8] = {};
            auto* tc = reinterpret_cast<CodeItem*>(tight);
            tc->registers_size = 5; tc->ins_size = 5; tc->outs_size = 5; tc->insns_size = 12; tc->tries_size = 1;
            auto* tr = reinterpret_cast<TryItem*>(tight + sizeof(CodeItem) + 24);
            tr->start_addr = 0; tr->insn_count = 5; tr->handler_off = 1;
            uint8_t* hl = tight + sizeof(CodeItem) + 24 + 8;
            hl[0] = 1; hl[1] = 0; hl[2] = 5;  // one handler list: catch-all at address 5 (inside the template)
            CHECK(patch_code_item_chromium(tc, sizeof(tight), 7, 9, true) == PatchResult::OK);
            CHECK(tr->start_addr == 0 && tr->insn_count == 1);
            CHECK(hl[2] == 0);  // catch-all repointed at the first safe slot
            tc->tries_size = 5;  // more tries than safe slots and no tail → refused
            CHECK(patch_code_item_chromium(tc, sizeof(tight), 7, 9, true) == PatchResult::TOO_SMALL);
        }
        // Too many parameters for a 4-bit scratch register.
        ci->registers_size = 17; ci->ins_size = 17; ci->outs_size = 17;
        CHECK(patch_code_item_chromium(ci, sizeof(raw), 7, 9, true) == PatchResult::NO_REGISTERS);
    }

    // 1d. RETURN_NEW_INSTANCE on a test-only target: `return new AndroidCertVerifyResult(0)`.
    {
        const JavaTarget t{"Lorg/chromium/net/X509Util;", "verifyServerCertificates",
                           "([[BLjava/lang/String;Ljava/lang/String;[B[B)Lorg/chromium/net/AndroidCertVerifyResult;",
                           ReplacementKind::RETURN_NEW_INSTANCE, Tier::MAX, SurfaceId::CHROMIUM, "test",
                           "Lorg/chromium/net/AndroidCertVerifyResult;", "(I)V"};
        View vo0;
        CHECK(open(original.data(), original.size(), &vo0));
        const CodeItem* before = find_code(vo0, t);
        CHECK(before && before->outs_size >= 2 && before->registers_size >= 2);
        CHECK(patch_target(v, t) == PatchResult::OK);
        const int32_t ts = v.find_string("Lorg/chromium/net/AndroidCertVerifyResult;");
        const int32_t ti = v.find_type(static_cast<uint32_t>(ts));
        const int32_t ctor = v.find_method("Lorg/chromium/net/AndroidCertVerifyResult;", "<init>", "(I)V");
        CHECK(ti >= 0 && ctor >= 0);
        const CodeItem* after = find_code(v, t);
        const uint16_t* insns = insns_of(after);
        const uint16_t expect[NEW_INSTANCE_MAX_UNITS] = {0x0022, static_cast<uint16_t>(ti), 0x0112, 0x0276,
                                                         static_cast<uint16_t>(ctor), 0, 0x0011};
        for (size_t u = 0; u < NEW_INSTANCE_MAX_UNITS; u++) CHECK(insns[u] == expect[u]);
        for (size_t u = NEW_INSTANCE_MAX_UNITS; u < after->insns_size; u++) CHECK(insns[u] == OP_NOP);
        JavaTarget bad = t;
        bad.aux_ctor = "(Z)V";
        CHECK(patch_target(v, bad) == PatchResult::NO_CALLEE);
    }

    // 2. Bytes: return-void first, nop to insns_size, header fields untouched.
    View vo;
    CHECK(open(original.data(), original.size(), &vo));
    for (size_t i = 0; i < kJavaTargetCount; i++) {
        const JavaTarget& t = kJavaTargets[i];
        if (!class_present(v, t) || t.replacement == ReplacementKind::INTERCEPTOR_PROCEED ||
            t.replacement == ReplacementKind::RETURN_NEW_INSTANCE || t.replacement == ReplacementKind::CHROMIUM_TRUST_LEAF)
            continue;
        const CodeItem* before = find_code(vo, t);
        const CodeItem* after = find_code(v, t);
        CHECK(before && after);
        CHECK(after->insns_size == before->insns_size);
        CHECK(after->tries_size == before->tries_size);
        CHECK(after->registers_size == before->registers_size);
        CHECK(after->debug_info_off == before->debug_info_off);
        const uint16_t* insns = insns_of(after);
        size_t prefix;
        if (t.replacement == ReplacementKind::RETURN_VOID) {
            CHECK(insns[0] == RETURN_VOID_UNIT);
            prefix = 1;
        } else if (t.replacement == ReplacementKind::RETURN_FALSE) {
            CHECK(insns[0] == CONST4_V0_0_UNIT && insns[1] == RETURN_V0_UNIT);
            prefix = 2;
        } else {
            CHECK(insns[0] == CONST4_V0_1_UNIT && insns[1] == RETURN_V0_UNIT);
            prefix = 2;
        }
        for (size_t u = prefix; u < after->insns_size; u++) CHECK(insns[u] == OP_NOP);
    }
    // The List overload carries try/catch blocks and a packed-switch payload: nop-fill ran over
    // handler code and payload data without touching tries_size or the handlers.
    {
        const CodeItem* big = find_code(vo, kJavaTargets[0]);
        CHECK(big && big->tries_size > 0 && big->insns_size > 20);
    }
    CHECK(memcmp(patched.data(), original.data(), HEADER_SIZE_V35) == 0);
    // This is why the interception returns the pre-patch checksum instead of recomputing it.
    CHECK(header_checksum_of(patched) != v.hdr->checksum);

    // 3. The remaining replacement kinds and the failure paths.
    const JavaTarget false_t{"Lfixture/Extra;", "flag", "(Ljava/lang/String;)Z", ReplacementKind::RETURN_FALSE,
                             Tier::MAX, SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, false_t) == PatchResult::OK);
    CHECK(insns_of(find_code(v, false_t))[0] == CONST4_V0_0_UNIT);
    const JavaTarget abstract_t{"Lfixture/Extra;", "abstractCheck", "(Ljava/lang/String;)V", ReplacementKind::RETURN_VOID,
                                Tier::MAX, SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, abstract_t) == PatchResult::NO_CODE);
    const JavaTarget native_t{"Lfixture/Extra;", "nativeCheck", "(Ljava/lang/String;)I", ReplacementKind::RETURN_FALSE,
                              Tier::MAX, SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, native_t) == PatchResult::NO_CODE);
    const JavaTarget wrong_sig{"Lfixture/Extra;", "flag", "(I)Z", ReplacementKind::RETURN_FALSE, Tier::MAX,
                               SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, wrong_sig) == PatchResult::METHOD_ABSENT);
    const JavaTarget wrong_name{"Lfixture/Extra;", "nope", "(I)Z", ReplacementKind::RETURN_FALSE, Tier::MAX,
                                SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, wrong_name) == PatchResult::METHOD_ABSENT);
    const JavaTarget missing_class{"Lcom/nope/Nope;", "x", "()V", ReplacementKind::RETURN_VOID, Tier::MAX,
                                   SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(patch_target(v, missing_class) == PatchResult::CLASS_ABSENT);
    CHECK(!class_present(v, missing_class));
    // A class referenced but not defined here (java.lang.String is in the fixture's type_ids).
    const JavaTarget foreign{"Ljava/lang/String;", "length", "()I", ReplacementKind::RETURN_FALSE, Tier::MAX,
                             SurfaceId::OKHTTP_PINNER, "test"};
    CHECK(v.find_string("Ljava/lang/String;") >= 0);
    CHECK(patch_target(v, foreign) == PatchResult::CLASS_ABSENT);

    // 4. Garbage in must not crash: truncated copies and a corrupted header.
    for (size_t cut : {size_t{0x70}, original.size() / 4, original.size() / 2, original.size() - 1}) {
        std::vector<uint8_t> trunc(original.begin(), original.begin() + cut);
        View tv;
        if (!open(trunc.data(), trunc.size(), &tv)) continue;
        for (size_t i = 0; i < kJavaTargetCount; i++) patch_target(tv, kJavaTargets[i]);  // any result; no crash
    }
    {
        std::vector<uint8_t> bad = original;
        memset(bad.data() + 0x38, 0xff, 0x70 - 0x38);  // all table offsets/sizes → garbage
        View bv;
        if (open(bad.data(), bad.size(), &bv))
            for (size_t i = 0; i < kJavaTargetCount; i++) CHECK(patch_target(bv, kJavaTargets[i]) != PatchResult::OK);
        std::vector<uint8_t> notdex = original;
        notdex[0] = 'x';
        CHECK(!open(notdex.data(), notdex.size(), &bv));
    }

    // 5. patch_code_item guards.
    {
        alignas(4) uint8_t tiny[sizeof(CodeItem) + 2] = {};
        auto* ci = reinterpret_cast<CodeItem*>(tiny);
        ci->insns_size = 1;
        ci->registers_size = 0;
        CHECK(patch_code_item(ci, sizeof(tiny), ReplacementKind::RETURN_TRUE) == PatchResult::TOO_SMALL);
        ci->insns_size = 2;
        CHECK(patch_code_item(ci, sizeof(tiny), ReplacementKind::RETURN_TRUE) == PatchResult::MALFORMED);  // lies about size
        CHECK(patch_code_item(ci, sizeof(tiny) + 2, ReplacementKind::RETURN_TRUE) == PatchResult::NO_REGISTERS);
        ci->registers_size = 1;
        ci->insns_size = 1;
        CHECK(patch_code_item(ci, sizeof(tiny), ReplacementKind::RETURN_VOID) == PatchResult::OK);
        CHECK(insns_of(ci)[0] == RETURN_VOID_UNIT);
    }

    // 6. Try/handler relocation: for every patched method that had tries, each try now covers one
    //    unit of the nop tail (ascending) and no handler address points inside the template.
    {
        struct Case { const JavaTarget* t; size_t program; };
        const JavaTarget* ct = nullptr; const JavaTarget* cr = nullptr;
        for (size_t i = 0; i < kJavaTargetCount; i++) {
            if (kJavaTargets[i].replacement == ReplacementKind::INTERCEPTOR_PROCEED && strstr(kJavaTargets[i].class_descriptor, "appmattus")) ct = &kJavaTargets[i];
            if (kJavaTargets[i].replacement == ReplacementKind::CHROMIUM_TRUST_LEAF && strstr(kJavaTargets[i].method_signature, "[B[B)")) cr = &kJavaTargets[i];
        }
        const Case cases[] = {{&kJavaTargets[0], 1}, {ct, INTERCEPTOR_PROCEED_UNITS}, {cr, 11}};
        int with_tries = 0;
        for (const Case& c : cases) {
            const CodeItem* ci = find_code(v, *c.t);
            CHECK(ci != nullptr);
            if (ci->tries_size == 0) continue;
            with_tries++;
            const auto* base = reinterpret_cast<const uint8_t*>(ci);
            size_t off = sizeof(CodeItem) + ci->insns_size * 2;
            if (ci->insns_size & 1) off += 2;
            const auto* tries = reinterpret_cast<const TryItem*>(base + off);
            uint32_t last = 0;
            for (uint16_t i = 0; i < ci->tries_size; i++) {
                // ascending, non-overlapping, and parked on something that cannot throw: either a
                // template instruction from the safe list or a nop on the tail
                CHECK(i == 0 || tries[i].start_addr >= last);
                last = tries[i].start_addr + tries[i].insn_count;
                CHECK(last <= ci->insns_size);
                const uint16_t op = insns_of(ci)[tries[i].start_addr] & 0xff;
                CHECK(op == OPCODE_CONST_4 || op == OPCODE_MOVE_RESULT_OBJECT || op == OPCODE_RETURN_OBJECT ||
                      op == OPCODE_RETURN_VOID || op == OPCODE_RETURN || op == OPCODE_MOVE_OBJECT_FROM16 || insns_of(ci)[tries[i].start_addr] == OP_NOP);
            }
            const uint8_t* p = base + off + ci->tries_size * sizeof(TryItem);
            const uint8_t* end = v.base + v.size;
            uint32_t list;
            CHECK(read_uleb128(&p, end, &list));
            for (uint32_t h = 0; h < list; h++) {
                int32_t count;
                CHECK(read_sleb128(&p, end, &count));
                const uint32_t pairs = count < 0 ? -count : count;
                for (uint32_t i = 0; i < pairs; i++) {
                    uint32_t type, addr;
                    CHECK(read_uleb128(&p, end, &type) && read_uleb128(&p, end, &addr));
                    CHECK(addr < ci->insns_size && (addr >= c.program || addr == 0 || addr == tries[0].start_addr));
                }
                if (count <= 0) {
                    uint32_t addr;
                    CHECK(read_uleb128(&p, end, &addr));
                    CHECK(addr < ci->insns_size && (addr >= c.program || addr == 0 || addr == tries[0].start_addr));
                }
            }
        }
        CHECK(with_tries == 3);  // every fixture method in this list carries a try block
    }

    FILE* out = fopen(argv[2], "wb");
    CHECK(out && fwrite(patched.data(), 1, patched.size(), out) == patched.size());
    fclose(out);
    printf("test_dex_patcher: %d checks passed; wrote %s\n", checks, argv[2]);
    return 0;
}
