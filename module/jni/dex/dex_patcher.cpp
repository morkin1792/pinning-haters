// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "dex_patcher.h"

#include <string.h>

namespace ph::dex {

namespace {

struct Template {
    uint16_t units[2];
    uint8_t count;
    uint8_t registers_needed;
};

Template template_for(ReplacementKind kind) {
    switch (kind) {
        case ReplacementKind::RETURN_VOID: return {{RETURN_VOID_UNIT, 0}, 1, 0};
        case ReplacementKind::RETURN_TRUE: return {{CONST4_V0_1_UNIT, RETURN_V0_UNIT}, 2, 1};
        case ReplacementKind::RETURN_FALSE: return {{CONST4_V0_0_UNIT, RETURN_V0_UNIT}, 2, 1};
        case ReplacementKind::INTERCEPTOR_PROCEED:
        case ReplacementKind::RETURN_NEW_INSTANCE:
        case ReplacementKind::CHROMIUM_TRUST_LEAF: break;  // handled by their own patch_code_item_* functions
    }
    return {{RETURN_VOID_UNIT, 0}, 1, 0};
}

}  // namespace

const char* patch_result_name(PatchResult r) {
    switch (r) {
        case PatchResult::OK: return "ok";
        case PatchResult::CLASS_ABSENT: return "class_absent";
        case PatchResult::METHOD_ABSENT: return "method_absent";
        case PatchResult::NO_CODE: return "no_code";
        case PatchResult::TOO_SMALL: return "too_small";
        case PatchResult::NO_REGISTERS: return "no_registers";
        case PatchResult::NO_CALLEE: return "no_callee";
        case PatchResult::MALFORMED: return "malformed";
    }
    return "?";
}


namespace {

// Rewrites a ULEB128 in place with the same byte length (non-canonical padding is legal).
void rewrite_uleb128(uint8_t* at, size_t len, uint32_t value) {
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if (i + 1 < len) byte |= 0x80;
        at[i] = byte;
    }
}

}  // namespace

// Why this exists: the method verifier walks tries[] and the handler list before anything else and
// rejects the class outright when a try start/end or a handler address is not an instruction
// boundary ("exception handler starts at bad address"). Our templates are shorter than the method
// they replace, so any such address inside the template's span now points mid-instruction, and
// any that lands on a boundary would make the verifier simulate the rest of the template from
// there with whatever register state the try block had. Moving each try range onto the nop tail
// makes the handlers unreachable (nops never throw) and keeps every address on a nop. Nothing
// changes size: tries_size, the handler list layout and insns_size are untouched.
PatchResult relocate_tries(CodeItem* code, size_t bytes_available, size_t program_units, const SafeSlot* safe,
                           size_t safe_count) {
    const size_t units = code->insns_size;
    const uint16_t tries_size = code->tries_size;
    if (tries_size == 0) return PatchResult::OK;
    const size_t tail = units > program_units ? units - program_units : 0;
    if (safe_count == 0 || size_t{tries_size} > safe_count + tail) return PatchResult::TOO_SMALL;

    auto* base = reinterpret_cast<uint8_t*>(code);
    const uint8_t* end = base + bytes_available;
    size_t off = sizeof(CodeItem) + units * sizeof(uint16_t);
    if (units & 1) off += 2;  // tries[] is 4-byte aligned
    if (off + size_t{tries_size} * sizeof(TryItem) > bytes_available) return PatchResult::MALFORMED;
    auto* tries = reinterpret_cast<TryItem*>(base + off);
    uint8_t* handlers = base + off + size_t{tries_size} * sizeof(TryItem);

    // Walk the encoded_catch_handler_list first so a malformed one leaves the code item untouched.
    const uint8_t* p = handlers;
    uint32_t list_size;
    if (!read_uleb128(&p, end, &list_size)) return PatchResult::MALFORMED;
    struct Fix {
        uint8_t* at;
        size_t len;
    };
    Fix fixes[64];
    size_t fix_count = 0;
    for (uint32_t h = 0; h < list_size; h++) {
        int32_t count;
        if (!read_sleb128(&p, end, &count)) return PatchResult::MALFORMED;
        const uint32_t pairs = count < 0 ? static_cast<uint32_t>(-count) : static_cast<uint32_t>(count);
        for (uint32_t i = 0; i <= pairs; i++) {
            if (i == pairs && count > 0) break;  // no catch-all
            if (i < pairs) {
                uint32_t type_idx;
                if (!read_uleb128(&p, end, &type_idx)) return PatchResult::MALFORMED;
            }
            uint8_t* addr_at = const_cast<uint8_t*>(p);
            uint32_t addr;
            if (!read_uleb128(&p, end, &addr)) return PatchResult::MALFORMED;
            if (addr < program_units) {
                if (fix_count == sizeof(fixes) / sizeof(fixes[0])) return PatchResult::MALFORMED;
                fixes[fix_count++] = {addr_at, static_cast<size_t>(p - addr_at)};
            }
        }
    }
    for (size_t i = 0; i < fix_count; i++) rewrite_uleb128(fixes[i].at, fixes[i].len, safe[0].addr);
    // Ascending start addresses: template slots come before the tail.
    for (uint16_t i = 0; i < tries_size; i++) {
        if (i < safe_count) {
            tries[i].start_addr = safe[i].addr;
            tries[i].insn_count = safe[i].len;
        } else {
            tries[i].start_addr = static_cast<uint32_t>(program_units + (i - safe_count));
            tries[i].insn_count = 1;
        }
    }
    return PatchResult::OK;
}

PatchResult patch_code_item(CodeItem* code, size_t bytes_available, ReplacementKind kind) {
    if (bytes_available < sizeof(CodeItem)) return PatchResult::MALFORMED;
    const size_t units = code->insns_size;
    if (units > (bytes_available - sizeof(CodeItem)) / sizeof(uint16_t)) return PatchResult::MALFORMED;
    const Template t = template_for(kind);
    if (units < t.count) return PatchResult::TOO_SMALL;
    if (code->registers_size < t.registers_needed) return PatchResult::NO_REGISTERS;

    // Neither const/4 nor any return instruction can throw.
    const SafeSlot safe[2] = {{0, 1}, {1, 1}};
    // tries[] and the handler list first: relocate_tries fails before it writes anything, and the
    // program must not land over a method whose try ranges still point into the old code.
    if (const PatchResult r = relocate_tries(code, bytes_available, t.count, safe, t.count); r != PatchResult::OK) return r;
    uint16_t* insns = insns_of(code);
    memcpy(insns, t.units, t.count * sizeof(uint16_t));
    // The method verifier sweeps every code unit up to insns_size, not just the reachable ones. A
    // 2-byte return landing on the first half of what used to be a 4-byte instruction would leave
    // its second half decoding as garbage, so everything after the replacement becomes nop. That
    // also keeps every try/catch address on an instruction boundary without touching tries[].
    for (size_t i = t.count; i < units; i++) insns[i] = OP_NOP;
    return PatchResult::OK;
}

bool class_present(const View& v, const JavaTarget& target) {
    const int32_t s = v.find_string(target.class_descriptor);
    if (s < 0) return false;
    const int32_t t = v.find_type(static_cast<uint32_t>(s));
    return t >= 0 && v.find_class_def(static_cast<uint32_t>(t)) != nullptr;
}

PatchResult patch_code_item_interceptor(CodeItem* code, size_t bytes_available, uint32_t request_method,
                                        uint32_t proceed_method) {
    if (bytes_available < sizeof(CodeItem)) return PatchResult::MALFORMED;
    const size_t units = code->insns_size;
    if (units > (bytes_available - sizeof(CodeItem)) / sizeof(uint16_t)) return PatchResult::MALFORMED;
    if (units < INTERCEPTOR_PROCEED_UNITS) return PatchResult::TOO_SMALL;
    // v0/v1 are scratch, `this` and `chain` are the two ins (p0, p1), and the verifier insists that
    // outs_size covers the widest invoke (proceed takes 2 registers). Any real intercept() already
    // calls chain.proceed(request), so outs_size >= 2 holds whenever the method is what we think.
    if (code->registers_size < 2 || code->ins_size < 2 || code->outs_size < 2) return PatchResult::NO_REGISTERS;
    if (request_method > 0xffff || proceed_method > 0xffff) return PatchResult::NO_CALLEE;
    const uint16_t chain = static_cast<uint16_t>(code->registers_size - code->ins_size + 1);  // p1

    // /range forms throughout: register numbers above v15 do not fit the 4-bit 35c encoding.
    const uint16_t program[INTERCEPTOR_PROCEED_UNITS] = {
        unit_11x(OPCODE_MOVE_OBJECT_FROM16, 0), chain,                                          // move-object/from16 v0, p1
        unit_11x(OPCODE_INVOKE_INTERFACE_RANGE, 1), static_cast<uint16_t>(request_method), 0,  // invoke-interface/range {v0}, request()
        unit_11x(OPCODE_MOVE_RESULT_OBJECT, 1),                                                 // move-result-object v1
        unit_11x(OPCODE_INVOKE_INTERFACE_RANGE, 2), static_cast<uint16_t>(proceed_method), 0,  // invoke-interface/range {v0..v1}, proceed(Request)
        unit_11x(OPCODE_MOVE_RESULT_OBJECT, 0),                                                 // move-result-object v0
        RETURN_OBJECT_V0_UNIT,                                                                  // return-object v0
    };
    // move-object/from16, the two move-result-object and return-object cannot throw.
    const SafeSlot safe[4] = {{0, 2}, {5, 1}, {9, 1}, {10, 1}};
    // tries[] and the handler list first: relocate_tries fails before it writes anything, and the
    // program must not land over a method whose try ranges still point into the old code.
    if (const PatchResult r = relocate_tries(code, bytes_available, INTERCEPTOR_PROCEED_UNITS, safe, 4); r != PatchResult::OK) return r;
    uint16_t* insns = insns_of(code);
    memcpy(insns, program, sizeof(program));
    for (size_t i = INTERCEPTOR_PROCEED_UNITS; i < units; i++) insns[i] = OP_NOP;
    return PatchResult::OK;
}

PatchResult patch_code_item_new_instance(CodeItem* code, size_t bytes_available, uint32_t type_idx,
                                         uint32_t ctor_method, bool int_arg) {
    if (bytes_available < sizeof(CodeItem)) return PatchResult::MALFORMED;
    const size_t units = code->insns_size;
    if (units > (bytes_available - sizeof(CodeItem)) / sizeof(uint16_t)) return PatchResult::MALFORMED;
    const uint16_t args = int_arg ? 2 : 1;  // `this` plus the int
    const size_t needed = int_arg ? NEW_INSTANCE_MAX_UNITS : NEW_INSTANCE_MAX_UNITS - 1;
    if (units < needed) return PatchResult::TOO_SMALL;
    if (code->registers_size < args || code->outs_size < args) return PatchResult::NO_REGISTERS;
    if (type_idx > 0xffff || ctor_method > 0xffff) return PatchResult::NO_CALLEE;

    uint16_t program[NEW_INSTANCE_MAX_UNITS];
    size_t n = 0;
    program[n++] = unit_11x(OPCODE_NEW_INSTANCE, 0);  // new-instance v0, type
    program[n++] = static_cast<uint16_t>(type_idx);
    if (int_arg) program[n++] = unit_11n(OPCODE_CONST_4, 1, 0);  // const/4 v1, #0
    program[n++] = unit_11x(OPCODE_INVOKE_DIRECT_RANGE, static_cast<uint8_t>(args));  // invoke-direct/range {v0..}, <init>
    program[n++] = static_cast<uint16_t>(ctor_method);
    program[n++] = 0;  // CCCC = v0
    program[n++] = RETURN_OBJECT_V0_UNIT;

    // const/4 (int form only) and return-object cannot throw.
    SafeSlot safe[2];
    size_t safe_count = 0;
    if (int_arg) safe[safe_count++] = {2, 1};
    safe[safe_count++] = {static_cast<uint16_t>(n - 1), 1};
    // tries[] and the handler list first: relocate_tries fails before it writes anything, and the
    // program must not land over a method whose try ranges still point into the old code.
    if (const PatchResult r = relocate_tries(code, bytes_available, n, safe, safe_count); r != PatchResult::OK) return r;
    uint16_t* insns = insns_of(code);
    memcpy(insns, program, n * sizeof(uint16_t));
    for (size_t i = n; i < units; i++) insns[i] = OP_NOP;
    return PatchResult::OK;
}

PatchResult patch_code_item_chromium(CodeItem* code, size_t bytes_available, uint32_t add_root_method,
                                     uint32_t inner_method, bool last_param_droppable) {
    if (bytes_available < sizeof(CodeItem)) return PatchResult::MALFORMED;
    const size_t units = code->insns_size;
    if (units > (bytes_available - sizeof(CodeItem)) / sizeof(uint16_t)) return PatchResult::MALFORMED;
    const uint16_t ins = code->ins_size;
    // The inner call re-passes every parameter, and the original method's own call to the inner
    // verifier already forced outs_size >= ins.
    if (ins < 1 || ins > 255 || code->registers_size < ins || code->outs_size < ins) return PatchResult::NO_REGISTERS;
    if (add_root_method > 0xffff || inner_method > 0xffff) return PatchResult::NO_CALLEE;
    const uint16_t p0 = static_cast<uint16_t>(code->registers_size - ins);
    if (p0 > 255) return PatchResult::NO_REGISTERS;  // aget-object takes 8-bit registers

    // R8 gives this method no locals at all (registers == ins), so the scratch register is the last
    // parameter, which the 5-argument form may legitimately pass as null (sctList).
    const bool free_local = code->registers_size > ins;
    if (!free_local && !last_param_droppable) return PatchResult::NO_REGISTERS;
    const uint16_t scratch = free_local ? 0 : static_cast<uint16_t>(code->registers_size - 1);
    if (scratch > 15) return PatchResult::NO_REGISTERS;  // const/4 takes 4-bit registers
    const uint16_t result = free_local ? 0 : p0;
    const size_t n = free_local ? 11 : 12;
    if (units < n) return PatchResult::TOO_SMALL;

    uint16_t program[CHROMIUM_TRUST_LEAF_MAX_UNITS];
    size_t k = 0;
    program[k++] = unit_11n(OPCODE_CONST_4, static_cast<uint8_t>(scratch), 0);        // const/4 s, #0
    program[k++] = unit_11x(OPCODE_AGET_OBJECT, static_cast<uint8_t>(scratch));      // aget-object s, p0, s
    program[k++] = static_cast<uint16_t>(p0 | (scratch << 8));
    program[k++] = unit_11x(OPCODE_INVOKE_STATIC_RANGE, 1);                          // addTestRootCertificate(s)
    program[k++] = static_cast<uint16_t>(add_root_method);
    program[k++] = scratch;
    if (!free_local) program[k++] = unit_11n(OPCODE_CONST_4, static_cast<uint8_t>(scratch), 0);  // sctList = null again
    program[k++] = unit_11x(OPCODE_INVOKE_STATIC_RANGE, static_cast<uint8_t>(ins));  // inner(p0 .. p_last)
    program[k++] = static_cast<uint16_t>(inner_method);
    program[k++] = p0;
    program[k++] = unit_11x(OPCODE_MOVE_RESULT_OBJECT, static_cast<uint8_t>(result));  // move-result-object
    program[k++] = unit_11x(OPCODE_RETURN_OBJECT, static_cast<uint8_t>(result));       // return-object

    // const/4 (one or two of them), move-result-object and return-object cannot throw.
    SafeSlot safe[4];
    size_t safe_count = 0;
    safe[safe_count++] = {0, 1};
    if (!free_local) safe[safe_count++] = {6, 1};
    safe[safe_count++] = {static_cast<uint16_t>(k - 2), 1};
    safe[safe_count++] = {static_cast<uint16_t>(k - 1), 1};
    // tries[] and the handler list first: relocate_tries fails before it writes anything, and the
    // program must not land over a method whose try ranges still point into the old code.
    if (const PatchResult r = relocate_tries(code, bytes_available, k, safe, safe_count); r != PatchResult::OK) return r;
    uint16_t* insns = insns_of(code);
    memcpy(insns, program, k * sizeof(uint16_t));
    for (size_t i = k; i < units; i++) insns[i] = OP_NOP;
    return PatchResult::OK;
}

// Dalvik instruction lengths by opcode, in 16-bit units. Same table the DexFileVerifier walks.
size_t insn_units(const uint16_t* units, size_t remaining) {
    static const uint8_t kLen[256] = {
        1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,  // 00-0f
        1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,  // 10-1f
        2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,  // 20-2f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,  // 30-3f
        1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 40-4f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 50-5f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,  // 60-6f
        3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,  // 70-7f
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 80-8f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 90-9f
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // a0-af
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // b0-bf
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // c0-cf
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // d0-df
        2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // e0-ef
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,  // f0-ff
    };
    const uint16_t u = units[0];
    const uint8_t op = u & 0xff;
    if (op == 0 && (u >> 8) >= 1 && (u >> 8) <= 3) {  // packed-switch / sparse-switch / fill-array-data payload
        if (remaining < 2) return remaining;
        const size_t size = units[1];
        size_t n;
        if ((u >> 8) == 1) n = size * 2 + 4;
        else if ((u >> 8) == 2) n = size * 4 + 2;
        else {
            if (remaining < 4) return remaining;
            const size_t count = units[2] | (static_cast<size_t>(units[3]) << 16);
            n = (count * size + 1) / 2 + 4;
        }
        return n < remaining ? n : remaining;
    }
    const size_t n = kLen[op];
    return n < remaining ? n : remaining;
}

namespace {

// One class: find the target method by name and signature, apply the replacement.
PatchResult patch_in_class(const View& v, const ClassDef& cd, const JavaTarget& target, int32_t name_string) {
    PatchResult result = PatchResult::METHOD_ABSENT;
    const bool well_formed = for_each_method(v, cd, [&](const EncodedMethod& m) {
        const MethodId* id = v.method_id(m.method_idx);
        if (!id) {
            result = PatchResult::MALFORMED;
            return false;
        }
        if (id->name_idx != static_cast<uint32_t>(name_string) ||
            !v.proto_matches(id->proto_idx, target.method_signature))
            return true;
        if (m.code_off == 0 || (m.access_flags & (ACC_NATIVE | ACC_ABSTRACT))) {
            result = PatchResult::NO_CODE;
            return false;
        }
        auto* code = const_cast<CodeItem*>(v.at<CodeItem>(m.code_off));
        if (!code) {
            result = PatchResult::MALFORMED;
            return false;
        }
        if (target.replacement == ReplacementKind::CHROMIUM_TRUST_LEAF) {
            const int32_t add_root = v.find_method(target.class_descriptor, "addTestRootCertificate", "([B)V");
            const int32_t inner = v.find_static_method_by_proto(target.method_signature, target.class_descriptor);
            if (add_root < 0 || inner < 0) {
                result = PatchResult::NO_CALLEE;
                return false;
            }
            // Only the 5-argument form ends in a nullable blob (sctList) that may serve as scratch.
            const bool droppable = strstr(target.method_signature, "[B[B)") != nullptr;
            result = patch_code_item_chromium(code, v.available_from(m.code_off), static_cast<uint32_t>(add_root),
                                              static_cast<uint32_t>(inner), droppable);
            return false;
        }
        if (target.replacement == ReplacementKind::RETURN_NEW_INSTANCE) {
            const bool int_arg = target.aux_ctor && strcmp(target.aux_ctor, "(I)V") == 0;
            if (!target.aux_type || !target.aux_ctor || (!int_arg && strcmp(target.aux_ctor, "()V") != 0)) {
                result = PatchResult::NO_CALLEE;
                return false;
            }
            const int32_t type_string = v.find_string(target.aux_type);
            const int32_t type_idx = type_string < 0 ? -1 : v.find_type(static_cast<uint32_t>(type_string));
            const int32_t ctor = v.find_method(target.aux_type, "<init>", target.aux_ctor);
            if (type_idx < 0 || ctor < 0) {
                result = PatchResult::NO_CALLEE;
                return false;
            }
            result = patch_code_item_new_instance(code, v.available_from(m.code_off), static_cast<uint32_t>(type_idx),
                                                  static_cast<uint32_t>(ctor), int_arg);
            return false;
        }
        if (target.replacement == ReplacementKind::INTERCEPTOR_PROCEED) {
            const int32_t request = v.find_method("Lokhttp3/Interceptor$Chain;", "request", "()Lokhttp3/Request;");
            const int32_t proceed =
                v.find_method("Lokhttp3/Interceptor$Chain;", "proceed", "(Lokhttp3/Request;)Lokhttp3/Response;");
            if (request < 0 || proceed < 0) {
                result = PatchResult::NO_CALLEE;
                return false;
            }
            result = patch_code_item_interceptor(code, v.available_from(m.code_off), static_cast<uint32_t>(request),
                                                 static_cast<uint32_t>(proceed));
            return false;
        }
        result = patch_code_item(code, v.available_from(m.code_off), target.replacement);
        return false;
    });
    return well_formed ? result : PatchResult::MALFORMED;
}

}  // namespace

PatchResult patch_target(const View& v, const JavaTarget& target) {
    const int32_t class_string = v.find_string(target.class_descriptor);
    if (class_string < 0) return PatchResult::CLASS_ABSENT;
    const int32_t type_idx = v.find_type(static_cast<uint32_t>(class_string));
    if (type_idx < 0) return PatchResult::CLASS_ABSENT;
    const ClassDef* cd = v.find_class_def(static_cast<uint32_t>(type_idx));
    if (!cd) return PatchResult::CLASS_ABSENT;  // referenced here, defined in another DEX
    const int32_t name_string = v.find_string(target.method_name);
    if (name_string < 0) return PatchResult::METHOD_ABSENT;
    return patch_in_class(v, *cd, target, name_string);
}

}  // namespace ph::dex
