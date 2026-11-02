// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include "../hooks/targets.h"
#include "dex_parser.h"

// Pure bytes-to-bytes transformation; no memory protection, no logging. The caller (dex_intercept
// on device, the unit test on the host) owns the pages.
namespace ph::dex {

enum class PatchResult : uint8_t {
    OK,
    CLASS_ABSENT,   // normal: most apps do not ship most targets
    METHOD_ABSENT,  // class is here but this overload is not (library version difference)
    NO_CODE,        // abstract or native
    TOO_SMALL,      // insns_size < units needed (never for real methods; guarded anyway)
    NO_REGISTERS,   // registers/ins/outs too small for the template
    NO_CALLEE,      // INTERCEPTOR_PROCEED / RETURN_NEW_INSTANCE: the DEX lacks the method or type the template needs
    MALFORMED,      // DEX structure out of bounds; ART's verifier will reject it too
};
const char* patch_result_name(PatchResult r);

// A template instruction that cannot throw: a legal place to park a try range.
struct SafeSlot {
    uint16_t addr;
    uint16_t len;
};

// Every template leaves the method's tries[]/handlers in place but moves each try range onto
// something that never throws — the template's own non-throwing instructions (`safe`, ascending)
// first, then one nop each on the tail — and points every handler address that fell inside the
// template at the first safe slot. Call before the program is written (it reads only insns_size and
// fails before writing anything), so a failure leaves the method untouched. Fails with TOO_SMALL when
// the tries outnumber safe slots plus tail nops, MALFORMED on bad encoding.
PatchResult relocate_tries(CodeItem* code, size_t bytes_available, size_t program_units, const SafeSlot* safe,
                           size_t safe_count);

// Writes the replacement over the first code units and nop-fills the rest of insns[]. insns_size,
// tries and handlers are untouched, so the code item stays structurally identical.
PatchResult patch_code_item(CodeItem* code, size_t bytes_available, ReplacementKind kind);

// `return new T()` (int_arg = false) or `return new T(0)` (int_arg = true); type_idx and ctor_method
// index the DEX being patched.
PatchResult patch_code_item_new_instance(CodeItem* code, size_t bytes_available, uint32_t type_idx,
                                         uint32_t ctor_method, bool int_arg);

// Chromium: `addTestRoot(args[0][0]); return inner(args...)`. add_root_method takes ([B)V; inner_method
// has the patched method's own signature; both are static and index this DEX. Scratch is v0 when
// the method has a free local; otherwise, if `last_param_droppable`, the last parameter register is
// used and passed to the inner call as null (the 5-argument form's sctList).
PatchResult patch_code_item_chromium(CodeItem* code, size_t bytes_available, uint32_t add_root_method,
                                     uint32_t inner_method, bool last_param_droppable);

// `return chain.proceed(chain.request())` for an intercept(Chain) body. request_method and
// proceed_method are method_ids indices in the same DEX (dex::View::find_method).
PatchResult patch_code_item_interceptor(CodeItem* code, size_t bytes_available, uint32_t request_method,
                                        uint32_t proceed_method);

// True when the target's class is defined in this DEX (cheap: two binary searches plus a scan of
// class_defs). Used for presence reporting even when the tier/surface blocks the patch.
bool class_present(const View& view, const JavaTarget& target);

PatchResult patch_target(const View& view, const JavaTarget& target);


// Length in 16-bit units of the instruction at units[0] (`remaining` units left), payloads included.
size_t insn_units(const uint16_t* units, size_t remaining);

}  // namespace ph::dex
