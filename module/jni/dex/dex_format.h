// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include <stddef.h>
#include <stdint.h>

// Just enough of the DEX format (https://source.android.com/docs/core/runtime/dex-format) to find
// a method's code item and rewrite its instructions. Standard DEX only; CompactDex lives in vdex
// files, which the companion deletes.
namespace ph::dex {

constexpr size_t MAGIC_SIZE = 8;
// magic + checksum: the bytes the header checksum does not cover, and therefore the distance
// between the buffer DexFileVerifier hands to adler32 and the start of the DEX.
constexpr size_t NON_SUM = 12;
constexpr uint32_t NO_INDEX = 0xffffffff;
constexpr uint32_t HEADER_SIZE_V35 = 0x70;
constexpr uint32_t HEADER_SIZE_V41 = 0x78;

struct Header {
    uint8_t magic[8];  // "dex\n039\0"
    uint32_t checksum;
    uint8_t signature[20];
    uint32_t file_size;
    uint32_t header_size;
    uint32_t endian_tag;
    uint32_t link_size;
    uint32_t link_off;
    uint32_t map_off;
    uint32_t string_ids_size;
    uint32_t string_ids_off;
    uint32_t type_ids_size;
    uint32_t type_ids_off;
    uint32_t proto_ids_size;
    uint32_t proto_ids_off;
    uint32_t field_ids_size;
    uint32_t field_ids_off;
    uint32_t method_ids_size;
    uint32_t method_ids_off;
    uint32_t class_defs_size;
    uint32_t class_defs_off;
    uint32_t data_size;
    uint32_t data_off;
};
static_assert(sizeof(Header) == HEADER_SIZE_V35);

// DEX 041 (Android 15 "container" format): offsets are relative to the container, not this header.
struct HeaderV41 : Header {
    uint32_t container_size;
    uint32_t header_offset;
};
static_assert(sizeof(HeaderV41) == HEADER_SIZE_V41);

struct StringId { uint32_t string_data_off; };
struct TypeId { uint32_t descriptor_idx; };
struct ProtoId { uint32_t shorty_idx; uint32_t return_type_idx; uint32_t parameters_off; };
struct MethodId { uint16_t class_idx; uint16_t proto_idx; uint32_t name_idx; };
struct ClassDef {
    uint32_t class_idx;
    uint32_t access_flags;
    uint32_t superclass_idx;
    uint32_t interfaces_off;
    uint32_t source_file_idx;
    uint32_t annotations_off;
    uint32_t class_data_off;
    uint32_t static_values_off;
};
struct TypeList { uint32_t size; /* uint16_t type_idx[size] follows */ };
inline const uint16_t* type_list_items(const TypeList* l) { return reinterpret_cast<const uint16_t*>(l + 1); }

struct TryItem {
    uint32_t start_addr;   // in code units
    uint16_t insn_count;
    uint16_t handler_off;  // into the encoded_catch_handler_list that follows tries[]
};
static_assert(sizeof(TryItem) == 8);

struct CodeItem {
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    uint16_t tries_size;
    uint32_t debug_info_off;
    uint32_t insns_size;  // in 16-bit code units; never changed by us
    /* uint16_t insns[insns_size] follows, then (4-byte aligned) TryItem tries[tries_size], then the
       encoded_catch_handler_list */
};
static_assert(sizeof(CodeItem) == 16);
inline uint16_t* insns_of(CodeItem* c) { return reinterpret_cast<uint16_t*>(c + 1); }
inline const uint16_t* insns_of(const CodeItem* c) { return reinterpret_cast<const uint16_t*>(c + 1); }

constexpr uint32_t ACC_STATIC = 0x0008;
constexpr uint32_t ACC_NATIVE = 0x0100;
constexpr uint32_t ACC_ABSTRACT = 0x0400;

// Instruction code units, little-endian: low byte = opcode, high byte = operands.
constexpr uint16_t OP_NOP = 0x0000;  // high byte must be 0: 0x01/0x02/0x03 are payload pseudo-ops
constexpr uint8_t OPCODE_MOVE_OBJECT_FROM16 = 0x08;     // 22x  AA|op BBBB
constexpr uint8_t OPCODE_MOVE_RESULT_OBJECT = 0x0c;     // 11x  AA|op
constexpr uint8_t OPCODE_RETURN_VOID = 0x0e;            // 10x
constexpr uint8_t OPCODE_RETURN = 0x0f;                 // 11x  AA|op
constexpr uint8_t OPCODE_RETURN_OBJECT = 0x11;          // 11x
constexpr uint8_t OPCODE_CONST_4 = 0x12;                // 11n  B|A|op  (A = register, B = signed nibble)
constexpr uint8_t OPCODE_NEW_INSTANCE = 0x22;           // 21c  AA|op BBBB  (type@BBBB)
constexpr uint8_t OPCODE_AGET_OBJECT = 0x46;            // 23x  AA|op CC|BB  (vAA = vBB[vCC])
constexpr uint8_t OPCODE_INVOKE_VIRTUAL = 0x6e;         // 35c  first of the invoke-kind block 0x6e..0x72
constexpr uint8_t OPCODE_INVOKE_INTERFACE = 0x72;       // 35c  last of it
constexpr uint8_t OPCODE_INVOKE_VIRTUAL_RANGE = 0x74;   // 3rc  first of the invoke-kind/range block 0x74..0x78
constexpr uint8_t OPCODE_INVOKE_DIRECT_RANGE = 0x76;    // 3rc  AA|op BBBB CCCC
constexpr uint8_t OPCODE_INVOKE_STATIC_RANGE = 0x77;    // 3rc  AA|op BBBB CCCC
constexpr uint8_t OPCODE_INVOKE_INTERFACE_RANGE = 0x78; // 3rc  AA|op BBBB CCCC  ({vCCCC .. vCCCC+AA-1}, meth@BBBB)

constexpr uint16_t unit_10x(uint8_t op) { return op; }
constexpr uint16_t unit_11x(uint8_t op, uint8_t reg) { return static_cast<uint16_t>(op | (reg << 8)); }
constexpr uint16_t unit_11n(uint8_t op, uint8_t reg, uint8_t value) {
    return static_cast<uint16_t>(op | ((reg & 0xf) << 8) | ((value & 0xf) << 12));
}

constexpr uint16_t RETURN_VOID_UNIT = unit_10x(OPCODE_RETURN_VOID);           // 0E 00
constexpr uint16_t CONST4_V0_1_UNIT = unit_11n(OPCODE_CONST_4, 0, 1);          // 12 10
constexpr uint16_t CONST4_V0_0_UNIT = unit_11n(OPCODE_CONST_4, 0, 0);          // 12 00
constexpr uint16_t RETURN_V0_UNIT = unit_11x(OPCODE_RETURN, 0);                // 0F 00
constexpr uint16_t RETURN_OBJECT_V0_UNIT = unit_11x(OPCODE_RETURN_OBJECT, 0);  // 11 00

// OkHttp interceptor pass-through, `return chain.proceed(chain.request())`, 11 code units. The two
// method indices and the register holding `chain` (p1) are filled in at patch time.
constexpr size_t INTERCEPTOR_PROCEED_UNITS = 11;
// `return new T()` / `return new T(0)`: 6 or 7 code units; type and constructor ids filled in at patch time.
constexpr size_t NEW_INSTANCE_MAX_UNITS = 7;
// Chromium verifier: add chain[0] as a test root, then call the inner static verifier. 11 code units
// with a free local, 12 when the last parameter register doubles as scratch.
constexpr size_t CHROMIUM_TRUST_LEAF_MAX_UNITS = 12;

}  // namespace ph::dex
