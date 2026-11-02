// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#pragma once

#include "dex_format.h"

// Read-only, bounds-checked view over an unverified DEX. Everything here runs *before* ART's own
// verifier has looked at the bytes, so every offset is checked: a malformed DEX must make us give
// up, not crash the app.
namespace ph::dex {

struct View {
    const uint8_t* base = nullptr;  // container base (same as the header for versions 035–040)
    size_t size = 0;
    const Header* hdr = nullptr;
    uint32_t version = 0;

    template <class T>
    const T* at(uint32_t off, size_t count = 1) const {
        if (off == 0 || off >= size || count > (size - off) / sizeof(T)) return nullptr;
        return reinterpret_cast<const T*>(base + off);
    }
    size_t available_from(uint32_t off) const { return off < size ? size - off : 0; }

    // MUTF-8 bytes of string `idx` (NUL-terminated inside the DEX), or nullptr.
    const char* string_data(uint32_t idx) const;
    const char* type_descriptor(uint32_t type_idx) const;
    // Binary searches: string_ids are sorted by UTF-16 code point and type_ids by descriptor_idx.
    // For an ASCII key, byte-wise MUTF-8 comparison orders identically, so no decoding is needed.
    int32_t find_string(const char* ascii) const;
    int32_t find_type(uint32_t string_idx) const;
    const ClassDef* find_class_def(uint32_t type_idx) const;  // linear; nullptr if defined elsewhere
    const MethodId* method_id(uint32_t idx) const;
    // "(Ljava/lang/String;Ljava/util/List;)V" against a proto_id.
    bool proto_matches(uint32_t proto_idx, const char* signature) const;
    // Index into method_ids of class->name(signature), or -1. The class only has to be *referenced*
    // by this DEX (an interface the patched method calls), not defined in it.
    int32_t find_method(const char* class_descriptor, const char* name, const char* signature) const;
    // First method_ids index whose proto matches `signature`, whose class is defined in this DEX and is
    // not `exclude_class`, and which that class lists as a static direct method. For R8-renamed
    // helpers that are only recognisable by shape.
    int32_t find_static_method_by_proto(const char* signature, const char* exclude_class) const;
    bool method_is_static(uint32_t method_idx) const;
};

bool open(const uint8_t* bytes, size_t size, View* out);

bool read_uleb128(const uint8_t** p, const uint8_t* end, uint32_t* out);
bool read_sleb128(const uint8_t** p, const uint8_t* end, int32_t* out);

struct EncodedMethod {
    uint32_t method_idx;
    uint32_t access_flags;
    uint32_t code_off;
};

// Visits direct then virtual methods. `fn` returns false to stop early. Returns false if the
// class_data_item is malformed.
template <class Fn>
bool for_each_method(const View& v, const ClassDef& cd, Fn fn) {
    if (cd.class_data_off == 0) return true;
    const uint8_t* p = v.at<uint8_t>(cd.class_data_off);
    if (!p) return false;
    const uint8_t* end = v.base + v.size;
    uint32_t counts[4];  // static fields, instance fields, direct methods, virtual methods
    for (auto& c : counts)
        if (!read_uleb128(&p, end, &c)) return false;
    for (uint64_t i = 0, n = uint64_t{counts[0]} + counts[1]; i < n; i++) {
        uint32_t skip;
        if (!read_uleb128(&p, end, &skip) || !read_uleb128(&p, end, &skip)) return false;
    }
    for (int kind = 2; kind < 4; kind++) {
        uint32_t idx = 0;
        for (uint32_t i = 0; i < counts[kind]; i++) {
            EncodedMethod m;
            uint32_t diff;
            if (!read_uleb128(&p, end, &diff) || !read_uleb128(&p, end, &m.access_flags) ||
                !read_uleb128(&p, end, &m.code_off))
                return false;
            idx += diff;
            m.method_idx = idx;
            if (!fn(m)) return true;
        }
    }
    return true;
}

}  // namespace ph::dex
