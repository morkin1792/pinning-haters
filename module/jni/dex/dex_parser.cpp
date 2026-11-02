// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "dex_parser.h"

#include <stdio.h>
#include <string.h>

namespace ph::dex {

bool read_uleb128(const uint8_t** p, const uint8_t* end, uint32_t* out) {
    uint32_t result = 0;
    for (int shift = 0; shift < 35; shift += 7) {
        if (*p >= end) return false;
        uint8_t byte = *(*p)++;
        result |= uint32_t{byte & 0x7fu} << shift;
        if (!(byte & 0x80)) {
            *out = result;
            return true;
        }
    }
    return false;  // more than 5 bytes: not a valid uleb128 for a 32-bit value
}

bool read_sleb128(const uint8_t** p, const uint8_t* end, int32_t* out) {
    int32_t result = 0;
    int shift = 0;
    uint8_t byte;
    do {
        if (*p >= end || shift >= 35) return false;
        byte = *(*p)++;
        result |= static_cast<int32_t>(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 32 && (byte & 0x40)) result |= -(1 << shift);
    *out = result;
    return true;
}

bool open(const uint8_t* bytes, size_t size, View* out) {
    if (!bytes || size < HEADER_SIZE_V35) return false;
    const auto* hdr = reinterpret_cast<const Header*>(bytes);
    if (memcmp(hdr->magic, "dex\n", 4) != 0 || hdr->magic[7] != 0) return false;
    uint32_t version = 0;
    for (int i = 4; i < 7; i++) {
        if (hdr->magic[i] < '0' || hdr->magic[i] > '9') return false;
        version = version * 10 + (hdr->magic[i] - '0');
    }
    if (hdr->endian_tag != 0x12345678) return false;  // we never see big-endian DEX on Android
    View v;
    v.hdr = hdr;
    v.version = version;
    v.base = bytes;
    v.size = size;
    if (version >= 41 && hdr->header_size == HEADER_SIZE_V41 && size >= HEADER_SIZE_V41) {
        // Container format: every *_off is relative to the container that holds this header.
        const auto* h41 = reinterpret_cast<const HeaderV41*>(bytes);
        if (h41->header_offset > reinterpret_cast<uintptr_t>(bytes)) return false;
        if (h41->container_size < h41->header_offset || h41->container_size - h41->header_offset < size)
            return false;
        v.base = bytes - h41->header_offset;
        v.size = h41->container_size;
    } else if (hdr->header_size != HEADER_SIZE_V35) {
        return false;
    }
    *out = v;
    return true;
}

const char* View::string_data(uint32_t idx) const {
    if (idx >= hdr->string_ids_size) return nullptr;
    const auto* ids = at<StringId>(hdr->string_ids_off, hdr->string_ids_size);
    if (!ids) return nullptr;
    const uint8_t* p = at<uint8_t>(ids[idx].string_data_off);
    if (!p) return nullptr;
    const uint8_t* end = base + size;
    uint32_t utf16_len;
    if (!read_uleb128(&p, end, &utf16_len)) return nullptr;
    if (!memchr(p, 0, static_cast<size_t>(end - p))) return nullptr;  // unterminated: refuse to strcmp
    return reinterpret_cast<const char*>(p);
}

const char* View::type_descriptor(uint32_t type_idx) const {
    if (type_idx >= hdr->type_ids_size) return nullptr;
    const auto* ids = at<TypeId>(hdr->type_ids_off, hdr->type_ids_size);
    return ids ? string_data(ids[type_idx].descriptor_idx) : nullptr;
}

int32_t View::find_string(const char* key) const {
    uint32_t lo = 0, hi = hdr->string_ids_size;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const char* s = string_data(mid);
        if (!s) return -1;
        int c = strcmp(s, key);
        if (c == 0) return static_cast<int32_t>(mid);
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return -1;
}

int32_t View::find_type(uint32_t string_idx) const {
    const auto* ids = at<TypeId>(hdr->type_ids_off, hdr->type_ids_size);
    if (!ids) return -1;
    uint32_t lo = 0, hi = hdr->type_ids_size;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (ids[mid].descriptor_idx == string_idx) return static_cast<int32_t>(mid);
        if (ids[mid].descriptor_idx < string_idx) lo = mid + 1; else hi = mid;
    }
    return -1;
}

const ClassDef* View::find_class_def(uint32_t type_idx) const {
    const auto* defs = at<ClassDef>(hdr->class_defs_off, hdr->class_defs_size);
    if (!defs) return nullptr;
    for (uint32_t i = 0; i < hdr->class_defs_size; i++)
        if (defs[i].class_idx == type_idx) return &defs[i];
    return nullptr;
}

const MethodId* View::method_id(uint32_t idx) const {
    if (idx >= hdr->method_ids_size) return nullptr;
    const auto* ids = at<MethodId>(hdr->method_ids_off, hdr->method_ids_size);
    return ids ? &ids[idx] : nullptr;
}

int32_t View::find_method(const char* class_descriptor, const char* name, const char* signature) const {
    const int32_t class_string = find_string(class_descriptor);
    const int32_t name_string = find_string(name);
    if (class_string < 0 || name_string < 0) return -1;
    const int32_t type_idx = find_type(static_cast<uint32_t>(class_string));
    if (type_idx < 0) return -1;
    const auto* ids = at<MethodId>(hdr->method_ids_off, hdr->method_ids_size);
    if (!ids) return -1;
    // method_ids are sorted by (class_idx, name_idx, proto_idx); a linear scan is still only a few
    // hundred thousand compares at the very worst and runs once per target per DEX.
    for (uint32_t i = 0; i < hdr->method_ids_size; i++) {
        if (ids[i].class_idx != type_idx || ids[i].name_idx != static_cast<uint32_t>(name_string)) continue;
        if (proto_matches(ids[i].proto_idx, signature)) return static_cast<int32_t>(i);
    }
    return -1;
}

bool View::method_is_static(uint32_t method_idx) const {
    const MethodId* id = method_id(method_idx);
    if (!id) return false;
    const ClassDef* cd = find_class_def(id->class_idx);
    if (!cd) return false;
    bool found = false;
    for_each_method(*this, *cd, [&](const EncodedMethod& m) {
        if (m.method_idx != method_idx) return true;
        found = (m.access_flags & ACC_STATIC) != 0;
        return false;
    });
    return found;
}

int32_t View::find_static_method_by_proto(const char* signature, const char* exclude_class) const {
    const auto* ids = at<MethodId>(hdr->method_ids_off, hdr->method_ids_size);
    if (!ids) return -1;
    const int32_t exclude_string = exclude_class ? find_string(exclude_class) : -1;
    const int32_t exclude_type = exclude_string < 0 ? -1 : find_type(static_cast<uint32_t>(exclude_string));
    for (uint32_t i = 0; i < hdr->method_ids_size; i++) {
        if (ids[i].class_idx == exclude_type) continue;
        if (!proto_matches(ids[i].proto_idx, signature)) continue;
        if (method_is_static(i)) return static_cast<int32_t>(i);
    }
    return -1;
}

bool View::proto_matches(uint32_t proto_idx, const char* signature) const {
    if (proto_idx >= hdr->proto_ids_size) return false;
    const auto* protos = at<ProtoId>(hdr->proto_ids_off, hdr->proto_ids_size);
    if (!protos) return false;
    const ProtoId& proto = protos[proto_idx];
    // Rebuild "(params)return" from the proto and compare. 512 bytes covers any realistic method;
    // a longer one simply does not match.
    char buf[512];
    size_t n = 0;
    auto append = [&](const char* s) {
        size_t len = strlen(s);
        if (n + len >= sizeof(buf)) return false;
        memcpy(buf + n, s, len);
        n += len;
        return true;
    };
    if (!append("(")) return false;
    if (proto.parameters_off != 0) {
        const auto* list = at<TypeList>(proto.parameters_off);
        if (!list || !at<uint16_t>(proto.parameters_off + sizeof(TypeList), list->size)) return false;
        const uint16_t* items = type_list_items(list);
        for (uint32_t i = 0; i < list->size; i++) {
            const char* d = type_descriptor(items[i]);
            if (!d || !append(d)) return false;
        }
    }
    const char* ret = type_descriptor(proto.return_type_idx);
    if (!append(")") || !ret || !append(ret)) return false;
    buf[n] = 0;
    return strcmp(buf, signature) == 0;
}

}  // namespace ph::dex
