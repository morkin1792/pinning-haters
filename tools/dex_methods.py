#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""List the methods a DEX (or every classes*.dex in an APK) defines or references for a class.

    tools/dex_methods.py <apk-or-dex> <class-descriptor-regex> [--defined-only]

Prints `descriptor->name(signature)` lines with the DEX file they come from and whether the class
is defined there (D) or only referenced (R). Use it to pick JavaTarget signatures from a real APK
instead of guessing from source.
"""
import re
import struct
import sys
import zipfile


def uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


class Dex:
    def __init__(self, data):
        self.d = data
        h = struct.unpack_from("<8sI20s20I", data, 0)
        (self.string_ids_size, self.string_ids_off, self.type_ids_size, self.type_ids_off, self.proto_ids_size,
         self.proto_ids_off, self.field_ids_size, self.field_ids_off, self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off) = h[9:21]
        self._strings = {}

    def string(self, idx):
        if idx not in self._strings:
            off = struct.unpack_from("<I", self.d, self.string_ids_off + idx * 4)[0]
            _, p = uleb128(self.d, off)
            end = self.d.index(b"\0", p)
            self._strings[idx] = self.d[p:end].decode("utf-8", "replace")
        return self._strings[idx]

    def type_desc(self, idx):
        return self.string(struct.unpack_from("<I", self.d, self.type_ids_off + idx * 4)[0])

    def proto(self, idx):
        shorty, ret, params_off = struct.unpack_from("<III", self.d, self.proto_ids_off + idx * 12)
        params = ""
        if params_off:
            n = struct.unpack_from("<I", self.d, params_off)[0]
            params = "".join(self.type_desc(t) for t in struct.unpack_from("<%dH" % n, self.d, params_off + 4))
        return "(%s)%s" % (params, self.type_desc(ret))

    def methods(self):
        for i in range(self.method_ids_size):
            cls, proto, name = struct.unpack_from("<HHI", self.d, self.method_ids_off + i * 8)
            yield i, self.type_desc(cls), self.string(name), self.proto(proto)

    def defined_classes(self):
        out = set()
        for i in range(self.class_defs_size):
            cls = struct.unpack_from("<I", self.d, self.class_defs_off + i * 32)[0]
            out.add(self.type_desc(cls))
        return out


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path, pattern = sys.argv[1], re.compile(sys.argv[2])
    defined_only = "--defined-only" in sys.argv
    dexes = []
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        for n in z.namelist():
            if re.fullmatch(r"classes\d*\.dex", n):
                dexes.append((n, z.read(n)))
    else:
        dexes.append((path, open(path, "rb").read()))
    for name, data in dexes:
        dex = Dex(data)
        defined = dex.defined_classes()
        for _, cls, meth, sig in dex.methods():
            if not pattern.search(cls):
                continue
            is_def = cls in defined
            if defined_only and not is_def:
                continue
            print("%s %s %s->%s%s" % (name, "D" if is_def else "R", cls, meth, sig))


if __name__ == "__main__":
    main()
