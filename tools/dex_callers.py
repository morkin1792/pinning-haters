#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Find the methods that call a given method, in a DEX or every classes*.dex of an APK.

    tools/dex_callers.py <apk-or-dex> <callee-regex> [--max N]
    tools/dex_callers.py <apk-or-dex> --string <text-regex> [--max N]

With --string, call sites are const-string instructions whose string matches the regex instead:
the way from a "device compromised" dialog back to the method that decided to show it.

The regex is matched against `class->name(signature)` of the callee, for example
`Ljava/lang/System;->exit\\(I\\)V` or `CertificatePinner;->check`. For each call site prints the caller
(`class->name(signature)`), the instruction offset and, when a constant was loaded into one of the
invoke's registers just before the call, its value (the status an app passes to System.exit, say).
Diagnostic only: it shows who reaches a pin check or a failure path in an app; per-app rows do not
go into the target table.
"""
import re
import struct
import sys
import zipfile

sys.path.insert(0, __import__("os").path.dirname(__file__))
from dex_methods import Dex, uleb128  # noqa: E402

# Dalvik instruction length in 16-bit units, by opcode (payload pseudo-instructions handled apart).
LEN = [1] * 256
for lo, hi, n in [(0x01, 0x01, 1), (0x02, 0x02, 2), (0x03, 0x03, 3), (0x04, 0x04, 1), (0x05, 0x05, 2), (0x06, 0x06, 3),
                  (0x07, 0x07, 1), (0x08, 0x08, 2), (0x09, 0x09, 3), (0x13, 0x13, 2), (0x14, 0x14, 3), (0x15, 0x17, 2),
                  (0x17, 0x17, 3), (0x18, 0x18, 5), (0x19, 0x1a, 2), (0x1b, 0x1b, 3), (0x1c, 0x1c, 2), (0x1f, 0x20, 2),
                  (0x22, 0x23, 2), (0x24, 0x26, 3), (0x29, 0x29, 2), (0x2a, 0x2c, 3), (0x2d, 0x3d, 2), (0x44, 0x6d, 2),
                  (0x6e, 0x72, 3), (0x74, 0x78, 3), (0x90, 0xaf, 2), (0xd0, 0xe2, 2), (0xfa, 0xfb, 4), (0xfc, 0xfd, 3),
                  (0xfe, 0xff, 2)]:
    for op in range(lo, hi + 1):
        LEN[op] = n
LEN[0x16] = 2  # const-wide/16 (the range above set 0x17 twice; fix the overlap explicitly)
LEN[0x17] = 3
INVOKE = {0x6e: "invoke-virtual", 0x6f: "invoke-super", 0x70: "invoke-direct", 0x71: "invoke-static",
          0x72: "invoke-interface", 0x74: "invoke-virtual/range", 0x75: "invoke-super/range",
          0x76: "invoke-direct/range", 0x77: "invoke-static/range", 0x78: "invoke-interface/range"}


def code_items(dex):
    """Yields (class, name, sig, code_off) for every method with code."""
    d = dex.d
    for i in range(dex.class_defs_size):
        cls_idx, _, _, _, _, _, class_data_off, _ = struct.unpack_from("<8I", d, dex.class_defs_off + i * 32)
        if not class_data_off:
            continue
        cls = dex.type_desc(cls_idx)
        p = class_data_off
        n_static, p = uleb128(d, p)
        n_inst, p = uleb128(d, p)
        n_direct, p = uleb128(d, p)
        n_virtual, p = uleb128(d, p)
        for _ in range(n_static + n_inst):
            _, p = uleb128(d, p)
            _, p = uleb128(d, p)
        for count in (n_direct, n_virtual):
            midx = 0
            for _ in range(count):
                diff, p = uleb128(d, p)
                _, p = uleb128(d, p)
                code_off, p = uleb128(d, p)
                midx += diff
                if code_off:
                    _, mcls, name, sig = next(m for m in [method_at(dex, midx)])
                    yield cls, name, sig, code_off


def method_at(dex, idx):
    cls, proto, name = struct.unpack_from("<HHI", dex.d, dex.method_ids_off + idx * 8)
    return idx, dex.type_desc(cls), dex.string(name), dex.proto(proto)


def scan(dex, code_off, wanted, report, string_mode=False):
    d = dex.d
    regs, ins, outs, tries, _, insns_size = struct.unpack_from("<HHHHII", d, code_off)
    base = code_off + 16
    units = struct.unpack_from("<%dH" % insns_size, d, base)
    consts = {}
    i = 0
    while i < insns_size:
        u = units[i]
        op = u & 0xff
        if op == 0x00 and (u >> 8) in (1, 2, 3):  # switch / array payloads
            kind = u >> 8
            size = units[i + 1]
            if kind == 1:
                n = size * 2 + 4
            elif kind == 2:
                n = size * 4 + 2
            else:
                width = size
                count = units[i + 2] | (units[i + 3] << 16)
                n = (count * width + 1) // 2 + 4
            i += n
            continue
        if op == 0x12:  # const/4 vA, #+B
            consts[(u >> 8) & 0xf] = ((u >> 12) & 0xf) - (16 if (u >> 15) & 1 else 0)
        elif op == 0x13:  # const/16 vAA, #+BBBB
            v = units[i + 1]
            consts[u >> 8] = v - 0x10000 if v & 0x8000 else v
        elif op == 0x14:  # const vAA, #+BBBBBBBB
            consts[u >> 8] = units[i + 1] | (units[i + 2] << 16)
        elif op in (0x1a, 0x1b) and string_mode:  # const-string vAA, string@BBBB[BBBB]
            idx = units[i + 1] | ((units[i + 2] << 16) if op == 0x1b else 0)
            text = dex.string(idx)
            if wanted.search(text):
                report(i, "const-string", repr(text[:80]), [])
        elif op in INVOKE and not string_mode:
            midx = units[i + 1]
            _, mcls, name, sig = method_at(dex, midx)
            callee = "%s->%s%s" % (mcls, name, sig)
            if wanted.search(callee):
                if op <= 0x72:
                    count = u >> 12
                    r = units[i + 2]
                    args = [(r >> (4 * k)) & 0xf for k in range(min(count, 4))]
                    if count == 5:
                        args.append((u >> 8) & 0xf)
                else:
                    count = u >> 8
                    first = units[i + 2]
                    args = list(range(first, first + count))
                known = ["v%d=%d" % (a, consts[a]) for a in args if a in consts]
                report(i, INVOKE[op], callee, known)
        i += LEN[op]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path = sys.argv[1]
    string_mode = "--string" in sys.argv
    wanted = re.compile(sys.argv[sys.argv.index("--string") + 1] if string_mode else sys.argv[2])
    limit = int(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else 200
    dexes = []
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        for n in z.namelist():
            if re.fullmatch(r"classes\d*\.dex", n):
                dexes.append((n, z.read(n)))
    else:
        dexes.append((path, open(path, "rb").read()))
    hits = 0
    for name, data in dexes:
        dex = Dex(data)
        for cls, mname, sig, code_off in code_items(dex):
            def report(unit, kind, callee, known, cls=cls, mname=mname, sig=sig, name=name):
                nonlocal hits
                hits += 1
                if hits <= limit:
                    print("%s %s->%s%s @%d %s %s%s" % (name, cls, mname, sig, unit, kind, callee,
                                                        (" [" + " ".join(known) + "]") if known else ""))
            scan(dex, code_off, wanted, report, string_mode)
    print("%d call sites" % hits, file=sys.stderr)


if __name__ == "__main__":
    main()
