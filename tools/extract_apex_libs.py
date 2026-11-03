#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pull the ART, conscrypt and bionic (libdl) APEX libraries out of an Android system image without root.

Usage: extract_apex_libs.py <system.img> <dest-dir>

Handles: raw ext4 images, GPT images whose `super` partition holds the logical system partition,
non-flattened (.apex / compressed .capex-style) and flattened APEXes, symlinked library names, and
ext4 APEX payloads (erofs payloads need fsck.erofs from erofs-utils). Everything is read with
debugfs(8); nothing is mounted.
"""
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

import re

# APEX file names vary by release and vendor: com.android.art.apex, com.google.android.art.apex,
# com.android.art.release.apex (Android 11), com.android.runtime.release.apex (Android 10), flattened
# directories on some emulator builds. Match by regex over the directory listing.
ART_APEX = re.compile(r"^(com\.google\.android|com\.android)\.(art|runtime)(\.(release|debug))?$")
CONSCRYPT_APEX = re.compile(r"^(com\.google\.android|com\.android)\.conscrypt$")
# bionic lives in the runtime APEX on every supported release; libdl.so carries the deferred-load
# contract (its __loader_* import slots).
RUNTIME_APEX = re.compile(r"^(com\.google\.android|com\.android)\.runtime(\.(release|debug))?$")
ART_LIBS = ["libart.so", "libartbase.so", "libdexfile.so", "libnativeloader.so"]
CONSCRYPT_LIBS = ["libjavacrypto.so", "libssl.so", "libcrypto.so"]
RUNTIME_LIBS = ["bionic/libdl.so"]  # paths under lib64/; saved under dest by basename
EXT4_MAGIC = b"\x53\xef"
EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"


def debugfs(img, offset, cmd):
    dev = f"{img}?offset={offset}" if offset else img
    p = subprocess.run(["debugfs", "-R", cmd, dev], capture_output=True, text=True)
    return p.stdout + p.stderr


def fs_kind(f, off):
    f.seek(off + 1024)
    sb = f.read(1024)
    if len(sb) < 1024:
        return None
    if sb[0x38:0x3A] == EXT4_MAGIC:
        return "ext4"
    if sb[:4] == EROFS_MAGIC:
        return "erofs"
    return None


def fs_candidates(img):
    """Yield (offset, kind) for every filesystem we can find in the image."""
    size = os.path.getsize(img)
    with open(img, "rb") as f:
        k = fs_kind(f, 0)
        if k:
            yield 0, k
        f.seek(512)
        if f.read(8) == b"EFI PART":
            f.seek(512 + 72)
            pe_lba, npe, pesz = struct.unpack("<QII", f.read(16))
            f.seek(pe_lba * 512)
            parts = []
            for _ in range(npe):
                e = f.read(pesz)
                if e[:16] == b"\0" * 16:
                    continue
                s, en = struct.unpack("<QQ", e[32:48])
                parts.append((s * 512, (en - s + 1) * 512))
            for start, length in parts:
                k = fs_kind(f, start)
                if k:
                    yield start, k
                else:  # a `super` partition: logical partitions are 1 MiB aligned inside it
                    for off in range(start, start + length, 1 << 20):
                        k = fs_kind(f, off)
                        if k:
                            yield off, k
        else:
            for off in range(0, size, 1 << 20):
                k = fs_kind(f, off)
                if k and off:
                    yield off, k


def entry_type(img, off, path):
    out = debugfs(img, off, f"stat {path}")
    if "File not found" in out:
        return None
    for line in out.splitlines():
        if line.startswith("Inode:") and "Type:" in line:
            return line.split("Type:")[1].split()[0].lower()
    return None


def symlink_target(img, off, path):
    out = debugfs(img, off, f"stat {path}")
    for line in out.splitlines():
        if "link dest:" in line:
            return line.split("link dest:")[1].strip().strip('"')
    return None


def dump(img, off, src, dst):
    """debugfs dump with symlink resolution (library names inside an APEX are often symlinks)."""
    for _ in range(4):
        t = entry_type(img, off, src)
        if t is None:
            return False
        if t == "symlink":
            tgt = symlink_target(img, off, src)
            if not tgt:
                return False
            src = tgt if tgt.startswith("/") else os.path.normpath(os.path.join(os.path.dirname(src), tgt))
            continue
        debugfs(img, off, f"dump -p {src} {dst}")
        return os.path.isfile(dst) and os.path.getsize(dst) > 0
    return False


def find_system(img):
    for off, kind in fs_candidates(img):
        if kind != "ext4":
            continue
        for apex_dir in ("/system/apex", "/apex"):
            if entry_type(img, off, apex_dir) == "directory":
                return off, apex_dir
    sys.exit(f"no ext4 filesystem with a /system/apex directory found in {img}")


def payload_libs(payload, libs, dest, tmp):
    with open(payload, "rb") as f:
        kind = fs_kind(f, 0)
    got = []
    if kind == "ext4":
        for lib in libs:
            if dump(payload, 0, f"/lib64/{lib}", os.path.join(dest, os.path.basename(lib))):
                got.append(lib)
    elif kind == "erofs":
        if not shutil.which("fsck.erofs"):
            sys.exit("APEX payload is erofs; install erofs-utils (fsck.erofs) to extract it")
        out = os.path.join(tmp, "erofs")
        subprocess.run(["fsck.erofs", f"--extract={out}", payload], check=True, capture_output=True)
        for lib in libs:
            src = os.path.realpath(os.path.join(out, "lib64", lib))
            if os.path.isfile(src):
                shutil.copy(src, os.path.join(dest, os.path.basename(lib)))
                got.append(lib)
    else:
        sys.exit(f"unknown APEX payload filesystem in {payload}")
    return got


def list_dir(img, off, path):
    """Names in a directory via `debugfs ls -p` (fields: /inode/mode/uid/gid/name/size//)."""
    names = []
    for line in debugfs(img, off, f"ls -p {path}").splitlines():
        parts = line.split("/")
        if len(parts) >= 6 and parts[5] not in (".", ".."):
            names.append(parts[5])
    return names


def extract_apex(img, off, apex_dir, pattern, libs, dest, tmp):
    entries = list_dir(img, off, apex_dir)
    # Prefer the real ART APEX over the Android 10 runtime APEX, and .apex over .capex.
    def rank(name):
        base = re.sub(r"\.c?apex$", "", name)
        return (0 if ".art" in base or base.endswith(".art") else 1, 0 if name.endswith(".apex") else 1, name)
    candidates = sorted((n for n in entries if pattern.match(re.sub(r"\.c?apex$", "", n))), key=rank)
    for name in candidates:
        path = f"{apex_dir}/{name}"
        kind = entry_type(img, off, path)
        if kind == "regular" and (name.endswith(".apex") or name.endswith(".capex")):
            local = os.path.join(tmp, name)
            dump(img, off, path, local)
            z = zipfile.ZipFile(local)
            if "original_apex" in z.namelist():  # compressed APEX: the real one is nested
                z = zipfile.ZipFile(io.BytesIO(z.read("original_apex")))
            payload = os.path.join(tmp, name + ".payload.img")
            with open(payload, "wb") as f:
                f.write(z.read("apex_payload.img"))
            got = payload_libs(payload, libs, dest, tmp)
            if got:
                return name, got
        elif kind == "directory" and entry_type(img, off, f"{path}/lib64") == "directory":
            got = [lib for lib in libs if dump(img, off, f"{path}/lib64/{lib}", os.path.join(dest, os.path.basename(lib)))]
            if got:
                return name + " (flattened)", got
    return None, []


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    img, dest = sys.argv[1], sys.argv[2]
    os.makedirs(dest, exist_ok=True)
    off, apex_dir = find_system(img)
    print(f"system filesystem at offset {off:#x}, APEX dir {apex_dir}")
    tmp = tempfile.mkdtemp(prefix="apexlibs-")
    try:
        for pattern, libs, tag in ((ART_APEX, ART_LIBS, "art"), (CONSCRYPT_APEX, CONSCRYPT_LIBS, "conscrypt"),
                                   (RUNTIME_APEX, RUNTIME_LIBS, "runtime")):
            found, got = extract_apex(img, off, apex_dir, pattern, libs, dest, tmp)
            print(f"{tag}: {found or 'NOT FOUND'} -> {', '.join(got) or 'nothing'}")
            missing = sorted(set(libs) - set(got))
            if missing:
                print(f"  missing: {', '.join(missing)}", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    bad = [lib for lib in map(os.path.basename, ART_LIBS + CONSCRYPT_LIBS + RUNTIME_LIBS)
           if os.path.isfile(os.path.join(dest, lib)) and open(os.path.join(dest, lib), "rb").read(4) != b"\x7fELF"]
    if bad:
        sys.exit(f"not ELF: {bad}")


if __name__ == "__main__":
    main()
