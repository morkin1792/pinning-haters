#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds zygisk/arm64-v8a.so with the NDK and assembles the flashable module zip.
#   tools/package.sh [version]        (default: version= from module/module.prop)
# Needs ANDROID_NDK_HOME (or ANDROID_NDK_ROOT), cmake 3.22+, ninja or make, python3 (for zipping).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
version=${1:-$(sed -n 's/^version=//p' "$root/module/module.prop")}
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
[ -d "$ndk" ] || { echo "set ANDROID_NDK_HOME to an NDK (r26d or later)" >&2; exit 2; }
gen=""; command -v ninja >/dev/null && gen="-G Ninja"

build="$root/build/arm64"
cmake -S "$root/module/jni" -B "$build" $gen \
    -DCMAKE_TOOLCHAIN_FILE="$ndk/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=MinSizeRel -DPH_VERSION="$version"
cmake --build "$build" -j"$(nproc)"

strip=$(ls "$ndk"/toolchains/llvm/prebuilt/*/bin/llvm-strip | head -1)
stage="$root/build/pkg"
rm -rf "$stage" && mkdir -p "$stage/zygisk"
"$strip" --strip-unneeded -o "$stage/zygisk/arm64-v8a.so" "$build/arm64-v8a.so"
cp -r "$root/module/module.prop" "$root/module/customize.sh" "$root/module/service.sh" \
      "$root/module/config.default.json" "$root/module/META-INF" "$root/module/webroot" "$stage/"
sed -i "s/^version=.*/version=$version/" "$stage/module.prop"

out="$root/build/pinning-haters-$version.zip"
python3 - "$stage" "$out" <<'PY'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dp, dn, fn in sorted(os.walk(stage)):
        dn.sort()
        for f in sorted(fn):
            p = os.path.join(dp, f)
            z.write(p, os.path.relpath(p, stage))
PY
sha256sum "$out"
