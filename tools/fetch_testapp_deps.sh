#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fetches what tests/test-app/build_manual.sh needs besides the SDK: the runtime jars from Maven
# Central and (with --openssl) a static OpenSSL for the static_openssl check, built with the NDK.
# Used by CI and by hand.
#
#   tools/fetch_testapp_deps.sh <out-dir> [--openssl <version>]
#
# Afterwards: JARS_DIR=<out-dir>  OPENSSL_DIR=<out-dir>/openssl-<version>  (needs ANDROID_NDK_HOME).
set -euo pipefail
out=${1:?output directory}
mkdir -p "$out"
maven=https://repo1.maven.org/maven2
fetch() { [ -s "$out/$2" ] || curl -fsSL --retry 3 -o "$out/$2" "$maven/$1"; }

fetch com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar okhttp-4.12.0.jar
fetch com/squareup/okio/okio-jvm/3.6.0/okio-jvm-3.6.0.jar okio-jvm-3.6.0.jar
fetch org/jetbrains/kotlin/kotlin-stdlib/1.8.21/kotlin-stdlib-1.8.21.jar kotlin-stdlib-1.8.21.jar

if [ "${2:-}" = --openssl ]; then
    v=${3:?OpenSSL version}
    ndk=${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME}
    src="$out/openssl-$v"
    if [ ! -f "$src/libssl.a" ]; then
        [ -d "$src" ] || curl -fsSL --retry 3 "https://github.com/openssl/openssl/releases/download/openssl-$v/openssl-$v.tar.gz" | tar xz -C "$out"
        # The NDK's clang must come first: Configure picks up whatever "clang" is on PATH.
        (cd "$src" && PATH="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH" ANDROID_NDK_ROOT="$ndk" \
            ./Configure android-arm64 -D__ANDROID_API__=30 no-shared no-tests no-engine no-dso >/dev/null &&
            PATH="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH" ANDROID_NDK_ROOT="$ndk" make -j"$(nproc)" build_libs >/dev/null)
    fi
    ls -la "$src/libssl.a" "$src/libcrypto.a"
fi
ls -la "$out"
