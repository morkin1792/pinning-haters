#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds and signs app-debug.apk without Gradle: aapt2 + javac + d8 + zipalign + apksigner.
# Needs: javac, keytool, $BUILD_TOOLS (a build-tools dir with aapt2/d8/zipalign/apksigner),
# $ANDROID_JAR (platforms/android-34/android.jar), and the three runtime jars in $JARS_DIR
# (okhttp-4.12.0.jar, okio-jvm-3.6.0.jar, kotlin-stdlib-1.8.21.jar).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${BUILD_TOOLS:?set BUILD_TOOLS}" "${ANDROID_JAR:?set ANDROID_JAR}" "${JARS_DIR:?set JARS_DIR}"
host=$(sed -n 's/^testHost=//p' "$here/gradle.properties")
out="$here/build-manual"; rm -rf "$out"; mkdir -p "$out/gen/dev/pinninghaters/testapp" "$out/classes" "$out/res"
src="$here/app/src/main"

cat > "$out/gen/dev/pinninghaters/testapp/BuildConfig.java" <<JAVA
package dev.pinninghaters.testapp;
public final class BuildConfig { public static final String TEST_HOST = "$host"; }
JAVA

"$BUILD_TOOLS/aapt2" compile --dir "$src/res" -o "$out/res.zip"
"$BUILD_TOOLS/aapt2" link -o "$out/base.apk" -I "$ANDROID_JAR" --manifest "$src/AndroidManifest.xml" \
    --java "$out/gen" --min-sdk-version 30 --target-sdk-version 34 --version-code 1 --version-name 0.1 "$out/res.zip"

cp="$ANDROID_JAR:$JARS_DIR/okhttp-4.12.0.jar:$JARS_DIR/okio-jvm-3.6.0.jar:$JARS_DIR/kotlin-stdlib-1.8.21.jar"
find "$src/java" "$out/gen" -name '*.java' -print0 | xargs -0 javac --release 17 -g -nowarn -cp "$cp" -d "$out/classes"
mapfile -d '' classes < <(find "$out/classes" -name '*.class' -print0)
"$BUILD_TOOLS/d8" --release --min-api 30 --lib "$ANDROID_JAR" --output "$out" "${classes[@]}" \
    "$JARS_DIR/okhttp-4.12.0.jar" "$JARS_DIR/okio-jvm-3.6.0.jar" "$JARS_DIR/kotlin-stdlib-1.8.21.jar"

# JNI helper for the executable-bytes check (needs the NDK; the APK still builds without it).
ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
if [ -d "$ndk" ]; then
    mkdir -p "$out/lib/arm64-v8a"
    "$ndk"/toolchains/llvm/prebuilt/*/bin/clang --target=aarch64-linux-android30 -shared -fPIC -O2 -Wall \
        -o "$out/lib/arm64-v8a/libintegrity.so" "$src/cpp/integrity.c" -lz
fi
# A statically linked OpenSSL for the static_openssl check: libssl.a and libcrypto.a whole-archived
# into one library with -Bsymbolic, so its chain check is a direct call (no GOT edge) and only the
# SSL_METHOD table swap reaches it. OPENSSL_DIR is an OpenSSL 3.x source tree built with
# `./Configure android-arm64 -D__ANDROID_API__=30 no-shared no-tests no-engine no-dso && make build_libs`.
if [ -n "$ndk" ] && [ -n "${OPENSSL_DIR:-}" ] && [ -f "$OPENSSL_DIR/libssl.a" ]; then
    mkdir -p "$out/lib/arm64-v8a"
    "$ndk"/toolchains/llvm/prebuilt/*/bin/clang --target=aarch64-linux-android30 -shared -fPIC -O2 -Wall \
        -I"$OPENSSL_DIR/include" -o "$out/lib/arm64-v8a/libtestossl.so" "$src/cpp/static_openssl.c" \
        -Wl,--whole-archive "$OPENSSL_DIR/libssl.a" "$OPENSSL_DIR/libcrypto.a" -Wl,--no-whole-archive -Wl,-Bsymbolic -lz
fi

(cd "$out" && python3 - <<'PY'
import os, zipfile
with zipfile.ZipFile("base.apk", "a", zipfile.ZIP_DEFLATED) as z:
    z.write("classes.dex", "classes.dex")
    for name in sorted(os.listdir("lib/arm64-v8a")) if os.path.isdir("lib/arm64-v8a") else []:
        z.write("lib/arm64-v8a/" + name, "lib/arm64-v8a/" + name)
PY
)
"$BUILD_TOOLS/zipalign" -f -p 4 "$out/base.apk" "$out/aligned.apk"
# One keystore per checkout, kept outside the build dir so reinstalls keep matching signatures.
ks="$here/debug.keystore"
[ -f "$ks" ] || keytool -genkeypair -keystore "$ks" -storepass android -keypass android -alias debug -keyalg RSA \
    -keysize 2048 -validity 3650 -dname "CN=pinning-haters test" >/dev/null 2>&1
"$BUILD_TOOLS/apksigner" sign --ks "$ks" --ks-pass pass:android --key-pass pass:android --ks-key-alias debug \
    --out "$out/app-debug.apk" "$out/aligned.apk"
ls -la "$out/app-debug.apk"
