#!/usr/bin/env bash
# Builds tests/dex_patcher/build/classes.dex from the fixture sources with javac + d8.
# d8 is found via $D8 (a d8 launcher), $R8_JAR (r8/d8 jar run with java), or $ANDROID_HOME build-tools.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out="$here/build"
rm -rf "$out" && mkdir -p "$out/classes"

d8() {
    if [ -n "${D8:-}" ]; then "$D8" "$@"
    elif [ -n "${R8_JAR:-}" ]; then java -cp "$R8_JAR" com.android.tools.r8.D8 "$@"
    else
        local bt
        bt=$(ls -d "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/nonexistent}}"/build-tools/* 2>/dev/null | sort -V | tail -1)
        [ -n "$bt" ] || { echo "no d8: set D8, R8_JAR or ANDROID_HOME" >&2; exit 2; }
        "$bt/d8" "$@"
    fi
}

find "$here/fixture" -name '*.java' -print0 | xargs -0 javac --release 11 -g -d "$out/classes"
mapfile -d '' classes < <(find "$out/classes" -name '*.class' -print0)
d8 --min-api 30 --output "$out" "${classes[@]}"
ls -la "$out/classes.dex"
