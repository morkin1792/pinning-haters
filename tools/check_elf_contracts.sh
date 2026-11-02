#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Asserts the ELF edges the `max` tier rests on, per API level, against real libraries in
# tools/reference-libs/<api>/ (pull them with tools/pull_reference_libs.sh). Runs in CI
# (contract.yml) so an Android release that moves one of these edges fails a build instead of
# failing silently on a user's device.
#
#   tools/check_elf_contracts.sh            # every API level present under tools/reference-libs/
#   tools/check_elf_contracts.sh 34 35      # just these
set -u  # no pipefail: grep -q closing the pipe early would turn readelf's SIGPIPE into a failure
here=$(cd "$(dirname "$0")" && pwd)
root="$here/reference-libs"
READELF=${READELF:-$(command -v llvm-readelf || command -v readelf)}
[ -n "$READELF" ] || { echo "need readelf or llvm-readelf" >&2; exit 2; }

apis=("$@")
if [ ${#apis[@]} -eq 0 ]; then
    mapfile -t apis < <(ls "$root" 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
fi
[ ${#apis[@]} -gt 0 ] || { echo "no reference libraries under $root" >&2; exit 2; }

# Does $1 import function $2 through a GOT slot? Both JUMP_SLOT (.rela.plt) and GLOB_DAT count as
# edges we could rewrite; the module only walks .rela.plt today, so GLOB_DAT-only is reported.
imports() {
    [ -f "$1" ] && "$READELF" -rW "$1" | grep -qE "JUMP_SLOT[[:space:]]+[0-9a-f]+[[:space:]]+$2(@|[[:space:]]|\$)"
}
imports_glob_dat() {
    [ -f "$1" ] && "$READELF" -rW "$1" | grep -qE "GLOB_DAT[[:space:]]+[0-9a-f]+[[:space:]]+$2(@|[[:space:]]|\$)"
}

status=0
for api in "${apis[@]}"; do
    dir="$root/$api"
    echo "== API $api ($dir)"
    for lib in libjavacrypto.so libdexfile.so libnativeloader.so libart.so libartbase.so; do
        [ -f "$dir/$lib" ] || echo "   missing reference library: $lib"
    done

    ok=1
    if imports "$dir/libjavacrypto.so" SSL_set_custom_verify || imports "$dir/libjavacrypto.so" SSL_CTX_set_custom_verify; then
        echo "   PASS platform TLS wrap: libjavacrypto.so imports SSL_(CTX_)?set_custom_verify via JUMP_SLOT"
    else
        echo "   FAIL platform TLS wrap: no JUMP_SLOT for SSL_(CTX_)?set_custom_verify in libjavacrypto.so"; ok=0
        imports_glob_dat "$dir/libjavacrypto.so" SSL_set_custom_verify && echo "        (present as GLOB_DAT only)"
    fi
    if imports "$dir/libdexfile.so" adler32; then
        echo "   PASS DEX interception: libdexfile.so imports adler32 via JUMP_SLOT"
    else
        echo "   FAIL DEX interception: no JUMP_SLOT for adler32 in libdexfile.so (static zlib?)"; ok=0
        imports_glob_dat "$dir/libdexfile.so" adler32 && echo "        (present as GLOB_DAT only)"
    fi
    dlopen_in=""
    for lib in libnativeloader.so libart.so; do
        imports "$dir/$lib" android_dlopen_ext && dlopen_in="$dlopen_in $lib"
    done
    if [ -n "$dlopen_in" ]; then
        echo "   PASS deferred load: android_dlopen_ext JUMP_SLOT in$dlopen_in"
    else
        echo "   FAIL deferred load: no JUMP_SLOT for android_dlopen_ext in libnativeloader.so or libart.so"; ok=0
    fi
    probe=""
    for lib in libartbase.so libart.so libdexfile.so; do
        found=""
        for sym in stat stat64 fstatat fstatat64 open open64 openat openat64 access; do
            imports "$dir/$lib" "$sym" && found="$found $sym"
        done
        [ -n "$found" ] && probe="$probe $lib:[$found ]"
    done
    if [ -n "$probe" ]; then
        echo "   PASS oat probe fallback edges:$probe"
    else
        echo "   FAIL oat probe fallback: none of the stat/open family imported by any ART library"; ok=0
    fi
    [ $ok = 1 ] || status=1
done
[ $status = 0 ] && echo "ALL CONTRACTS HOLD" || echo "CONTRACT FAILURE: see above; record the API level in docs/android-versions.md"
exit $status
