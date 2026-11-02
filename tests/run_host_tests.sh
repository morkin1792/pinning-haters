#!/usr/bin/env bash
# Builds the d8 fixture, the host test binaries, runs them, and re-dexes the patched output with d8
# as a structural verifier. Used by .github/workflows/contract.yml and by hand.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
"$here/dex_patcher/build_fixture.sh"
cmake -S "$here" -B "$here/build" -DCMAKE_BUILD_TYPE=Debug ${CMAKE_GENERATOR:+-G "$CMAKE_GENERATOR"} >/dev/null
cmake --build "$here/build" -j"$(nproc)"
"$here/build/test_dex_patcher" "$here/dex_patcher/build/classes.dex" "$here/dex_patcher/build/patched.dex"
"$here/build/test_got"
"$here/build/test_config" "$here/../examples/config.example.json"
# Real static-BoringSSL libraries (libflutter.so builds, WebRTC…), when present (gitignored; see docs/testing.md).
"$here/build/test_self_remap"
# The call-site finder must see the Function0 overload delegate to check$okhttp.
[ "$(python3 "$here/../tools/dex_callers.py" "$here/dex_patcher/build/classes.dex" 'CertificatePinner;->check\$okhttp' 2>/dev/null | wc -l)" = 1 ] || { echo "dex_callers.py: expected 1 call site" >&2; exit 1; }
shopt -s nullglob; "$here/build/test_boringssl_table" "$here"/../tools/reference-libs/boringssl/*.so --absent "$here"/../tools/reference-libs/boringssl-negative/*.so; shopt -u nullglob
# d8 parses every instruction of every method when it reads a .dex input; a broken nop-fill or a
# try/handler address that no longer sits on an instruction boundary fails here.
rm -rf "$here/dex_patcher/build/redex" && mkdir -p "$here/dex_patcher/build/redex"
source <(sed -n '/^d8() {/,/^}/p' "$here/dex_patcher/build_fixture.sh")
d8 --min-api 30 --output "$here/dex_patcher/build/redex" "$here/dex_patcher/build/patched.dex"
echo "patched.dex re-dexed by d8: structurally valid"
echo "ALL HOST TESTS PASSED"
