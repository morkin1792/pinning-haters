# Testing

Three layers: host-side tests that run on every push, the ELF contract check against reference
libraries, and a manual on-device matrix that gates every release. No release ships without the
matrix passing on at least three Android versions across at least two root managers.

## Host-side tests

```sh
tests/run_host_tests.sh
```

Requirements: a C++20 compiler, CMake 3.22+, `javac`, and `d8` found through one of `D8` (a d8
launcher), `R8_JAR` (an r8/d8 jar run with `java`) or `ANDROID_HOME` (newest `build-tools`). Builds
with `-fsanitize=address,undefined`.

What runs, in order:

1. `tests/dex_patcher/build_fixture.sh`: compiles `tests/dex_patcher/fixture/` (a shape-compatible
   stand-in for `okhttp3.CertificatePinner` with every overload in the production table, bodies with
   try/catch/finally, a `switch` payload and 4-byte instructions; `OkHostnameVerifier`;
   `fixture.Extra` with abstract, native and boolean methods) to
   `build/classes.dex` with `d8 --min-api 30`.
2. `test_dex_patcher classes.dex patched.dex`: runs the **production** Java table against the
   fixture and asserts every OkHttp overload patches, both OkHttp hostname entries patch, and the
   Apache entries are absent; checks bytes (`return-void` or `const/4; return` first, `nop` to
   `insns_size`, `insns_size`/`tries_size`/`registers_size`/`debug_info_off` unchanged, header
   bytes unchanged, header checksum no longer matching the content, which is why the interception
   returns the pre-patch value); exercises `RETURN_FALSE`, `NO_CODE`,
   `METHOD_ABSENT`, `CLASS_ABSENT` (including a class referenced but defined elsewhere); feeds
   truncated and corrupted DEX files to the parser; and checks the `patch_code_item` guards.
   Writes `patched.dex`.
3. `test_got`: rewrites the test binary's own `getpid` import slot, calls through it, verifies the
   original still works, checks idempotence (no stacking), restores, and checks `has_edge`,
   `basename_of` and `is_app_private`.
4. `test_config examples/config.example.json`: parses the example, checks every default, the
   per-package override, the global ceiling, tolerant parsing (comments, unknown keys, wrong types
   falling back per field with an error note), garbage input, and the inert result for a missing
   file.
5. `test_boringssl_table [lib.so ...] [--absent lib.so ...]`: decodes synthetic ADRP+ADD pairs,
   then for every library given "loads" the file the way the linker would (PT_LOADs at their vaddrs,
   `R_AARCH64_RELATIVE` applied) and runs the real locator over it, asserting the
   `session_verify_cert_chain` slot is found inside a table of function pointers; libraries after
   `--absent` must carry the purpose strings and yield *no* slot (OpenSSL builds). The runner passes
   `tools/reference-libs/boringssl/*.so` and `tools/reference-libs/boringssl-negative/*.so`
   (gitignored). Current fixtures: three Flutter engines, a WebRTC `libjingle_peerconnection_so.so`,
   OpenTok, Google's Brella, WebView 156 (packed APS2 and RELR relocations, which the loader
   applies), and one OpenVPN3 (OpenSSL) negative. To add one, pull the APK and extract
   `lib/arm64-v8a/<lib>.so` with `python3 -m zipfile -e`, or `cat` it out of `/data/app/*/<pkg>-*/lib/arm64/`
   on a rooted device; a new build that breaks the locator fails here, before it fails on a device.
6. `test_self_remap`: the test binary re-maps its own mappings with `hide/self_remap.cpp`, then
   checks that `/proc/self/maps` no longer names the file while code, `.rodata`, `.data` and `.bss`
   all survived. Same code path the module runs in an app after hooking.
7. `tools/dex_callers.py` over the fixture: the call-site finder must report the one call of
   `CertificatePinner.check$okhttp` (a parser regression would show as a different count).
8. `d8 --min-api 30 --output ... patched.dex`: **re-dexes the patched DEX**. d8 parses every
   instruction of every method when it reads a `.dex` input, so a broken nop-fill or a try/handler
   address off an instruction boundary fails here.

`ALL HOST TESTS PASSED` is the success line. CI runs this and the contract check in
`.github/workflows/contract.yml` on every push.

## ELF contract check

```sh
tools/pull_reference_libs.sh 30 31 33 34 35 36   # once; gitignored output
tools/check_elf_contracts.sh                       # all pulled API levels
```

Asserts the four contracts the `max` tier depends on against real libraries. Results and the
procedure are in `docs/android-versions.md`.

## Manual matrix

Android 11, 12, 13, 14, 15, 16 × Magisk, KernelSU + ZygiskNext, APatch + Zygisk. (KernelSU-Next +
NeoZygisk is API-compatible with ZygiskNext for our purposes and may substitute for it.)

| | Magisk | KernelSU + ZygiskNext | APatch + Zygisk |
|---|---|---|---|
| Android 11 (API 30) | pending | pending | **passed 2026-10-25** (Redmi K20, APatch + Zygisk Next; test app through Burp, all expected verdicts, `exec_bytes PASS`, dexopt survival, WebUI read/write/log viewer in the APatch manager, HTTP Toolkit SSL Pinning Demo 5/5 pinned surfaces flipped through Burp, WebView against an untrusted root passes with no CA) |
| Android 12 (API 31) | pending | pending | pending |
| Android 13 (API 33) | pending | pending | pending |
| Android 14 (API 34) | pending | pending | pending |
| Android 15 (API 35) | pending | pending | pending |
| Android 16 (API 36) | pending | **passed 2026-11-02/03** (Mi 9T custom ROM, KernelSU + SUSFS, Zygisk Next 1.5.0; test app with no proxy straight to an untrusted root: every expected verdict incl. WebView and OpenSSL 3.4.1 through both tables, `exec_bytes PASS` over 380 mappings; Flutter swap applied in a real app; `bg-dexopt` survival: artifacts regenerated with `pm compile`, `oat_evicted=2` at the next launch, `okhttp_pinner` PASS; a React Native app with a protection SDK targeted through Burp; launch-churn stability runs clean, 20-minute 60-second-interval run on the release candidate) | pending |

**`tools/device_test.sh`** wraps the per-device steps below so the matrix can be re-run on a new phone
in minutes: `install` (through a new inode, then reboot and unlock), `config`, `log`, `testapp`
(verdicts from the test app's logcat lines), `integrity`, `demo` (taps the HTTP Toolkit demo's
buttons by text and reads their colour), `dnat` (redirect a package's TCP 443, what a Flutter test
needs) and `maps`. `PH_DEVICE` is the adb serial, `PH_PIN` the lock PIN.

**Updating the library on a test device.** Install the zip through the host manager, or replace
the file through a *new inode*: push to a temporary name next to it and `mv` it over
`/data/adb/modules/pinning_haters/zygisk/arm64-v8a.so`, then reboot. Never `cp` over the live file.
The Zygisk companion (and any targeted app with logging on) keeps the old file mapped; `cp`
rewrites the pages underneath it, the new build's PLT stubs then read `.got.plt` at offsets the old
process never relocated, and the next libc call jumps to the file-relative address of `.plt` and
dies with `SIGSEGV` at a small address (seen five times on 2026-10-25, one per in-place overwrite,
`fault addr` equal to the build's `.plt` start). Zygisk Next respawns the companion, so the damage
is one lost request, but the tombstones look like a module bug until the timestamps are matched.

Phase 1 exit requires passes on Android 11 to 15 (plan §1.16 item 3) and clean installs on all three
hosts. Update this table in the release PR.

### Per-cell procedure

1. Flash the zip, reboot. Confirm `/data/adb/pinning_haters/config.json` and `log/` exist and are
   root-only.
2. Launch any **non-targeted** app with logging on. Confirm no log file is created for it and that
   `/proc/<pid>/maps` of that app does not contain our library (on Magisk it will have been
   `dlclose`d; on hiding hosts it was never visible).
3. Add `tests/test-app` to `packages` with `log.enabled: true` and `log.verbose: true`. Force-stop,
   launch, run the four checks below, read the log (`docs/coverage.md`).
4. Add three real F-Droid apps that ship pinning. Confirm the proxy sees their traffic in clear.
5. Add a Flutter sample app. Confirm the `flutter` line says `reachable=yes applied=1` at `max`,
   and that its traffic passes through an untrusted interception (Flutter ignores the system proxy:
   set the package's `redirect` key, or use `tools/device_test.sh dnat` or a VPN-based transparent
   proxy).
6. **`bg-dexopt` survival** (plan §1.16 item 7): with the test app targeted, regenerate its oat
   artifacts the way the nightly job does (`pm compile -m speed-profile -f <pkg>` for one package,
   or `cmd package bg-dexopt-job` for all of them), confirm `oat/arm64/base.{odex,vdex}` exist,
   force-stop and relaunch, confirm `[init]` shows `oat_evicted > 0`, the directory is empty again
   and the `okhttp_pinner` bypass still works. A `verify`-filter vdex is the dangerous case: it
   carries `VerifierDeps`, so without eviction the interception would never fire.
7. **Stability**: 24 hours of normal use with the targets configured, no crashes attributable to the
   module (check `logcat -b crash` and tombstones). `tools/stability_run.sh 24 1800 <pkg>...`
   covers the automated half: it relaunches each target every interval and records liveness, crash
   lines, new tombstones and companion restarts. Leave banking apps out of it: dozens of identical
   launches are exactly what their fraud telemetry looks for. `tools/stability_ondevice.sh` is the
   same loop running as root on the phone, so the cable can be unplugged: it holds a CPU wakelock,
   exempts the test app from Doze, starts it with `--ez run true` so every round runs the checks,
   and writes `/data/local/tmp/ph-stability.log`. Unlock once after a reboot before starting it.
   The compressed form is `stability_ondevice.sh 20m 60 <pkg>...`: what the loop can find
   (companion state across requests, the log pipe, eviction on every launch, hooks across process
   lifetimes) scales with launches, not hours, so a 20-minute run at a 60-second interval covers
   the same paths; the 24 hours of hands-on use remain the criterion before a tag.

### What `tests/test-app` must exercise

Source in `tests/test-app` (plain Java, OkHttp 4.12; built by `tests/test-app/build_manual.sh` and CI). One APK contains all
four of the things that distinguish this architecture; an app where everything passes teaches
nothing about the tier boundaries.

| Check | Mechanism under test | Expected at `max` |
|---|---|---|
| A custom `X509TrustManager` that rejects every chain **and records that it was invoked** | conscrypt wrap | Connection succeeds; the app asserts the `TrustManager` ran. A wrap that never invoked it is a regression. |
| Network Security Config `<pin-set>` for the test host | conscrypt wrap | Connection succeeds. |
| OkHttp `CertificatePinner` with a wrong pin | DEX patch at verification + oat eviction | Connection succeeds; log shows `okhttp_pinner ... reachable=yes applied=N/M`. |
| A manual post-handshake digest comparison (`getPeerCertificates()` SHA-256 vs a constant) | nothing at `max` | **Fails**, by design. There is no shipped coverage line for app-specific checks; the test confirms the failure is clean and the proxy sees a completed handshake followed by a client close. |

Its second button runs the release check below (`IntegrityCheck.java`).

## Release check: zero modified executable bytes at `max`

The headline property gets a mechanical check, not a README claim (plan §1.16 item 6). Procedure,
run from inside a targeted process at `max` after the hooks are installed and after at least one TLS
connection and one DEX verification have happened:

1. Walk `/proc/self/maps`. Select every mapping with `x` permission that is backed by a file
   (a path, not `[anon]`, not a memfd). The JIT code cache and ART's own anonymous executable
   mappings are excluded because they are not file-backed; they are expected to differ from disk.
2. For each selected mapping, open the backing file (the app can read every library it has mapped),
   parse its program headers, and locate the `PT_LOAD` segment with `PF_X` that covers the mapping's
   file offset.
3. Compute a CRC-32 (or SHA-256) over the mapped bytes and over the same byte range read from the
   file. The two must be equal for **every** mapping, including `libjavacrypto.so`, `libdexfile.so`,
   `libart.so`, `libartbase.so`, `libnativeloader.so`, the conscrypt `libssl.so`, `libc.so`, and the
   app's own libraries.
4. Any inequality fails the release.

`tests/test-app`'s `IntegrityCheck` does exactly this from Java: it reads the mapped bytes through
`/proc/self/mem` (a process may always read its own memory that way, no privilege or native code
needed) and reports on screen and in logcat as `exec_bytes PASS|FAIL`. Do not use Frida for this
check; it introduces its own executable modifications.

Note the check is about `.text`. GOT pages are data and are expected to differ (that is the hook);
the in-memory DEX is expected to differ from the APK (that is the patch).

## Release checklist

1. Host tests green; contract check green for every API level in the matrix.
2. Matrix table above updated with passes for at least three Android versions and two hosts.
3. Zero-modified-executable-bytes check passed on at least one device.
4. `bg-dexopt` survival confirmed.
5. `docs/android-versions.md` on-device items updated.
6. `CHANGELOG.md` entry, `module.prop` version and `versionCode` bumped, `update.json` updated by the
   release workflow.
