# pinning-haters

A Zygisk module that bypasses TLS certificate pinning in Android apps you are authorised to test.
It is the Android counterpart to iOS's ssl-kill-switch: install it once, name the packages you want
to inspect, and point them at your interception proxy. No Frida, no recompiled APKs, no Xposed
framework, no manager app.

The one property that distinguishes it from other Zygisk unpinning modules: **in the default
configuration it modifies zero bytes of executable code in the target process.** Every action at the
default tier is one of three things: a pointer rewrite in a data page (a GOT slot), a bytecode
rewrite inside the app's own DEX performed while ART is verifying it, or a file operation done by a
root companion outside the process. A memory-versus-disk CRC of any library's text finds nothing,
because nothing was changed. The ranking behind that choice is in [docs/detection-model.md](docs/detection-model.md).

## Status

**Pre-release (v0.1.0, unreleased).** Phase 1 code is complete and the host-side tests pass, but
the module has been verified on **one device** so far:

- Host-side ELF contracts hold on every supported API level (30, 31, 33, 34, 35, 36), checked
  against real ART and conscrypt libraries ([docs/android-versions.md](docs/android-versions.md)).
- The three on-device checks the design rests on (the verifier interception fires, the conscrypt
  wrap completes a handshake with the app's `TrustManager` still invoked, oat eviction holds for
  the launch) pass on Android 11 / APatch + Zygisk Next, together with the zero-modified-executable-
  bytes check, the HTTP Toolkit pinning demo and a WebView load of an untrusted root ([docs/android-versions.md](docs/android-versions.md)). Other releases and hosts are
  pending.
- Flutter's bundled BoringSSL, and any other statically linked BoringSSL in an app-private library,
  is reached at `max` by swapping a pointer in its `ssl_crypto_x509_method` table (verified on the
  HTTP Toolkit demo and the Flutter bank app, Android 11; locator checked against WebRTC, OpenTok and Brella builds).
  The `balanced` and `compat` tiers have no backend yet; selecting them changes only what the
  coverage log says ([docs/stealth-tiers.md](docs/stealth-tiers.md)).
- The module hides its own mapping (`hide.self_remap`). The host's `libzygisk.so` stays visible by path on Zygisk Next 1.4.5; that is the one injection trace a generic detector finds in a targeted app ([docs/known-limitations.md](docs/known-limitations.md)).
- TLS only. Root and tamper hiding (RASP verdicts, root-indicator probes) moved to a separate module; this one does not touch them.
- `tests/test-app` builds and runs (`tools/device_test.sh testapp`): every check passes on the device above, including a packed (DexHelper) app whose unpacked DEX is patched like any other.

Do not rely on it for an engagement until the manual matrix in `docs/testing.md` has been run.

## How it works, in one screen

- A root **companion** inside the Zygisk daemon decides at each launch whether the package is a
  target, resolves its stealth tier, deletes the package's oat artifacts, and answers the app side
  with a fixed-size decision. The app process reads no files and no system properties of ours.
- **Platform TLS.** The GOT slot for `SSL_set_custom_verify` in conscrypt's `libjavacrypto.so` is
  rewritten so that conscrypt's certificate-verify callback is *wrapped*: the app's real
  `TrustManager` still runs with every side effect, and only a rejection is turned into "ok". This
  one edge reaches platform trust, Network Security Config pin-sets, TrustKit, hand-rolled
  `X509TrustManager`s, Volley, gRPC-over-OkHttp and anything else that validates through
  `javax.net.ssl`.
- **Java pinning that runs after the handshake** (OkHttp `CertificatePinner`). The `adler32` GOT
  slot in `libdexfile.so` is rewritten; when ART's `DexFileVerifier` checksums a DEX, the module
  patches the target methods in place and returns the checksum of the unpatched bytes. ART then
  verifies and compiles the patched method itself; the result is indistinguishable from a method
  that was written to do nothing.
- **App-bundled BoringSSL/OpenSSL** with exported symbols: GOT slots in the *calling* library
  (libcurl, gRPC, Qt, the app's own code) are rewritten; the provider's text is untouched.
- **Statically linked BoringSSL and OpenSSL** without import slots (Flutter, WebRTC, OpenVPN cores,
  an app's own build): one pointer in the library's own method table (`ssl_crypto_x509_method` for
  BoringSSL, the client `SSL_METHOD` for OpenSSL) is swapped in a data page. Still no executable
  bytes changed; the original verifier still runs.
- **Libraries loaded later.** Two import slots in `libdl.so` (the linker's `__loader_dlopen` and
  `__loader_android_dlopen_ext` entry points) re-run the native scan after every load, whether it
  came from `System.loadLibrary`, Dart FFI or an SDK's own `dlopen`. No app-private GOT is touched
  for this.
- **Oat eviction.** ART ignores DEX bytes for methods it has already AOT-compiled, and skips the
  verifier when a vdex exists. The companion deletes the package's `.odex/.vdex/.art` files before
  the app starts, so the DEX path works at all, at the cost of a slower launch.

Details, including the file-to-component map: [docs/architecture.md](docs/architecture.md).

## Requirements

- Android 11 to 16 (API 30 to 36). Android 10 is unsupported.
- arm64-v8a only. x86_64 (emulators) is backlog; ARM32 is out of scope.
- A rooted device with a Zygisk implementation that speaks Zygisk API v4 or later.

### Host tiers

The host module manager decides whether our own library is visible in the target's memory map. We
deliberately do not hide it ourselves, because doing so needs inline hooks in libc, which is the
loudest primitive on the ranking (see `docs/detection-model.md`).

| Host | Our `.so` in `/proc/self/maps` | Tier |
|---|---|---|
| KernelSU + ZygiskNext | hidden by host | preferred |
| KernelSU-Next + NeoZygisk | hidden by host | preferred |
| APatch + Zygisk | hidden by host | preferred |
| Magisk 26+ (built-in Zygisk) | visible as a memfd mapping | degraded, documented |

If stealth is your priority, prefer a host that hides module libraries.

## Install

1. Download `pinning-haters-<version>.zip` from the Releases page, or build it (below).
2. Flash it from your root manager's module screen and reboot.
3. On install, `customize.sh` creates `/data/adb/pinning_haters/config.json` with an inert default
   configuration (no packages) and `/data/adb/pinning_haters/log/`. `service.sh` re-asserts the
   permissions on every boot. Both are root-only (0700 directory, 0600 files).

## Nothing happens until you add a package

**The module is inert after installation.** The default config has an empty `packages` object, and
the module does nothing in any process until you name one. There is no denylist mode and no
"all apps" switch: a global mode would mean installing hooks in every process including
`system_server`, which is a bad idea on every axis this project cares about.

For every process that is *not* a configured target, the module asks the companion, receives
"not a target", and unloads itself before the app's code runs. It never attaches to `system_server`.

## Configuring

The package key is the app's package name exactly as it appears in `pm list packages`
(the module identifies the process by the basename of its data directory, so processes declared
with `android:process` still match on the package name).

### KernelSU and APatch: WebUI

Open the module in the manager and choose its WebUI. It offers the global tier, the package list with
a `pm list packages` picker and a per-package tier override, the surface and hostname toggles under
"advanced", the log switches, and a viewer for the most recent log with coverage lines highlighted
and a summary on top: which surfaces were reached, and which are present but not reached and why.
The WebUI runs in the manager's WebView through `ksu.exec` (APatch is API-compatible), which already
has your root context; there is no additional authentication because none is available.

### Magisk: edit the JSON over adb

The Magisk app has no module WebUI. Write the file on your workstation and push it:

```sh
cat > config.json <<'EOF'
{
  "version": 2,
  "stealth": "max",
  "packages": {
    "com.example.app": {}
  },
  "log": { "enabled": true }
}
EOF
adb push config.json /data/local/tmp/ph-config.json
adb shell su -c 'cp /data/local/tmp/ph-config.json /data/adb/pinning_haters/config.json && chmod 600 /data/adb/pinning_haters/config.json && rm /data/local/tmp/ph-config.json'
adb shell am force-stop com.example.app
```

The companion re-reads the file on every app launch, so there is nothing to reload and no reboot;
force-stop the target and start it again. If the file is unreadable or not a JSON object, the
companion falls back to the inert defaults and writes the reason to
`/data/adb/pinning_haters/log/companion.log`. Comments (`//`, `/* */`) are tolerated.

## Configuration reference

The complete schema is `examples/config.example.json`:

```json
{
  "version": 2,
  "stealth": "max",
  "packages": {
    "com.example.targetapp": {},
    "com.example.hardened": { "stealth": "balanced" }
  },
  "relax_hostname_verification": false,
  "surfaces": {
    "platform_tls": true,
    "java_dex": true,
    "bundled_tls": true,
    "foreign_runtime": false
  },
  "aot": {
    "evict_oat": true,
    "stat_hook_fallback": true
  },
  "hide": {
    "self_remap": true
  },
  "log": { "enabled": false, "verbose": false }
}
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | `2` | Schema version. Any other value is noted in `companion.log`; the file is still parsed. |
| `stealth` | `"max"` \| `"balanced"` \| `"compat"` | `"max"` | Global tier ceiling. Every target carries a `min_tier`; only targets at or below the ceiling are installed. See `docs/stealth-tiers.md`. |
| `packages` | object | `{}` | Package name → per-package options. An empty value `{}` means "target with the global settings". Empty object: the module is inert. |
| `packages.<pkg>.stealth` | tier string | inherits `stealth` | Replaces the global ceiling **for that package only**, in either direction. |
| `relax_hostname_verification` | bool | `false` | Also neutralise hostname verifiers (`okhttp3.internal.tls.OkHostnameVerifier`, an app-bundled Apache `AbstractVerifier`). Not `HttpsURLConnection`'s default verifier, which is bootclasspath. Hostname verification is not pinning; a proxy presenting a certificate for the right host does not need this. |
| `surfaces.platform_tls` | bool | `true` | The conscrypt `custom_verify` wrap. |
| `surfaces.java_dex` | bool | `true` | DEX patching at verification time. `okhttp_pinner` and `hostname_verifier` depend on it. |
| `surfaces.bundled_tls` | bool | `true` | GOT hooks for app-shipped `libssl`/`libcrypto` consumers, and the Flutter `libflutter.so` pointer swap. |
| `surfaces.foreign_runtime` | bool | `false` | IL2CPP and Mono targets. Nothing is installable here in v0.1.0; those targets have no backend yet (Phase 2). Flutter pin plugins are Java and live under `java_dex`. |
| `aot.evict_oat` | bool | `true` | The companion deletes the package's oat artifacts before replying. Required for the DEX path to work across `bg-dexopt`; see `docs/known-limitations.md` for the startup cost. |
| `aot.stat_hook_fallback` | bool | `true` | In-process GOT hooks on the `stat`/`open`/`access` imports of ART's libraries return `ENOENT` for oat artifacts under `/data`. Covers read-only paths, unusual layouts and DEX opened mid-run. |
| `hide.self_remap` | bool | `true` | After hooking, re-map this module's own pages into anonymous memory so `/proc/self/maps` no longer shows its path. Same addresses, nothing else touched. The host's own `libzygisk.so` stays visible on Zygisk Next; see `docs/threat-model.md`. |
| `log.enabled` | bool | `false` | Write a per-launch log file (below). |
| `log.verbose` | bool | `false` | Include `DEBUG` lines (per-method patch results, each hidden oat path, each overridden verdict). |

Unknown keys are ignored. A key with the wrong type falls back to its default and is noted in
`companion.log`; the rest of the file still applies.

## Logging

Logging is **off by default** and goes nowhere an app can read. Log records travel from the app
process over the companion socket; the companion writes
`/data/adb/pinning_haters/log/<package>-<YYYYMMDD-HHMMSS>.log`, root-owned, mode 0600, one file per
launch. Nothing is written to logcat or `/sdcard`: both are readable by the app itself and a greppable
indicator is cheaper to check than any hook-detection technique. Companion-side notes (config errors)
go to `companion.log` in the same directory. Rotation runs at the start of each logging session:
files older than 7 days are deleted, and the directory is capped at 100 MB, oldest first.

With logging on, the module creates a pipe before specialization and hands the read end to the
companion; the write end stays open for the app's lifetime so class-load-time DEX patches and
deferred library loads can still report. It is one extra file descriptor in the target process. (The
Zygisk companion socket itself cannot be used after specialization: it carries zygote's SELinux label
and the app domain may not write to it.) With logging off, no descriptor of ours survives
`preAppSpecialize`.

Read the latest log:

```sh
adb shell su -c 'ls -t /data/adb/pinning_haters/log | head -5'
adb shell su -c 'cat /data/adb/pinning_haters/log/<file>'
```

Line format: `[YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] text`, levels `DEBUG`, `INFO`, `WARN`, `ERROR`.
The first line of every file comes from the companion itself:
`[companion] package=<pkg> process=<name> uid=<uid> oat_evicted=<n>`.

### Reading a coverage line

The `[init]` line and the `[coverage]` lines are the ones that matter when a bypass does not work:

```
[2026-10-24 12:00:01.123] [INFO ] [init] pinning-haters v0.1.0 api=34 build=Google/14/2024-05-05 tier=max surfaces=0x07 flags=0x0a oat_evicted=2
[2026-10-24 12:00:01.125] [INFO ] [coverage] surface=platform_tls present=yes reachable=yes applied=1 style=got target=SSL_set_custom_verify
[2026-10-24 12:00:01.126] [INFO ] [coverage] surface=java_dex present=yes reachable=yes applied=1 style=got target=adler32
[2026-10-24 12:00:01.130] [INFO ] [coverage] surface=flutter present=yes reachable=yes applied=1 style=pattern target=ssl_crypto_x509_session_verify_cert_chain lib=libflutter.so
[2026-10-24 12:00:02.410] [INFO ] [coverage] surface=okhttp_pinner present=yes reachable=yes applied=3/4 dex_size=8482816
```

`present=yes reachable=yes` means the surface was found and hooked. `present=yes reachable=no` is the
line to act on: it names the `reason` and, when a higher tier would help, the `required_tier`.
`present=no` lines are normal; most apps ship few of the libraries in the table. The full field
reference, the surface-to-tier table and a triage walkthrough are in
[docs/coverage.md](docs/coverage.md).

## Proxy CA

For **targeted packages, no CA installation is needed.** The conscrypt wrap accepts any chain the
proxy presents, and the bundled-TLS hooks disable verification outright. The hostname in the proxy's
certificate still has to match, which any interception proxy does by construction.

For broad interception of apps you have *not* targeted, install your proxy's CA as a **system CA**
with a dedicated CA-certificate module. That modifies no app process and is quieter than listing
every package here. pinning-haters does not do this and will not.

## Building

Requirements: Android NDK r26d or later (r27c is what the module has been built with), CMake 3.22+.

```sh
cmake -S module/jni -B build/arm64 \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DPH_VERSION=v0.1.0
cmake --build build/arm64
```

`tools/package.sh [version]` runs that build, strips the library and assembles the flashable zip
(`module.prop`, `customize.sh`, `service.sh`, `zygisk/arm64-v8a.so`, `webroot/`). The CMake file
refuses any ABI other than arm64-v8a. The `PH_DEBUG_LOGCAT` option additionally prints log lines to
logcat for debug builds; never ship a build with it on.

Host-side tests (no device needed; need `javac` and `d8` via `D8`, `R8_JAR` or `ANDROID_HOME`):

```sh
tests/run_host_tests.sh
```

ELF contract check against reference libraries (needs `curl`, `python3`, `debugfs`, `readelf`; see
`docs/android-versions.md`):

```sh
tools/pull_reference_libs.sh 34
tools/check_elf_contracts.sh 34
```

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Process flow, components, the wire protocol, the three GOT edges, the DEX path. |
| [docs/detection-model.md](docs/detection-model.md) | The primitive ranking that decides every hook, the footprint at `max`, the GOT limitation. |
| [docs/stealth-tiers.md](docs/stealth-tiers.md) | `max` / `balanced` / `compat`, per-package override, what each tier exposes. |
| [docs/coverage.md](docs/coverage.md) | The coverage ladder: every surface, every field, every reason, and what to change. |
| [docs/adding-hooks.md](docs/adding-hooks.md) | Hooks are data: how to add a Java or native target. |
| [docs/android-versions.md](docs/android-versions.md) | The ELF contract verification record per API level. |
| [docs/known-limitations.md](docs/known-limitations.md) | What is not and will not be reached. |
| [docs/testing.md](docs/testing.md) | Host tests, the manual matrix, the zero-modified-bytes release check. |
| [docs/threat-model.md](docs/threat-model.md) | Who this is for, what detects it, what it never defends against. |
| [DISCLAIMER.md](DISCLAIMER.md) | Terms of use. |
| [CHANGELOG.md](CHANGELOG.md) | Release history. |
| [AGENTS.md](AGENTS.md) | Decision log for contributors: why things are the way they are. |

## License

GPL-3.0-or-later. See `LICENSE`. The vendored `nlohmann/json` single header (`module/jni/config/json.hpp`)
is MIT. shadowhook (Apache-2.0) is planned for the inline-hook backend and is not yet part of the
tree; the Flutter backend does not need it.
