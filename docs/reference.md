# Reference: how it works, configuration, logging, building

The README covers installing the module and targeting a package. This file holds the rest of what
used to be there: the mechanism in one screen, the host table, every configuration key, the log
format, and the full build and test commands.

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

Details, including the file-to-component map: [architecture.md](architecture.md). The ranking that
decides which primitive each surface uses: [detection-model.md](detection-model.md).

## Host tiers

The host module manager decides whether its own `libzygisk.so` is visible in the target's memory
map. The module hides its own mapping (`hide.self_remap`); it does not hide the host's.

| Host | Our `.so` in `/proc/self/maps` | Tier |
|---|---|---|
| KernelSU + ZygiskNext | hidden (self-remap) | preferred |
| KernelSU-Next + NeoZygisk | hidden (self-remap) | preferred |
| APatch + Zygisk | hidden (self-remap) | preferred |
| Magisk 26+ (built-in Zygisk) | memfd mapping, hidden (self-remap) | degraded, documented |

Measured per host in [android-versions.md](android-versions.md); Magisk is not yet measured.

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

Open the module in the manager and choose its WebUI. Search the installed apps by name or package
and tap one to target it; each targeted app opens to its tier override and its proxy redirect.
"Settings" holds the default tier and the surface toggles, "Logs" the log switches and a viewer with
coverage lines highlighted and a summary on top: which surfaces were reached, and which are present
but not reached and why. Press Save, then force-stop and reopen the app; nothing in the WebUI needs
a reboot.

App names, versions and icons come from `apps.dex`, a small helper the WebUI runs as root under
`app_process` (managers differ in what their WebView offers; APatch 11039 has no package API). It
caches one icon per app under the module's `webroot/icons/`. If it fails, the list falls back to
bare package names from `pm list packages`.
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
    "com.example.hardened": { "stealth": "balanced" },
    "com.example.ignoresproxy": { "redirect": "192.168.1.10:8081" }
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
| `stealth` | `"max"` \| `"balanced"` \| `"compat"` | `"max"` | Global tier ceiling. Every target carries a `min_tier`; only targets at or below the ceiling are installed. See [stealth-tiers.md](stealth-tiers.md). |
| `packages` | object | `{}` | Package name → per-package options. An empty value `{}` means "target with the global settings". Empty object: the module is inert. |
| `packages.<pkg>.stealth` | tier string | inherits `stealth` | Replaces the global ceiling **for that package only**, in either direction. |
| `packages.<pkg>.redirect` | `"<ipv4>:<port>"` | unset | Send that package's TCP 443 to a proxy listener with a firewall rule on its uid, for apps that ignore the system proxy. Off unless set. See [Apps that ignore the system proxy](#apps-that-ignore-the-system-proxy). |
| `relax_hostname_verification` | bool | `false` | Also neutralise hostname verifiers (`okhttp3.internal.tls.OkHostnameVerifier`, an app-bundled Apache `AbstractVerifier`). Not `HttpsURLConnection`'s default verifier, which is bootclasspath. Hostname verification is not pinning; a proxy presenting a certificate for the right host does not need this. |
| `surfaces.platform_tls` | bool | `true` | The conscrypt `custom_verify` wrap. |
| `surfaces.java_dex` | bool | `true` | DEX patching at verification time. `okhttp_pinner` and `hostname_verifier` depend on it. |
| `surfaces.bundled_tls` | bool | `true` | GOT hooks for app-shipped `libssl`/`libcrypto` consumers, and the Flutter `libflutter.so` pointer swap. |
| `surfaces.foreign_runtime` | bool | `false` | IL2CPP and Mono targets. Nothing is installable here in v0.1.0; those targets have no backend yet (Phase 2). Flutter pin plugins are Java and live under `java_dex`. |
| `aot.evict_oat` | bool | `true` | The companion deletes the package's oat artifacts before replying. Required for the DEX path to work across `bg-dexopt`; see [known-limitations.md](known-limitations.md) for the startup cost. |
| `aot.stat_hook_fallback` | bool | `true` | In-process GOT hooks on the `stat`/`open`/`access` imports of ART's libraries return `ENOENT` for oat artifacts under `/data`. Covers read-only paths, unusual layouts and DEX opened mid-run. |
| `hide.self_remap` | bool | `true` | After hooking, re-map this module's own pages into anonymous memory so `/proc/self/maps` no longer shows its path. Same addresses, nothing else touched. The host's own `libzygisk.so` stays visible on Zygisk Next; see [threat-model.md](threat-model.md). |
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
reference, the surface-to-tier table and a triage walkthrough are in [coverage.md](coverage.md).

## Proxy CA

For **targeted packages, no CA installation is needed.** The conscrypt wrap accepts any chain the
proxy presents, and the bundled-TLS hooks disable verification outright. The hostname in the proxy's
certificate still has to match, which any interception proxy does by construction.

For broad interception of apps you have *not* targeted, install your proxy's CA as a **system CA**
with a dedicated CA-certificate module. That modifies no app process and is quieter than listing
every package here. pinning-haters does not do this and will not.

## Apps that ignore the system proxy

Flutter (`dart:io`) and most native TLS stacks never read the Android proxy setting, so the bypass
works and the proxy still sees nothing. For those packages, set `redirect`:

```json
"packages": { "com.example.app": { "redirect": "192.168.1.10:8081" } }
```

At the app's next launch the root companion installs firewall rules for that app's uid:

- **TCP 443** goes to the address you gave. The listener must accept TLS directly and take the
  destination from the TLS server name (Burp: "Support invisible proxying" on the listener), because
  the app does not send `CONNECT`.
- **UDP 443** goes to a closed local port, so HTTP/3 fails the way it does against a server without
  QUIC and the app falls back to TCP.
- **IPv6 443** is refused, so the app falls back to IPv4. The proxy address is IPv4 only.

Nothing changes inside the app: no hook, no descriptor, and its sockets still report the real server
address. The rules follow the config at each launch of that package: change the address or remove
the key, force-stop the app, start it again. A reboot clears every rule. Other ports are untouched.

What to know before turning it on:

- If the proxy is unreachable, the app has no HTTPS at all until the key is removed.
- A connection to an address that does not exist now succeeds (the proxy answers). An app that
  probes for exactly that can notice; see [threat-model.md](threat-model.md).
- On kernels without IPv6 NAT the IPv6 UDP block is a plain reject, which the app sees as `EPERM`,
  the same error Android's own firewall produces.
- The per-launch log shows the outcome on its first line: `redirect=<ip:port>`, `redirect=off` or
  `redirect=failed` (details in `companion.log`).

## Building

Requirements: Android NDK r26d or later (r27c is what the module has been built with), CMake 3.22+,
`python3`; Ninja is used when it is on `PATH`. The WebUI's app-list helper (`module/apps/Apps.java`)
needs `javac`, an `android.jar` (`ANDROID_JAR`, or the newest platform under `ANDROID_HOME`) and d8
(`D8`, `R8_JAR`, or `ANDROID_HOME` build-tools).

The flashable zip in one command:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r27c   # or ANDROID_NDK_ROOT
tools/package.sh                                    # version from module/module.prop
tools/package.sh v0.1.1                             # or name the version explicitly
```

It configures and builds `module/jni` for arm64-v8a (MinSizeRel, API 30), strips the library, stages
`module.prop`, `customize.sh`, `service.sh`, `config.default.json`, `META-INF/`, `webroot/`,
`apps.dex` and `zygisk/arm64-v8a.so` under `build/pkg/`, writes `build/pinning-haters-<version>.zip` and prints its
SHA-256. Flash that zip from the root manager, or push only the library to a test device with
`PH_DEVICE=<serial> tools/device_test.sh install build/pkg/zygisk/arm64-v8a.so`, which replaces it
through a new inode and reboots.

The underlying build, if you want the library alone:

```sh
cmake -S module/jni -B build/arm64 \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=MinSizeRel -DPH_VERSION=v0.1.0
cmake --build build/arm64
```

The CMake file refuses any ABI other than arm64-v8a. The `PH_DEBUG_LOGCAT` option additionally
prints log lines to logcat for debug builds; never ship a build with it on. CI (`contract.yml`)
builds the same zip on every push and attaches it as the `pinning-haters-module` artifact. Pushing a
`v*` tag runs `build.yml`: it builds the zip from the tagged commit, publishes a GitHub release named
`pinning-haters <tag>` (pre-release while the tag starts with `v0.`) with the SHA-256 in its notes, and
commits the new `zipUrl` to `module/update.json` on `main`.

Host-side tests (no device needed; need `javac` and `d8` via `D8`, `R8_JAR` or `ANDROID_HOME`):

```sh
tests/run_host_tests.sh
```

ELF contract check against reference libraries (needs `curl`, `python3`, `debugfs`, `readelf`; see
[android-versions.md](android-versions.md)):

```sh
tools/pull_reference_libs.sh 34
tools/check_elf_contracts.sh 34
```

On-device checks, the manual matrix and the release checklist: [testing.md](testing.md).
