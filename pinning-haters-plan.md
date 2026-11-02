# pinning-haters — Implementation Plan (v2)

A Zygisk module that bypasses TLS certificate pinning on Android apps while minimising the number of
observable modifications it makes to the target process.

**Audience for this document**: Claude Code, working through the phases in order. Each phase is
independently shippable. Phase 0.5 is blocking — do not start Phase 1.1 until it passes.

**Supersedes** the v1 plan. The strategic decisions (Zygisk, no Frida, no LSPosed, no Rust, ARM64,
shadowhook available but not primary, GPL-3, monorepo, opt-in allowlist, no network) are unchanged.
The hooking mechanics are substantially revised. `update1.md` and `update2.md` are absorbed into
§2.3, §3.3, Phase 1.5 and Phase 2; they are kept on disk as source material.

---

## 0. Charter

### Priority order (this is the tiebreaker for every design decision)

1. **Low detectability.** When two designs reach the same surface, take the one that modifies less of
   the target process, in the places least likely to be checked.
2. **Coverage.** Reach as many pinning surfaces as possible *within* the detectability budget.
3. **Maintainability.** Hooks are data. Small dependency set.
4. **Convenience.** Last. Never traded against item 1.

Coverage beyond what the quiet primitives can reach is exposed as an **opt-in stealth tier**, never as
a default. See §2.

### Goals

- Bypass pinning on the large majority of Android apps without Frida and without recompiling APKs.
- In the default configuration, modify **zero bytes of executable code** in the target process.
- Installable on any Zygisk-compatible host: Magisk, KernelSU + ZygiskNext, KernelSU-Next +
  NeoZygisk, APatch + Zygisk.
- When a bypass fails, tell the user *which* surface was present and *which* tier would reach it.

### Non-goals

- Root and tamper hiding, RASP defeat: moved to a separate module.
- Hardware-backed pinning (TEE / StrongBox). Out of scope permanently.
- Replacing system CA installation. Orthogonal problem; see §3.4.
- x86_64. Backlog. ARM32. Out of scope.
- Any network traffic from the module.

### Project metadata

- **Module ID**: `pinning_haters`
- **Module name**: `pinning-haters`
- **License**: GPL-3.0
- **Repo**: monorepo, single GitHub repository

### Tech stack (locked)

- C++20, NDK r26d or later. No Rust.
- CMake 3.22+.
- Zygisk API v4, **companion process required** (see §Phase 1.2).
- Own GOT/PLT rewriter (~150 lines, §Phase 1.1). Primary hooking primitive.
- **shadowhook** (ByteDance, Apache-2.0) for inline hooks. Compiled in, but only reachable at
  `balanced` tier and above.
- No LSPlant, no Xposed-family framework, in Phase 1.
- WebUI: vanilla HTML/CSS/JS, no build step.
- GitHub Actions CI: host-side ELF contract tests, host-side DEX patcher unit tests, release zip on tag.

### Supported Android versions

- **Minimum Android 11 (API 30).** Android 10 (API 29) is try-it-last; drop and document if ART
  internals diverge enough to complicate the abstraction.
- **Maximum Android 16 (API 36)** at time of writing.

### Host tiers (new)

The host module manager determines whether our own `.so` is hideable. We do not fix this ourselves.

| Host | Our `.so` in `/proc/self/maps` | Tier |
|---|---|---|
| KernelSU + ZygiskNext | module hides itself (`hide.self_remap`); host's `libzygisk.so` stays visible by path (measured, 1.4.5) | preferred |
| KernelSU-Next + NeoZygisk | module hides itself; host behaviour not yet measured | preferred |
| APatch + Zygisk Next | module hides itself; host's `libzygisk.so` visible (measured, 1.4.5) | preferred |
| Magisk (built-in Zygisk) | module hides itself; host loads modules from memfd and hides its own library | untested |

Document in `README.md` that users whose priority is stealth should prefer a host that hides module
libraries, and that pinning-haters deliberately does not implement its own `/proc/self/maps`
filtering (§1.11 explains why).

---

## 1. Detection model

Everything downstream follows from this ranking. It is an ordering of *hooking primitives* by how
likely a real app is to notice them.

### 1.1 Primitive ranking, quietest first

| # | Primitive | What detects it | Seen outside RASP? |
|---|---|---|---|
| 1 | DEX bytecode patched in memory before verification | comparing in-memory DEX against the APK's DEX | effectively never |
| 2 | Companion-side file operations (oat eviction, config, logs) outside the app process | nothing in-process; only noticing oat artifacts are absent | effectively never |
| 3 | GOT / PLT slot rewrite in a *system* library (libart, libdexfile, libjavacrypto) | snapshotting GOT at load and re-reading; checking slot targets fall inside the expected provider library | rare |
| 4 | GOT / PLT slot rewrite in an *app-private* library | same, and app libs are the first thing a scanner walks | uncommon |
| 5 | Inline `.text` patch in a system library | CRC of that library's executable segment vs the file on disk | uncommon |
| 6 | Inline `.text` patch in libc | same, and libc is the most CRC-checked library on the device | common |
| 7 | ArtMethod entry-point flip (LSPlant-style) | entry point outside the legitimate `.oat` mapping | common, this is the standard Xposed check |

Phase 1 default uses **1, 2, 3 only**. 4 is used when a target is only reachable that way and is
labelled accordingly. 5 is `balanced`. 6 and 7 are `compat` / Phase 2.

### 1.2 Things we never do, at any tier

- Hook libc functions in order to *hide ourselves* (`open`, `openat`, `stat`, `fopen` filtering of
  `/proc/self/maps`, `/data/adb/...`). This buys nothing against apps that do not already hunt for
  hooks, and it writes into the single most-verified library on the device. The original plan's
  §1.9 items 1–4 are cut. See §1.11.
- Allocate RWX pages.
- Any outbound network request.
- Patch a surface in a process we were not configured to target.

### 1.3 Consequence for the module's own footprint

In the default (`max`) configuration a target process contains:

- our `.so`, mapped (hidden by the host on preferred hosts, visible on Magisk);
- three to five rewritten GOT slots in ART APEX / conscrypt APEX libraries;
- modified `insns[]` bytes inside the app's own in-memory DEX;
- no modified executable bytes anywhere;
- no additional threads, no additional mappings beyond our `.so` and its allocations.

In non-target processes it contains nothing: we return from `preAppSpecialize` with
`DLCLOSE_MODULE_LIBRARY` set.

---

## 2. Stealth tiers

### 2.1 Definition

```
max       (default)  primitives 1-3, plus 4 only where explicitly labelled
balanced             + inline .text hooks in system and app libraries, + pattern scanning
compat               + ArtMethod fallback, + libc-level hooks, + foreign-runtime metadata patching
```

Every target entry in `targets_*.cpp` carries a `min_tier`. The configured tier is a **ceiling**: the
module installs every target whose `min_tier <=` the ceiling and skips the rest. The tier does not
change code paths per target; it filters a data table. This keeps the "hooks are data" rule intact.

### 2.2 Tier contents and trade-offs

| | `max` (default) | `balanced` | `compat` (mostly Phase 2) |
|---|---|---|---|
| **Primitives** | DEX patch, GOT in system libs, companion-side oat eviction | + inline hooks, + pattern scan | + LSPlant, + libc hooks |
| **Reaches** | all TrustManager-based pinning (platform trust, Network Security Config pin-sets, TrustKit, any custom `X509TrustManager`), OkHttp `CertificatePinner`, app-bundled TLS when the calling library is identifiable | + Flutter, + statically linked / symbol-stripped BoringSSL, + libraries with no usable GOT edge | + methods ART compiled before our window, + bootclasspath methods, + Unity IL2CPP, + Mono/Xamarin, + Dart-side pin libraries, + Cronet pin APIs |
| **New detection exposure** | GOT snapshot diff; in-memory-DEX vs APK-DEX compare; absent oat artifacts | + text CRC of each hooked library | + standard Xposed entry-point checks; + libc CRC |
| **Needs CRC countermeasures (§Phase 2.1)** | no | yes | yes |

The important property: at `max` there is **nothing for a text-CRC check to find**, so the whole
CRC-defeat problem described in `update1.md` does not arise. CRC countermeasures only become
necessary at `balanced`, which is exactly why they live in Phase 2 and not Phase 1.

### 2.3 Configuration

`/data/adb/pinning_haters/config.json`:

```json
{
  "version": 2,
  "stealth": "max",
  "packages": {
    "com.example.targetapp": {},
    "com.example.flutterapp": { "stealth": "balanced" }
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
  "log": { "enabled": false, "verbose": false }
}
```

- `stealth` is the global ceiling. A per-package `stealth` raises or lowers it **for that package
  only**. This is how "universal coverage" is achieved without a globally loud default: the user
  escalates the one app that needs it.
- `packages` is an object, not an array, so per-package overrides have somewhere to live. Empty
  object means "target with global defaults".
- There is **no denylist mode**. A denylist would mean installing hooks in every process on the
  device including `system_server`. Removed.
- Default: `stealth: "max"`, `packages: {}` — the module does nothing until the user adds a package.

### 2.4 The coverage ladder (this is what makes tiers usable)

A tier ceiling is only tolerable if the user can tell *why* a bypass failed. Every target that is
skipped because of the ceiling, and every surface detected present but unreachable, emits one log
line in a fixed format:

```
[<ts>] [INFO ] [coverage] surface=flutter present=yes reachable=no required_tier=balanced current_tier=max
[<ts>] [INFO ] [coverage] surface=okhttp_pinner present=yes reachable=yes applied=3/3
[<ts>] [INFO ] [coverage] surface=platform_tls present=yes reachable=yes mode=wrap
```

Presence detection is cheap and tier-independent: it is a scan of loaded library names and of the
class/method strings already being searched in the DEX. Detecting that `libflutter.so` is mapped
costs nothing and never requires a hook.

`docs/coverage.md` is the user-facing table mapping `required_tier` values to what the user should
put in the config. This doc is part of the Phase 1 deliverable, not polish.

---

## 3. Pinning surface map

The v1 plan split surfaces into Java and native. That is two categories where there are three, and
it attributed several surfaces to the wrong one. Corrected map:

### 3.1 Category A — Java/Kotlin reachable by DEX patching

Reached by patching `insns[]` in the app's DEX before ART verifies it. `min_tier: max`.

The *only* pinning that genuinely belongs here is pinning performed **after** the TLS handshake has
already succeeded, by app or library code reading the negotiated certificate chain. Anything that
runs *inside* the handshake as a `TrustManager` is reached more cheaply by §3.2 and must not be
listed here.

- OkHttp `CertificatePinner` — runs in `RealConnection` after the handshake, reading
  `handshake.peerCertificates`. The conscrypt wrap has already returned "ok" by then, so this
  genuinely needs a DEX patch. Primary Category A target.
- Certificate Transparency interceptors (`com.appmattus.certificatetransparency`) when implemented
  as an OkHttp interceptor rather than a `TrustManager`.
- App-specific post-handshake chain comparison (custom code calling `getPeerCertificates()` and
  comparing SHA-256 digests). Needs per-app targets; not shippable as a default list.
- `WebViewClient.onReceivedSslError` overrides. App-specific subclass.

**Removed from the v1 Java list, with reasons** — these were not reachable by the stated mechanism:

| v1 target | Why removed |
|---|---|
| `com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive` / `verifyChain` | bootclasspath; preloaded in zygote and AOT-compiled into the boot image before our module exists. Reached by §3.2 instead. |
| `android.security.net.config.NetworkSecurityTrustManager.checkServerTrusted` / `checkPins` | bootclasspath, same problem. It is invoked from conscrypt's verify callback, so §3.2 reaches it. |
| `android.net.http.X509TrustManagerExtensions.checkServerTrusted` | bootclasspath. Covered by §3.2 when invoked during a handshake; when an app calls it directly it is a Category A app-specific target. |
| `javax.net.ssl.X509TrustManager.checkServerTrusted` | interface method. No bytecode exists to patch. |

Because all four `RETURN_FIRST_ARG` consumers are gone, the `RETURN_FIRST_ARG` replacement kind is
**not implemented in Phase 1**. Remaining kinds: `RETURN_VOID`, `RETURN_TRUE`, `RETURN_FALSE`.

Apache `AbstractVerifier.verify` is **hostname verification, not pinning**. Moved to the opt-in
hostname group, §Phase 1.10.

### 3.2 Category B — native, reachable by symbol

Two sub-cases, and the distinction decides the primitive:

**B1. Platform TLS (conscrypt).** `libjavacrypto.so` in the conscrypt APEX calls
`SSL_CTX_set_custom_verify` / `SSL_set_custom_verify` in the conscrypt APEX's `libssl.so`. This is a
cross-library call, so a GOT slot exists in `libjavacrypto.so`. Rewriting that slot modifies no
executable bytes in either library. `min_tier: max`. Detail in §Phase 1.4.

This single edge is the highest-leverage hook in the project. Everything that validates certificates
through a `javax.net.ssl` `TrustManager` funnels through it: platform trust, Network Security Config
pin-sets, TrustKit, Volley with a custom `SSLSocketFactory`, gRPC over OkHttp, any app's hand-rolled
`X509TrustManager`, and Cronet's default system-trust path.

**B2. App-bundled TLS.** An app shipping its own BoringSSL/OpenSSL with exported symbols. Rule: hook
the GOT slot **in the calling library** (e.g. `libcurl.so`'s slot for `SSL_CTX_set_verify`), which is
`min_tier: max` when the caller is identifiable, falling back to an inline hook in the exporting
library at `min_tier: balanced`.

Targets: `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_CTX_set_custom_verify`,
`SSL_set_custom_verify`, `SSL_CTX_set_cert_verify_callback`, `SSL_get_verify_result`,
`X509_verify_cert`.

### 3.3 Category C — symbol-stripped native and foreign AOT runtimes

Machine code, not resolvable by symbol, not reachable as DEX. Needs pattern scanning. `min_tier:
balanced` or `compat`. This is the category the v1 plan collapsed into a single sentence about
"statically-linked stripped BoringSSL being rare" — which is true for stripped libssl and false for
Flutter and Unity, which are common.

- **Flutter.** `dart:io` goes through BoringSSL inside `libflutter.so`, but that library is built
  with hidden visibility: there are no exported `SSL_*` symbols to resolve. The real target is
  Flutter's own `ssl_crypto_x509_session_verify_cert_chain`, located by byte pattern or by walking
  back from the `SSL_CTX_set_custom_verify` call site. `min_tier: balanced`. Separately, Dart-side
  pinning packages (`http_certificate_pinning`, `ssl_pinning_plugin`, Dio interceptors) do the digest
  comparison in AOT-compiled Dart inside `libapp.so` and abort before the handshake finishes — no
  BoringSSL hook fires at all. `min_tier: compat`, Phase 2.
- **Unity / IL2CPP.** `UnityWebRequest` reaches libcurl or platform HTTP, so platform-trust pinning
  is covered by B1. Custom C# pinning (`CertificateHandler`, manual chain walk) is stripped native
  code in `libil2cpp.so`, located via `global-metadata.dat`. `min_tier: compat`, Phase 2.
- **Xamarin / .NET MAUI.** Two sub-cases. `Mono.Android` using the Java `HttpClient` is Category A/B.
  `HttpClient` with `ServerCertificateValidationCallback` lives in C#/Mono assemblies, not in DEX.
  `min_tier: compat`, Phase 2. The v1 plan listed Xamarin under §1.5.1 polish as "a few extra Java
  targets"; that is wrong, it is its own layer.
- **Qt for Android.** `QSslSocket` in `libQt{5,6}Network.so` over BoringSSL or system OpenSSL, so B2
  usually wins. `QSslConfiguration::setCaCertificates` pinning is in Qt's own code.
- **Statically linked, symbol-stripped BoringSSL in an app-private `.so`.** Pattern scan.
  `min_tier: balanced`.
- **React Native, Cordova, Ionic, Capacitor.** No new category — OkHttp or WebView underneath,
  already covered by A and B.

### 3.4 What pinning-haters is not responsible for

Installing the interception proxy's CA. For target packages the B1 wrap accepts any chain, so no CA
installation is needed at all. For broad, non-targeted interception the user should install the CA as
a system CA via a separate CA-cert module — that modifies no app process and is quieter than
targeting every package here. `README.md` states this.

---

## 4. Repository structure

```
pinning-haters/
├── README.md
├── LICENSE                          # GPL-3.0
├── DISCLAIMER.md
├── CHANGELOG.md
├── AGENTS.md                        # decision log, read before architectural changes
├── pinning-haters-plan.md           # this file
├── .github/workflows/
│   ├── build.yml                    # tag → module zip → release
│   └── contract.yml                 # host-side ELF contract + DEX patcher unit tests
├── module/
│   ├── module.prop
│   ├── customize.sh
│   ├── service.sh                   # config dir creation, permissions
│   ├── update.json
│   ├── webroot/                     # index.html, style.css, app.js
│   └── jni/
│       ├── CMakeLists.txt
│       ├── module.cpp               # Zygisk entry, lifecycle, companion handshake
│       ├── companion.cpp            # root-side: config, logs, oat eviction
│       ├── got/
│       │   ├── got_hook.h
│       │   └── got_hook.cpp         # .rela.plt walker + slot rewriter
│       ├── art/
│       │   ├── art_api.h
│       │   ├── art_probe.cpp        # version detect, ELF contract resolution
│       │   └── art_contracts.cpp    # per-version GOT edge + symbol candidates
│       ├── dex/
│       │   ├── dex_format.h
│       │   ├── dex_parser.cpp
│       │   ├── dex_patcher.cpp
│       │   └── dex_intercept.cpp    # adler32 GOT hook, patch-at-verify
│       ├── tls/
│       │   ├── conscrypt_wrap.cpp   # B1 custom_verify wrap
│       │   └── bundled_tls.cpp      # B2
│       ├── hooks/
│       │   ├── hook_manager.h
│       │   ├── hook_manager.cpp     # tier gate, GOT-vs-inline selection
│       │   ├── targets_java.h/.cpp
│       │   └── targets_native.h/.cpp
│       ├── config/
│       │   ├── config.h
│       │   ├── config.cpp
│       │   └── json.hpp             # nlohmann/json single header
│       ├── log/
│       │   ├── log.h
│       │   └── log.cpp              # forwards to companion socket
│       └── third_party/shadowhook/  # submodule, pinned tag, balanced tier only
├── tools/
│   ├── package.sh
│   ├── pull_reference_libs.sh       # Pixel factory image → reference-libs/
│   ├── check_elf_contracts.sh       # readelf -r assertions, runs in CI
│   └── verify_install.sh
├── tests/
│   ├── dex_patcher/                 # host-side unit tests + d8-built fixtures
│   └── test-app/                    # OkHttp + custom TrustManager + NSC pins
├── docs/
│   ├── architecture.md
│   ├── detection-model.md           # §1 of this plan, user-facing
│   ├── stealth-tiers.md             # §2
│   ├── coverage.md                  # §2.4 ladder, surface → required tier
│   ├── adding-hooks.md
│   ├── android-versions.md
│   ├── known-limitations.md
│   ├── testing.md
│   └── threat-model.md
└── examples/config.example.json
```

`tools/reference-libs/<api>/` is gitignored. It holds `libart.so`, `libartbase.so`, `libdexfile.so`,
`libjavacrypto.so`, `libssl.so` per API level — not just libart, because the ELF contracts we depend
on span all five.

---

## Phase 0 — Bootstrap

1. Repo structure as above, placeholders where content comes later.
2. `module.prop`:
   ```
   id=pinning_haters
   name=pinning-haters
   version=v0.1.0
   versionCode=1
   author=morkin1792
   description=Bypass TLS certificate pinning on Android apps. Zygisk-based, stealth-first, opt-in per package.
   updateJson=https://raw.githubusercontent.com/morkin1792/pinning-haters/main/module/update.json
   ```
3. Build skeleton: a Zygisk module that resolves its own Android version, connects to its companion,
   and returns. Verify it loads under Magisk, KernelSU+ZygiskNext, APatch+Zygisk.
4. CI: release zip on tag.
5. README scaffold, DISCLAIMER.md.

**Exit criteria**: tagged release installs cleanly on three hosts; companion handshake succeeds;
non-target processes `dlclose` the library.

---

## Phase 0.5 — ELF contract spike (BLOCKING)

The whole `max` tier rests on three GOT edges existing and one behaviour holding. Verify before
building anything on top. Most of this is host-side and cheap.

### Host-side, from `tools/reference-libs/<api>/`, for API 30, 31, 33, 34, 35, 36

1. `libjavacrypto.so` has a `R_AARCH64_JUMP_SLOT` relocation for `SSL_CTX_set_custom_verify` and/or
   `SSL_set_custom_verify`:
   ```bash
   readelf -r libjavacrypto.so | grep -E 'SSL_(CTX_)?set_custom_verify'
   ```
2. `libdexfile.so` has a `JUMP_SLOT` for `adler32`:
   ```bash
   readelf -r libdexfile.so | grep adler32
   ```
3. Which ART APEX library carries the `stat` / `stat64` / `fstatat64` / `openat` import used to probe
   for vdex files — enumerate `libart.so`, `libartbase.so`, `libdexfile.so` and record where the slot
   is per API level. Do not assume; the code uses a candidate list over all three.

Codify all three as assertions in `tools/check_elf_contracts.sh` and wire into `contract.yml`. A
future Android version that breaks a contract then fails CI instead of failing silently on a user's
device.

### On-device, with a throwaway probe module

4. **Is `verify_checksum` true for the app's primary DEX when no vdex is present?** This is the one
   that can invalidate the design. The `adler32` interception only fires if `DexFileVerifier`
   actually computes the checksum. Log from the hook; confirm it fires once per DEX with a non-null
   buffer on API 30–36.
5. **Does the conscrypt wrap complete a handshake?** Call conscrypt's original verify callback, and
   when it returns `ssl_verify_invalid`, clear the pending Java exception and return `ssl_verify_ok`.
   Confirm the handshake completes and the app's `TrustManager` still observes having been invoked,
   on API 30–36.
6. **Does companion-side oat eviction hold for the launch?** Delete the target package's
   `base.odex` / `base.vdex` immediately before launch and confirm ART runs from the APK's DEX
   (interpreter + JIT) without synchronously regenerating them.

### Outcomes

- All pass → build Phase 1 as written.
- (1) fails on some API → that API's platform-TLS target drops to `balanced` with an inline hook on
  `SSL_CTX_set_custom_verify` in the conscrypt `libssl.so`. Record in `art_contracts.cpp`.
- (2) or (4) fails on some API → that API's Java path drops to `balanced` with an inline hook on
  `art::DexFileLoader::OpenCommon`. Record it; do not silently ship a Java path that never fires.
- (5) fails → platform TLS falls back to replacing the callback outright instead of wrapping it.
  Louder (the app's `TrustManager` is no longer invoked, which is itself detectable) but still
  `max`-tier in terms of bytes modified.

Write results into `docs/android-versions.md`. This document is the record of what was actually
verified versus assumed.

---

## Phase 1 — Core

### 1.1 — GOT/PLT rewriter

**Files**: `got/got_hook.{h,cpp}`

Own implementation, roughly 150 lines. Not a dependency: bhook can do this but drags in a dlopen
monitor and background threads we do not want in the process.

Mechanics:

1. Locate the target library's load bias and `PT_DYNAMIC` by reading `dl_iterate_phdr`. Reading it is
   fine; we never hook or filter it.
2. From `PT_DYNAMIC` take `DT_JMPREL` and `DT_PLTRELSZ` — the `.rela.plt` table — plus `DT_SYMTAB`
   and `DT_STRTAB` for symbol names.
3. Only `.rela.plt` is needed. Imported *function* symbols on ARM64 get `R_AARCH64_JUMP_SLOT`
   entries there, and `.rela.plt` is never subject to Android's packed-relocation encoding (only
   `.rela.dyn` is). This is why the implementation stays small.
4. Match on symbol name, `mprotect` the containing page to `PROT_READ|PROT_WRITE` (full RELRO leaves
   the GOT read-only after relocation), write the replacement address, restore the original
   protection.
5. Record the original value so the replacement can call through, and so the slot can be restored.

API:

```cpp
namespace got {
  // Rewrite the GOT slot for `symbol` in `library`. Returns the original value, or nullptr.
  void* hook(const char* library, const char* symbol, void* replacement);
  bool  restore(const char* library, const char* symbol);
  // Does the edge exist at all? Used for presence detection and tier reporting; no modification.
  bool  has_edge(const char* library, const char* symbol);
}
```

**Known limitation to document in `docs/detection-model.md`**: if the provider and consumer are the
same library, or the library was linked `-Bsymbolic`, no slot exists and the target must fall to an
inline hook at `balanced`. `has_edge` is how the module discovers this and reports it through the
coverage ladder.

### 1.2 — Companion process (config, logging, oat eviction)

**Files**: `companion.cpp`, `config/config.{h,cpp}`, `log/log.{h,cpp}`

This is mandatory, not an optimisation. Module code in `postAppSpecialize` runs as the app's UID in
the `untrusted_app` SELinux domain. It **cannot** read `/data/adb/pinning_haters/config.json` and
**cannot** write to `/sdcard` under scoped storage. A build without a companion reads no config and
writes no logs — the v1 plan's §1.7 and §1.8 paths were not reachable from where they were called.

Design:

- Register the companion with `REGISTER_ZYGISK_COMPANION`. It runs as root in the Zygisk daemon.
- In `preAppSpecialize`: read the process's package name and UID from the Zygisk args, call
  `connectCompanion()`, send `{package, uid, api_level}`.
- Companion re-reads the config file on every request (small file, microseconds, no stale state),
  resolves the per-package tier, and replies with a fixed-size decision struct: target or not,
  effective tier, surface toggles, hostname-relaxation flag, log flags.
- **Not a target** → set `DLCLOSE_MODULE_LIBRARY`, return. Nothing else happens.
- **Target** → keep the socket for the lifetime of hook installation and use it as the log sink.
- Companion performs oat eviction (§1.5) before replying, because only it has the privilege.

Logging: records travel over the companion socket; the companion writes
`/data/adb/pinning_haters/log/<package>-<timestamp>.log`, mode 0600, root-owned.

**Superseded v1 decision**: logs no longer go to `/sdcard/pinning-haters/log/`. Not because of
sensitivity — the v1 reasoning that our internal state is not very sensitive was fine — but because
the app process cannot write there, and because a world-readable log is a trivially greppable
indicator for an app that wants to know whether this tool is on the device. Not logcat either, for
the same reason: an app can read its own process's logcat. Rotation: delete files older than 7 days
on companion start; cap the directory at 100 MB, oldest first.

### 1.3 — Package gate

**File**: `module.cpp`

The decision comes from the companion (§1.2), so there is no in-process config parsing and no
in-process file access. On a non-target, request unload and return before installing anything. There
is no denylist mode to implement.

### 1.4 — Platform TLS: the conscrypt wrap

**File**: `tls/conscrypt_wrap.cpp`. `min_tier: max`.

```
got::hook("libjavacrypto.so", "SSL_CTX_set_custom_verify", &our_set_custom_verify);
got::hook("libjavacrypto.so", "SSL_set_custom_verify",     &our_set_custom_verify_ssl);
```

Our replacement calls the original with **our** callback in place of conscrypt's, remembering
conscrypt's. Our callback:

1. Invokes conscrypt's original callback.
2. If it returned `ssl_verify_ok`, return that. Nothing to do.
3. Otherwise, conscrypt has a pending Java exception (a `CertificateException` from the
   `TrustManager`). Get the `JNIEnv` for the current thread from the cached `JavaVM`, call
   `ExceptionClear()`, and return `ssl_verify_ok`.

**Wrap, do not replace.** Running the app's real `TrustManager` and then discarding its verdict
preserves every observable side effect: the `TrustManager` is constructed, invoked, its logging runs,
and a check of the form "was my custom trust manager actually called" passes. Replacing the callback
outright is one line simpler and strictly louder.

This is the hook that reaches platform trust, Network Security Config pin-sets, TrustKit, custom
`X509TrustManager` implementations, Volley, gRPC-over-OkHttp, and Cronet's system-trust path — none
of which are reachable by DEX patching, because all of them live on the bootclasspath or are invoked
from it.

**Deferred load**: zygote normally preloads conscrypt, so `libjavacrypto.so` is already mapped at
`postAppSpecialize`. If `has_edge` reports it absent, register the target with the deferred-load
mechanism in §1.8 rather than polling.

### 1.5 — AOT: oat eviction, with a GOT fallback

**Primary, companion-side, zero in-process footprint.** When ART has compiled code for a method in
the package's `.odex`, it runs that code and the DEX bytes are irrelevant — so a DEX patch works on
the day it is applied and silently dies after the next overnight `bg-dexopt`. The v1 plan did not
address this at all.

The companion, which already has root and is already in the launch path, deletes the target
package's oat artifacts before replying:

```
/data/app/~~*/<package>-*/oat/arm64/base.odex
/data/app/~~*/<package>-*/oat/arm64/base.vdex
```

ART then opens the DEX from the APK and runs it under the interpreter plus JIT. App start is slower.
That is the whole cost, and it modifies nothing inside the app process.

Two details that matter:

- Deleting the artifacts is required, not `pm compile --reset` and not
  `--compiler-filter=verify`. A `verify`-filter vdex still carries `VerifierDeps`, which makes ART
  skip `DexFileVerifier` — and skipping the verifier means the `adler32` interception in §1.6 never
  fires. We need *no vdex at all*.
- Secondary DEX (`DexClassLoader`, feature splits) has its own oat artifacts in the app's data
  directory; enumerate and evict those too.

**Fallback, in-process, `min_tier: max`.** `aot.stat_hook_fallback` GOT-hooks the `stat` family
import in whichever ART library carries it (candidate list from Phase 0.5 item 3) and returns
`ENOENT` for paths ending in `.vdex` / `.odex`. ART fast-fails the oat open and falls back to the
APK's DEX. Use this when eviction is not possible (read-only path, unusual install layout) or when a
DEX is opened mid-run. It is a GOT write in an ART library, not libc, so it stays within `max`.

### 1.6 — DEX patching at verification time

**Files**: `dex/dex_format.h`, `dex/dex_parser.cpp`, `dex/dex_patcher.cpp`, `dex/dex_intercept.cpp`

**Interception point**: the `adler32` GOT slot in `libdexfile.so`. `min_tier: max`.

`DexFileVerifier::CheckHeader` computes the file's Adler-32 over everything after `magic` and
`checksum` and compares it to the header field. It does that by calling zlib's `adler32` — a
cross-library call, so there is a GOT slot. Our replacement:

1. Ignore the initialiser call (`buf == nullptr`, used to seed the running sum).
2. On the real call, `buf - 12` is the DEX base and `len + 12` is the DEX size. Call the original
   `adler32` **first** and keep the result — that is the checksum of the *unpatched* bytes.
3. Patch the DEX in place (below).
4. Return the saved original checksum.

The verifier compares our returned value against the untouched header field, they match, and
verification proceeds over the patched DEX. **We never rewrite the header checksum**, so the header
and the APK on disk stay consistent; only `insns[]` differ in memory.

Why this point rather than hooking `DexFileLoader::OpenCommon`: `OpenCommon` requires an inline hook
in `libdexfile.so` (`balanced`, text modified, CRC-detectable) plus per-version knowledge of the
`DexFile` object layout, and LSPlant-family projects have no DexFile symbol candidates to copy. The
`adler32` edge needs neither. It is also a single choke point covering the primary APK, feature
splits, `DexClassLoader`, and `InMemoryDexClassLoader`, because all of them are verified.

Its dependency, and the reason Phase 0.5 item 4 is blocking: it only fires when verification
actually runs. §1.5 is what guarantees that, by ensuring there is never a vdex whose `VerifierDeps`
would let ART skip the verifier. The two mechanisms are coupled by design; neither works alone.

**Patch mechanics** — several corrections to v1:

1. **Make the page private and writable**: `mprotect(page, len, PROT_READ|PROT_WRITE)`, write,
   `mprotect` back to `PROT_READ`. The mapping is `MAP_PRIVATE` file-backed (or a memfd for
   in-memory DEX), so the write triggers copy-on-write and touches neither the file nor another
   process.
2. **No `madvise(MADV_DONTNEED)`.** v1 called for this and v1's AGENTS.md defended it as deliberate.
   It is wrong. App DEX mappings are created after fork and are not shared with zygote, so there is
   nothing to detach; and on an anonymous mapping — which is what a DEX extracted from a compressed
   APK entry lives in — `MADV_DONTNEED` zero-fills the page and corrupts the DEX. Removed.
3. **Never change `insns_size`.** Overwrite the leading instruction units in place and leave the
   size field alone. This sidesteps the `tries[]` / `handlers[]` offset problem entirely.
4. **Nop-fill the remainder of `insns[]`.** This is the correction that matters most. v1 said to
   leave the trailing bytes alone because "ART won't execute past `return`" — true of *execution*,
   false of *verification*. `DexFileVerifier` does a linear sweep of the whole instruction array, so
   if our 2-byte `return-void` lands where a 4-byte instruction began, the byte at offset 2 is the
   second half of that instruction and the sweep hits an invalid opcode. Verification then fails and
   the class is rejected. Writing `nop` (`0x0000`) over everything from the end of the replacement to
   `insns_size` keeps the sweep valid, keeps every `try` / `catch` address on a legal instruction
   boundary, and costs one `memset`-shaped write.
5. **Verify capacity before writing.** Require `insns_size >= units_needed`. Bail and log otherwise.
6. **Finish before returning.** All patching completes inside our `adler32` replacement, before the
   verifier proceeds.

Replacement templates (`dex/dex_format.h` gets named constants for every opcode):

```
RETURN_VOID   : 0E 00                      ; 1 unit
RETURN_TRUE   : 12 10  0F 00               ; 2 units  (const/4 v0,1 ; return v0)
RETURN_FALSE  : 12 00  0F 00               ; 2 units
```

`RETURN_FIRST_ARG` is not implemented in Phase 1 — see §3.1.

**Host-side unit tests** (`tests/dex_patcher/`): the patcher is a pure function from bytes to bytes,
so the v1 claim that no unit testing is possible without a device is false. Build fixture DEX files
with `d8`, run the parser and patcher on the host, assert the patched output still passes a DEX
verifier and that the target method's instruction stream is what we expect. Runs in CI on every push.

### 1.7 — Java target list

**File**: `hooks/targets_java.cpp`

```cpp
struct JavaTarget {
  const char*      class_descriptor;   // "Lokhttp3/CertificatePinner;"
  const char*      method_name;        // "check"
  const char*      method_signature;   // "(Ljava/lang/String;Ljava/util/List;)V"
  ReplacementKind  replacement;        // RETURN_VOID | RETURN_TRUE | RETURN_FALSE
  Tier             min_tier;           // MAX for everything shipping in Phase 1
  SurfaceId        surface;            // for the coverage ladder
  const char*      label;              // "okhttp3.CertificatePinner v3-v4"
};
```

Phase 1 list, deliberately short — everything that used to pad it out is reached by §1.4 instead:

- `Lokhttp3/CertificatePinner;->check(Ljava/lang/String;Ljava/util/List;)V` → `RETURN_VOID`
- `Lokhttp3/CertificatePinner;->check(Ljava/lang/String;[Ljava/security/cert/Certificate;)V` → `RETURN_VOID`
- `Lokhttp3/CertificatePinner;->check$okhttp(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V` → `RETURN_VOID`
- `Lokhttp3/CertificatePinner;->check(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V` → `RETURN_VOID`

A target absent from the app is skipped silently and logged as `present=no`. That is the normal case
for most entries in most apps.

### 1.8 — Deferred library loads

**File**: `hooks/hook_manager.cpp`

Some targets live in libraries loaded after `postAppSpecialize`: `libflutter.so`, `libcronet.*.so`,
app-private `libssl.so`, `libil2cpp.so`.

**Mechanism**: GOT-hook `android_dlopen_ext` **in `libart.so`**. Every `System.loadLibrary` from Java
routes through `JavaVMExt::LoadNativeLibrary` to `android_dlopen_ext`, which is a cross-library call
into libdl — so the slot exists. This is a GOT write in an ART library, `min_tier: max`.

Critically, this is *not* an inline hook on libc's `dlopen`, which is what the v1 plan implied and
which would be primitive #6, the loudest thing on the list.

After each load, re-evaluate pending native targets and install the ones that now resolve. Native
libraries that `dlopen` other native libraries directly are not caught by this; when that case shows
up, GOT-hook `android_dlopen_ext` in the loading library once it is known.

### 1.9 — Bundled TLS targets

**File**: `hooks/targets_native.cpp`, `tls/bundled_tls.cpp`

```cpp
struct NativeTarget {
  const char*  provider_library;   // where the symbol is defined, e.g. "libssl.so"
  const char*  symbol;
  const char*  consumer_library;   // where to rewrite the GOT slot; nullptr = any consumer
  void*        replacement;
  HookStyle    style;              // GOT_IN_CONSUMER | INLINE_IN_PROVIDER | PATTERN
  Tier         min_tier;
  SurfaceId    surface;
  const char*  label;
};
```

The `style` field is what encodes "prefer GOT, fall back to inline" as *data* rather than as
per-target C++ logic, satisfying the hooks-are-data rule. `hook_manager` picks the quietest listed
style that both resolves and is permitted by the tier ceiling, and reports the rest through the
coverage ladder.

Phase 1 entries, all `GOT_IN_CONSUMER` where a consumer is identifiable:

- `SSL_CTX_set_verify`, `SSL_set_verify` → call original with `SSL_VERIFY_NONE` and a null callback.
- `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify` → substitute a callback returning
  `ssl_verify_ok`.
- `SSL_CTX_set_cert_verify_callback` → substitute a callback returning 1.
- `SSL_get_verify_result` → return 0 (`X509_V_OK`).
- `X509_verify_cert` → return 1.

Consumer libraries worth listing by default: `libcurl.so`, `libgrpc*.so`, `libcronet*.so`, plus any
app-private library that imports these symbols, discovered by walking `.rela.plt` of loaded
libraries. Flutter and stripped-static BoringSSL are `PATTERN` entries at `min_tier: balanced`;
they ship in the table in Phase 1 but only install when the user raises the tier.

### 1.10 — Hostname verification (opt-in, separate)

Hostname verification is not pinning. An interception proxy that presents a certificate for the
right host does not need it relaxed, and relaxing it by default would weaken the target app further
than the user asked. Gated behind `relax_hostname_verification: false`.

Group contents: `Lorg/apache/http/conn/ssl/AbstractVerifier;->verify(...)` (both overloads, moved
out of the v1 pinning list where it was miscategorised), `Lokhttp3/internal/tls/OkHostnameVerifier;`
and `javax.net.ssl.HostnameVerifier` implementations.

### 1.11 — Stealth hygiene (deliberately small)

What is in scope for Phase 1:

1. `DLCLOSE_MODULE_LIBRARY` on every non-target process.
2. No RWX pages. Verify shadowhook's configuration does not create any, even though it is only
   reachable at `balanced`.
3. Restore GOT page protections immediately after each write.
4. No threads created in the target process. Log records go out over the companion socket on the
   calling thread.
5. No files opened, created, or stat'ed by us in the target process. The companion does all file work.

What is explicitly **cut** from the v1 plan, with reasons:

| v1 §1.9 item | Why cut |
|---|---|
| Filter `/proc/self/maps`, `smaps`, `status` | Requires inline hooks on `open`/`openat`/`fopen` in libc — primitive #6, the most CRC-verified library on the device. It defends only against apps that already hunt for injected libraries, i.e. RASP, which Phase 1 does not engage. Net effect on a non-RASP app: strictly more detectable than doing nothing. Hiding our `.so` is the host's job (§0, host tiers). |
| Filter `dl_iterate_phdr` | Same reasoning. We *read* `dl_iterate_phdr`; we do not hook it. |
| Hide `/data/adb/pinning_haters/*` behind `ENOENT` | Nothing in the target process ever touches those paths now that the companion owns them, and an app cannot read them anyway. The hook would create the exposure it was meant to remove. |
| `getprop` filtering | We set no properties. Nothing to hide. |

These techniques return in Phase 2.2, where there is finally something
shooting at them and where the CRC countermeasures that make them survivable also exist.

### 1.12 — WebUI

`module/webroot/`, vanilla JS, no build step, dark by default, no external assets.

- Current global tier, with an explanation of what each tier exposes (sourced from `docs/stealth-tiers.md`).
- Package list: add, remove, per-package tier override.
- `pm list packages` picker.
- Surface toggles and the hostname-relaxation toggle, collapsed under "advanced".
- Log on/off, verbose on/off, and a viewer that renders the most recent log with the coverage-ladder
  lines highlighted — this is the primary "why didn't my bypass work" surface.

Shell bridge via `ksu.exec` (APatch is API-compatible). Magisk Manager has no WebUI; those users edit
the JSON, documented in README with a copy-paste `adb` recipe.

### 1.13 — Build, test infrastructure, CI

`tools/package.sh`: arm64-v8a only, strip release symbols, assemble zip.

`.github/workflows/contract.yml`, on every push:
- `tools/check_elf_contracts.sh` — the Phase 0.5 assertions against `tools/reference-libs/`. A new
  Android version that moves one of our GOT edges fails CI rather than failing on a device. This is
  v1's §1.5.5, promoted from Phase 1.5 into Phase 1 because the `max` tier depends on these edges
  existing.
- `tests/dex_patcher/` host-side unit tests.

`.github/workflows/build.yml`, on `v*` tags: build, release, attach zip, update `update.json`.

### 1.14 — Manual test matrix

`docs/testing.md`. Android 11, 12, 13, 14, 15, 16 × Magisk, KernelSU+ZygiskNext, APatch+Zygisk.

`tests/test-app/` must exercise, in one APK, the four things that distinguish this architecture:
a custom `X509TrustManager` (→ §1.4 wrap, and asserts the `TrustManager` still ran), Network
Security Config pin-sets (→ §1.4), OkHttp `CertificatePinner` (→ §1.6 DEX patch), and a post-handshake
manual digest comparison (→ expected to *fail* at `max` with a coverage-ladder line pointing at
`compat`). A test app where everything passes teaches nothing about the tier boundaries.

Plus three real apps from F-Droid that ship pinning, and a Flutter sample app for the
`balanced`-tier path.

### 1.15 — Documentation

`README.md`, `docs/architecture.md`, `docs/detection-model.md` (§1), `docs/stealth-tiers.md` (§2),
`docs/coverage.md` (§2.4), `docs/adding-hooks.md`, `docs/android-versions.md` (including the Phase 0.5
verification record), `docs/known-limitations.md`, `docs/threat-model.md`.

`docs/known-limitations.md` must name, explicitly: TEE/StrongBox pinning (never), Dart-side and
IL2CPP and Mono pinning (`compat`, Phase 2), app-specific post-handshake checks (per-app targets),
slower app start caused by oat eviction, and Magisk's visible module mapping.

### 1.16 — Phase 1 exit criteria

1. Phase 0.5 contracts pass on API 30–36, recorded in `docs/android-versions.md`.
2. Installs cleanly on Magisk, KernelSU+ZygiskNext, APatch+Zygisk.
3. Test matrix passes on Android 11, 12, 13, 14, 15.
4. On `tests/test-app/`: platform-trust pinning, NSC pin-sets and OkHttp `CertificatePinner` all
   bypassed at `max`; the app's custom `TrustManager` is confirmed to have been invoked; the
   post-handshake manual check correctly fails with a coverage line naming `compat`.
5. Bypass verified on at least three real F-Droid apps that ship pinning.
6. **Zero executable bytes modified at `max`**, verified mechanically: CRC every mapped library's
   executable segment against its file on disk from inside a target process, and assert equality.
   This is the headline property of the architecture; it gets an automated check, not an assertion.
7. Bypass survives an overnight `bg-dexopt` cycle (proves §1.5 works).
8. WebUI functional on KernelSU and APatch; documented JSON path works for Magisk.
9. No crashes in 24 hours of normal device use.
10. Docs complete, including the coverage ladder.

---

## Phase 1.5 — `balanced` tier

> **Status (2026-10-25).** The Flutter item shipped without shadowhook: `libflutter.so`'s
> BoringSSL is reached by swapping the `session_verify_cert_chain` pointer in its
> `ssl_crypto_x509_method` table, located from the `"ssl_client"`/`"ssl_server"` purpose strings.
> No executable bytes change, so the entry sits at `max` (owner decision, same day). The inline
> backend (shadowhook) is deferred until a table entry needs it; see AGENTS.md "Phase 1.5, Flutter".


Each item independently shippable.

1. **Inline hook backend.** Wire shadowhook in behind the `INLINE_IN_PROVIDER` style, gated on tier.
2. **Flutter.** Pattern-locate `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so`, or walk
   back from the `SSL_CTX_set_custom_verify` call site. Maintain patterns per Flutter version range.
3. **Static stripped BoringSSL.** Pattern scan for the verification entry points in app-private libraries.
4. **`OpenCommon` fallback** for any Android version where Phase 0.5 item 2 or 4 failed.
5. **CRC countermeasures** become mandatory here, not optional — see Phase 2.1. A `balanced` build
   without them is detectable by exactly the check `update1.md` describes.
6. **Additional Category A surfaces** as issues arrive: Certificate Transparency interceptors,
   Volley, gRPC-Java direct, `WebViewClient` patterns.
7. **Android 10 (API 29)** backend, if it was dropped in Phase 1.
8. Diagnostic improvements: patched-bytecode hashing to detect re-patching, per-package summary at exit.

---

## Phase 2 — `compat` tier

The sections below are the original sketch. The detailed plan, written when Phase 2 started on
2026-10-26 with Phase 1 and 1.5 shipped, follows first.

### Phase 2 detailed plan (2026-10-26)

**What Phase 1 changed about Phase 2.** No inline hook exists, so §2.1's CRC countermeasures have
nothing to protect: deferred until a table entry needs `INLINE_IN_PROVIDER`. The module hides its
own mapping (`hide.self_remap`); the remaining in-process trace on Zygisk Next is the host's own
`libzygisk.so`, which is the host's to fix (§2.2 is done as far as this module can take it). Nothing
needed ArtMethod hooks (§2.5 stays unbuilt until a real case appears). Flutter and every static
BoringSSL landed at `max` through a data-pointer swap, so the "Category C" list shrank: what is
left is pure-Dart certificate comparison, Unity IL2CPP and Mono. Phase 2 therefore
runs on data: an inventory of the apps actually installed on the test phone, and per-app failures.

**Inventory of the test phone (72 third-party apps, 2026-10-26).** Pinning: OkHttp
`CertificatePinner` in 15 apps (covered). Packer: Bangcle DexHelper in a packed Flutter wallet app
(Flutter; did not start under `monkey`). Unity IL2CPP: three games, no pinning
expected. No app uses `http_certificate_pinning` or `ssl_pinning_plugin`. React Native apps ride
OkHttp.

**2.A Flutter pinning packages (done the same day).** Both popular packages check in the plugin's
Android code; they are DEX targets at `max` (`dart_pinning`). Pure-Dart comparison stays a marker.

**2.B RASP.** Root and tamper hiding moved to a separate module.

**2.C Unity IL2CPP and Mono.** No installed app pins there. Build the IL2CPP metadata resolver only
when an app asks for it. Mono `ServerCertificateValidationCallback`: same.

**2.D CRC countermeasures (§2.1).** Only when an inline hook ships. Not before.

**2.E Hosts.** Measure NeoZygisk and Magisk when a device is available: whether the host hides its
own library, whether modules are loaded through bionic (`loader=` in the init log), whether
`hide.self_remap` still finds its mapping.

**Not planned**: the recipe system (no demand yet), a companion app, x86_64.

### 2.1 — CRC countermeasures for inline hooks

Required by `balanced`, not by `max`. The recipe, from `update1.md`, corrected and ordered:

1. Install the inline hooks.
2. Dump the **post-hook** in-memory executable segment of each modified library.
3. Redirect disk reads of that library's path to the dump.
4. Both sides of any memory-vs-disk comparison now return the hooked bytes, so they match by
   construction.

Two refinements over the source material:

- **Dump only `PT_LOAD` segments with `PF_X`**, not the whole module. Whole-module dumps of a large
  library are slow and wasteful; only the segments our hooks touched matter.
- **Timing is a hard dependency.** The redirect must be active before any CRC check runs, and the
  dump must already contain the hooks. Reuse the §1.8 `android_dlopen_ext` GOT hook: when a library
  loads, dump-and-redirect every library we have inline-hooked before any of the new library's code
  runs.

**Tier this countermeasure, because a Zygisk module cannot deliver all of it:**

- **(a) In-process path redirection.** Intercept the file-read path from inside the process. Defeats
  RASP that reads through libc faithfully, which is most of it. Ships inside pinning-haters.
- **(b) Kernel-side redirection.** RASP that issues `svc #0` directly bypasses every userland hook,
  and no amount of in-process work reaches it. This needs a companion KernelSU/APatch kernel module
  intercepting the `openat` syscall path. It becomes a **separate optional component** and a
  documented requirement for "hardened mode" — not something the Zygisk module can claim to do.

State this boundary plainly in `docs/known-limitations.md` as soon as `balanced` ships: a
purely-Zygisk-resident solution cannot reach tier (b) coverage.

A cheaper partial measure worth trying before any of this: prefer **GOT hooks in the caller** even
at `balanced`, because they leave the provider's `.text` byte-identical to disk and its CRC clean.
`max`-tier targets already do this; the point is that some `balanced` targets may be convertible.

### 2.2 — Maximal stealth

Trampolines in existing library padding so no new mappings appear; polymorphic prologues against
signature scanners; thread naming and scheduling-class matching; anti-`process_vm_readv`;
anti-`memfd_create` reflection. Also where the §1.11 cut items return, now that there is something
to hide from and countermeasures to make them survivable.

### 2.3 — RASP defeat

Root and tamper hiding moved to a separate module.

### 2.4 — Foreign AOT runtimes

The Category C remainder from §3.3: Dart-side pinning packages in `libapp.so`, Unity IL2CPP via
`global-metadata.dat`, Xamarin/Mono assemblies. Each is a distinct toolchain problem. Sequence by
demand.

### 2.5 — ArtMethod fallback (conditional)

Only if Phase 1 and 1.5 surface real cases where the §1.6 path cannot reach a method. Bundle
LSPlant, add `HookStyle::ARTMETHOD` with `min_tier: compat`. It is primitive #7, the single loudest
thing on the ranking, which is why it is last and why there is a real chance it is never built. If
the DEX path reaches everything that matters, skip it.

### 2.6 — Cronet pin APIs, recipe system, companion app, x86_64

Cronet's own `CertVerifier` / pin configuration, beyond the system-trust path §1.4 already covers.
The recipe system only if issue volume proves demand (see AGENTS.md). Companion app probably never —
the WebUI is sufficient. x86_64 if emulator-based researchers turn up.

---

## Sequencing (TL;DR)

1. Phase 0 — skeleton, companion handshake, three hosts, CI.
2. **Phase 0.5 — ELF contract spike. Blocking. Do not skip.**
3. 1.1 GOT rewriter → 1.2 companion → 1.3 package gate.
4. 1.4 conscrypt wrap. Largest coverage win; ship and test it alone before touching DEX.
5. 1.5 oat eviction, then 1.6 DEX interception and patcher. Coupled; neither works alone.
6. 1.7 Java targets → 1.8 deferred loads → 1.9 bundled TLS → 1.10 hostname group.
7. 1.11 stealth hygiene, 1.12 WebUI, 1.13 CI, 1.14 matrix, 1.15 docs.
8. 1.16 exit criteria → tag v1.0.0.
9. Phase 1.5 (`balanced`) → Phase 2 (`compat`; separate detailed plan).

Order rationale: §1.4 alone reaches more pinning than the entire v1 Java target list did, and it
depends on nothing but §1.1 and §1.2. It is the shortest path to a module that works, and it is also
the cheapest thing to validate. The DEX path is strictly harder, strictly later, and only reaches
one additional surface class — albeit an important one, because OkHttp `CertificatePinner` is the
single most common explicit pinning implementation on Android.
