# Changelog

All notable changes to pinning-haters are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the module's `module.prop`.

## [0.1.0] - 2026-11-04

First code-complete cut of Phase 1 (the `max` tier) plus the Phase 1.5 and Phase 2 work recorded
below. Verified on two devices (Android 11, APatch + Zygisk Next; Android 16, KernelSU + Zygisk
Next). The release matrix in `docs/testing.md` asks for three Android versions; this tag ships on
two, and Android 12 to 15 and Magisk as a host are still pending (see the Status section of
`README.md`).

### Added

- WebUI log viewer: a summary above each log names the surfaces reached and those present but not reached (with reason, required tier and library), and counts WARN/ERROR lines. Computed in the WebUI from the coverage lines; the target process does nothing extra.
- CI builds the test app with a statically linked OpenSSL 3.4.1 (`tools/fetch_testapp_deps.sh`) and feeds that library to the host tests as an OpenSSL 3.2+ fixture.
- `tools/stability_run.sh`: the automated half of the 24-hour stability criterion.
- `static_openssl` surface at `max`: a statically linked OpenSSL 1.1.1 / 3.x in an app-private library is reached by swapping the `ssl_connect` member of its client `SSL_METHOD` table (`.data.rel.ro`, found through the library's `TLS_client_method`, `SSL_set_verify`, `SSL_get_verify_callback` and `SSL_set_verify_result` exports) for a wrapper that runs the handshake with `SSL_VERIFY_NONE` and stores `X509_V_OK`; the app's verify callback still runs. A build that hides those exports reports `pattern_not_found`; the BoringSSL backend no longer claims OpenSSL libraries. `got::find_export` (DT_HASH / DT_GNU_HASH) and `got::segments_contain` carry it; the host test covers an OpenVPN3 core and the test app bundles an NDK-built OpenSSL 3.0.16 (`OPENSSL_DIR`) for the on-device check.
- The GOT rewriter also rewrites `GLOB_DAT` slots, consumer lists accept a trailing `*`, and `NativeTarget::optional_edge` keeps a consumer's missing imports out of the ladder.
- `go_tls` and `rust_tls` markers: a Go `crypto/tls` or rustls stack statically linked into an app library is reported by the strings it carries, with the library named, so the ladder explains the failure instead of staying silent (`compat`, Phase 2; nothing is hooked).
- `bundled_tls` DEX rows for a Conscrypt the app bundles or Play services installs (`verifyCertificateChain` → return): the platform wrap in libjavacrypto never sees those handshakes. Measured on API 30 that `ProviderInstaller` loads no second stack when the Conscrypt APEX is present, so the rows are for older devices and bundled builds.
- `deferred_load` re-scans after every load in the process, not only after `System.loadLibrary`: the edge is `libdl.so`'s two import slots for the linker's `__loader_dlopen` / `__loader_android_dlopen_ext`, which every `dlopen` / `android_dlopen_ext` call passes through (Dart FFI's `DynamicLibrary.open`, plugin hosts, SDK loaders, packers). The caller address is forwarded unchanged, so names resolve in the real caller's namespace. Contract C3 and `test_got` check the slots on real `libdl.so` files; `tools/pull_reference_libs.sh` now pulls `libdl.so` from the runtime APEX.
- `tools/device_test.sh` (install through a new inode, unlock, config, ladder log, test-app verdicts, demo buttons by text, TCP 443 redirect, mappings) and `tools/dex_callers.py` (call-site finder for diagnosing an app). The host suite gained `test_self_remap`.
- `dart_pinning` targets at `max`: the Android-side `checkConnexion` of the Flutter `http_certificate_pinning` and `ssl_pinning_plugin` packages returns true. Gated by `surfaces.java_dex`; the `libapp.so` marker stays for pure-Dart comparisons.
- `hide.self_remap` (default on): after hooking, the module re-maps its own four mappings into anonymous memory, so its path is gone from `/proc/self/maps`. A generic detector app on Zygisk Next 1.4.5 now reports only the host's `libzygisk.so` in a targeted app. Hooks, the executable-bytes check and the log pipe are unaffected.
- `static_boringssl` surface at `max`: the Flutter method-table backend now runs on every app-private library (one wildcard `PATTERN` entry); originals are kept per library and picked by return address. Verified on the host against WebRTC, OpenTok and Brella builds, and against an OpenSSL build that must not match.
- `flutter` surface at `max`: the first `PATTERN`-style backend. `libflutter.so`'s hidden BoringSSL is reached by swapping the `session_verify_cert_chain` pointer in its `ssl_crypto_x509_method` table (`.data.rel.ro`); the function is located from the `"ssl_client"`/`"ssl_server"` purpose strings it references. Wraps the original, so Dart's `badCertificateCallback` still runs. No executable bytes change. `NativeTarget::locator` and `got::hook_slot` carry it; `tests/host/test_flutter` runs the locator over real engine builds. Flutter now lives under `surfaces.bundled_tls`; the `libflutter.so` runtime marker is gone (the entry reports instead).
- `chromium` surface: WebView / Cronet / HTTP/3 certificate verification bypassed at `max` by the new `CHROMIUM_TRUST_LEAF` kind (the chain's leaf is registered in Chromium's own test trust store before its real verifier runs). `RETURN_NEW_INSTANCE` is available as a generic kind.
- `certificate_transparency` surface: appmattus / babylon CT is disabled per host (`enabledForCertificateTransparency` → false) and its OkHttp interceptor passes through, via the new `INTERCEPTOR_PROCEED` replacement kind, at `max`.

- Zygisk module (API v4; Magisk 26+, KernelSU + ZygiskNext, KernelSU-Next + NeoZygisk, APatch)
  with a root companion that owns config parsing, per-package tier resolution, log files and oat
  eviction. The app process performs no file or property reads of ours.
- Own GOT/PLT rewriter over `.rela.plt` (`got/got_hook.cpp`), the primary hooking primitive. No
  executable bytes are modified at the default tier.
- Platform TLS bypass: wrap of conscrypt's certificate-verify callback through the
  `SSL_set_custom_verify` import of `libjavacrypto.so`. The app's `TrustManager` still runs; only a
  rejection is overridden.
- DEX patching at verification time through the `adler32` import of `libdexfile.so`, with nop-fill
  of the remaining instruction units and no change to `insns_size`, tries or handlers. DEX versions
  035 to 041 (including the Android 15 container format).
- Java targets: OkHttp `CertificatePinner.check` (four overloads, OkHttp 3.x to 5.x). Opt-in
  hostname-verification group (`relax_hostname_verification`): OkHttp `OkHostnameVerifier` and an
  app-bundled Apache `AbstractVerifier`.
- App-bundled BoringSSL/OpenSSL targets hooked in the calling library: `SSL_CTX_set_verify`,
  `SSL_set_verify`, `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify`,
  `SSL_CTX_set_cert_verify_callback`, `SSL_get_verify_result`, `X509_verify_cert`.
- Deferred-load support: native targets are re-evaluated after each library load (see the
  `deferred_load` entry above for the edge).
- Companion-side oat eviction (`/data/app/*/<pkg>-*/oat/*/*` plus oat artifacts under the app data
  directory) and an in-process fallback that hides oat artifacts from ART's `stat`/`open`/`access`
  imports.
- Stealth tiers (`max`, `balanced`, `compat`) as a filter over the target tables, with a global
  ceiling and per-package override. Only `max` has a backend in this release.
- Coverage ladder: one `[coverage]` log line per surface with `present`, `reachable`, `reason`,
  `required_tier` and `current_tier`. Presence markers for Flutter, Dart AOT, IL2CPP, Mono and
  Cronet.
- Logging over the companion socket to `/data/adb/pinning_haters/log/`, root-only, off by default,
  with 7-day / 100 MB rotation.
- Host-side tests: DEX parser and patcher on a d8-built fixture (re-dexed with d8 as a structural
  check), GOT rewriter against the test binary's own imports, config parser and decision logic.
- `tools/pull_reference_libs.sh` (reference libraries from AVD system images) and
  `tools/check_elf_contracts.sh` (the Phase 0.5 ELF contract assertions).
- Module packaging (`module.prop`, `customize.sh`, `service.sh`, `tools/package.sh`) and a WebUI for
  KernelSU and APatch managers.
- Documentation set under `docs/`.

### Removed

- App- and build-specific rows (one app's network-library probes, Topaz Heartbeat letter wrappers from one build, one Kony build's exit dispatcher) and the `NOP_CALLS` kind they alone used: the module ships generic surfaces only.
- The `rasp` surface (`surfaces.rasp`): the Java root-detection rows (RootBeer, jail-monkey, safe_device, freeRASP, Kony, Datablink), the root-indicator filter (`rasp/path_filter`), the `RETURN_NULL` kind and wildcard-class rows they alone used, `tools/device_trace.sh` and `tools/hprof_refs.py`. Root and tamper hiding moved to a separate module; pinning-haters is TLS-only.

### Fixed (review of 2026-11-01)

- GOT hooks published their original pointer only after the slot went live; a thread calling through the slot in that window jumped through null. Originals are now stored first, unresolved (null) weak imports are left alone, and the static BoringSSL / OpenSSL backends publish their per-library entry before the swap.
- OpenSSL 3.2 and later reorder `SSL_METHOD` (`ssl_connect` moved from +48 to +72): the swap took the wrong member there and reported success. The layout now follows the version text; `TLS_method`'s table is swapped too. Verified with NDK-built 3.0.16 and 3.4.1.
- `hide.self_remap` matched mappings by name only; on Magisk, whose module memfd shares ART's `jit-cache` name, it could have replaced the JIT cache's two views with private copies. It now matches device and inode as well, and runs before the hooks go live.
- The companion's secondary-DEX eviction walk ran as root over an app-writable directory, so a swapped-in symlink could steer the unlink outside it. The walk now runs with the directory owner's filesystem identity.
- A log file could grow without bound from the app side, and records could forge log lines; each file is capped at 16 MB and record newlines are flattened. `companion.log` is truncated past 1 MB. Socket writes no longer raise SIGPIPE, and the app's log pipe is non-blocking (a stalled companion drops records instead of parking app threads).
- The DEX interception changed page protection on every checksummed DEX and restored plain `PROT_READ`; it now touches only DEX that hold a target, requires one private mapping (never a shared one, never beyond it) and restores the original protection. A fresh copy of a patched DEX mapped at the same address is patched instead of being answered from the table.
- Try-range relocation could fail after a template was already written, leaving a method ART rejects; it now runs, and fails, before anything is written.
- The oat fallback no longer hides a system or product partition's odex/vdex when its APK or jar has no `classes.dex` (dex-stripped ROMs), which would have left the code unloadable.
- The deferred-load rescan could deadlock against the linker's lock when a library constructor reached a hooked `dlopen`; the wait is now bounded and the rescan handed to the lock holder.
- Smaller: `open(…, O_DIRECTORY)` no longer reads a mode argument that was never passed; the WebUI no longer breaks on a config without a `hide` section (every config from before that option).

### Fixed (2026-11-03)

- A React Native app carrying a protection SDK died with a null-pointer `SIGSEGV` about two seconds into every targeted launch, with every surface switched off and oat eviction disabled. The trigger was the deferred-load edge rewriting `dlopen` import slots inside the app's own libraries, the SDK's included, and the SDK verifies its `.got.plt`. The edge moved to `libdl.so`'s linker slots (above); the module writes no app-private GOT slot for it any more, and that app runs with every surface applied.

- Review of the libdl edge (same day): the evaluated-library set is dropped when the linker's unload counter moves (at most once every 5 s), so a library mapped into an address range a `dlclose` freed is evaluated instead of being mistaken for the one that used to live there; `RTLD_NOLOAD` probes and `dlopen(NULL)` no longer trigger a re-scan; the bounded wait in the dlopen hooks uses `CLOCK_MONOTONIC` (a wall-clock step could stretch the 200 ms bound); the two libdl rows are marked load-bearing, so a missing `__loader_android_dlopen_ext` slot is a `contract_missing` line even when the `__loader_dlopen` slot was rewritten; `skip_consumers` now applies to GOT rows as well as pattern rows; the Go/Rust string markers skip Chromium's libraries like the table rows do.

### Known gaps in this release

- Release matrix: passes on Android 11 (APatch + Zygisk Next) and Android 16 (KernelSU + Zygisk
  Next 1.5.0) only; Android 12 to 15 and Magisk as a host are untested.
- Real apps with enforced pins verified end to end: the HTTP Toolkit demo and a Flutter bank app on
  Android 11, a React Native app carrying a protection SDK on Android 16. The plan asks for three
  F-Droid apps.
- `INLINE_IN_PROVIDER` has no backend (shadowhook is not vendored); no table row needs it today.
  `balanced` and `compat` change only what the coverage log says.
- Stability evidence is automated launch churn (`tools/stability_ondevice.sh`: clean stretches of
  10.5 h, 4 h and 2 h on earlier builds, a 20-minute 60-second-interval run on the release
  candidate), not 24 hours of hands-on use.
- WebUI verified in the APatch manager only; KernelSU's manager and the Magisk JSON path are not
  recorded.
