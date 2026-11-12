# Known limitations

What pinning-haters does not reach, and what it costs. Entries marked *permanent* are design
boundaries; the rest are tier or phase boundaries with a planned path.

## Never reachable (permanent)

- **TEE / StrongBox-backed pinning.** A chain validated inside TrustZone or a StrongBox applet,
  with the verdict attested by hardware, cannot be altered by anything running in the rich execution
  environment. No tier will ever reach it.
- **Kernel-level coverage of CRC countermeasures.** A purely Zygisk-resident module cannot intercept
  an anti-tamper library that issues `openat` through a raw `svc` instruction. That is a documented
  boundary for the `balanced` tier's future CRC countermeasures, not a gap that will be quietly
  closed; it would need a separate kernel-module component.

## Out of reach in v0.1.0 (tier or phase boundary)

- **Dart-side pinning packages** (`http_certificate_pinning`, `ssl_pinning_plugin`, Dio
  interceptors) do their digest comparison in AOT-compiled Dart inside `libapp.so` and abort before
  the handshake completes; no TLS hook ever fires. `compat`, Phase 2. Reported as `dart_pinning`.
- **Unity IL2CPP custom pinning** (`CertificateHandler`, manual chain walks) is stripped native code
  in `libil2cpp.so`. `compat`, Phase 2. Reported as `unity_il2cpp`. Platform-trust pinning in a
  Unity app that uses platform HTTP is still reached by `platform_tls`.
- **Xamarin / .NET MAUI `ServerCertificateValidationCallback`** lives in Mono assemblies, not in DEX.
  `compat`, Phase 2. Reported as `xamarin_mono`.
- **Go and Rust TLS stacks** (`crypto/tls` in a gomobile library, rustls in a Rust library) verify
  chains inside their own code with no symbol and no table to reach; a pin there is a
  `VerifyPeerCertificate` or `ServerCertVerifier` closure. `compat`, Phase 2. Reported as `go_tls`
  and `rust_tls`, found by the strings those stacks always carry, with the library named.
- **Flutter's own TLS** (`dart:io` over the BoringSSL built into `libflutter.so`, hidden visibility,
  no exported `SSL_*`) is reached at `max` through a pointer swap in BoringSSL's
  `ssl_crypto_x509_method` table, located by heuristic. Reported as `flutter`. Two things the module
  cannot change: `dart:io` ignores the Android HTTP proxy setting and user-installed CAs, so Flutter
  traffic only reaches a proxy through an invisible listener plus traffic redirection (the
  per-package `redirect` key does the redirection; `docs/reference.md`); and a Flutter
  engine built from a BoringSSL that no longer references the `"ssl_client"`/`"ssl_server"` purpose
  strings makes the locator return nothing (the ladder then says `reason=pattern_not_found`;
  `tests/host/test_boringssl_table` against the engine's `libflutter.so` is the check).
- **Root and tamper detection.** Not this module's job: it changes TLS verification only, and an
  app that refuses to run on a rooted device stays refused. Root and tamper hiding moved to a
  separate module.
- **Flutter pinning packages.** `http_certificate_pinning` and `ssl_pinning_plugin` are patched
  (`dart_pinning`), because their comparison runs in the plugin's Android code. A Dart
  `badCertificateCallback` or a custom `SecurityContext` is already covered by the BoringSSL swap.
  What is not reached: an app that reads `SecureSocket.peerCertificate` in Dart and compares digests
  itself; that code is AOT-compiled into `libapp.so` (`compat`, Phase 2.4). R8 may rename plugin
  classes in a minified app, in which case the target reports `present=no`.
- **Statically linked BoringSSL** in an app-private library is reached at `max` through the same
  method-table swap as Flutter (`static_boringssl`), *if* its chain check runs through the classic
  `SSL_CTX_set_verify` path. A static BoringSSL whose user installed a custom-verify callback
  (`SSL_CTX_set_custom_verify`, as Cronet does) never consults the table; Cronet is reached through
  its Java verifier instead, anything else of that shape is not. **Statically linked OpenSSL** has no
  x509 method table, but its client `SSL_METHOD` is one, and `max` swaps that table's `ssl_connect`
  (`static_openssl`) when the build keeps its exports: the handshake runs with verification
  relaxed and the stored verify result reads OK. A build that hides `TLS_client_method` /
  `SSL_set_verify` / `SSL_get_verify_callback` / `SSL_set_verify_result` (hidden visibility, a
  version script) reports `static_openssl present=yes reachable=no reason=pattern_not_found`; that
  needs an inline hook (`balanced`, not shipped). Same for any library whose verify calls do not
  cross a library boundary and is neither BoringSSL nor OpenSSL. An app that checks the chain itself
  after the handshake (`SSL_get_peer_certificate` plus a digest compare) is per-app work either way.
- **Apps on adopted storage** (`/mnt/expand/<uuid>/`) are not evicted by the companion and are
  reported with `reason=system_app`; the DEX path then relies on `aot.stat_hook_fallback` alone.
- **Cronet.** Statically links BoringSSL, so the bundled-TLS slots do not exist; its own pin APIs
  are a separate matter. `balanced` for the TLS stack, `compat` for the pin APIs. Reported as
  `cronet`. Whether Cronet's default system-trust path passes through the conscrypt edge has not been
  verified on a device; the module does not count on it.
- **The `balanced` and `compat` tiers themselves.** No inline or pattern backend ships in v0.1.0.
  Raising the tier changes the coverage lines, not what is installed (`docs/stealth-tiers.md`).
- **libcurl `CURLOPT_PINNEDPUBLICKEY`.** curl compares the public key hash itself, inside libcurl,
  after the TLS backend has returned. The bundled-TLS hooks in `libcurl.so`'s GOT disable chain
  verification but do not reach curl's own comparison. Needs a per-library target (`balanced`,
  inline in libcurl, or a GOT edge if a future curl build calls out for the hash).
- **App-specific post-handshake checks.** Code that calls `getPeerCertificates()` and compares
  digests, `WebViewClient.onReceivedSslError` overrides, Certificate Transparency interceptors: these
  are per-app Java targets, not a default list. `docs/adding-hooks.md` describes how to add one.
  The signature in the proxy is a completed handshake followed by a client-side close.
- **Bootclasspath classes** cannot be patched: they are AOT-compiled into the boot image before the
  module exists. Everything that matters on the bootclasspath is reached through the conscrypt wrap
  instead, with one exception below.
- **Native TLS stacks accept a wrong hostname whenever they are targeted.** In Flutter, a static
  BoringSSL and a static OpenSSL the name check runs inside the chain verification the module
  overrides (`X509_verify_cert` with the host set as a verify parameter), so a certificate for
  another name is accepted whether `relax_hostname_verification` is on or off. When the chain is
  also untrusted, the name check is never even reached, so the override cannot tell the two apart
  and keep one. Java stacks are unaffected: their hostname verifiers run after the handshake and
  follow the switch. For an engagement this rarely matters (the proxy's certificate names the right
  host); it does mean the switch is not the whole story for native code.
- **The platform `org.apache.http.legacy`.** The hostname-verifier entries for
  `org.apache.http.conn.ssl.AbstractVerifier` reach only a copy the app bundles itself. The platform
  copy is a dexpreopted system library and is not reached by the DEX path.
- **`relax_hostname_verification` does not reach `HttpsURLConnection`'s default verifier.** That
  verifier is the platform's internal OkHttp copy (`com.android.okhttp`), bootclasspath, so it is
  not patchable; only app-bundled `okhttp3` and Apache verifiers are. Observed on the HTTP Toolkit
  demo (2026-10-25): with an untrusted proxy certificate for the *wrong* name, its
  `HttpsURLConnection` request stayed red at `max` with the switch on, while the Flutter request,
  whose hostname check sits inside `X509_verify_cert`, passed. Give the proxy a certificate whose
  name matches (Burp's per-host mode, or a custom certificate with the right SANs); hostname
  verification is not pinning and the module is not the tool for it.
- **DEX loaded with verification disabled** (for example `-Xverify:none` runtimes, or any path where
  ART skips `DexFileVerifier`, including a surviving vdex with `VerifierDeps`) is never seen by the
  `adler32` interception and is not patched. Oat eviction and the stat fallback exist to prevent the
  vdex case; `docs/coverage.md` explains how to tell when it happened.
- **Native libraries loaded without `libdl.so`** (a loader that calls the linker by hand or maps
  ELF images itself) are not re-scanned. Everything that goes through `dlopen` /
  `android_dlopen_ext`, from Java or from native code, is.
- **Two different bundled TLS providers** in one process (two BoringSSL copies): the first one
  hooked wins for each symbol; the second is skipped with a warning, because the recorded original
  pointer can only belong to one provider.
- **Capacity ceilings**, chosen for a small footprint: at most 512 loaded libraries are examined,
  at most 256 GOT slots rewritten, and at most 64 patched DEX files remembered for re-checksum
  requests, per process. Apps beyond a ceiling get a warning line and the excess is not installed.
- **System and priv-apps** keep their oat artifacts on a read-only partition (`/system/app/<x>/oat/`)
  or in `/data/dalvik-cache/`. Nothing can be evicted there; the in-process stat fallback hides the
  `/oat/` ones so the DEX path still runs, but `/data/dalvik-cache/` entries are left alone (boot
  image extensions live next to them). The coverage line says `reason=system_app`.
- **x86_64** (emulators) is backlog. **ARM32** is out of scope. **Android 10** is unsupported.

## Costs you will notice

- **Slower app start for targeted packages.** Oat eviction means the app runs under the interpreter
  plus JIT for that launch, and ART may recompile in the background afterwards (which the companion
  evicts again at the next launch). This is the price of the DEX path working at all and is not a bug.
  It affects only packages in `packages`.
- **Absent oat artifacts are themselves observable.** An app that checks for its own `.odex` will
  notice. See `docs/threat-model.md`.
- **One extra file descriptor** in the target process while logging is enabled.
- **`redirect` covers port 443 over IPv4 only.** HTTP/3 and IPv6 are blocked for that app rather than
  intercepted, other ports are left alone, and the app loses HTTPS while the proxy is unreachable.
  Verified on Android 11 (APatch + Zygisk Next); KernelSU and Magisk as hosts are untested for this
  key.

## Stealth posture

- **The host's own library stays visible.** The module hides its own mapping (`hide.self_remap`),
  but Zygisk Next 1.4.5 keeps `libzygisk.so` mapped by path in every process where a module stays
  loaded, and a generic detector app reports exactly that (and nothing of ours) in a targeted app. No host
  we have measured hides itself in that situation; the claim in earlier drafts that ZygiskNext,
  NeoZygisk and APatch "hide module libraries" was wrong for loaded modules. The module does not
  touch the host's mapping and does not paper over it with libc hooks (`docs/detection-model.md`).
- **`max` is quiet, not invisible.** GOT snapshot comparison, in-memory-DEX versus APK-DEX
  comparison and noticing missing oat artifacts all work against it. RASP products (Promon SHIELD,
  Talsec, Appdome, Build38, V-Key, DexProtector) are not engaged in Phase 1. Expect banking,
  payment, government and DRM apps to detect or resist it until Phase 2.
- **Not a replacement for a system CA.** For broad interception of apps you have not targeted,
  install the proxy CA as a system CA with a separate module. For targeted packages, no CA is needed.
