# The coverage ladder

When a bypass does not work, the log tells you which surface the app has, whether the module reached
it, and if not, why and what to change. This document is the reference for those lines. It is the
first thing to read before opening an issue, and the first thing maintainers will ask for.

## Getting the lines

1. Set `"log": { "enabled": true }` in `/data/adb/pinning_haters/config.json` (`docs/reference.md`, "Configuring").
2. Force-stop the app and start it again. Exercise the connection that fails.
3. Read the newest file:

```sh
adb shell su -c 'f=$(ls -t /data/adb/pinning_haters/log/*.log | head -1); grep -E "\[init\]|\[coverage\]" "$f"'
```

Coverage lines are `INFO` level, so they appear without `verbose`. `verbose` adds the `DEBUG`
lines that show individual decisions (each patched method, each hidden oat path, each overridden
verdict), which are useful once you know which surface to look at.

If there is **no log file at all** for the launch, the package was not a target: logging only starts
for targeted packages. Check the package name in `packages`, and check
`/data/adb/pinning_haters/log/companion.log` for config parse errors.

## Line anatomy

```
[2026-10-24 12:00:01.125] [INFO ] [coverage] surface=platform_tls present=yes reachable=yes applied=1 style=got target=SSL_set_custom_verify
[2026-10-24 12:00:02.410] [INFO ] [coverage] surface=okhttp_pinner present=yes reachable=yes applied=3/4 dex_size=8482816
[2026-10-24 12:00:01.130] [INFO ] [coverage] surface=flutter present=yes reachable=yes applied=1 style=pattern target=ssl_crypto_x509_session_verify_cert_chain lib=libflutter.so
[2026-10-24 12:00:01.127] [INFO ] [coverage] surface=aot present=yes reachable=no reason=contract_missing target=openat consumer=libartbase.so|libart.so|libdexfile.so
[2026-10-24 12:00:01.131] [INFO ] [coverage] surface=unity_il2cpp present=no
```

Every line starts with `[coverage] surface=<name>` followed by `present=` and, when present,
`reachable=`. The remaining fields depend on the outcome:

| Field | Values | Meaning |
|---|---|---|
| `surface` | one of the names in the table below | The pinning surface (or supporting mechanism) this line is about. |
| `present` | `yes` / `no` | `yes`: the library, runtime, or class this surface lives in is loaded in this process. `no`: it is not; nothing to do. |
| `reachable` | `yes` / `no` | `yes`: the module installed something for it. `no`: it did not, and `reason` says why. Only present when `present=yes`. |
| `applied=N` | integer | Native: how many import slots were rewritten (one per consumer library that had the edge). |
| `applied=N/M` | integers | Java (per DEX): `N` methods patched out of `M` target-table entries whose class is defined in this DEX. `M` counts table rows, not methods the library has, so `3/4` with one overload absent in this library version is normal. |
| `dex_size` | bytes | Java: size of the DEX in which the class was found. Identifies which DEX of a multidex app the line refers to. |
| `style` | `got` / `inline` / `pattern` | The hook style that was used (`reachable=yes`) or would be needed (`reason=backend_unavailable`). |
| `target` | symbol name | Native: the imported symbol whose slot was (or would be) rewritten. |
| `lib` | basename | The library that triggered the line. Present on marker lines and on lines emitted after a deferred load. |
| `consumer` | `a.so\|b.so` | With `contract_missing`: the candidate consumer list that was searched. |
| `reason` | see next table | Why `reachable=no`. |
| `required_tier` | `max` / `balanced` / `compat` | The lowest tier at which this surface is reachable. |
| `current_tier` | tier | The effective tier for this package (global ceiling or per-package override). |
| `note` | quoted text | Marker lines: a one-sentence explanation of what the runtime does with TLS. |

## Reasons

| `reason` | Meaning | What to do |
|---|---|---|
| `tier` | The entry's `min_tier` is above the package's effective tier. | Set `packages.<pkg>.stealth` to the `required_tier` shown, for that package only (`docs/stealth-tiers.md`). In v0.1.0 that will turn this into `backend_unavailable`, below. |
| `backend_unavailable` | The tier permits the entry but the hook style (`inline`, `pattern`) has no implementation in this release. | Nothing you can configure. This is Phase 1.5 work; the line exists so the gap is visible. |
| `surface_disabled` | The entry's surface group is switched off in `surfaces`. | Turn the corresponding `surfaces.*` key back on. |
| `aot.stat_hook_fallback=false` | The in-process oat-hiding hooks are disabled by config. | Only matters if eviction did not succeed (`oat_evicted=0` in the `[init]` line). Re-enable `aot.stat_hook_fallback`. |
| `relax_hostname_verification=false` | A hostname verifier class is present but hostname relaxation is off (the default). | Usually nothing: a proxy presenting a certificate for the right host does not need it. Set `relax_hostname_verification: true` only if the app pins a hostname your setup cannot satisfy. |
| `contract_missing` | The named consumer library is loaded but has no import slot for `target`. The ELF contract this edge rests on does not hold on this build. | For `aot` members it is expected (see "Expected noise"). For `platform_tls` with `target=SSL_set_custom_verify`, `java_dex`, or `deferred_load` it is a real gap: open an issue with the `[init]` line and the device model; `docs/android-versions.md` tracks which builds were verified. |
| `system_app` | the package is not installed under `/data/app`; its oat artifacts are on a read-only partition and cannot be evicted. `reachable=yes` means the stat fallback is covering it, `reachable=no` means `aot.stat_hook_fallback` is off | enable `aot.stat_hook_fallback` |

Marker lines (Flutter, Dart, IL2CPP, Mono, Cronet) carry `required_tier` and `current_tier`
without a `reason`: the runtime was detected by its library name, and nothing at the current tier
reaches it.

## Surfaces

| `surface` | What it is | `present=yes` means | Reached by | Required tier | Config |
|---|---|---|---|---|---|
| `platform_tls` | Everything that validates through a `javax.net.ssl` `TrustManager` during the handshake: platform trust, Network Security Config pin-sets, TrustKit, custom `X509TrustManager`s, Volley, gRPC-over-OkHttp | `libjavacrypto.so` is loaded (always, in every app) | GOT wrap of `SSL_set_custom_verify` in `libjavacrypto.so`; the app's `TrustManager` still runs, its rejection is overridden | `max` | `surfaces.platform_tls` (default on) |
| `java_dex` | The DEX interception itself: the `adler32` edge in `libdexfile.so` that lets every Java target below be patched | `libdexfile.so` is loaded (always) | GOT | `max` | `surfaces.java_dex` (default on) |
| `okhttp_pinner` | `okhttp3.CertificatePinner.check` and `check$okhttp`, OkHttp 3.x to 5.x. Runs *after* the handshake, so the platform wrap cannot help | the class is defined in a DEX that ART verified during this session | DEX patch (`return-void`) | `max` | `surfaces.java_dex`; needs the verifier to run, which needs `aot.evict_oat` or `aot.stat_hook_fallback` |
| `certificate_transparency` | appmattus (formerly babylon) Certificate Transparency: the OkHttp interceptor, the HostnameVerifier wrapper and the TrustManager wrapper. All post-handshake | the library's classes are defined in a DEX that ART verified during this session | DEX patch: `enabledForCertificateTransparency(host)` returns false (CT off for every host, delegate hostname check untouched); the interceptor body additionally becomes `return chain.proceed(chain.request())` | `max` | `surfaces.java_dex`; same verifier requirement; `no_callee` in the log means the DEX never references `okhttp3.Interceptor.Chain` |
| `chromium` | WebView, Cronet and HTTP/3: Chromium verifies chains in its own Java code (`AndroidNetworkLibrary.verifyServerCertificates`), inside the WebView provider's or the app's Cronet DEX, never through conscrypt's callback | that DEX was verified in this process (the provider APK's own oat artifacts are hidden by the stat fallback) | DEX patch: the method first registers the chain's leaf in Chromium's own test trust store (`addTestRootCertificate`), then runs the real inner verifier, which now succeeds and returns a proper non-empty verified chain with `is_issued_by_known_root=false` (no pin enforcement) | `max` | `surfaces.java_dex` and `aot.stat_hook_fallback` (the provider's oat lives in another package, so companion eviction does not cover it); `applied=1/2` is normal, the two rows are the 5- and 3-argument shapes; one test-store entry is added per TLS handshake while targeted |
| `hostname_verifier` | `okhttp3.internal.tls.OkHostnameVerifier.verify`; an app-bundled `org.apache.http.conn.ssl.AbstractVerifier.verify`. Not pinning | class defined in a verified DEX | DEX patch (`return-true` / `return-void`) | `max` | `relax_hostname_verification: true` |
| `bundled_tls` | App-shipped BoringSSL/OpenSSL with exported symbols, used by libcurl, gRPC, Qt or the app's own code; and a Conscrypt the app bundles (`org.conscrypt`, OkHttp's `ConscryptPlatform`, gRPC) or that Play services installs (`com.google.android.gms.org.conscrypt`), whose statically linked BoringSSL the platform wrap never sees | at least one app-private library importing the verify symbols was hooked; for Conscrypt, the class is defined in a verified DEX | GOT in the *calling* library: `SSL_CTX_set_verify`, `SSL_set_verify`, `SSL_CTX_set_custom_verify`, `SSL_set_custom_verify`, `SSL_CTX_set_cert_verify_callback`, `SSL_get_verify_result`, `X509_verify_cert`; for Conscrypt a DEX patch of `verifyCertificateChain` (`return-void`; a replacement, the TrustManager is not invoked). On API 30 with the Conscrypt APEX, `ProviderInstaller` loads no second stack, measured; the rows matter for older devices and bundled builds | `max` | `surfaces.bundled_tls` (default on); the Conscrypt rows follow `surfaces.java_dex` |
| `cronet` | Cronet (`libcronet.*.so`): statically linked BoringSSL, no import slots | a library named `libcronet*` is loaded | nothing in v0.1.0; needs an inline or pattern hook | `balanced` | Phase 1.5 |
| `flutter` | `dart:io` TLS inside `libflutter.so` (hidden-visibility BoringSSL, no exported `SSL_*`) | `libflutter.so` is loaded | pointer swap in BoringSSL's `ssl_crypto_x509_method` table (`.data.rel.ro`): the `session_verify_cert_chain` member is wrapped so a rejected chain is accepted. Located from the `"ssl_client"`/`"ssl_server"` purpose strings, not from a symbol; no executable bytes change. The same backend serves `static_boringssl`; this line is the `libflutter.so` instance | `max` | `surfaces.bundled_tls` (default on). Flutter ignores the system proxy: redirect its TCP 443 to an invisible-proxy listener |
| `static_boringssl` | Statically linked BoringSSL in any app-private library other than `libflutter.so` (WebRTC, OpenTok, Brella, private curl builds), when its chain check runs through the classic `SSL_CTX_set_verify` path | the library carries the `"ssl_client"`/`"ssl_server"` purpose strings | pointer swap in its `ssl_crypto_x509_method` table, same backend as `flutter`; `reason=pattern_not_found` when the strings exist but no table does (a BoringSSL laid out differently; an OpenSSL is left to `static_openssl`) | `max` | `surfaces.bundled_tls` (default on) |
| `static_openssl` | Statically linked OpenSSL 1.1.1 / 3.x in an app-private library (OpenVPN cores, SDKs that bundle libssl, the app's own build) whose chain check is a direct call, so no GOT slot exists | the library carries an `OpenSSL 1.`/`OpenSSL 3.` version text that is not BoringSSL's "compatible" one | pointer swap in the client `SSL_METHOD` tables (`.data.rel.ro`; both `TLS_client_method`'s and the generic `TLS_method`'s, with the member layout of 1.1.x–3.1 or of 3.2 and later taken from the version text): the `ssl_connect` member is wrapped so the handshake runs with `SSL_VERIFY_NONE` (the app's verify callback still runs, its verdict no longer aborts) and `SSL_get_verify_result` reads `X509_V_OK` afterwards. The table is found through the library's own exports (`TLS_client_method` decoded, `SSL_set_verify`, `SSL_get_verify_callback`, `SSL_set_verify_result`); no executable bytes change. `reason=pattern_not_found` when the build hides those exports (`-fvisibility=hidden`, a version script) | `max` | `surfaces.bundled_tls` (default on). OpenSSL ignores the system proxy like Flutter does: redirect its TCP 443 or use the untrusted-root host |
| `dart_pinning` | Flutter pinning packages. `http_certificate_pinning` and `ssl_pinning_plugin` do their check in the plugin's *Android* code (`checkConnexion`, fetches the server digest over its own connection and compares), which is a DEX target; a pure-Dart comparison of `SecureSocket.peerCertificate` would live in `libapp.so` and is out of reach | the plugin class is defined in a verified DEX (targets); `libapp.so` is loaded (marker, always printed for Flutter apps) | DEX patch (`return-true`) for the plugins; nothing for pure Dart | `max` for the plugins; `compat` for the marker | `surfaces.java_dex` (default on) |
| `unity_il2cpp` | C# `CertificateHandler` and manual chain walks compiled by IL2CPP | `libil2cpp.so` is loaded | nothing; needs `global-metadata.dat` work | `compat` | Phase 2 |
| `xamarin_mono` | `ServerCertificateValidationCallback` in Mono assemblies | `libmonosgen-2.0.so` is loaded | nothing | `compat` | Phase 2 |
| `go_tls` | Go's `crypto/tls` statically linked into an app library (gomobile builds): verification and any `VerifyPeerCertificate` pin run inside Go code | an app-private library carries the `crypto/tls: ` string; the line names it | nothing; marker only | `compat` | Phase 2 |
| `rust_tls` | rustls statically linked into an app library: its verifier and any custom `ServerCertVerifier` run inside Rust code | an app-private library carries a `/rustls-` crate path; the line names it | nothing; marker only | `compat` | Phase 2 |
| `aot` | The in-process fallback that hides oat artifacts from ART's `stat`/`open`/`access` imports so the verifier runs | the ART libraries are loaded (always); one line per family member | GOT in `libartbase.so` / `libart.so` / `libdexfile.so` | `max` | `aot.stat_hook_fallback` (default on). Eviction itself is reported as `oat_evicted=N` in the `[init]` line |
| `deferred_load` | The edge that re-scans native targets after a library load: `libdl.so`'s own import slots for the linker's `__loader_dlopen` and `__loader_android_dlopen_ext`. Every load in the process passes through them: `System.loadLibrary` (libnativeloader), Dart FFI's `DynamicLibrary.open` in `libflutter.so`, plugin hosts, SDK loaders, packers, libc. The caller address libdl's wrappers pass is forwarded unchanged, so a bare library name still resolves in the real caller's namespace. No app-private GOT is written for this edge (protection SDKs verify their own) | `libdl.so` loaded (always) | GOT, two slots in one system library | `max` | not configurable |

Surfaces a Unity, Flutter or Xamarin app *also* has are still reached: a Flutter app whose plugins use
OkHttp still gets `okhttp_pinner`; a Unity app whose `UnityWebRequest` goes through platform HTTP
still gets `platform_tls`. The marker only says that the runtime's *own* TLS stack is out of reach.

## Expected noise

These lines are normal and are not errors:

- After a `dlclose` in the process, the next load (at most once every 5 s) re-evaluates every
  library (the evaluated set is keyed by load address, and a freed range can be reused), so
  `applied=` lines for libraries hooked earlier are printed again. Slot rewrites are idempotent;
  nothing is hooked twice.

- **`present=no`** for most surfaces in most apps. The table covers many libraries; apps ship few.
- **`aot ... reason=contract_missing`** for individual members of the stat/open/access family. The
  family is a candidate list; on any one Android version only some members are imported by some of
  the three libraries (API 34: `open`, `stat` in `libartbase.so`; `access`, `open`, `stat` in
  `libart.so`). As long as at least one `aot` line says `reachable=yes`, the fallback is in place.
- **`platform_tls ... reason=contract_missing target=SSL_CTX_set_custom_verify`**. conscrypt only
  uses the per-connection `SSL_set_custom_verify`; the `SSL_CTX` variant is in the table in case a
  future build imports it. The line that matters is the one for `SSL_set_custom_verify`.
- **`okhttp_pinner ... applied=3/4`** (or `2/4`, `1/4`). The denominator counts table rows for the
  class; which overloads exist depends on the OkHttp version. OkHttp 4.3+ typically patches
  `check(String, List)`, `check(String, Certificate...)` and `check$okhttp`; OkHttp 3.x has no
  `check$okhttp`. Any `N >= 1` means the pinner is neutralised.
- **Two `flutter` lines**: one from the pattern entry in the native table (`reason=tier` or
  `reason=backend_unavailable`), one from the runtime marker (with `note=`).
- **Java lines appearing late** or more than once: they are emitted whenever ART verifies a DEX
  that defines the class, which can be at launch, on first use of a feature split, or when a
  `DexClassLoader` opens something. Each line names its `dex_size`.
- **Lines with `lib=` appearing after launch**: a deferred load re-ran the native scan for one
  library and reported the result.

## What a missing line means

- **No `okhttp_pinner` (or `hostname_verifier`) line at all.** These surfaces are reported per DEX
  and have no `present=no` summary. Either the app does not ship that class, or **no DEX defining it
  was verified**. The second case is the one to check: look at `oat_evicted=` in the `[init]` line and
  at the `aot` lines. `oat_evicted=0` together with no `aot ... reachable=yes` means a vdex probably
  survived and ART skipped the verifier, so the interception never fired.
- **No `[init]` line.** The decision came back but hook installation never ran, which should not
  happen; or the launch was not of the configured package. Check `companion.log`.
- **No log file.** Not a target, or logging off.

## Triage: "the connection still fails"

1. **Is there a log for this launch?** No: the package is not targeted. Fix `packages` (exact
   package name), check `companion.log` for `config:` lines, force-stop, relaunch.
2. **Read the `[init]` line.** `tier` is what you expect? `surfaces=0x07` (all default groups on)?
   `flags` bit `0x08` set (stat fallback on)? `oat_evicted` non-zero on the first launch after
   installing the app, or after a `bg-dexopt`?
   Bits: `surfaces` 0x01 platform_tls, 0x02 java_dex, 0x04 bundled_tls, 0x08 foreign_runtime;
   `flags` 0x01 relax_hostname, 0x02 log_enabled, 0x04 log_verbose, 0x08 stat_fallback.
3. **`platform_tls` must say `reachable=yes applied=1 target=SSL_set_custom_verify`.** If it says
   `contract_missing` for that symbol, the most valuable hook in the module is not installed on this
   build. Open an issue with the `[init]` line and the ROM; nothing else here will compensate.
   With `verbose` on, a successful override logs
   `[platform_tls] TrustManager rejected the chain; verdict overridden to ok` per connection.
4. **Does the app use OkHttp with a `CertificatePinner`?** Look for the `okhttp_pinner` line. Missing:
   see the previous section. `reachable=yes applied=N/M` with `N >= 1`: the pinner is gone.
5. **Any marker lines** (`flutter`, `cronet`, `dart_pinning`, `unity_il2cpp`, `xamarin_mono`)? The
   app's own TLS stack is out of reach at this tier and, in v0.1.0, at any tier. The line names the
   tier that will reach it once the backend exists (`docs/stealth-tiers.md`).
6. **`bundled_tls present=no` while the app clearly uses native networking?** The app's TLS library
   has no import slots for the verify symbols (statically linked, stripped, same-library calls).
   `docs/detection-model.md`, "The GOT limitation". This needs `balanced`.
7. **Everything reachable, still failing.** The app checks the chain itself after the handshake
   (manual `getPeerCertificates()` digest comparison, a `WebViewClient.onReceivedSslError` override,
   a Certificate Transparency interceptor). These need a per-app Java target; see
   `docs/adding-hooks.md` and `docs/known-limitations.md`. Confirm with the proxy: a TLS handshake
   that completes and is then closed by the client is the signature of a post-handshake check.

Attach the whole log file to any issue. It contains the Android version, the resolved contracts, the
effective tier and the ladder, which is all the context a maintainer needs, and nothing sensitive.
