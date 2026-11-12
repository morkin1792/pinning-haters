# Android versions and the ELF contract record

The `max` tier rests on a small number of **ELF contracts**: cross-library calls in ART and
conscrypt libraries that leave an import slot the module can rewrite. Each one is a dependency on
another project's build configuration, so each one is verified mechanically against real binaries
rather than assumed. This document is the record of what has been verified and what has not.

Supported range: **Android 11 (API 30) to Android 16 (API 36)**, arm64-v8a. Android 10 is not
supported. API 32 (Android 12L) is not in the verification matrix; it shares the API 31 ART and
conscrypt lineage and is treated as 31 until checked.

## The contracts

| # | Contract | Used for | If it fails on a build |
|---|---|---|---|
| C1 | `libjavacrypto.so` imports `SSL_set_custom_verify` (`R_AARCH64_JUMP_SLOT`) from the conscrypt APEX `libssl.so` | platform TLS wrap, the single most valuable hook | `platform_tls` reports `contract_missing`; everything validated through a `TrustManager` is unreached. Planned fallback (Phase 1.5): inline hook on `SSL_set_custom_verify` in the conscrypt `libssl.so` at `balanced`. |
| C1b | `libjavacrypto.so` imports `SSL_CTX_set_custom_verify` | also wrapped when present | Not required. conscrypt uses the per-connection variant; the table entry exists in case a build imports both. A `contract_missing` line for this symbol is expected. |
| C2 | `libdexfile.so` imports `adler32` from `libz.so` | DEX patching at verification | The Java path (`okhttp_pinner`, `hostname_verifier`) is unreached. Planned fallback: inline hook on `art::DexFileLoader::OpenCommon` at `balanced`. |
| C3 | `libdl.so` imports `__loader_dlopen` and `__loader_android_dlopen_ext` from the linker (`R_AARCH64_JUMP_SLOT`); every `dlopen` / `android_dlopen_ext` in the process goes through those two slots | deferred library loads (`System.loadLibrary`, Dart FFI, SDK loaders, packers) | Native targets in libraries loaded after specialization are not installed; those loaded at specialization still are. |
| C4 | At least one of `stat`, `fstatat`, `open`, `__open_2`, `openat`, `access` is imported by at least one of `libartbase.so`, `libart.so`, `libdexfile.so` | the in-process oat-hiding fallback | The fallback is unavailable; companion-side eviction still works. Members that are not imported on a given version are expected to report `contract_missing`. |

## Host-side record (Phase 0.5 items 1 to 3)

Checked with `tools/check_elf_contracts.sh` against `tools/reference-libs/<api>/` on 2026-10-24;
C3 re-checked on 2026-11-03 against `libdl.so` from the same images after the deferred-load edge
moved there (the earlier `android_dlopen_ext` slots in `libnativeloader.so` / `libart.so` are no
longer used). "verified" means the relocation was found in the real library from that release.
**All four contracts hold on every supported API level (30, 31, 33, 34, 35, 36).** Every row below
comes from an arm64 `google_apis` AVD system image of that release, pulled with
`tools/pull_reference_libs.sh`.

| Contract | API 30 (11) | API 31 (12) | API 33 (13) | API 34 (14) | API 35 (15) | API 36 (16) |
|---|---|---|---|---|---|---|
| C1 `SSL_set_custom_verify` in `libjavacrypto.so` | **verified** | **verified** | **verified** | **verified** | **verified** | **verified** |
| C1b `SSL_CTX_set_custom_verify` in `libjavacrypto.so` | not imported (expected) | not imported (expected) | not imported (expected) | not imported (expected) | not imported (expected) | not imported (expected) |
| C2 `adler32` in `libdexfile.so` | **verified** | **verified** | **verified** | **verified** (`adler32@ZLIB_NDK`, `NEEDED libz.so`) | **verified** | **verified** |
| C3 `__loader_dlopen` + `__loader_android_dlopen_ext` in `libdl.so` | **verified** | **verified** | **verified** | **verified** | **verified** | **verified** (AVD and device) |
| C4 `libartbase.so` stat/open family | `open`, `stat` | `open`, `stat` | `open`, `stat` | `open`, `stat` | `open`, `stat` | `open`, `stat` |
| C4 `libart.so` stat/open family | `access`, `open`, `stat` | `access`, `open`, `stat` | `access`, `open`, `stat` | `access`, `open`, `stat` | `access`, `open`, `stat` | `access`, `open`, `stat` |
| C4 `libdexfile.so` stat/open family | `open` | `open` | `open` | none imported | none imported | none imported |
| C4 `openat` / `fstatat` in any of the three | none imported | none imported | none imported | none imported | none imported | none imported |

### API 31 and 33

Same source as API 34 (`google_apis` arm64 AVD images for Android 12 and 13; ART and conscrypt APEX
payloads from the image). Identical findings to API 34 for C1, C1b, C2 and C3. C4 differs only in
that `libdexfile.so` also imports `open` on 31 and 33. All contracts hold on both.

### API 30

Android 11 (`google_apis` arm64 AVD image, revision 16). The ART APEX file on this image is not
`com.android.art.apex`: a first extractor pass that looked for that exact name found only the
`com.android.runtime` APEX, so the extractor now matches APEX names by pattern
(`com.(google.)android.art` with an optional `.release`/`.debug` suffix, flattened directories
included). Findings identical to API 31 and 33: all four contracts hold, with `libdexfile.so`
importing `open`.

### API 35 and 36

Android 15 and 16 (`google_apis` arm64 AVD images, revisions 9 and 7). Identical findings to
API 34 for every contract, including `libdexfile.so` importing none of the stat/open family. The
ART and conscrypt APEX payloads on both images are still ext4; no erofs tooling was needed.

### API 34 detail

Source: Google's `google_apis` arm64-v8a AVD system image for API 34 (Android 14), ART and conscrypt
APEX payloads taken from that image. Findings:

- `libjavacrypto.so`: one `R_AARCH64_JUMP_SLOT` for `SSL_set_custom_verify`. No import of
  `SSL_CTX_set_custom_verify`; conscrypt only uses the per-SSL variant. C1 holds.
- `libdexfile.so`: `R_AARCH64_JUMP_SLOT` for `adler32` with symbol version `ZLIB_NDK`; `libz.so`
  is in `NEEDED`. C2 holds.
- `libdl.so`: `JUMP_SLOT` for `__loader_dlopen` and `__loader_android_dlopen_ext`, both inside
  `PT_GNU_RELRO`. C3 holds. (`android_dlopen_ext` is also a `JUMP_SLOT` in `libnativeloader.so` and
  `libart.so`, the edge used before 2026-11-03; both wrappers end in the libdl slots.)
- Stat/open family: `libartbase.so` imports `open` and `stat`; `libart.so` imports `access`, `open`
  and `stat`; `libdexfile.so` imports none of them; none of the three imports `openat`, `fstatat`
  or `fstatat`. C4 holds through `stat`/`open`/`access`. On this version the expected `aot`
  coverage output is `reachable=yes` for `stat`, `open` and `access`; the remaining family members
  (`fstatat`, `openat`, `__open_2` where absent) are optional edges and only appear in verbose logs.

Note that symbol names and relocation structure are identical between the x86_64 and arm64 builds of
the same source tree, so an x86_64 AVD image is acceptable for *name* verification if an arm64 image
is unavailable; the record above was taken from an arm64 image.

## On-device record (Phase 0.5 items 4 to 6)

**All three hold on API 30** (Redmi K20 "davinci", Android 11 RQ3A.211001.001, arm64, APatch 11039
with Zygisk Next 1.4.5), run on 2026-10-25 with `tests/test-app` targeted at `max`:

| check | result |
|---|---|
| 4 verifier interception fires | `okhttp_pinner PASS`: the `CertificatePinner` patch took effect after the companion evicted `base.odex/.vdex/.art` (`oat_evicted=2`) |
| 5 conscrypt wrap completes a handshake | `custom_trustmanager PASS` with the app's `X509TrustManager` reporting it was invoked; `nsc_pins PASS`; `untrusted_chain PASS` against untrusted-root.badssl.com |
| 6 eviction holds for the launch | same launch as above; ART did not regenerate the artifacts synchronously |
| release check, zero modified executable bytes | `exec_bytes PASS: 283 executable mappings identical to disk` from inside the target process |
| `chromium` surface (WebView) | `webview PASS: loaded https://untrusted-root.badssl.com/` with no proxy and no CA installed, WebView provider 156.0.8078.47; the module log shows `chromium ... applied=1/2`. Untargeted the same check fails with an SSL error |
| 7 (plan §1.16) survives dexopt | after `cmd package compile -m speed -f` recreated `base.odex`/`base.vdex`, the next launch logged `oat_evicted=2`, the oat directory was empty again and `okhttp_pinner applied=3/4` with all verdicts unchanged |
| through an interception proxy | same verdicts with the phone's global proxy pointed at Burp, and the requests visible decrypted in Burp's history. Caveat: this phone already carries Burp's CA as a system certificate, so platform trust alone passes here; the pin-set, `CertificatePinner` and rejecting-`TrustManager` checks are unaffected by that, the `untrusted_chain` check is only meaningful without the proxy |
| negative control | `post_handshake_digest FAIL` as designed; in a non-target process (`com.android.systemui`) the `SSL_set_custom_verify` slot still points into the conscrypt `libssl.so`, while in the target all three slots point into the module library |

Real apps on the same device, each launched through Burp (phone proxy set; note the phone has
Burp's CA installed as a system certificate, so only *pinned* traffic tests the bypass) and
targeted at `max`, 2026-10-25:

| app | coverage lines | note |
|---|---|---|
| `ch.protonvpn.android` | `platform_tls`, `java_dex`, `deferred_load`, `aot` all `reachable=yes` | API traffic (`/core/v4/...` to the Proton API, Sentry envelopes, promo assets) decrypted in Burp's history |
| a Flutter banking app | as above, plus `flutter present=yes reachable=no required_tier=balanced` and `dart_pinning present=yes reachable=no required_tier=compat` | nothing from the Flutter bank app reached Burp in this run because `dart:io` ignores the system proxy setting, not because of pinning; see the `balanced` run below |
| A large chat app | `platform_tls`, `java_dex`, `deferred_load`, `aot` all `reachable=yes` | its API, gateway websocket and asset fetches decrypted in Burp's history |
| `org.fdroid.fdroid` (not targeted) | no module log | its repo traffic also appears in Burp, because F-Droid trusts the system store where Burp's CA sits; not a pinning control on this phone |

The definitive real-world control is the HTTP Toolkit **SSL Pinning Demo** (`tech.httptoolkit.pinning_demo`
1.6.1), run twice through Burp on 2026-10-25, every button tapped, verdict read from the button colour:

| button | not targeted | targeted at `max` | why |
|---|---|---|---|
| Unpinned | pass | pass | system store trusts Burp's CA on this phone |
| Config-pinned (Network Security Config pin-set) | **fail** | **pass** | conscrypt wrap |
| Context-pinned (custom `SSLContext`/`TrustManager`) | **fail** | **pass** | conscrypt wrap |
| OkHttp pinned (`CertificatePinner`) | **fail** | **pass** | `adler32` DEX patch after oat eviction |
| Volley pinned | **fail** | **pass** | conscrypt wrap |
| TrustKit pinned | **fail** | **pass** | conscrypt wrap |
| Appmattus CT (HttpsURLConnection + CT HostnameVerifier) | fail | **pass** (since the `certificate_transparency` targets) | `enabledForCertificateTransparency` patched to false |
| Appmattus + OkHttp CT (interceptor) | fail | **pass** (since the `certificate_transparency` targets) | same, plus the interceptor pass-through |
| Appmattus + raw TLS CT | fail | **pass** | this variant validates inside a `TrustManager`, which the wrap reaches |
| Flutter | pass | pass | not a bypass test here: the Flutter request bypasses the system proxy entirely (`dart:io`), so it never met Burp; see the `balanced` run below |
| Raw custom-pinned (manual chain check on a raw socket) | fail | fail | app-specific post-handshake comparison, per-app target by design |

**Flutter run, 2026-10-25, same phone, module built with the Flutter pointer-table backend (then at
`balanced`; promoted to `max` the same day, owner decision, same code).**
Because `dart:io` ignores the proxy setting, the Flutter request was steered with
`iptables -t nat -I OUTPUT -p tcp --dport 443 -m owner --uid-owner <uid> -j DNAT --to-destination
104.154.89.105:443` (untrusted-root.badssl.com), which presents a chain that is both untrusted and
for the wrong name:

| app / case | tier | result |
|---|---|---|
| demo, Flutter button | `max` | **red**; log: `surface=flutter present=yes reachable=no reason=tier required_tier=balanced current_tier=max` |
| demo, Flutter button | `balanced` | **green**; log: `[flutter] session_verify_cert_chain at …, table slot …`, `surface=flutter present=yes reachable=yes applied=1 style=pattern`, then `[flutter] BoringSSL rejected the chain; verdict overridden to ok` when the button was pressed |
| The Flutter bank app, TCP 443 redirected to Burp's invisible listener | `max` | app loads normally; `flutter … reachable=no reason=tier`; 40 packets redirected |
| The Flutter bank app, same | `balanced` | app loads normally; slot located (`0x71abfc` / `0xa808a0` relative, identical to the host test on the extracted library) and applied; **zero** `verdict overridden` lines: the Flutter bank app's `dart:io` trusted Burp's CA-signed certificate from the system store, so its pre-login traffic does not pin at the BoringSSL level |

| demo, Flutter button, after promotion to `max` | `max`, targeted | **green**, `applied=1 style=pattern`, one `verdict overridden` line |
| demo, Flutter button, after promotion to `max` | not targeted | **red** |
| The Flutter bank app, TCP 443 redirected to untrusted-root.badssl.com | `max` | slot applied; 14 `verdict overridden` lines during the first 25 s (its `dart:io` rejected badssl's chain each time and the module accepted it), app shows its normal welcome screen |

Same day, through Burp instead of badssl: a listener in "custom certificate" mode with a self-signed
PKCS#12 (`CN=pinning-haters-untrusted.invalid`, trusted by nothing) on 8084 with invisible proxying,
the demo's TCP 443 DNAT'ed to it:

| case | result |
|---|---|
| demo, Flutter button, targeted at `max` | **green**; Burp's history shows `GET / HTTP/1.1`, `user-agent: Dart/3.12 (dart:io)`, `host: testserver.host`, decrypted |
| demo, Flutter button, not targeted | **red** |
| demo, unpinned `HttpsURLConnection` request via the same certificate on an explicit-proxy listener (8083), targeted, `relax_hostname_verification: true` | **red** both ways: the certificate's name does not match and `HttpsURLConnection`'s hostname verifier is bootclasspath (`docs/known-limitations.md`). The conscrypt wrap did override the trust failure (one `[platform_tls]` override line); the name check is a separate, unpatched step. A certificate whose SANs match the host is the fix, not the module |

The Flutter bank app through the same untrusted invisible listener, targeted at `max`: 18 `verdict overridden`
lines (its BoringSSL rejected the self-signed certificate on every connection and the module
accepted it) and Burp's history shows the app's own API traffic decrypted: `GET /api/v2/remote-config`
on its own hosts, `GET /api/app/discovery` on
its own hosts, `GET /api/locales/pt-BR/delta` on
its own hosts (user-agent `Android/10.8.51-…`, the Flutter bank app's own Dart
client), plus the AppsFlyer SDK's Java request. A first read of this run concluded the opposite
because the MCP history queries were failing and a few pre-warmed connections sat idle after their
handshake; the history settled it. The Flutter bank app's TLS layer is fully bypassed at `max` with an
untrusted certificate the phone does not know.

`tests/test-app` through the explicit-proxy listener (8083) carrying a self-signed certificate whose
SANs match its hosts (`*.badssl.com`), so only trust can fail, phone proxy pointed at it:

| check | targeted at `max` | not targeted |
|---|---|---|
| `custom_trustmanager` | PASS (TrustManager invoked, verdict overridden) | FAIL |
| `nsc_pins` | PASS | FAIL |
| `okhttp_pinner` | PASS | FAIL |
| `untrusted_chain` | PASS | FAIL |
| `webview` | PASS | FAIL (SSL error 3) |
| `post_handshake_digest` | FAIL, by design | FAIL |

No proxy CA on the phone was involved: the certificate is signed by nothing the device knows. The
demo app's Java buttons stayed red through the same listener only because its hosts are
`testserver.host` and subdomains, absent from that certificate's SANs (hostname verification, not
trust; see `docs/known-limitations.md`).

**`static_boringssl`, 2026-10-26, same phone, generic method-table backend.** Targeted apps that
ship a static BoringSSL outside Flutter:

| app / library | ladder |
|---|---|
| A job-search app, WebRTC `libjingle_peerconnection_so.so`, loaded at startup | `static_boringssl present=yes reachable=yes applied=1 style=pattern`; the locator's offsets match the host fixture |
| same app, `libwebviewchromium.so` (WebView provider) | loaded, deliberately skipped (`skip_consumers`); no line |
| An insurance app, OpenTok | `present=no`: `libopentok.so` is not loaded until a call starts |
| demo, test app | unchanged: `flutter` green through the badssl redirect, every test-app check PASS through the untrusted listener, WebView included, no tombstone |

Lesson from the first run: the wildcard scan reported `pattern_not_found` in every process because the
deny-list form of `is_app_private` counted `/data/adb/modules/pinning_haters/zygisk/arm64-v8a.so` as
app code and the scan found its own needle strings in it. Now a positive list plus a load-address
self check.

**`static_openssl`, 2026-11-01, same phone, `SSL_METHOD` table backend.** The test app now bundles
an OpenSSL 3.0.16 built with the NDK (`libtestossl.so`, whole-archived and `-Bsymbolic`, so
`X509_verify_cert` has no slot) and handshakes with `untrusted-root.badssl.com` under
`SSL_VERIFY_PEER` against the system CA directory. It connects directly, so the Android proxy
setting is irrelevant to it and Burp's system CA cannot make it pass.

| run | `static_openssl` | ladder |
|---|---|---|
| targeted at `max` | `PASS: handshake ok, TLSv1.2, verify_result=0 (ok)` | `deferred_load` re-scan after `System.loadLibrary`, then `static_openssl present=yes reachable=yes applied=1 style=pattern target=ssl_connect lib=libtestossl.so`, `[openssl_table] handshake completed with verification relaxed` |
| untargeted | `FAIL: handshake failed: SSL_connect=-1 error=1 verify_result=19 certificate verify failed` | no log |
| `exec_bytes`, targeted | `PASS: 283 executable mappings identical to disk` | |

The first targeted run also printed `static_boringssl present=yes reachable=no
reason=pattern_not_found lib=libtestossl.so` on the same library (OpenSSL carries the same purpose
strings); the BoringSSL backend now answers `ABSENT` for an OpenSSL so the library gets one line.
Host side, the locator finds the same table in the OpenVPN3 core fixture (`openssl-ovpn3-*.so`):
`SSL_METHOD` at `0x6971b8`, `ssl_connect` = `ossl_statem_connect`.

**Review fixes, 2026-11-01, same phone.** After the four-way code review (fixes listed in
`CHANGELOG.md`): the test app with an OpenSSL 3.4.1 `libtestossl.so` passes `static_openssl` through
both `TLS_client_method` and `TLS_method` (untargeted: `verify_result=19`), every other check as
before, `exec_bytes PASS` (283 mappings), the module's path absent from the target's maps while ART's
four `jit-cache` mappings are intact, the HTTP Toolkit demo's eight pinned and WebView buttons green
through Burp with `flutter applied=1`, and no new tombstone. The eviction walk's new filesystem
identity was checked directly: a fake `oat/arm64/*.odex` under an app-owned directory in the app's
data dir is deleted, the same under a root-owned directory is kept.

**No proxy CA needed for targeted apps, 2026-11-02, same phone.** With the proxy cleared
(`settings put global http_proxy :0`; `settings delete` leaves ConnectivityService on the old
proxy, which made two earlier "untargeted" runs go through Burp and pass on Burp's system CA), the
test app talks to `untrusted-root.badssl.com` directly, whose root is in no store:

| check | untargeted | targeted at `max` |
|---|---|---|
| `untrusted_chain` (platform `HttpsURLConnection`) | FAIL, `Trust anchor for certification path not found` | PASS |
| `webview` | FAIL, `SSL error 3` | PASS |
| `custom_trustmanager` | FAIL (its TrustManager rejects everything) | PASS, TrustManager still invoked |
| `static_openssl` (3.4.1, both tables) | FAIL, `verify_result=19` | PASS, `verify_result=0` |

**First Android 16 device, 2026-11-02: Mi 9T, custom ROM on API 36, KernelSU + SUSFS, Zygisk Next
1.5.0** (with Vector, Play Integrity Fix, Zygisk Assistant and a TEE simulator also installed).
Fresh install from the release zip through `ksud module install`.

- Test app, targeted, no proxy, straight to `untrusted-root.badssl.com`: `custom_trustmanager`,
  `nsc_pins`, `okhttp_pinner`, `untrusted_chain`, `static_openssl` (3.4.1, both
  tables), `webview` all PASS, `post_handshake_digest` FAIL as designed; `exec_bytes PASS` over 380
  executable mappings. Every `max` edge resolved on API 36 (`adler32`, `SSL_set_custom_verify`,
  `android_dlopen_ext`, the oat-probe libc edges).
- **Zygisk Next 1.5.0 hides modules itself**: the target's maps have neither our library nor
  `libzygisk.so`, and `hide.self_remap` finds its code already anonymous (the log now says so at
  INFO instead of warning). Contrast with 1.4.5 on the K20, which showed both by path.
- A carrier app (its framework's security layer, Guardsquare-style guard names: root, hook,
  dynamic instrumentation, virtualization, …, plus Topaz Heartbeat) shows its tamper screen,
  code #1009, **with and without** the module targeting it; targeted, it does not crash and the
  module applies `bundled_tls 2/2`. The verdict comes from the device environment, not from us. Its sibling sales app (Flutter) runs targeted
  with `flutter applied=1` and `bundled_tls 2/2`.
- **Stability, first 10.5 hours** (Android 16, on-device loop, screen off, unplugged): 21 rounds,
  test app 7/7 every round, the Flutter app alive every round, no crash line, no tombstone, same
  companion pid. Interrupted only by the reboot for the rows above; restarted.
- An untargeted crypto-exchange app crashes on its own whenever it starts in the background
  (`kopi.mNO: 16`), including before the module was installed: its RASP, not us.

**2026-10-26, LSPosed disabled (`/data/adb/modules/zygisk_lsposed/disable`).**

| app | what happened |
|---|---|
| A packed Flutter wallet app (DexHelper packer) | starts now (`am start`, not `monkey`), but no module log and no Zygisk library in its maps: it is on APatch's exclude list (`/data/adb/ap/package_config`: its package), so the host injects nothing. The user's call |
| The Flutter bank app, targeted, through Burp 8080 | its RASP (`rasp-channel`, posted to its own hosts) reports per launch: su binaries, Zygisk libraries, init.rc, busybox, hiding apps, root APKs, preloads, KSU socket label, Magisk mounts, mountinfo differentials, `/debug_ramdisk (tmpfs)` as a suspicious mount, dump tools, `dlsym` address mismatches, **root framework libraries by path** and soinfo gaps. Before `hide.self_remap` it listed both `/data/adb/modules/pinning_haters/zygisk/arm64-v8a.so` and `/data/adb/modules/zygisksu/lib64/libzygisk.so`. **With `hide.self_remap` (measured 2026-10-26, fresh Burp history, read by the user):** `rootFrameworkLibsDetails` names only `libzygisk.so` (twice, "zygisk in" and "/data/adb/modules in"), `soinfoGapDetected: false`, `zygiskLibrariesDetected: false`, `dlsymAddrMismatchDetected: false`; the only other finding is `/debug_ramdisk (tmpfs)` in `suspiciousMounts` (APatch). So the anonymous re-mapping is invisible to this detector and the host's own library is the remaining trace. The telemetry is informational (the app kept working); it is the clearest picture yet of what a bank's RASP collects |

The engine builds involved (`libflutter.so` from the demo 1.7.1, the Flutter bank app and a packed Flutter wallet app), WebRTC,
OpenTok, Brella and WebView 156, plus the OpenVPN3 (OpenSSL) negative, are the host fixtures for
`tests/host/test_boringssl_table`. No crash in `logcat -b crash` for either app.

Five of five pinning surfaces the design claims at `max` flip from fail to pass. The two Appmattus
CT buttons were red in the first run and went green the same day once the `certificate_transparency`
targets landed (`applied=2/2` in the log); the only button still red when targeted is the raw
custom-pinned socket in 1.6.1, which is app-specific by design. Re-run on demo 1.7.1 the same day with the same outcome; 1.7.1
adds a "native CT" button (green either way on Android 11, which does not enforce CT) and its raw
custom-pinned button passes either way, so it stops being a datapoint there. Burp's proxy history is the second witness: the pinned buttons
fetch `https://ecc384.badssl.com/`, and every targeted run shows those requests decrypted with
`200 OK` responses (`okhttp/4.11.0` and `Dalvik` user agents), while the untargeted run produced no
`ecc384.badssl.com` entry at all, only TrustKit pin-failure reports.

Other API levels remain pending on device. The table below describes each
check for the next run.

| # | Check | Pass condition | If it fails |
|---|---|---|---|
| 4 | Does `DexFileVerifier` run, and does the `adler32` interception fire, for the app's primary DEX when no vdex is present? | With `verbose` logging, one `[java_dex]` patch line (or `okhttp_pinner` coverage line) per DEX that defines a target class, on API 30 to 36. | That API's Java path drops to `balanced` with an inline hook on `art::DexFileLoader::OpenCommon` (Phase 1.5). Do not ship a Java path that never fires silently: the line must say so. |
| 5 | Does the conscrypt wrap complete a handshake? | Against an interception proxy, the handshake completes, the app's custom `TrustManager` observes that it was invoked (the test app asserts this), and the verbose log shows `[platform_tls] TrustManager rejected the chain; verdict overridden to ok`. On API 30 to 36. | Fall back to replacing the callback outright instead of wrapping. Louder (the app's `TrustManager` is never invoked, which is itself detectable) but still `max` in terms of bytes modified. |
| 6 | Does companion-side oat eviction hold for the launch? | After the companion deletes `base.odex`/`base.vdex`/`base.art`, ART runs the APK's DEX under interpreter plus JIT for that launch without synchronously regenerating them; `[init]` shows `oat_evicted > 0` on the first launch after installing or after `bg-dexopt`, and the `okhttp_pinner` line appears. | Rely on the `aot.stat_hook_fallback` GOT hooks, and investigate whether ART on that version regenerates artifacts in the launch path. |

A related exit criterion (plan §1.16 item 7): the bypass survives an overnight `bg-dexopt` cycle.
Also pending; procedure in `docs/testing.md`.

### The `redirect` key (2026-11-11, Redmi K20, API 30, APatch + Zygisk Next 1.4.5)

The demo package with `"redirect": "104.154.89.105:443"` (untrusted-root.badssl.com) and the system
proxy cleared, targeted at `max`. Kernel 4.14, no IPv6 NAT table.

| case | result |
|---|---|
| rules after launch | installed by the companion (`u:r:magisk:s0`): a `nat` chain for the uid with TCP 443 → the address and UDP 443 → `127.0.0.1:9`, an `ip6tables` filter chain rejecting 443; first log line `redirect=104.154.89.105:443` |
| Flutter button | **green**; one hit on the TCP rule, one `verdict overridden` line |
| socket view of a redirected connection | `ss` shows the address the client dialled, not the redirect target (checked on a shell-uid connection with hand-installed rules of the same shape; a dialled address that does not exist connects too) |
| HTTP/3 button | **red** with the key (one 1278-byte hit on the UDP rule), **green** without it |
| key removed, app relaunched | both chains and both jumps gone, `redirect: removed for uid` in `companion.log`, first log line `redirect=off` |
| rules across a Wi-Fi off/on cycle | unchanged (checked with hand-installed rules of the same shape) |
| errno seen by the sender | UDP 443 over IPv4: `ECONNREFUSED`, same as a closed port; TCP 443 over IPv6: `ECONNREFUSED`; UDP 443 over IPv6: `EPERM` |

Not covered: KernelSU and Magisk as hosts, a network with global IPv6, a kernel with IPv6 NAT.

2026-11-12, same device, redirect pointed at a Burp listener **without** "Support invisible
proxying": the TCP rule is hit once, the connection stays established, the Flutter button never
resolves and the log has no `verdict overridden` line; a plain non-proxy-style request to the same
listener gets Burp's own page. A Burp listener with invisible proxying on was not tested.

### The WebUI app list (2026-11-12, Redmi K20, API 30, APatch 11039)

`apps.dex` under `app_process` as root, from the manager's `ksu.exec`: 77 user apps with labels,
versions and icons in about 2 s on the first run and 0.4 s with the icons cached; 324 packages with
"Include system apps". Names, versions and icons render in the APatch WebView; search, the per-app
panel and the info dialogs work there. Not covered: KernelSU's manager, any other Android version.

### A protection SDK versus the deferred-load edge (2026-11-03, Mi 9T, API 36)

A React Native app that ships a protection SDK (anti-tamper, Frida/Xposed/Magisk probes, its own
guard libraries) died on every targeted launch: `SIGSEGV` at address 0 on the `create_react_context`
thread about two seconds in, no tombstone (the reaction is the SDK's own; under strace one of the
app's threads ended the process with `kill(getpid(), SIGKILL)` after a double fork). Untargeted it
ran. It still died with every surface off, with `aot.stat_hook_fallback` off and with `aot.evict_oat`
off; a build without the two app-private `dlopen` rows ran it with every surface applied
(`okhttp_pinner applied=3/4`, `bundled_tls` DEX rows `2/2`, `flutter applied=1`, `chromium
applied=1/2`). The SDK's libraries import `dlopen`, so the old wildcard rows rewrote slots in them,
and the SDK verifies its own `.got.plt` against `.rela.plt` (the strings are in its guard library).

The edge now lives in `libdl.so`'s two linker slots (C3 above): same app, same config, both slots
`applied=1`, 27 deferred loads seen including bare-name `dlopen`s from native code
(`vulkan.adreno.so`), app alive. Test app on the same build: `custom_trustmanager`, `nsc_pins`,
`okhttp_pinner`, `untrusted_chain`, `static_openssl`, `webview` PASS; `post_handshake_digest` FAIL as
designed.

### Packed apps (2026-11-01, same device)

- A DexHelper-packed Flutter app: the packer's loader library imports `dlopen` and its loads were
  seen by the `deferred_load` edge (then a hook in the importer, since 2026-11-03 the `libdl.so`
  slots every `dlopen` passes through); the DEX it unpacks goes through `DexFileVerifier` like any other
  and came out with `okhttp_pinner applied=3/4`; `flutter applied=1`. Nothing packer-specific was
  needed. (The app's own "service error" screen is the same with the module off: environmental.)
- Exit criterion 8 (WebUI): the module's WebUI opens inside APatch's manager (`WebUIActivity`,
  APatch 11039), renders the tier, the package list and the surface toggles, and saves.
- Exit criterion 5 (real apps with enforced pins): a survey of 46 installed apps found that most
  `sha256/` strings are OkHttp's own `CertificatePinner` library strings, not app pins. Apps with
  real pin sets (a cosmetics retailer, an IoT vendor, a loyalty programme, an alternative app store)
  all pin hosts they only contact after login, so a launch through the proxy neither fails nor
  proves anything; their ladders show `okhttp_pinner applied=3/4` and the wrap in place. Enforced
  pins verified end to end remain the HTTP Toolkit demo (every mechanism) and the Flutter bank
  through the invisible listener; a third needs an account on one of the apps above.

## Getting reference libraries

`tools/reference-libs/<api>/` is **gitignored**: do not commit Google's binaries. Each directory holds
`libart.so`, `libartbase.so`, `libdexfile.so`, `libnativeloader.so`, `libjavacrypto.so` and, from
the runtime APEX, `libdl.so` for that API level; the contracts read all of them. The conscrypt `libssl.so`/`libcrypto.so` are pulled when
they are real files in the APEX payload; on builds where they are symlinks into the `sharedlibs`
APEX (API 34 and later) they are absent, which no contract needs.

### From AVD system images (default)



```sh
tools/pull_reference_libs.sh 30 31 33 34 35 36
```

Downloads Google's arm64-v8a system image for each API level from the SDK repository, extracts the
ART and conscrypt APEX payloads, and pulls the libraries out of the ext4 images with `python3` and
`debugfs`. Needs `curl`, `python3` and `debugfs`; no root and no loop mounting are required. Output goes to
`tools/reference-libs/<api>/`; intermediate downloads are kept under `tools/reference-libs/.download/`.

### From Pixel factory images (manual)

1. Download the factory image zip for the target version from `developers.google.com/android/images`.
2. Unzip it; inside is `image-<device>-<build>.zip`. Unzip that; find `system.img`.
3. `simg2img system.img system.raw.img` if it is sparse.
4. `sudo mount -o loop,ro system.raw.img /mnt/sysimg`.
5. ART libraries: `/mnt/sysimg/apex/com.android.art/lib64/`. conscrypt:
   `/mnt/sysimg/apex/com.android.conscrypt/lib64/`. `libnativeloader.so` is in `/mnt/sysimg/system/lib64/`.
6. If the APEX is a `.apex` file (a zip containing an image): `unzip`, loop-mount `apex_payload.img`,
   pull from there.
7. Save to `tools/reference-libs/<api>/`.

Other sources, in order of preference: `adb pull` from a stock Pixel (`/apex/com.android.art/lib64/`,
`/apex/com.android.conscrypt/lib64/`, `/system/lib64/libnativeloader.so`); a GSI; an AOSP self-build.

## Running the check

```sh
tools/check_elf_contracts.sh          # every tools/reference-libs/<api>/ directory
tools/check_elf_contracts.sh 34 35    # only these
```

It runs `readelf -r` over the reference libraries and asserts C1 to C4 for each API level, printing
which family members resolved so this document can be updated. A symbol imported only through a
`GLOB_DAT` relocation (`.rela.dyn`) is reported separately: the rewriter walks `.rela.plt` only, so
such an edge is not usable today. It is wired into CI
(`.github/workflows/contract.yml`), so a new Android version that moves an edge fails the build
rather than failing silently on a user's device. The assertions, in `readelf` terms:

```sh
readelf -r libjavacrypto.so | grep -E 'SSL_(CTX_)?set_custom_verify'           # C1
readelf -r libdexfile.so    | grep adler32                                     # C2
readelf -r libdl.so | grep -E '__loader_(dlopen|android_dlopen_ext)'            # C3
readelf -r libart.so libartbase.so libdexfile.so | grep -E '\b(f?stat(at)?(64)?|open(at)?(64)?|access)\b'  # C4
```

## Version notes

- **DEX 041 container format (Android 15+)**: `*_off` fields are relative to the container, not the
  header. The parser re-bases its view when it sees version 041 with a 0x78-byte header. The
  interception itself is unchanged: `DexFileVerifier` still passes `header + 12`.
- **CompactDex** lives only in vdex files, which the companion deletes; the parser handles standard
  DEX only.
- **APEX naming**: the ART APEX is `com.android.art` on every supported version (Android 10's
  `com.android.runtime` is below the supported range). Reference libraries from `google_apis` images
  come from the `com.google.android.*` APEXes, which are the same binaries under Google's prefix.
- When a contract fails on a specific version, the fix is a table change (`consumer_library`
  candidate list in `targets_native.cpp`) plus a row here, not code.
