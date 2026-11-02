# tests/test-app

The one APK that exercises the four things that distinguish this architecture (plan §1.14):

| check | surface | expected at `max` |
|---|---|---|
| `custom_trustmanager` | `platform_tls` (conscrypt wrap) | PASS, and the app's `X509TrustManager` must report it was invoked |
| `nsc_pins` | `platform_tls` | PASS |
| `okhttp_pinner` | `okhttp_pinner` (DEX patch) | PASS |
| `untrusted_chain` | `platform_tls` (an `untrusted-root.badssl.com` chain, the no-proxy stand-in for interception) | PASS |
| `post_handshake_digest` | app-specific post-handshake code | FAIL by design: needs a per-app target |
| `webview` | `chromium` (WebView loads `untrusted-root.badssl.com`) | PASS once the Chromium verifier patch is in; FAIL with SSL error 3 otherwise |
| `static_openssl` | `static_openssl` (a bundled OpenSSL 3.x, `libtestossl.so`, handshakes with `untrusted-root.badssl.com` under `SSL_VERIFY_PEER`, once through `TLS_client_method` and once through `TLS_method`; it connects directly, so Burp's system CA cannot make it pass) | PASS with `verify_result=0` twice; FAIL with `verify_result=19` untargeted; SKIP when the APK was built without `OPENSSL_DIR` |
| `exec_bytes` (second button) | release check, plan §1.16 item 6 | PASS: every file-backed executable mapping is byte-identical to disk (read through `/proc/self/mem`, no native code) |

A test app where everything passes teaches nothing about the tier boundaries.

## Build

Needs the Android SDK and a JDK 17. `testHost` in `gradle.properties` (default `example.com`) feeds
the OkHttp pinner and the UI; the Network Security Config cannot read Gradle properties, so change
the `<domain>` in `app/src/main/res/xml/network_security_config.xml` too. Put your interception
proxy in front of that host.

```
cd tests/test-app && gradle assembleDebug          # or ./gradlew after `gradle wrapper`
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`tools/fetch_testapp_deps.sh <dir> --openssl 3.4.1` downloads the runtime jars from Maven
Central and builds the static OpenSSL with the NDK (about a minute); CI does exactly that and
publishes the APK as the `pinning-haters-test-app` artifact.

Without Gradle, `build_manual.sh` does the same with `aapt2` + `javac` + `d8` + `apksigner`:
`BUILD_TOOLS`, `ANDROID_JAR` and `JARS_DIR` (the OkHttp, Okio and Kotlin stdlib jars) are
required; `ANDROID_NDK_HOME` adds the native helpers, and `OPENSSL_DIR` (an OpenSSL 3.x tree
configured with `./Configure android-arm64 no-shared` and built with `make build_libs`) adds
`libtestossl.so` for the `static_openssl` check.

Target `dev.pinninghaters.testapp` in `/data/adb/pinning_haters/config.json`, enable logging, run
the checks, then compare the on-screen verdicts (also in `adb logcat -s pinning-haters-test`) with
the coverage lines in the log file.

CI (`contract.yml`, job `build-test-app`) builds it on every push. Running it still needs a rooted
device; its `libtestossl.so` also feeds the host tests as the OpenSSL 3.2+ fixture.
