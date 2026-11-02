Consider:

```
there's effectively a third tier: AOT-compiled non-Java runtimes whose
  pinning logic lives above BoringSSL but isn't reachable as Java/DEX. They're technically "native"
   (machine code), but they aren't hookable by symbol name the way libssl.so is. Worth calling out
  separately because the plan's current Java/native split silently lumps them in.

  Concretely, by framework:

  - Flutter (Dart, AOT in libapp.so) — dart:io HttpClient routes through BoringSSL, so your
  libflutter.so hooks on SSL_set_custom_verify / SSL_CTX_set_verify catch the common case. Gap:
  Dart-side pinning libraries (http_certificate_pinning, ssl_pinning_plugin, Dio interceptors) do
  the SHA-256 pin compare in Dart code and abort before the handshake completes — your BoringSSL
  hooks never fire. Also Flutter's own ssl_verify_peer_cert static fn inside libflutter.so is
  unexported; you find it by call-pattern from SSL_set_custom_verify. Both are pattern-match jobs,
  not symbol-resolve jobs.
  - Unity (C# → IL2CPP → libil2cpp.so) — UnityWebRequest ultimately hits libcurl or platform HTTP.
  Custom pinning is often done in C# (manual chain walk, custom CertificateHandler). After IL2CPP
  it's stripped native code; you find methods via global-metadata.dat mapping or pattern. Same
  problem class as Dart-side pinning.
  - Xamarin / .NET MAUI — two sub-cases. Mono.Android using Java HttpClient → DEX patching catches
  it. But HttpClient + ServerCertificateValidationCallback lives in C#/Mono assemblies — not in
  DEX. Plan §1.5.1 already lists Xamarin as polish; reality is it's its own layer, not a "few extra
   Java targets."
  - Qt for Android — QSslSocket via libQt{5,6}Network.so. Uses BoringSSL or system OpenSSL
  underneath, so libssl hooks usually win. Pinning via QSslConfiguration::setCaCertificates is in
  Qt's own code path.
  - React Native, Cordova/Ionic/Capacitor — both end up in Java OkHttp / WebView underneath.
  Already covered by your existing Java + native layers; no new tier.
  - WebView-side pinning — Java (WebViewClient.onReceivedSslError, custom shouldInterceptRequest).
  DEX patching covers it but the target classes are app-specific subclasses.

  So practically the plan should distinguish three categories rather than two:

  1. Java/Kotlin via DEX — what §1.4 handles.
  2. Symbol-resolvable native — what §1.5 handles via shadowhook + symbol lookup in
  libssl/libcronet/libflutter.
  3. Symbol-stripped native / AOT'd foreign runtimes — Flutter Dart-side pinning, Unity IL2CPP,
  Xamarin Mono AOT, statically-linked-and-stripped BoringSSL inside app-private .so. Needs pattern
  scanning, not symbol resolve. The plan currently mentions this only in passing
  (pinning-haters-plan.md:359, "Symbol-stripped static BoringSSL is rare outside heavily-protected
  apps and is correctly punted to Phase 2") — that's accurate for stripped libssl, but understates
  Flutter/Unity/Xamarin which are common, not rare.


```
