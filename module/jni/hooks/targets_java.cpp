// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters — Zygisk-based TLS certificate pinning bypass for Android.
// Copyright (C) 2026 morkin1792 and contributors.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version. This program is distributed WITHOUT ANY WARRANTY;
// see <https://www.gnu.org/licenses/> for details.
#include "targets.h"

// Category A: Java/Kotlin pinning that runs AFTER the handshake, reading the negotiated chain. Only
// that belongs here. Anything invoked as a TrustManager during the handshake is already reached by
// the conscrypt custom_verify wrap (targets_native.cpp) — bootclasspath classes are AOT-compiled
// into the boot image before this module exists, and interface methods have no bytecode. Before
// adding an entry, check which side of the handshake it runs on.
namespace ph {

using enum ReplacementKind;

const JavaTarget kJavaTargets[] = {
    // OkHttp CertificatePinner: RealConnection calls it after connectTls() succeeded, reading
    // handshake.peerCertificates. The conscrypt wrap has already said "ok" by then.
    {"Lokhttp3/CertificatePinner;", "check", "(Ljava/lang/String;Ljava/util/List;)V", RETURN_VOID, Tier::MAX,
     SurfaceId::OKHTTP_PINNER, "okhttp3.CertificatePinner.check(String, List) 3.x-5.x"},
    {"Lokhttp3/CertificatePinner;", "check", "(Ljava/lang/String;[Ljava/security/cert/Certificate;)V", RETURN_VOID,
     Tier::MAX, SurfaceId::OKHTTP_PINNER, "okhttp3.CertificatePinner.check(String, Certificate...) 3.x"},
    {"Lokhttp3/CertificatePinner;", "check$okhttp", "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V",
     RETURN_VOID, Tier::MAX, SurfaceId::OKHTTP_PINNER, "okhttp3.CertificatePinner.check$okhttp(String, Function0) 4.x-5.x"},
    {"Lokhttp3/CertificatePinner;", "check", "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", RETURN_VOID,
     Tier::MAX, SurfaceId::OKHTTP_PINNER, "okhttp3.CertificatePinner.check(String, Function0) 4.0-4.2"},

    // Conscrypt bundled by the app (org.conscrypt:conscrypt-android, used by OkHttp's ConscryptPlatform
    // and gRPC) and the copy Google Play services may install through ProviderInstaller
    // (jarjar'd under com.google.android.gms.org.conscrypt): their BoringSSL is statically linked,
    // so the platform wrap in libjavacrypto never sees these handshakes. The chain check is the
    // Java SSLHandshakeCallbacks.verifyCertificateChain, which calls the TrustManager and throws;
    // returning instead skips it (a replacement, not a wrap: the TrustManager is not invoked).
    // Measured on API 30 with the Conscrypt APEX: ProviderInstaller loads no second stack there,
    // so these rows report present=no on such devices; they are for older or bundled setups.
#define CONSCRYPT_ROW(cls, what)                                                                          \
    {cls, "verifyCertificateChain", "([[BLjava/lang/String;)V", RETURN_VOID, Tier::MAX, SurfaceId::BUNDLED_TLS, \
     "bundled Conscrypt " what ".verifyCertificateChain"}
    CONSCRYPT_ROW("Lorg/conscrypt/ConscryptEngine;", "ConscryptEngine"),
    CONSCRYPT_ROW("Lorg/conscrypt/ConscryptFileDescriptorSocket;", "ConscryptFileDescriptorSocket"),
    CONSCRYPT_ROW("Lcom/google/android/gms/org/conscrypt/ConscryptEngine;", "(GmsCore) ConscryptEngine"),
    CONSCRYPT_ROW("Lcom/google/android/gms/org/conscrypt/ConscryptFileDescriptorSocket;", "(GmsCore) ConscryptFileDescriptorSocket"),
#undef CONSCRYPT_ROW

    // Certificate Transparency (appmattus, formerly babylon) runs after the handshake on the
    // negotiated chain, as an OkHttp interceptor, a HostnameVerifier wrapper or a TrustManager
    // wrapper. All three consult enabledForCertificateTransparency(host) first; answering false
    // disables CT for every host without touching the delegate hostname check, which is why the
    // HostnameVerifier variant is not patched to `true`. The interceptor pass-through stays as the
    // fallback for builds where that private method was renamed by R8.
    {"Lcom/appmattus/certificatetransparency/internal/verifier/CertificateTransparencyBase;",
     "enabledForCertificateTransparency", "(Ljava/lang/String;)Z", RETURN_FALSE, Tier::MAX, SurfaceId::CERT_TRANSPARENCY,
     "appmattus CertificateTransparencyBase.enabledForCertificateTransparency (2.x)"},
    {"Lcom/appmattus/certificatetransparency/internal/verifier/CertificateTransparencyInterceptor;", "intercept",
     "(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;", INTERCEPTOR_PROCEED, Tier::MAX, SurfaceId::CERT_TRANSPARENCY,
     "appmattus certificatetransparency OkHttp interceptor (2.x)"},
    {"Lcom/babylon/certificatetransparency/internal/verifier/CertificateTransparencyBase;",
     "enabledForCertificateTransparency", "(Ljava/lang/String;)Z", RETURN_FALSE, Tier::MAX, SurfaceId::CERT_TRANSPARENCY,
     "babylon CertificateTransparencyBase.enabledForCertificateTransparency (1.x)"},
    {"Lcom/babylon/certificatetransparency/internal/verifier/CertificateTransparencyInterceptor;", "intercept",
     "(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;", INTERCEPTOR_PROCEED, Tier::MAX, SurfaceId::CERT_TRANSPARENCY,
     "babylon certificatetransparency OkHttp interceptor (1.x)"},

    // Chromium (WebView, Cronet, HTTP/3) verifies chains in Java, in the provider's own DEX: native
    // CertVerifyProcAndroid calls the @CalledByNative AndroidNetworkLibrary.verifyServerCertificates,
    // which delegates to X509Util (R8-renamed). Native insists on a NON-EMPTY verified chain with an
    // OK status, so a fabricated result object does not do; instead the leaf of the chain under
    // verification is registered as a root of Chromium's own test trust store
    // (addTestRootCertificate, also @CalledByNative and therefore name-stable) and the real inner
    // verifier runs, succeeds against that anchor, and returns a proper result. is_issued_by_known_root
    // stays false, so no pin enforcement either. The provider APK's oat is hidden by the stat
    // fallback, which is what makes its DEX reachable here. 5-argument (2023+) and 3-argument shapes.
    {"Lorg/chromium/net/AndroidNetworkLibrary;", "verifyServerCertificates",
     "([[BLjava/lang/String;Ljava/lang/String;[B[B)Lorg/chromium/net/AndroidCertVerifyResult;", CHROMIUM_TRUST_LEAF,
     Tier::MAX, SurfaceId::CHROMIUM, "chromium AndroidNetworkLibrary.verifyServerCertificates (5 args)"},
    {"Lorg/chromium/net/AndroidNetworkLibrary;", "verifyServerCertificates",
     "([[BLjava/lang/String;Ljava/lang/String;)Lorg/chromium/net/AndroidCertVerifyResult;", CHROMIUM_TRUST_LEAF,
     Tier::MAX, SurfaceId::CHROMIUM, "chromium AndroidNetworkLibrary.verifyServerCertificates (3 args)"},

    // Flutter "Dart-side" pinning packages mostly are not Dart-side at all: their check runs in the
    // plugin's Android code, which fetches the server's certificate digest over its own
    // HttpsURLConnection and compares it with the list Dart passed. That Java method is a DEX
    // target like any other; the Dart side only sees "CONNECTION_SECURE". Pure-Dart comparisons
    // (SecureSocket.peerCertificate) stay out of reach (libapp.so marker, compat).
    {"Ldiefferson/http_certificate_pinning/HttpCertificatePinningPlugin;", "checkConnexion",
     "(Ljava/lang/String;Ljava/util/List;Ljava/util/Map;ILjava/lang/String;)Z", RETURN_TRUE, Tier::MAX,
     SurfaceId::DART_PINNING, "Flutter http_certificate_pinning: Android-side fingerprint check"},
    {"Lcom/macif/plugin/sslpinningplugin/SslPinningPlugin;", "checkConnexion",
     "(Ljava/lang/String;Ljava/util/List;Ljava/util/Map;ILjava/lang/String;Ljava/lang/String;)Z", RETURN_TRUE, Tier::MAX,
     SurfaceId::DART_PINNING, "Flutter ssl_pinning_plugin: Android-side fingerprint check"},

    // Hostname verification is not pinning. Opt-in via relax_hostname_verification; see §1.10.
    {"Lokhttp3/internal/tls/OkHostnameVerifier;", "verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
     RETURN_TRUE, Tier::MAX, SurfaceId::HOSTNAME_VERIFIER, "okhttp3 OkHostnameVerifier.verify(String, SSLSession)"},
    {"Lokhttp3/internal/tls/OkHostnameVerifier;", "verify", "(Ljava/lang/String;Ljava/security/cert/X509Certificate;)Z",
     RETURN_TRUE, Tier::MAX, SurfaceId::HOSTNAME_VERIFIER, "okhttp3 OkHostnameVerifier.verify(String, X509Certificate)"},
    // Apache HttpClient as bundled by the app. The platform copy (org.apache.http.legacy) is a
    // dexpreopted system library and is not reached by the DEX path.
    {"Lorg/apache/http/conn/ssl/AbstractVerifier;", "verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSocket;)V",
     RETURN_VOID, Tier::MAX, SurfaceId::HOSTNAME_VERIFIER, "apache AbstractVerifier.verify(String, SSLSocket)"},
    {"Lorg/apache/http/conn/ssl/AbstractVerifier;", "verify", "(Ljava/lang/String;Ljava/security/cert/X509Certificate;)V",
     RETURN_VOID, Tier::MAX, SurfaceId::HOSTNAME_VERIFIER, "apache AbstractVerifier.verify(String, X509Certificate)"},
    {"Lorg/apache/http/conn/ssl/AbstractVerifier;", "verify",
     "(Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/String;Z)V", RETURN_VOID, Tier::MAX,
     SurfaceId::HOSTNAME_VERIFIER, "apache AbstractVerifier.verify(String, String[], String[], boolean)"},
    {"Lorg/apache/http/conn/ssl/AbstractVerifier;", "verify", "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
     RETURN_TRUE, Tier::MAX, SurfaceId::HOSTNAME_VERIFIER, "apache AbstractVerifier.verify(String, SSLSession)"},
};
const size_t kJavaTargetCount = sizeof(kJavaTargets) / sizeof(kJavaTargets[0]);

}  // namespace ph
