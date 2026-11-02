// SPDX-License-Identifier: GPL-3.0-or-later
package dev.pinninghaters.testapp;

import java.io.IOException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * The four checks that distinguish this architecture (plan §1.14). Each returns a one-line verdict.
 * With an interception proxy in front of TEST_HOST and the package targeted at tier max:
 *   custom_trustmanager   PASS  (conscrypt wrap; the TrustManager must still have been invoked)
 *   nsc_pins              PASS  (conscrypt wrap)
 *   okhttp_pinner         PASS  (DEX patch of CertificatePinner.check*)
 *   post_handshake_digest FAIL  (app-specific post-handshake comparison: needs a per-app target)
 */
final class Checks {
    private Checks() {}

    private static final String URL = "https://" + BuildConfig.TEST_HOST + "/";
    private static final String BOGUS_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /** Rejects every chain, and records that it was asked. */
    static final class RecordingTrustManager implements X509TrustManager {
        final AtomicBoolean invoked = new AtomicBoolean(false);

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client auth not expected");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            invoked.set(true);
            throw new CertificateException("RecordingTrustManager rejects everything");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    static String customTrustManager() {
        RecordingTrustManager tm = new RecordingTrustManager();
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {tm}, null);
            HttpsURLConnection c = (HttpsURLConnection) new URL(URL).openConnection();
            c.setSSLSocketFactory(ctx.getSocketFactory());
            int code = c.getResponseCode();
            c.disconnect();
            if (!tm.invoked.get()) return "custom_trustmanager FAIL: handshake ok but TrustManager was never invoked (replaced, not wrapped?)";
            return "custom_trustmanager PASS: HTTP " + code + ", TrustManager invoked and overridden";
        } catch (Exception e) {
            return "custom_trustmanager FAIL: " + e + (tm.invoked.get() ? " (TrustManager invoked)" : " (TrustManager NOT invoked)");
        }
    }

    static String nscPins() {
        try {
            HttpsURLConnection c = (HttpsURLConnection) new URL(URL).openConnection();
            int code = c.getResponseCode();
            c.disconnect();
            return "nsc_pins PASS: HTTP " + code + " despite a non-matching network_security_config pin-set";
        } catch (Exception e) {
            return "nsc_pins FAIL: " + e;
        }
    }

    static String okhttpPinner() {
        OkHttpClient client = new OkHttpClient.Builder()
                .certificatePinner(new CertificatePinner.Builder().add(BuildConfig.TEST_HOST, BOGUS_PIN).build())
                .build();
        try (Response r = client.newCall(new Request.Builder().url(URL).build()).execute()) {
            return "okhttp_pinner PASS: HTTP " + r.code() + " despite a non-matching CertificatePinner";
        } catch (IOException e) {
            return "okhttp_pinner FAIL: " + e;
        }
    }

    /** The interception scenario without a proxy: a chain platform trust rejects. */
    static String untrustedChain() {
        try {
            HttpsURLConnection c = (HttpsURLConnection) new URL("https://untrusted-root.badssl.com/").openConnection();
            int code = c.getResponseCode();
            c.disconnect();
            return "untrusted_chain PASS: HTTP " + code + " from untrusted-root.badssl.com (platform trust overridden)";
        } catch (Exception e) {
            return "untrusted_chain FAIL: " + e;
        }
    }

    static String postHandshakeDigest() {
        try {
            HttpsURLConnection c = (HttpsURLConnection) new URL(URL).openConnection();
            c.connect();
            Certificate[] chain = c.getServerCertificates();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded());
            c.disconnect();
            boolean allZero = true;
            for (byte b : digest) allZero &= b == 0;
            // An all-zero digest can never match a real certificate: this check fails by design at
            // tier max, which is the point — app-specific post-handshake code needs a per-app target.
            return allZero ? "post_handshake_digest PASS (unexpected)" : "post_handshake_digest FAIL (expected at max): leaf digest does not match the app's pin";
        } catch (Exception e) {
            return "post_handshake_digest FAIL: " + e;
        }
    }
}
