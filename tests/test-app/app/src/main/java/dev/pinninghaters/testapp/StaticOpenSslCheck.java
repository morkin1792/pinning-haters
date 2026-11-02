// SPDX-License-Identifier: GPL-3.0-or-later
package dev.pinninghaters.testapp;

/**
 * A statically linked OpenSSL (libtestossl.so, built by build_manual.sh when OPENSSL_DIR is set)
 * handshakes with an untrusted-root host under SSL_VERIFY_PEER. No GOT edge exists for its chain
 * check, so only the SSL_METHOD table swap (`static_openssl` surface) can make this pass.
 */
final class StaticOpenSslCheck {
    private StaticOpenSslCheck() {}

    private static native String connect(String host);

    static String run() {
        try {
            System.loadLibrary("testossl");
        } catch (UnsatisfiedLinkError e) {
            return "static_openssl SKIP: libtestossl.so not bundled (build with OPENSSL_DIR set)";
        }
        try {
            String r = connect("untrusted-root.badssl.com");
            final boolean client = r.contains("client: handshake ok") && !r.contains("client: handshake failed");
            final boolean generic = r.contains("generic: handshake ok") && !r.contains("generic: handshake failed");
            if (client && generic && r.split("verify_result=0 ", -1).length == 3) {
                return "static_openssl PASS: " + r + " (SSL_METHOD ssl_connect swapped, verification relaxed)";
            }
            return "static_openssl FAIL: " + r;
        } catch (Throwable e) {
            return "static_openssl FAIL: " + e;
        }
    }
}
