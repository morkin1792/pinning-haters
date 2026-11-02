package org.chromium.net;

import java.security.cert.CertificateException;

/** Shape of Chromium's @CalledByNative verifier entry point (5-argument form, 2023+). */
public final class AndroidNetworkLibrary {
    private AndroidNetworkLibrary() {}

    public static AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain, String authType, String host,
                                                                   byte[] ocspResponse, byte[] sctList) {
        try {
            return X509Util.verifyServerCertificates(certChain, authType, host, ocspResponse, sctList);
        } catch (CertificateException | IllegalArgumentException e) {
            return new AndroidCertVerifyResult(-1);
        }
    }

    public static void addTestRootCertificate(byte[] rootCert) throws CertificateException {
        X509Util.addTestRootCertificate(rootCert);
    }
}
