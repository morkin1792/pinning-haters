package org.chromium.net;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

/** Shape of Chromium's X509Util: the static inner verifier plus an instance method with the same proto. */
public final class X509Util {
    private static final List<byte[]> TEST_ROOTS = new ArrayList<>();

    private X509Util() {}

    public static AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain, String authType, String host,
                                                                   byte[] ocspResponse, byte[] sctList)
            throws CertificateException {
        if (certChain == null || certChain.length == 0) throw new IllegalArgumentException("empty chain");
        int total = 0;
        try {
            for (byte[] cert : certChain) total += cert.length;
        } catch (RuntimeException e) {
            return new AndroidCertVerifyResult(-4);
        }
        if (total == 0 || authType.isEmpty() || host == null) throw new CertificateException("bad input");
        return new CertificateVerifier().verifyServerCertificates(certChain, authType, host, ocspResponse, sctList);
    }

    public static void addTestRootCertificate(byte[] rootCert) throws CertificateException {
        if (rootCert == null || rootCert.length == 0) throw new CertificateException("empty root");
        TEST_ROOTS.add(rootCert);
    }

    /** Instance method with the identical signature: must NOT be picked as the inner static verifier. */
    static final class CertificateVerifier {
        AndroidCertVerifyResult verifyServerCertificates(byte[][] certChain, String authType, String host,
                                                         byte[] ocspResponse, byte[] sctList) {
            return new AndroidCertVerifyResult(TEST_ROOTS.isEmpty() && ocspResponse == null && sctList == null ? -2 : 0);
        }
    }
}
