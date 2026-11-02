package org.chromium.net;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/** Shape of Chromium's AndroidCertVerifyResult as found in the WebView provider DEX. */
public final class AndroidCertVerifyResult {
    private final int status;
    private final boolean issuedByKnownRoot;
    private final List<X509Certificate> chain;

    public AndroidCertVerifyResult(int status) {
        this.status = status;
        this.issuedByKnownRoot = false;
        this.chain = Collections.emptyList();
    }

    public int getStatus() {
        return status;
    }

    public boolean isIssuedByKnownRoot() {
        return issuedByKnownRoot;
    }

    public byte[][] getCertificateChainEncoded() {
        return new byte[chain.size()][];
    }
}
