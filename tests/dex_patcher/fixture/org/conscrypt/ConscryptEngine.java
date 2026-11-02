package org.conscrypt;

// Shape of Conscrypt's SSLHandshakeCallbacks implementation: the chain check that throws.
public class ConscryptEngine {
    public void verifyCertificateChain(byte[][] certChain, String authMethod) throws java.security.cert.CertificateException {
        if (certChain == null || certChain.length == 0) throw new java.security.cert.CertificateException("Peer sent no certificate");
    }
}
