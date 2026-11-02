package okhttp3;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import kotlin.jvm.functions.Function0;

/**
 * Shape-compatible stand-in for okhttp3.CertificatePinner across 3.x–5.x: every overload the
 * production target table names, with bodies that use try/catch/finally, a switch (payload data
 * inside insns[]) and 4-byte instructions, so the nop-fill and tries-untouched rules get exercised.
 */
public final class CertificatePinner {
    public static final CertificatePinner DEFAULT = new CertificatePinner();

    public void check(String hostname, List<Certificate> peerCertificates) throws SSLPeerUnverifiedException {
        if (hostname == null) throw new IllegalArgumentException("hostname");
        try {
            switch (peerCertificates.size()) {
                case 1: throw new SSLPeerUnverifiedException("pin mismatch for " + hostname);
                case 2: System.out.println("two certificates");
                    break;
                case 7: System.out.println("seven");
                    break;
                default: break;
            }
        } catch (RuntimeException e) {
            throw new SSLPeerUnverifiedException(e.toString());
        } finally {
            System.out.println("checked " + hostname);
        }
        throw new SSLPeerUnverifiedException("Certificate pinning failure!");
    }

    public void check(String hostname, Certificate... peerCertificates) throws SSLPeerUnverifiedException {
        check(hostname, java.util.Arrays.asList(peerCertificates));
    }

    public void check$okhttp(String hostname, Function0<List<X509Certificate>> cleanedPeerCertificatesFn)
            throws SSLPeerUnverifiedException {
        List<X509Certificate> certs = cleanedPeerCertificatesFn.invoke();
        long sum = 0L;
        for (X509Certificate c : certs) sum += c.getSerialNumber().longValue();
        if (sum != 0x1234567890L) throw new SSLPeerUnverifiedException("Certificate pinning failure! " + sum);
    }

    public void check(String hostname, Function0<List<X509Certificate>> cleanedPeerCertificatesFn)
            throws SSLPeerUnverifiedException {
        check$okhttp(hostname, cleanedPeerCertificatesFn);
    }
}
