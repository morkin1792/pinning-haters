package okhttp3.internal.tls;

import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;

public final class OkHostnameVerifier {
    public boolean verify(String host, SSLSession session) {
        return host != null && session != null && host.length() > 3;
    }

    public boolean verify(String host, X509Certificate certificate) {
        return host != null && certificate.getSubjectX500Principal() != null;
    }
}
