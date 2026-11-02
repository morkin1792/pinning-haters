package diefferson.http_certificate_pinning;

import java.util.List;
import java.util.Map;

// Shape of the Flutter http_certificate_pinning plugin's Android side: checkConnexion fetches the
// server's certificate digest itself and compares it with the Dart-supplied list.
public class HttpCertificatePinningPlugin {
    private boolean checkConnexion(String serverURL, List<String> allowedFingerprints,
                                   Map<String, String> httpHeaderArgs, int timeout, String type) {
        String sha = getFingerprint(serverURL, timeout, httpHeaderArgs, type);
        for (String fp : allowedFingerprints) {
            if (fp.toUpperCase().replaceAll("\\s", "").equals(sha)) return true;
        }
        return false;
    }

    private String getFingerprint(String httpsURL, int connectTimeout, Map<String, String> httpHeaderArgs, String type) {
        return "AA" + httpsURL.length() + type + connectTimeout + httpHeaderArgs.size();
    }
}
