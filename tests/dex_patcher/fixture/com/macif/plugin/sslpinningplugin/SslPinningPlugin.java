package com.macif.plugin.sslpinningplugin;

import java.util.List;
import java.util.Map;

// Shape of the Flutter ssl_pinning_plugin's Android side (six-argument checkConnexion).
public class SslPinningPlugin {
    private boolean checkConnexion(String serverURL, List<String> allowedFingerprints, Map<String, String> httpHeaderArgs,
                                   int timeout, String type, String httpMethod) {
        String sha = getFingerprint(serverURL, timeout, httpHeaderArgs, type, httpMethod);
        for (String fp : allowedFingerprints) {
            if (fp.toUpperCase().replaceAll("\\s", "").equals(sha)) return true;
        }
        return false;
    }

    private String getFingerprint(String httpsURL, int connectTimeout, Map<String, String> httpHeaderArgs, String type,
                                  String httpMethod) {
        return "BB" + httpsURL.length() + type + httpMethod + connectTimeout + httpHeaderArgs.size();
    }
}
