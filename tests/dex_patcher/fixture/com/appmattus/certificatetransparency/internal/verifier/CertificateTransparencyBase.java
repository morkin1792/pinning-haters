package com.appmattus.certificatetransparency.internal.verifier;

import java.util.List;

/** Shape of appmattus CertificateTransparencyBase: the private host gate every variant consults. */
public class CertificateTransparencyBase {
    private final List<String> excludeHosts;

    public CertificateTransparencyBase(List<String> excludeHosts) {
        this.excludeHosts = excludeHosts;
    }

    private boolean enabledForCertificateTransparency(String host) {
        for (String excluded : excludeHosts) {
            if (host.endsWith(excluded)) return false;
        }
        return host.indexOf('.') > 0;
    }

    public boolean check(String host) {
        return enabledForCertificateTransparency(host);
    }
}
