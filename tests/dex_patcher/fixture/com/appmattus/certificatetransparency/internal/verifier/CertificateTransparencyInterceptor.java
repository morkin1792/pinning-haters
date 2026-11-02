package com.appmattus.certificatetransparency.internal.verifier;

import java.io.IOException;
import javax.net.ssl.SSLPeerUnverifiedException;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/** Shape of the appmattus CT interceptor: proceed, inspect, throw. Enough locals to push p1 past v1. */
public final class CertificateTransparencyInterceptor implements Interceptor {
    private final boolean failOnError = true;

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        long started = System.nanoTime();
        int attempts = 0;
        String host = request.url;
        try {
            for (int i = 0; i < 3; i++) attempts += host.length() + i;
        } catch (RuntimeException e) {
            attempts = -1;
        }
        Response response;
        try {
            response = chain.proceed(request);
        } finally {
            attempts++;
        }
        long elapsed = System.nanoTime() - started;
        if (failOnError && (attempts % 2 == 0 || elapsed > 0)) {
            throw new SSLPeerUnverifiedException("Certificate transparency failed for " + host);
        }
        return response;
    }
}
