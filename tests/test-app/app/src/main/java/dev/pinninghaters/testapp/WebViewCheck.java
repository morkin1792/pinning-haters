// SPDX-License-Identifier: GPL-3.0-or-later
package dev.pinninghaters.testapp;

import android.app.Activity;
import android.net.http.SslError;
import android.os.Handler;
import android.os.Looper;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.util.function.Consumer;

/**
 * WebView against a chain platform trust rejects. Chromium verifies in its own Java code
 * (AndroidNetworkLibrary.verifyServerCertificates in the provider's DEX), not through conscrypt's
 * callback, so this exercises the `chromium` surface and nothing else. No proxy involved.
 */
final class WebViewCheck {
    private WebViewCheck() {}

    private static final String URL = "https://untrusted-root.badssl.com/";

    static void run(Activity activity, Consumer<String> done) {
        final boolean[] reported = {false};
        final WebView wv = new WebView(activity);
        final Handler handler = new Handler(Looper.getMainLooper());
        final Runnable timeout = () -> report(reported, done, "webview FAIL: no verdict after 25s");
        wv.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler h, SslError error) {
                h.cancel();
                handler.removeCallbacks(timeout);
                report(reported, done, "webview FAIL: SSL error " + error.getPrimaryError() + " (platform trust rejected the chain)");
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (!request.isForMainFrame()) return;
                handler.removeCallbacks(timeout);
                report(reported, done, "webview FAIL: " + error.getDescription());
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                handler.removeCallbacks(timeout);
                report(reported, done, "webview PASS: loaded " + url + " (Chromium verifier overridden)");
            }
        });
        handler.postDelayed(timeout, 25000);
        wv.loadUrl(URL);
    }

    private static void report(boolean[] reported, Consumer<String> done, String line) {
        if (reported[0]) return;
        reported[0] = true;
        done.accept(line);
    }
}
