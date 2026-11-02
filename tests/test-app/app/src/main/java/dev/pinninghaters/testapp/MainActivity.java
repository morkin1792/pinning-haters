// SPDX-License-Identifier: GPL-3.0-or-later
package dev.pinninghaters.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** One button runs the four checks on a background thread and prints their verdicts. */
public final class MainActivity extends Activity {
    private static final String TAG = "pinning-haters-test";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        TextView header = new TextView(this);
        header.setText("Target: https://" + BuildConfig.TEST_HOST + "/\nPut an interception proxy in front of it and target "
                + getPackageName() + " in pinning-haters.");
        Button run = new Button(this);
        run.setText("Run pinning checks");
        Button integrity = new Button(this);
        integrity.setText("Check executable bytes vs disk");
        TextView out = new TextView(this);
        out.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        root.addView(header);
        root.addView(run);
        root.addView(integrity);
        root.addView(scroll);
        setContentView(root);

        run.setOnClickListener(v -> {
            run.setEnabled(false);
            out.setText("running...");
            new Thread(() -> {
                StringBuilder sb = new StringBuilder();
                for (String line : new String[] {Checks.customTrustManager(), Checks.nscPins(), Checks.okhttpPinner(),
                                                 Checks.untrustedChain(), Checks.postHandshakeDigest(),
                                                 StaticOpenSslCheck.run()}) {
                    Log.i(TAG, line);
                    sb.append(line).append("\n\n");
                }
                runOnUiThread(() -> {
                    out.setText(sb.toString());
                    // WebView must live on the UI thread; its verdict is appended when the page settles.
                    WebViewCheck.run(MainActivity.this, line -> {
                        Log.i(TAG, line);
                        out.append(line + "\n\n");
                        run.setEnabled(true);
                        saveVerdicts(sb + line + "\n");
                    });
                });
            }).start();
        });

        // `am start -n dev.pinninghaters.testapp/.MainActivity --ez run true`: run the checks without a tap
        // (unattended stability runs; screen off is fine).
        if (getIntent().getBooleanExtra("run", false)) run.performClick();

        integrity.setOnClickListener(v -> {
            integrity.setEnabled(false);
            out.setText("hashing executable mappings...");
            new Thread(() -> {
                String line = IntegrityCheck.run();
                Log.i(TAG, line);
                runOnUiThread(() -> {
                    out.setText(line);
                    integrity.setEnabled(true);
                });
            }).start();
        });
    }

    // Some ROMs drop app log lines; files/last_run.txt is readable as root whatever logcat does.
    private void saveVerdicts(String text) {
        try (java.io.FileOutputStream f = new java.io.FileOutputStream(new java.io.File(getFilesDir(), "last_run.txt"))) {
            f.write((System.currentTimeMillis() / 1000 + "\n" + text).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            Log.w(TAG, "cannot save verdicts: " + e);
        }
    }
}
