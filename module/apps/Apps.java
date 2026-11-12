// SPDX-License-Identifier: GPL-3.0-or-later
// App list for the WebUI: one line per installed package (name, system flag, version, label) on
// stdout, and one icon file per package in the directory given as the first argument.
//
// Run as root from the manager's shell:
//   app_process -Djava.class.path=<module>/apps.dex /system/bin ph.Apps <icon dir> [all]
// Managers differ in what their WebView offers (older ones have no package or icon API at all), so
// the WebUI asks the platform itself. This never runs inside a target app.
package ph;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Looper;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;

public final class Apps {
    private static final int ICON_PX = 96;

    public static void main(String[] args) throws Exception {
        File dir = new File(args[0]);
        boolean all = args.length > 1 && args[1].equals("all");
        dir.mkdirs();

        // A system context without an app: the usual route for a root tool under app_process.
        Looper.prepareMainLooper();
        Object thread = Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
        Context context = (Context) thread.getClass().getMethod("getSystemContext").invoke(thread);
        PackageManager pm = context.getPackageManager();

        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), false, "UTF-8");
        for (PackageInfo p : pm.getInstalledPackages(0)) {
            ApplicationInfo app = p.applicationInfo;
            boolean system = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            if (system && !all) continue;
            out.println(p.packageName + "\t" + (system ? 1 : 0) + "\t" + oneLine(p.versionName) + "\t"
                    + oneLine(String.valueOf(app.loadLabel(pm))));
            File icon = new File(dir, p.packageName + ".png");
            if (icon.exists() && icon.lastModified() >= p.lastUpdateTime) continue;
            try {
                writeIcon(app.loadUnbadgedIcon(pm), icon);
            } catch (Throwable t) {
                // No icon: the WebUI draws a letter instead.
            }
        }
        out.flush();
        System.exit(0);  // systemMain left threads running
    }

    private static String oneLine(String s) {
        return s == null ? "" : s.replaceAll("[\\t\\r\\n]", " ");
    }

    private static void writeIcon(Drawable icon, File file) throws Exception {
        Bitmap bitmap = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888);
        icon.setBounds(0, 0, ICON_PX, ICON_PX);
        icon.draw(new Canvas(bitmap));
        try (FileOutputStream f = new FileOutputStream(file)) {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, f);
        }
    }
}
