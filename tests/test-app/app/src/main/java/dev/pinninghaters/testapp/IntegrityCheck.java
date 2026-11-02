// SPDX-License-Identifier: GPL-3.0-or-later
package dev.pinninghaters.testapp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

/**
 * The release check from plan §1.16 item 6: every file-backed executable mapping of this process
 * must be byte-identical to the file on disk. The mapped bytes are hashed by a 20-line JNI helper
 * (SELinux denies an app /proc/self/mem, even its own), the file bytes in Java; both are CRC-32
 * with the zlib polynomial. GOT pages are data and are not covered — the hook is supposed to change
 * those. Run it after a TLS connection and a class load.
 */
final class IntegrityCheck {
    private IntegrityCheck() {}

    static {
        System.loadLibrary("integrity");
    }

    private static native long crcRange(long addr, long len);

    static String run() {
        List<String> bad = new ArrayList<>();
        int checked = 0;
        try (BufferedReader maps = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = maps.readLine()) != null) {
                // 7f1234000-7f1235000 r-xp 00002000 fe:00 1234   /path
                String[] f = line.trim().split("\\s+", 6);
                if (f.length < 6 || f[1].charAt(2) != 'x' || !f[5].startsWith("/")) continue;
                File file = new File(f[5]);
                if (!file.isFile() || !file.canRead()) continue;  // apex/system libs are world-readable
                String[] range = f[0].split("-");
                long start = Long.parseUnsignedLong(range[0], 16), end = Long.parseUnsignedLong(range[1], 16);
                long offset = Long.parseLong(f[2], 16);
                long len = Math.min(end - start, file.length() - offset);
                if (len <= 0) continue;
                try (RandomAccessFile disk = new RandomAccessFile(file, "r")) {
                    long memCrc = crcRange(start, len) & 0xffffffffL, diskCrc = crc(disk, offset, len);
                    checked++;
                    if (memCrc != diskCrc) bad.add(String.format("%s @%s (+%x, %d bytes)", f[5], range[0], offset, len));
                }
            }
        } catch (Exception e) {
            return "exec_bytes ERROR: " + e;
        }
        if (bad.isEmpty()) return "exec_bytes PASS: " + checked + " executable mappings identical to disk";
        return "exec_bytes FAIL: " + bad.size() + "/" + checked + " modified:\n  " + String.join("\n  ", bad);
    }

    private static long crc(RandomAccessFile f, long pos, long len) throws Exception {
        CRC32 crc = new CRC32();
        byte[] buf = new byte[1 << 16];
        f.seek(pos);
        while (len > 0) {
            int n = f.read(buf, 0, (int) Math.min(buf.length, len));
            if (n < 0) throw new java.io.EOFException("short read at " + Long.toHexString(pos));
            crc.update(buf, 0, n);
            len -= n;
        }
        return crc.getValue();
    }
}
