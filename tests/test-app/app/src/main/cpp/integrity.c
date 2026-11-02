// SPDX-License-Identifier: GPL-3.0-or-later
// CRC-32 over a range of this process's own memory, for IntegrityCheck. An app may not open
// /proc/self/mem under SELinux, but it can of course read its own mappings directly.
#include <jni.h>
#include <stdint.h>
#include <zlib.h>

JNIEXPORT jlong JNICALL Java_dev_pinninghaters_testapp_IntegrityCheck_crcRange(JNIEnv* env, jclass clazz, jlong addr,
                                                                                jlong len) {
    (void)env;
    (void)clazz;
    uLong crc = crc32(0L, Z_NULL, 0);
    const Bytef* p = (const Bytef*)(uintptr_t)addr;
    while (len > 0) {
        const uInt chunk = len > (1 << 20) ? (1 << 20) : (uInt)len;
        crc = crc32(crc, p, chunk);
        p += chunk;
        len -= chunk;
    }
    return (jlong)crc;
}
