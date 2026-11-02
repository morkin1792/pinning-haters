// SPDX-License-Identifier: GPL-3.0-or-later
// A statically linked OpenSSL the way apps ship it: libssl and libcrypto whole-archived into this
// one library, linked -Bsymbolic so every internal call (ssl_verify_cert_chain → X509_verify_cert)
// is direct and no GOT slot exists for the bundled-TLS rows to rewrite. The only lever left is the
// SSL_METHOD table swap (module/jni/tls/openssl_table.cpp), which is what this check exercises:
// a TLS 1.2+ handshake to an untrusted-root host with SSL_VERIFY_PEER against the system CA
// directory, once through each client-capable table. Untargeted both fail at the chain check;
// targeted both complete and SSL_get_verify_result reads X509_V_OK.
#include <jni.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int tcp_connect(const char* host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo* a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// One handshake through `method`; the verdict is appended to out.
static void handshake(const SSL_METHOD* method, const char* label, const char* host, char* out, size_t cap) {
    char line[256];
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, NULL, "/system/etc/security/cacerts");
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    int fd = tcp_connect(host);
    if (fd < 0) {
        snprintf(line, sizeof line, "%s: tcp connect to %s failed; ", label, host);
    } else {
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set1_host(ssl, host);
        const int r = SSL_connect(ssl);
        if (r == 1) {
            const long vr = SSL_get_verify_result(ssl);
            snprintf(line, sizeof line, "%s: handshake ok, %s, verify_result=%ld (%s); ", label, SSL_get_version(ssl), vr,
                     X509_verify_cert_error_string(vr));
        } else {
            const unsigned long e = ERR_peek_last_error();
            snprintf(line, sizeof line, "%s: handshake failed: SSL_connect=%d error=%d verify_result=%ld %s; ", label, r,
                     SSL_get_error(ssl, r), SSL_get_verify_result(ssl), e ? ERR_reason_error_string(e) : "");
        }
        SSL_free(ssl);
        close(fd);
    }
    SSL_CTX_free(ctx);
    strncat(out, line, cap - strlen(out) - 1);
}

// Both tables a client handshake can run through: TLS_client_method (curl and most apps) and the
// generic TLS_method (gRPC, VPN cores).
JNIEXPORT jstring JNICALL Java_dev_pinninghaters_testapp_StaticOpenSslCheck_connect(JNIEnv* env, jclass clazz,
                                                                                   jstring jhost) {
    (void)clazz;
    char out[600] = "";
    const char* host = (*env)->GetStringUTFChars(env, jhost, NULL);
    snprintf(out, sizeof out, "%s; ", OpenSSL_version(OPENSSL_VERSION));
    handshake(TLS_client_method(), "client", host, out, sizeof out);
    handshake(TLS_method(), "generic", host, out, sizeof out);
    (*env)->ReleaseStringUTFChars(env, jhost, host);
    return (*env)->NewStringUTF(env, out);
}
