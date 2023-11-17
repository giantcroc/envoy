// NOLINT(namespace-envoy)
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bytestring.h"
#include <zlib.h>

static int zlib_compress(SSL *, CBB* out,
                         const uint8_t *in, size_t inlen)
{

    
    size_t outlen = compressBound(inlen);

    uint8_t * outbuf =new uint8_t[outlen];

    if (compress2(outbuf, &outlen, in, inlen, Z_DEFAULT_COMPRESSION) != Z_OK){
     delete out;
     return 0;
    }
    CBB_add_bytes(out, outbuf, outlen);
    return 1;
}

// static int zlib_decompress(SSL *,
//                            const unsigned char *in, size_t inlen,
//                            unsigned char *out, size_t outlen)
// {
//     size_t len = outlen;

//     if (uncompress(out, &len, in, inlen) != Z_OK)
//         return 0;

//     if (len != outlen)
//         return 0;

//     return 1;
// }

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

// [](SSL *ssl, CBB *out, bssl::Span<const uint8_t> in) -> bool {
// +             if (in.size() < 2 || in[0] != 0 || in[1] != 0) {
// +               return false;
// +             }
// +             return CBB_add_bytes(out, in.data() + 2, in.size() - 2);
// +           },
// +           [](SSL *ssl, bssl::UniquePtr<CRYPTO_BUFFER> *out,
// +              size_t uncompressed_len, bssl::Span<const uint8_t> in) -> bool {
// +             if (uncompressed_len != 2 + in.size()) {
// +               return false;
// +             }
// +             std::unique_ptr<uint8_t[]> buf(new uint8_t[2 + in.size()]);
// +             buf[0] = 0;
// +             buf[1] = 0;
// +             OPENSSL_memcpy(&buf[2], in.data(), in.size());
// +             out->reset(CRYPTO_BUFFER_new(buf.get(), 2 + in.size(), nullptr));
// +             return true;
// +           }

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // ssl_cert_compression_func_t
    SSL_CTX_add_cert_compression_alg(ctx, TLSEXT_cert_compression_zlib,
                                    zlib_compress, NULL);
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int , char **)
{
    int sock;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, reinterpret_cast<struct sockaddr*>(&addr), &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}
