#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

int create_socket(int port) {
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

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
}

int main(int argc, char **argv) {
    int server_socket, client_socket;
    SSL_CTX *ctx;

    initialize_openssl();
    ctx = create_context();

    configure_context(ctx);

    server_socket = create_socket(1234);

    printf("Waiting for incoming connections...\n");

    client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        char buf[1024];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = '\0';
        printf("Received: %s\n", buf);

        SSL_write(ssl, "Hello from server", 18);
    }

    SSL_free(ssl);
    close(server_socket);
    close(client_socket);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}