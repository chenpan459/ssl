#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "log.h"


#define SERVER_PORT 4433


#define filename_path "/home/Kylin-Server-V10-SP3-2403-Release-20240426-x86_64.iso"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "/root/4119/cert/certificate.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/root/4119/cert/private.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

 static EVP_CIPHER_CTX *ctx;
void init_encrypt(ENGINE *e)
{
    int len;
    int final_len;
    int ret;
 // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里使用 SKF 引擎提供的加密算法
  //  const EVP_CIPHER *cipher = ENGINE_get_cipher(e, NID_sm4_ecb); // 假设使用 SM4 ECB 模式

    printf("Using cipher NID: %d\n", NID_sm4_cbc);
    const EVP_CIPHER *cipher = ENGINE_get_cipher(e, NID_sm4_cbc);
    if (!cipher) {
        fprintf(stderr, "ENGINE_get_cipher failed\n");
        return;
    }

      ret= EVP_EncryptInit_ex(ctx, cipher, e, NULL, NULL);
      if(1 != ret){

       // printf("EVP_EncryptFinal_ex failed ret=%d\n",ret);
       // handleErrors();
     }

}


// 假设 SKF 引擎已经加载和初始化

void encrypt_data(ENGINE *e, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len) {
    //EVP_CIPHER_CTX *ctx;
    int len;
    int final_len;
    int ret;
/*
    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // 初始化加密操作，这里使用 SKF 引擎提供的加密算法
  //  const EVP_CIPHER *cipher = ENGINE_get_cipher(e, NID_sm4_ecb); // 假设使用 SM4 ECB 模式

    printf("Using cipher NID: %d\n", NID_sm4_cbc);
    const EVP_CIPHER *cipher = ENGINE_get_cipher(e, NID_sm4_cbc);
    if (!cipher) {
        fprintf(stderr, "ENGINE_get_cipher failed\n");
        return;
    }

      ret= EVP_EncryptInit_ex(ctx, cipher, e, NULL, NULL);
      if(1 != ret){

       // printf("EVP_EncryptFinal_ex failed ret=%d\n",ret);
       // handleErrors();
     }
     */
    // 加密数据
    ret= EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
     if(1 != ret){

        printf("EVP_EncryptFinal_ex failed ret=%d\n",ret);
       // handleErrors();
    }
    *ciphertext_len = len;

    // 结束加密操作
    ret= EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
     if(1 != ret){

        printf("EVP_EncryptFinal_ex failed ret=%d\n",ret);
       // handleErrors();
    }
    *ciphertext_len += final_len;

}

void free_encrypt()
{
    // 清理
    EVP_CIPHER_CTX_free(ctx);

}

void send_file(SSL *ssl, const char *filename, ENGINE *e) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Unable to open file");
        return;
    }


    char plaintext[4096];
    char ciphertext[4096 + EVP_MAX_BLOCK_LENGTH]; // 加密后的数据可能比原文长
    size_t bytes;
    size_t ciphertext_len;
    init_encrypt(e);
    while ((bytes = fread(plaintext, 1, sizeof(plaintext), fp)) > 0) {
        encrypt_data(e, (unsigned char *)plaintext, bytes, (unsigned char *)ciphertext, &ciphertext_len);
        if (SSL_write(ssl, ciphertext, ciphertext_len) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
    }
    free_encrypt();

    fclose(fp);
}

void test_encrypt(ENGINE *e) {
    
    
    char plaintext[4096];
    char ciphertext[4096 + EVP_MAX_BLOCK_LENGTH]; // 加密后的数据可能比原文长
    size_t plaintext_len;
    size_t ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    int len;
    int final_len;
    char key[32];
    char iv[16];
    int ret=0;
    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));


    TRACE_INFO("Using cipher NID: %d\n", NID_sm4_cbc);
    const EVP_CIPHER *cipher = ENGINE_get_cipher(e, NID_sm4_cbc);
    if (!cipher) {
        fprintf(stderr, "ENGINE_get_cipher failed\n");
        return;
    }

    memset(plaintext, 0x11, sizeof(plaintext));
    plaintext_len = 16;//sizeof(plaintext); // 假设要加密的数据长度为 4096 字节
   // encrypt_data(e, (unsigned char *)plaintext, bytes, (unsigned char *)ciphertext, &ciphertext_len);
    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    // 初始化加密操作，这里使用 SKF 引擎提供的加密算法
    ret = EVP_EncryptInit_ex(ctx, cipher, e, key, iv);
    if(1 != ret){

        printf("EVP_EncryptInit_ex failed ret=%d\n",ret);
       // handleErrors();
    }
       // handleErrors();

    // 加密数据
    ret= EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if(1 != ret){

        printf("EVP_EncryptUpdate failed ret=%d\n",ret);
       // handleErrors();
       
    }
    dump_hex("plaintext", plaintext, plaintext_len);
    dump_hex("ciphertext", ciphertext, len);
   // *ciphertext_len = len;

    // 结束加密操作
    ret= EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
    if(1 != ret){

        printf("EVP_EncryptFinal_ex failed ret=%d\n",ret);
       // handleErrors();
    }
   // *ciphertext_len += final_len;
  
    // 清理
    EVP_CIPHER_CTX_free(ctx);

 
}

int main(int argc, char **argv) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx;
    SSL *ssl;
    char buf[1024];

    /* 初始化 OpenSSL 库 */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* 创建并配置 SSL 上下文 */
    ctx = create_context();
    configure_context(ctx);

    /* 加载 SKF 引擎 */
    ENGINE *skf_engine = ENGINE_by_id("skf_engine");
    if (skf_engine == NULL) {
        fprintf(stderr, "ENGINE_by_id failed\n");
        exit(1);
    }
    if (!ENGINE_init(skf_engine)) {
        fprintf(stderr, "ENGINE_init failed\n");
        ENGINE_free(skf_engine);
        exit(1);
    }
/////////////////////////////////////////////////

//test_encrypt(skf_engine);
/////////////////////////////////////////////////
    /* 创建 TCP 套接字 */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /* 绑定套接字到端口 */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    /* 监听端口 */
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Waiting for a client to connect...\n");

        /* 接受客户端连接 */
        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
            perror("accept failed");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        printf("Client connected. Creating SSL connection...\n");

        /* 创建 SSL 对象 */
        ssl = SSL_new(ctx);
        if (!ssl) {
            perror("SSL_new failed");
            close(client_fd);
            continue;
        }

        /* 将文件描述符附加到 SSL 对象 */
        if (!SSL_set_fd(ssl, client_fd)) {
            perror("SSL_set_fd failed");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        /* 执行 SSL 握手 */
        if (SSL_accept(ssl) <= 0) {
            //ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        printf("SSL connection established. Receiving data...\n");
       /* 发送数据 */
       const char *message = "Hello, client!";
        /* 接收数据 */
        int len = SSL_read(ssl, buf, sizeof(buf) - 1);
        TRACE_INFO("len=%d",len);
        if (len > 0) {
            buf[len] = '\0';
            printf("Received: %s\n", buf);
            send_file(ssl, filename_path,skf_engine);
           // SSL_write(ssl, message, strlen(message));
           // printf("Sent: %s\n", message);
        } else {
            ERR_print_errors_fp(stderr);
        }

        /* 关闭 SSL 连接 */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    /* 清理 */
    close(server_fd);
    SSL_CTX_free(ctx);
    ENGINE_finish(skf_engine);
    ENGINE_free(skf_engine);
    ENGINE_cleanup();
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
