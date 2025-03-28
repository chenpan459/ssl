#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"


#define IP_SERVER "127.0.0.1"
#define PORT_SERVER 4433
#define SAVE_PATH "/root/4119/"
#define MAXBUF 1024

#define rcv_file_name "test.txt"


#include <pthread.h>

// 全局变量，用于在接收线程和速率更新线程之间共享数据
size_t total_bytes_received = 0;
pthread_mutex_t lock;

void *update_rate(void *arg) {
    size_t last_total_bytes = 0;
    while (1) {
        sleep(1); // 每秒更新一次

        pthread_mutex_lock(&lock);
        size_t current_total_bytes = total_bytes_received;
        pthread_mutex_unlock(&lock);

        double rate = (current_total_bytes - last_total_bytes) / (1024.0); // 转换为兆字节
        printf("Current rate: %.2f Kb/s\n", rate);

        last_total_bytes = current_total_bytes;
    }
    return NULL;
}



void receive_file(SSL *ssl, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Unable to open file");
        return;
    }

    char buffer[4096];
    int bytes;
    pthread_mutex_init(&lock, NULL);
    // 创建一个线程来更新速率
    pthread_t rate_thread;
    if (pthread_create(&rate_thread, NULL, update_rate, NULL) != 0) {
        perror("Unable to create thread");
        fclose(fp);
        return;
    }

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes, fp);
         pthread_mutex_lock(&lock);
        total_bytes_received += bytes;
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_destroy(&lock);
    //结束速率更新线程
    pthread_cancel(rate_thread);
    pthread_join(rate_thread, NULL);

    fclose(fp);
}

int main(int argc, char *argv[]) {
   /* if (argc != 4) {
        printf("Usage: %s <server_ip> <port> <save_path>\n", argv[0]);
        return 1;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);
    const char *savePath = argv[3];
    */
    const char *serverIp = IP_SERVER;
    int port = PORT_SERVER;//atoi(argv[2]);
    const char *savePath = SAVE_PATH;


    // 初始化 OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 创建 SSL 上下文
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        perror("Failed to create SSL context");
        return 1;
    }

    // 创建套接字并连接到服务器
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Failed to connect to server");
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }
    TRACE_INFO("connect success");

    // 创建 SSL 对象并绑定套接字
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // 执行 SSL 握手
    if (SSL_connect(ssl) != 1) {
        perror("Failed to establish SSL connection");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }
    TRACE_INFO("SSL_connect success");

    printf("SSL connection established. Sending data...\n");

    /* 发送数据 */
    const char *message = "Hello, server!";
    if (SSL_write(ssl, message, strlen(message)) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Message sent: %s\n", message);
    }
    receive_file(ssl, rcv_file_name);
    // const char buf[1024];
    // if (SSL_read(ssl, buf, sizeof(buf)) <= 0) {
    //     ERR_print_errors_fp(stderr);
    // } else {
    //     printf("Message read: %s\n", buf);
    // }
    //while(1);
    // 下载文件
    //DownloadFile(ssl, savePath);

    // 关闭连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}