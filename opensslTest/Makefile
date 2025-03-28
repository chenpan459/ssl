# 设置编译器
CC = gcc

# 设置编译标志
CFLAGS = -Wall -g -I/usr/local/openssl/include/openssl
LDFLAGS = -L/usr/local/openssl/lib64 -lssl -lcrypto -lpthread

# 定义目标文件
TARGETS = server_ssl_engine client_ssl

# 定义源文件和目标文件
SRCS = ssl_server_engine.c ssl_client.c
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGETS)

# 编译服务端
server_ssl_engine: ssl_server_engine.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译客户端
client_ssl: ssl_client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译源文件为对象文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理生成的文件
clean:
	rm -f $(OBJS) $(TARGETS)

# 重新构建
rebuild: clean all