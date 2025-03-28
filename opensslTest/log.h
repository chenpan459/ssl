
#ifndef __LOG_H__
# define __LOG_H__

#define TRACE_INFO(fmt, ...) \
	{printf("[INFO]%s,%s,%d: "fmt"\n", __FILE__,__func__, __LINE__, ##__VA_ARGS__);}

#define TRACE_WARN(fmt, ...) \
	{printf("[WARN]%s,%d: "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__);}

#define TRACE_ERRO(fmt, ...)  \
	{printf("[ERRO]%s,%d: "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__);}


void dump_hex(const char *prompt, void *data, long len)
{
    int i;
	unsigned char *p = (unsigned char *)data;

    if (prompt != NULL)
		fprintf(stderr, "[%s] [length = %ld]\n", prompt, len);

	for (i = 0; i < len; i +=2) {
    	if (((i%16) == 0) && (i != 0))
			fprintf(stderr, "\n%04x: ", i);
		if (i == 0)
			fprintf(stderr, "%04x: ", i);
		fprintf(stderr, "%02X", p[i]);
		if ((i+1) < len)
			fprintf(stderr, "%02X ", p[i+1]);
	}
    fprintf(stderr, "\n");

	fflush(stderr);
	return;
}

#endif