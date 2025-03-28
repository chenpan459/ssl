
#ifndef __BASE_TYPE_DEF_H__
#define __BASE_TYPE_DEF_H__ 1

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
//#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HANDLE	HDEV;

#else /* linux */
#include <stdbool.h>
#include <stddef.h>

typedef int		HDEV;
typedef void*	        HANDLE;
typedef unsigned long   ULONG;
typedef unsigned char   BYTE;
typedef char *          LPSTR;
typedef unsigned long   DWORD;
typedef unsigned char * PBYTE;
typedef short           BOOL;
typedef int             INT_PTR;

typedef int             INT;
typedef char            INT8;
typedef short           INT16;
typedef int             INT32;
typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef INT8            CHAR;
typedef UINT8           UCHAR;
typedef INT16           SHORT;
typedef UINT16          USHORT;
typedef INT32           LONG;
typedef UINT32          UINT;
typedef UINT16          WORD;
typedef	UINT32          FLAGES;

#define _GNU_SOURCE
#define __USE_GNU

#endif

typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned int    u32;

#define NULL_PTR ((void *)0)


#endif /* __BASE_TYPE_DEF_H__ */
