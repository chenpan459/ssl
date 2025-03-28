#ifndef _SGTYPE_H_
#define _SGTYPE_H_

#ifdef WIN32
#include <Windows.h>
#define DEVAPI __stdcall
#define WINAPI __stdcall
#define LOCALAPI
#else
#define __stdcall
#define _stdcall
#define DEVAPI __attribute__ ((visibility ("default")))
#define WINAPI __attribute__ ((visibility ("default")))
#define LOCALAPI __attribute__ ((visibility ("hidden")))
typedef int             INT;
typedef char            INT8;
typedef short           INT16;
typedef int             INT32;
typedef unsigned char   UINT8;
typedef unsigned short  UINT16;
typedef unsigned int    UINT32;
typedef int             BOOL;
typedef UINT8           BYTE;
typedef INT8            CHAR;
typedef UINT8           UCHAR;
typedef INT16           SHORT;
typedef UINT16          USHORT;
typedef INT32           LONG;
typedef UINT32          ULONG;
typedef UINT32          UINT;
typedef UINT16          WORD;
typedef UINT32          DWORD;
typedef	UINT32          FLAGES;
typedef CHAR*           LPSTR;
typedef void*           HANDLE;
#endif

#ifndef TRUE
#define TRUE	0x00000001
#endif
#ifndef FALSE
#define FALSE	0x00000000
#endif
#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif

/*算法标识*/

/*对称算法*/
#define SGD_SM1_ECB                     0x00000101
#define SGD_SM1_CBC                     0x00000102
#define SGD_SM1_MAC                     0x00000110

#define SGD_SMS4_ECB                    0x00000401
#define SGD_SMS4_CBC                    0x00000402
#define SGD_SMS4_MAC                    0x00000410

#define SGD_DES_ECB                     0x00000801
#define SGD_DES_CBC                     0x00000802
#define SGD_DES_MAC                     0x00000810

#define SGD_3DES_ECB                    0x00000811
#define SGD_3DES_CBC                    0x00000812
#define SGD_3DES_MAC                    0x00000820

#define SGD_3DES_ECB_3KEY               0x00000821
#define SGD_3DES_CBC_3KEY               0x00000822
#define SGD_3DES_MAC_3KEY               0x00000830

/*非对称算法*/
#define SGD_RSA                         0x00010000
#define SGD_RSA_SIGN                    0x00010100
#define SGD_RSA_ENC                     0x00010200
#define SGD_SM2_1                       0x00020100
#define SGD_SM2_2                       0x00020200
#define SGD_SM2_3                       0x00020400

/*哈希算法标识*/
#define SGD_SM3                         0x00000001
#define SGD_SHA1                        0x00000002
#define SGD_SHA256                      0x00000004

/*错误代码定义和说明*/
#define SAR_OK                          0x00000000              /*成功*/
#define SAR_FAIL                        0x0A000001              /*失败*/
#define SAR_UNKNOWNERR                  0x0A000002              /*异常错误*/
#define SAR_NOTSUPPORTYETERR            0x0A000003              /*不支持的服务*/
#define SAR_FILEERR                     0x0A000004              /*文件操作错误*/
#define SAR_INVALIDHANDLEERR            0x0A000005              /*无效的句柄*/
#define SAR_INVALIDPARAMERR             0x0A000006              /*无效的参数*/
#define SAR_READFILEERR                 0x0A000007              /*读文件错误*/
#define SAR_WRITEFILEERR                0x0A000008              /*写文件错误*/
#define SAR_NAMELENERR                  0x0A000009              /*名称长度错误*/
#define SAR_KEYUSAGEERR                 0x0A00000A              /*密钥用途错误*/
#define SAR_MODULUSLENERR               0x0A00000B              /*模长度错误*/
#define SAR_NOTINITIALIZEERR            0x0A00000C              /*未初始化*/
#define SAR_OBJERR                      0x0A00000D              /*对象错误*/
#define SAR_MEMORYERR                   0x0A00000E              /*内存错误*/
#define SAR_TIMEOUTERR                  0x0A00000F              /*超时错误*/
#define SAR_INDATALENERR                0x0A000010              /*输入数据长度错误*/
#define SAR_INDATAERR                   0x0A000011              /*输入数据错误*/
#define SAR_GENRANDERR                  0x0A000012              /*生成随机数错误*/
#define SAR_HASHOBJERR                  0x0A000013              /*哈希对象错误*/
#define SAR_HASHERR                     0x0A000014              /*哈希运算错误*/
#define SAR_GENRSAKEYERR                0x0A000015              /*生成RSA密钥对错误*/
#define SAR_RSAMODULUSLENERR            0x0A000016              /*RSA密钥模长错误*/
#define SAR_CSPIMPRTPUBKEYERR           0x0A000017              /*CSP服务导入公钥错误*/
#define SAR_RSAENCERR                   0x0A000018              /*RSA加密错误*/
#define SAR_RSADECERR                   0x0A000019              /*RSA解密错误*/
#define SAR_HASHNOTEQUALERR             0x0A00001A              /*哈希值不相等*/
#define SAR_KEYNOTFOUNDERR              0x0A00001B              /*密钥未发现*/
#define SAR_CERTNOTFOUNDERR             0x0A00001C              /*证书未发现*/
#define SAR_NOTEXPORTERR                0x0A00001D              /*对象未导出*/
#define SAR_DECRYPTPADERR               0x0A00001E              /*解密时做补丁错误*/
#define SAR_MACLENERR                   0x0A00001F              /*MAC长度错误*/
#define SAR_BUFFER_TOO_SMALL            0x0A000020              /*缓冲区不足*/
#define SAR_KEYINFOTYPEERR              0x0A000021              /*密钥类型错误*/
#define SAR_EVENTERR                    0x0A000022              /*无事件错误*/
#define SAR_DEVICE_REMOVED              0x0A000023              /*设备已移除*/
#define SAR_PIN_INCORRECT               0x0A000024              /*PIN不正确*/
#define SAR_PIN_LOCKED                  0x0A000025              /*PIN被锁定*/
#define SAR_PIN_INVALID                 0x0A000026              /*PIN无效*/
#define SAR_PIN_LEN_RANGE               0x0A000027              /*PIN长度错误*/
#define SAR_USER_ALREADY_LOGGED_IN      0x0A000028              /*用户已经登录*/
#define SAR_USER_PIN_NOT_INITIALIZED    0x0A000029              /*没有初始化用户口令*/
#define SAR_USER_TYPE_INVALID           0x0A00002A              /*PIN类型错误*/
#define SAR_APPLICATION_NAME_INVALID    0x0A00002B              /*应用名称无效*/
#define SAR_APPLICATION_EXISTS          0x0A00002C              /*应用已经存在*/
#define SAR_USER_NOT_LOGGED_IN          0x0A00002D              /*用户未登录*/
#define SAR_APPLICATION_NOT_EXISTS      0x0A00002E              /*应用不存在*/
#define SAR_FILE_ALREADY_EXISTS         0x0A00002F              /*文件已存在*/
#define SAR_NO_ROOM                     0x0A000030              /*空间不足*/
#define SAR_FILE_NOT_EXIST              0x0A000031              /*文件不存在*/
#define SAR_REACH_MAX_CONTAINER_COUNT   0x0A000032              /*已达到最大可管理容器数*/
#endif