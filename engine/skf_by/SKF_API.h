#ifndef _SKFAPI_H_
#define _SKFAPI_H_

#include "SG_Type.h"

#ifdef __cplusplus
extern "C" {
#endif
    
    /*****************************************数据类型结构定义*****************************************/
    /*基本数据类型*/
     typedef HANDLE DEVHANDLE;           //设备句柄
     typedef HANDLE HAPPLICATION;        //应用句柄
     typedef HANDLE HCONTAINER;          //容器句柄
     /*常量定义*/
     #define ADMIN_TYPE      0           //管理员PIN类型
     #define USER_TYPE       1           //用户PIN类型
    /*复合数据类型*/
    //版本定义
    typedef struct Struct_Version
    {
         BYTE    major;                  //主版本号
         BYTE    minor;                  //次版本号
    } VERSION;
    //设备信息数据结构
    #pragma pack(push, 1)
    typedef struct Struct_DEVINFO
    {
         VERSION Version;                // 版本号,设置为2.0
         CHAR    Manufacturer[64];       // 设备厂商信息,以'\0'为结束符的ASCII字符串
         CHAR    Issuer[64];             // 发行厂商信息,以'\0'为结束符的ASCII字符串
         CHAR    Label[32];              // 设备标签,以'\0'为结束符的ASCII字符串
         CHAR    SerialNumber[32];       // 序列号,以'\0'为结束符的ASCII字符串
         VERSION HWVersion;              // 设备硬件版本
         VERSION FirmwareVersion;        // 设备本身固件版本
         ULONG   AlgSymCap;              // 分组密码算法标识
         ULONG   AlgAsymCap;             // 非对称密码算法标识
         ULONG   AlgHashCap;             // 密码杂凑算法标识
         ULONG   DevAuthAlgId;           // 设备认证的分组密码算法标识
         ULONG   TotalSpace;             // 设备总空间大小
         ULONG   FreeSpace;              // 用户可用空间大小
         ULONG   MaxECCBufferSize;       // 能够处理的ECC加密数据大小 
         ULONG   MaxBufferSize;          // 能够处理的分组运算和杂凑运算的数据大小
         BYTE    Reserved[64];           // 保留扩展
    }DEVINFO, *PDEVINFO;
    #pragma pack(pop)
    /*RSA*/
    #define MAX_RSA_MODULUS_LEN     256                 //RSA算法模数的最大长度
    #define MAX_RSA_EXPONENT_LEN    4                   //RSA算法指数的最大长度
    // RSA公钥数据结构
    typedef struct Struct_RSAPUBLICKEYBLOB{
        ULONG   AlgID;                                  // 算法标识
        ULONG   BitLen;                                 // 算法的实际位长度,必须是8的倍数
        BYTE    Modulus[MAX_RSA_MODULUS_LEN];           // 模数N
        BYTE    PublicExponent[MAX_RSA_EXPONENT_LEN];   // 公开密钥E,一般固定为00010001
    }RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;
    // RSA私钥数据结构
    typedef struct Struct_RSAPRIVATEKEYBLOB{
        ULONG   AlgID;                                  // 算法标识
        ULONG   BitLen;                                 // 算法的实际位长度,必须是8的倍数
        BYTE    Modulus[MAX_RSA_MODULUS_LEN];           // 模数N,实际长度为BitLen/8
        BYTE    PublicExponent[MAX_RSA_EXPONENT_LEN];   // 公开密钥E,一般固定为00010001
        BYTE    PrivateExponent[MAX_RSA_MODULUS_LEN];   // 私钥D,实际长度为BitLen/8
        BYTE    Prime1[MAX_RSA_MODULUS_LEN/2];          // 素数p,实际长度为BitLen/16 
        BYTE    Prime2[MAX_RSA_MODULUS_LEN/2];          // 素数q,实际长度为BitLen/16 
        BYTE    Prime1Exponent[MAX_RSA_MODULUS_LEN/2];  // dp,实际长度为BitLen/16 
        BYTE    Prime2Exponent[MAX_RSA_MODULUS_LEN/2];  // dq,实际长度为BitLen/16
        BYTE    Coefficient[MAX_RSA_MODULUS_LEN/2];     // q模p的乘法逆元,实际长度为BitLen/16
    }RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;
    /*ECC*/
    #define ECC_MAX_XCOORDINATE_BITS_LEN    512         //ECC算法X坐标的最大长度
    #define ECC_MAX_YCOORDINATE_BITS_LEN    512         //ECC算法Y坐标的最大长度
    #define ECC_MAX_MODULUS_BITS_LEN        512         //ECC算法模数的最大长度
    /*ECC公钥数据结构*///4+64+64=132
    typedef struct Struct_ECCPUBLICKEYBLOB{
        ULONG   BitLen;                                 // 模数的实际位长度,必须是8的倍数
        BYTE    XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];// 曲线上点的X坐标
        BYTE    YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];// 曲线上点的Y坐标
    }ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;
    /*ECC私钥数据结构*/
    typedef struct Struct_ECCPRIVATEKEYBLOB{
        ULONG   BitLen;                                 // 模数的实际位长度,必须是8的倍数
        BYTE    PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8]; // 私有密钥
    }ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;
    /*ECC密文数据结构*///64+64+32+4+1=165
    typedef struct Struct_ECCCIPHERBLOB{
        BYTE    XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
        BYTE    YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
        BYTE    HASH[32];                               // 明文的杂凑值
        ULONG   CipherLen;                              // 密文数据长度
        BYTE    Cipher[1];                              // 密文数据
    }ECCCIPHERBLOB, *PECCCIPHERBLOB;
    /*ECC签名数据结构*/
    typedef struct Struct_ECCSIGNATUREBLOB{
        BYTE    r[ECC_MAX_XCOORDINATE_BITS_LEN/8];      // 签名结果r部分
        BYTE    s[ECC_MAX_XCOORDINATE_BITS_LEN/8];      // 签名结果s部分
    }ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;
    /*ECC加密密钥对保护结构*///4+4+4+64+132+165=373
    typedef struct SKF_ENVELOPEDKEYBLOB{
        ULONG               Version;                    // 当前版本为 1
        ULONG               ulSymmAlgID;                // 规范中的对称算法标识，限定ECB模式
        ULONG               ulBits;                     // 加密密钥对的密钥位长度
        BYTE                cbEncryptedPriKey[64];      // 加密密钥对私钥的密文
        ECCPUBLICKEYBLOB    PubKey;                     // 加密密钥对的公钥
        ECCCIPHERBLOB       ECCCipherBlob;              // 用保护公钥加密的对称密钥密文
    }ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;
    #define MAX_IV_LEN 32                               //初始向量的最大长度
    /*分组密码参数*/
    typedef struct Struct_BLOCKCIPHERPARAM
    {
        BYTE    IV[MAX_IV_LEN];                         // 初始向量IV
        ULONG   IVLen;                                  // 初始向量的实际长度(按字节计算)
        ULONG   PaddingType;                            // 填充方式,0表示不填充,1表示按照PKCS#5方式进行填充
        ULONG   FeedBitLen;                             // 反馈值的位长度(按位计算),只针对OFB、CFB
    } BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;
    /*文件属性*/
    typedef struct Struct_FILEATTRIBUTE
    {
        CHAR    FileName[32];                           // 文件名
        ULONG   FileSize;                               // 文件大小
        ULONG   ReadRights;                             // 读取权限
        ULONG   WriteRights;                            // 写入权限
    } FILEATTRIBUTE, *PFILEATTRIBUTE;
    /*权限类型*/
    #define SECURE_NEVER_ACCOUNT    0x00000000          //不允许
    #define SECURE_ADM_ACCOUNT      0x00000001          //管理员权限
    #define SECURE_USER_ACCOUNT     0x00000010          //用户权限
    #define SECURE_ANYONE_ACCOUNT   0x000000FF          //任何人
    /*设备状态*/
    #define DEV_ABSENT_STATE        0x00000000          //设备不存在
    #define DEV_PRESENT_STATE       0x00000001          //设备存在
    #define DEV_UNKNOW_STATE        0x00000002          //设备状态未知
    
    /*********************************************接口函数*********************************************/
    
    /*****************************************设备管理系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_WaitForDevEvent
    //   函数功能：等待设备插拔事件
    //   函数参数：
    //   [OUT] szDevName 发生事件的设备名称
    //   [IN,OUT] pulDevNameLen 输入/输出参数，当输入时表示缓冲区长度，输出时表示设备名称的有效长度,长度包含字符串结束符
    //   [OUT] szDevName 事件类型
    //        1 - 表示插入
    //        2 - 表示拔出
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：本函数为阻塞函数
    /**************************************************************************/
    ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName, ULONG *pulDevNameLen, ULONG *pulEvent);
    /**************************************************************************/
    //   函数名称：SKF_CancelWaitForDevEvent
    //   函数功能：取消等待设备插拔事件
    //   函数参数：
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：使本进程正在执行的SKF_WaitForDevEvent函数立即返回。
    /**************************************************************************/
    ULONG DEVAPI SKF_CancelWaitForDevEvent();
    /**************************************************************************/
    //   函数名称：SKF_EnumDev
    //   函数功能：枚举设备
    //   函数参数：
    //   [IN] bPresent 枚举类型
    //        TRUE  - 取当前设备状态为存在的设备列表
    //        FALSE - 取当前驱动支持的设备列表
    //   [OUT] saNameList 设备名称列表，如果该参数为NULL，将由pulSize返回所需要的内存空间大小
    //  			每个设备的名称以单个‘\0’结束，以双‘\0’表示列表的结束
    //   [IN,OUT] pulSize 输入时表示设备名称列表的缓冲区长度，输出时表示szNameList所占用的空间大小
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EnumDev(BOOL bpresent, LPSTR saNameList, ULONG *pulSize);
    /**************************************************************************/
    //   函数名称：SKF_ConnectDev
    //   函数功能：连接设备
    //   函数参数：
    //   [IN] szName 设备名称
    //   [OUT] phDev 返回设备句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ConnectDev(LPSTR szName, DEVHANDLE *phDev);
    /**************************************************************************/
    //   函数名称：SKF_DisConnectDev
    //   函数功能：断开设备，并释放句柄
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：如果该设备已被锁定，函数应首先解锁该设备
    /**************************************************************************/
    ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev);
    /**************************************************************************/
    //   函数名称：SKF_GetDevState
    //   函数功能：获取设备状态
    //   函数参数：
    //   [IN] szDevName 设备名称
    //   [OUT] pulDevState 返回设备状态
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);
    /**************************************************************************/
    //   函数名称：SKF_SetLabel
    //   函数功能：设置设备标签
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] szLabel 设备标签字符串，该字符串应小于32字节
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel);
    /**************************************************************************/
    //   函数名称：SKF_GetDevInfo
    //   函数功能：获取设备信息，包括设备标签、厂商信息、支持的算法等
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [OUT] pDevInfo 返回设备信息
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *pDevInfo);
    /**************************************************************************/
    //   函数名称：SKF_LockDev
    //   函数功能：锁定设备，获得设备的独占使用权
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] ulTimeOut 超时时间，单位为毫秒；如果为0xFFFFFFFF表示无限等待
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_LockDev(DEVHANDLE hDev, ULONG ulTimeOut);
    /**************************************************************************/
    //   函数名称：SKF_UnlockDev
    //   函数功能：解锁设备，释放对设备的独占使用权
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev);
    /**************************************************************************/
    //   函数名称：SKF_Transmit
    //   函数功能：设备命令传输，将命令直接发送给设备，并返回结果
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pbCommand 设备命令（完整的APDU指令，接口内部不做任何填充）
    //   [IN] ulCommandLen 命令长度
    //   [OUT] pbData 返回结果数据
    //   [IN,OUT] pulDataLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE *pbCommand, ULONG ulCommandLen, BYTE *pbData, ULONG *pulDataLen);
    
    /*****************************************访问控制系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_ChangeDevAuthKey
    //   函数功能：修改设备认证密钥
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pbKeyValue 密钥值
    //   [IN] ulKeyLen 密钥长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：设备认证成功后才能使用
    /**************************************************************************/
    ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);
    /**************************************************************************/
    //   函数名称：SKF_DevAuth
    //   函数功能：设备认证，是设备对应用的认证
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pbAuthData 认证数据
    //   [IN] ulLen 认证数据的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：认证过程参见国密规范（GM/T 0016）8.2.3
    /**************************************************************************/
    ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);
    /**************************************************************************/
    //   函数名称：SKF_ChangePIN
    //   函数功能：修改PIN
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] ulPINType PIN类型
    //        ADMIN_TYPE(0) - 管理员PIN类型
    //        USER_TYPE(1)  - 用户PIN类型
    //   [IN] szOldPin 原PIN值（字符串）
    //   [IN] szNewPin 新PIN值（字符串）
    //   [OUT] pulRetryCount 返回出错后重试次数，当剩余次数为0时，表示PIN已经被锁死
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);
    /**************************************************************************/
    //   函数名称：SKF_GetPINInfo
    //   函数功能：获取PIN信息，包括最大重试次数、当前剩余重试次数，以及当前PIN码是否为出厂默认PIN码
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] ulPINType PIN类型
    //        ADMIN_TYPE(0) - 管理员PIN类型
    //        USER_TYPE(1)  - 用户PIN类型
    //   [OUT] pulMaxRetryCount 最大重试次数
    //   [OUT] pulRemainRetryCount 当前剩余重试次数，当为0时表示已锁死
    //   [OUT] pbDefaultPin 是否为出厂默认PIN码
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);
    /**************************************************************************/
    //   函数名称：SKF_VerifyPIN
    //   函数功能：校验PIN码
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] ulPINType PIN类型
    //        ADMIN_TYPE(0) - 管理员PIN类型
    //        USER_TYPE(1)  - 用户PIN类型
    //   [IN] szPin PIN值（字符串）
    //   [OUT] pulRetryCount 返回出错后重试次数，当剩余次数为0时，表示PIN已经被锁死
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：校验成功后，会获得相应的应用权限
    /**************************************************************************/
    ULONG DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPin, ULONG *pulRetryCount);
    /**************************************************************************/
    //   函数名称：SKF_UnblockPIN
    //   函数功能：解锁用户PIN，解锁后，用户PIN码被设置成新值，用户PIN码的重试次数也恢复到原值
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szAdminPin 管理员PIN值（字符串）
    //   [IN] szNewUserPin 新用户PIN值（字符串）
    //   [OUT] pulRetryCount 返回出错后重试次数，当剩余次数为0时，表示PIN已经被锁死
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：验证完管理员PIN才能够解锁用户PIN码，如果输入的管理员PIN不正确或者已经锁死，会返回失败，并返回管理员PIN的剩余重试次数
    /**************************************************************************/
    ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication, LPSTR szAdminPin, LPSTR szNewUserPin, ULONG *pulRetryCount);
    /**************************************************************************/
    //   函数名称：SKF_ClearSecureState
    //   函数功能：清除应用当前的安全状态
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication);
    
    /*****************************************应用管理系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_CreateApplication
    //   函数功能：创建应用
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] szAppName 应用名称，长度不得大于32个字节
    //   [IN] szAdminPin 管理员PIN值（字符串）
    //   [IN] dwAdminPinRetryCount 管理员PIN值最大重试次数
    //   [IN] szUserPin 用户PIN值（字符串）
    //   [IN] dwUserPinRetryCount 用户PIN值最大重试次数
    //   [IN] dwCreateFileRights 在该应用下创建文件的权限（可为下列权限的或值）
    //        SECURE_NEVER_ACCOUNT  - 不允许
    //        SECURE_ADM_ACCOUNT    - 管理员权限
    //        SECURE_USER_ACCOUNT   - 用户权限
    //        SECURE_ANYONE_ACCOUNT - 任何人
    //   [OUT] phApplication 返回的应用句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：设备认证成功后才能使用
    /**************************************************************************/
    ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount, LPSTR szUserPin, 
    	DWORD dwUserPinRetryCount, DWORD dwCreateFileRights, HAPPLICATION *phApplication);
    /**************************************************************************/
    //   函数名称：SKF_EnumApplication
    //   函数功能：枚举应用
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [OUT] szAppName 返回应用名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小
    //  			每个应用的名称以单个‘\0’结束，以双‘\0’表示列表的结束
    //   [IN,OUT] pulSize 输入时表示应用名称的缓冲区长度，输出时返回szAppName所占用的空间大小
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：设备认证成功后才能使用
    /**************************************************************************/
    ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName, ULONG *pulSize);
    /**************************************************************************/
    //   函数名称：SKF_DeleteApplication
    //   函数功能：删除应用
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] szAppName 应用名称，长度不得大于32个字节
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：设备认证成功后才能使用
    /**************************************************************************/
    ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);
    /**************************************************************************/
    //   函数名称：SKF_OpenApplication
    //   函数功能：打开应用
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] szAppName 应用名称，长度不得大于32个字节
    //   [OUT] phApplication 返回的应用句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *hApplication);
    /**************************************************************************/
    //   函数名称：SKF_CloseApplication
    //   函数功能：关闭应用并释放应用句柄
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);
    
    /*****************************************文件管理系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_CreateFile
    //   函数功能：创建文件
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szFileName 文件名称，长度不得大于32个字节
    //   [IN] ulFileSize 文件大小
    //   [IN] ulReadRights 文件读权限（可为下列权限的或值）
    //   [IN] ulWriteRights 文件写权限（可为下列权限的或值）
    //        SECURE_NEVER_ACCOUNT  - 不允许
    //        SECURE_ADM_ACCOUNT    - 管理员权限
    //        SECURE_USER_ACCOUNT   - 用户权限
    //        SECURE_ANYONE_ACCOUNT - 任何人
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：创建文件需要应用指定的创建文件权限。
    /**************************************************************************/
    ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);
    /**************************************************************************/
    //   函数名称：SKF_DeleteFile
    //   函数功能：删除指定文件，文件删除后，文件中写入的所有信息将丢失；文件在设备中的占用的空间将被释放
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szFileName 要删除文件的名称，长度不得大于32个字节
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：删除文件需要应用指定的创建文件权限。
    /**************************************************************************/
    ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName);
    /**************************************************************************/
    //   函数名称：SKF_EnumFiles
    //   函数功能：枚举文件
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [OUT] szFileList 返回文件名称列表，该参数为空，由pulSize返回文件信息所需要的空间大小
    //  			每个文件名称以单个‘\0’结束，以双‘\0’表示列表的结束
    //   [IN,OUT] pulSize 输入时表示数据缓冲区的大小，输出时表示实际文件名称列表的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EnumFiles( HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);
    /**************************************************************************/
    //   函数名称：SKF_GetFileInfo
    //   函数功能：获取文件属性，如文件的大小、权限等
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szFileName 文件名称，长度不得大于32个字节
    //   [OUT] pFileInfo 文件信息，指向文件属性结构的指针
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);
    /**************************************************************************/
    //   函数名称：SKF_ReadFile
    //   函数功能：读文件
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szFileName 文件名称，长度不得大于32个字节
    //   [IN] ulOffset 文件读取偏移位置
    //   [IN] ulSize 要读取的长度
    //   [OUT] pbOutData 返回数据的缓冲区
    //   [IN,OUT] pulOutLen 输入时表示给出的缓冲区大小；输出时表示实际读取返回的数据大小
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：需要应用具有该文件的读权限。
    /**************************************************************************/
    ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE *pbOutData, ULONG *pulOutLen);
    /**************************************************************************/
    //   函数名称：SKF_WriteFile
    //   函数功能：写文件
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szFileName 文件名称，长度不得大于32个字节
    //   [IN] ulOffset 写入文件的偏移位置
    //   [IN] pbData 写入数据缓冲区
    //   [IN] ulSize 写入数据的大小
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：需要应用具有该文件的写权限。
    /**************************************************************************/
    ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, BYTE *pbData, ULONG ulSize);
    
    /*****************************************容器管理系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_CreateContainer
    //   函数功能：创建容器
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szContainerName 容器名称，长度不得大于64个字节
    //   [OUT] phContainer 返回容器句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：需要应用具有用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
    /**************************************************************************/
    //   函数名称：SKF_DeleteContainer
    //   函数功能：删除容器，并释放设备内容器相关的资源
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szContainerName 容器名称，长度不得大于64个字节
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：需要应用具有用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);
    /**************************************************************************/
    //   函数名称：SKF_OpenContainer
    //   函数功能：打开容器
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [IN] szContainerName 容器名称，长度不得大于64个字节
    //   [OUT] phContainer 返回容器句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
    /**************************************************************************/
    //   函数名称：SKF_CloseContainer
    //   函数功能：关闭容器，并释放容器句柄
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer);
    /**************************************************************************/
    //   函数名称：SKF_EnumContainer
    //   函数功能：枚举容器
    //   函数参数：
    //   [IN] hApplication 应用句柄
    //   [OUT] szContainerName 返回容器名称列表, 如果该参数为空，将由pulSize返回所需要的内存空间大小
    //  			每个容器的名称以单个‘\0’结束，以双‘\0’表示列表的结束
    //   [IN,OUT] pulSize 输入时表示szContainerName缓冲区的长度，输出时表示容器名称列表的实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication, LPSTR szContainerName, ULONG *pulSize);
    /**************************************************************************/
    //   函数名称：SKF_GetContainerType
    //   函数功能：获取容器的类型
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [OUT] pulContainerType 获得的容器类型
    //        0 - 未定、尚未分配类型或者为空容器
    //        1 - RSA容器
    //        2 - ECC容器
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType);
    /**************************************************************************/
    //   函数名称：SKF_ImportCertificate
    //   函数功能：导入数字证书
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] bSignFlag 证书类型
    //        TRUE  - 签名证书
    //        FALSE - 加密证书
    //   [IN] pbCert 指向证书内容缓冲区
    //   [IN] ulCertLen 证书长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbCert, ULONG ulCertLen);
    /**************************************************************************/
    //   函数名称：SKF_ExportCertificate
    //   函数功能：导出数字证书
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] bSignFlag 证书类型
    //        TRUE  - 签名证书
    //        FALSE - 加密证书
    //   [OUT] pbCert 指向证书内容缓冲区, 如果该参数为空，将由pulCertLen返回所需要的内存空间大小
    //   [IN,OUT] pulCertLen 输入时表示pbCert缓冲区的长度，输出时表示证书内容的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbCert, ULONG *pulCertLen);
    
    /*****************************************密码服务系列函数*****************************************/
    /**************************************************************************/
    //   函数名称：SKF_GenRandom
    //   函数功能：生成随机数
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [OUT] pbRandom 返回的随机数
    //   [IN] ulRandomLen 随机数长度，应不大于pbRandom的缓冲区的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
    
    /**************************************************************************/
    //   函数名称：SKF_GenExtRSAKey
    //   函数功能：由设备生成RSA密钥对并明文输出
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] ulBitsLen 密钥模长
    //   [OUT] pBlob 返回私钥数据结构
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：生成私有密钥只用于输出，接口内不做保留和计算
    /**************************************************************************/
    ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);
    /**************************************************************************/
    //   函数名称：SKF_GenRSAKeyPair
    //   函数功能：由设备产生RSA签名密钥对并导出公钥
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulBitsLen 密钥模长
    //   [OUT] pBlob 返回RSA公钥数据结构
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_GenRSAKeyPair(HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);
    /**************************************************************************/
    //   函数名称：SKF_ImportRSAKeyPair
    //   函数功能：导入RSA加密密钥对
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulSymAlgId 对称算法密钥标识
    //   [IN] pbWrappedKey 使用该容器内签名公钥保护的对称算法密钥密文
    //   [IN] ulWrappedKeyLen 保护的对称算法密钥密文长度
    //   [IN] pbEncryptedData 对称算法密钥保护的RSA加密私钥。私钥的格式遵循PKCS #1 v2.1: RSA Cryptography Standard中的私钥格式定义
    //   [IN] ulEncryptedDataLen 对称算法密钥保护的RSA加密公私钥对长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_ImportRSAKeyPair(HCONTAINER hContainer, ULONG ulSymAlgId, BYTE *pbWrappedKey, ULONG ulWrappedKeyLen, 
    	BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);
    /**************************************************************************/
    //   函数名称：SKF_RSASignData
    //   函数功能：RSA签名
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] pbData 待签名数据
    //   [IN] ulDataLen 待签名数据长度,应不大于RSA密钥模长 -11
    //   [OUT] pbSignature 签名值
    //   [IN/OUT] pulSignLen 输入为签名缓冲区长度，输出返回签名结果长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);
    /**************************************************************************/
    //   函数名称：SKF_RSAVerify
    //   函数功能：验证RSA签名，用RSAPUBLICKEYBLOB结构中的公钥对签名数据进行验证
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pRSAPubKeyBlob 公钥结构体指针
    //   [IN] pbData 待验证签名数据
    //   [IN] ulDataLen 待验证签名数据长度，应不大于公钥模长-11
    //   [IN] pbSignature 签名值
    //   [IN] ulSignLen 签名值长度，应等于公钥模长
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pRSAPubKeyBlob, BYTE *pbData, ULONG ulDataLen, BYTE *pbSignature, ULONG ulSignLen);
    /**************************************************************************/
    //   函数名称：SKF_RSAExportSessionKey
    //   函数功能：生成会话密钥并用外部RSA公钥加密输出
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulAlgId 会话密钥算法标识
    //   [IN] pPubKey 加密会话密钥的RSA公钥数据结构
    //   [OUT] pbData 导出的加密会话密钥密文，按照PKCS#1v1.5要求封装
    //   [IN/OUT] pulDataLen 输入时表示会话密钥密文数据缓冲区长度，输出时表示会话密钥密文的实际长度
    //   [OUT] phSessionKey 导出的密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_RSAExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG *pulDataLen, HANDLE *phSessionKey);
    /**************************************************************************/
    //   函数名称：SKF_GenECCKeyPair
    //   函数功能：生成ECC签名密钥对并输出签名公钥
    //   函数参数：
    //   [IN] hContainer 密钥容器句柄
    //   [IN] ulAlgId 算法标识，只支持SGD_SM2_1算法
    //   [OUT] pBlob 返回ECC公钥数据结构
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_GenECCKeyPair(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);
    /**************************************************************************/
    //   函数名称：SKF_ImportECCKeyPair
    //   函数功能：导入ECC加密密钥对
    //   函数参数：
    //   [IN] hContainer 密钥容器句柄
    //   [IN] pEnvelopedKeyBlob 受保护的加密密钥对
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_ImportECCKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);
    /**************************************************************************/
    //   函数名称：SG_ECCSignData
    //   函数功能：ECC数字签名
    //   函数参数：
    //   [IN] hContainer 密钥容器句柄
    //   [IN] pbData 待签名的数据
    //   [IN] ulDataLen 待签名数据长度，必须小于密钥模长
    //   [OUT] pbSignature 签名值
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    //  	   输入数据为待签数据的杂凑值。
    //  	   当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果，预处理过程遵循《GM/T 0009》。
    /**************************************************************************/
    ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
    /**************************************************************************/
    //   函数名称：SKF_ECCVerify
    //   函数功能：用ECC公钥对数据进行验签
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pECCPubKeyBlob ECC公钥数据结构
    //   [IN] pbData 待验证签名的数据
    //   [IN] ulDataLen 数据长度
    //   [IN] pbSignature 待验证签名值
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：输入数据为待签数据的杂凑值。
    //  	   当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果，预处理过程遵循《GM/T 0009》。
    /**************************************************************************/
    ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
    /**************************************************************************/
    //   函数名称：SKF_ECCExportSessionKey
    //   函数功能：生成会话密钥并用外部公钥加密导出
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulAlgId 会话密钥算法标识
    //   [IN] pPubKey 外部输入的公钥结构
    //   [OUT] pData 会话密钥密文
    //   [OUT] phSessionKey 会话密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer,ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, PECCCIPHERBLOB pData, HANDLE *phSessionKey);
    /**************************************************************************/
    //   函数名称：SKF_ExtECCEncrypt
    //   函数功能：使用外部传入的ECC公钥对输入数据做加密运算并输出结果
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pECCPubKeyBlob ECC公钥数据结构
    //   [IN] pbPlainText 待加密的明文数据
    //   [IN] ulPlainTextLen 待加密明文数据的长度
    //   [OUT] pCipherText 密文数据
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pECCPubKeyBlob, BYTE *pbPlainText,ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText);
    /**************************************************************************/
    //   函数名称：SKF_GenerateAgreementDataWithECC
    //   函数功能：ECC生成密钥协商参数并输出,返回临时ECC密钥对的公钥及协商句柄
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulAlgId 会话密钥算法标识
    //   [OUT] pTempECCPubKeyBlob 发起方临时ECC公钥
    //   [IN] pbID 发起方的ID
    //   [IN] ulIDLen 发起方ID的长度，不大于32
    //   [OUT] phAgreementHandle 返回的密钥协商句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：为协商会话密钥，协商的发起方应首先调用本函数
    /**************************************************************************/
    ULONG DEVAPI SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, 
    	BYTE *pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
    /**************************************************************************/
    //   函数名称：SKF_GenerateAgreementDataAndKeyWithECC
    //   函数功能：ECC产生协商数据并计算会话密钥,返回临时ECC密钥对的公钥及产生的密钥句柄
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulAlgId 会话密钥算法标识
    //   [IN] pSponsorECCPubKeyBlob 发起方的ECC公钥
    //   [IN] pSponsorTempECCPubKeyBlob 发起方的临时ECC公钥
    //   [OUT] pTempECCPubKeyBlob 响应方的临时ECC公钥
    //   [IN] pbID 响应方的ID
    //   [IN] ulIDLen 响应方ID的长度，不大于32
    //   [IN] pbSponsorID 发起方的ID
    //   [IN] ulSponsorIDLen 发起方ID的长度，不大于32
    //   [OUT] phKeyHandle 返回的对称算法密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    //  		本函数由响应方调用
    /**************************************************************************/
    ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob, 
    	ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, BYTE *pbID, ULONG ulIDLen, 
    	BYTE *pbSponsorID, ULONG ulSponsorIDLen, HANDLE *phKeyHandle);
    /**************************************************************************/
    //   函数名称：SKF_GenerateKeyWithECC
    //   函数功能：ECC计算会话密钥，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
    //   函数参数：
    //   [IN] hAgreement 密钥协商句柄
    //   [IN] pECCPubKeyBlob 外部输入的响应方ECC公钥
    //   [IN] pTempECCPubKeyBlob 外部输入的响应方临时ECC公钥
    //   [IN] pbID 响应方的ID
    //   [IN] ulIDLen 响应方ID的长度，不大于32
    //   [OUT] phKeyHandle 返回的密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    //  		协商的发起方获得响应方的协商参数后调用本函数，计算会话密钥。
    /**************************************************************************/
    ULONG DEVAPI SKF_GenerateKeyWithECC(HANDLE hAgreement, ECCPUBLICKEYBLOB *pECCPubKeyBlob, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, 
    	BYTE *pbID, ULONG ulIDLen, HANDLE *phKeyHandle);
    
    /**************************************************************************/
    //   函数名称：SKF_ExportPublicKey
    //   函数功能：导出公钥
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] bSignFlag 公钥类型
    //        TRUE  - 签名公钥
    //        FALSE - 加密公钥
    //   [OUT] pbBlob 指向RSA公钥结构（RSAPUBLICKEYBLOB）或者ECC公钥结构（ECCPUBLICKEYBLOB），
    //  			如果此参数为NULL时，由pulBlobLen返回pbBlob的长度
    //   [IN/OUT] pulBlobLen 输入时表示pbBlob缓冲区的长度，输出时表示导出公钥结构的大小
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_ExportPublicKey(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbBlob,ULONG *pulBlobLen);
    /**************************************************************************/
    //   函数名称：SKF_ImportSessionKey
    //   函数功能：导入会话密钥密文，使用容器中的加密私钥解密得到会话密钥并返回密钥句柄
    //   函数参数：
    //   [IN] hContainer 容器句柄
    //   [IN] ulAlgID 会话密钥算法标识
    //   [IN] pbWrapedData 要导入的会话密钥密文。
    //  			当容器为ECC类型时，此参数为ECCCIPHERBLOB密文数据
    //  			当容器为RSA类型时，此参数为RSA公钥加密后的数据
    //   [IN] ulWrapedLen 会话密钥密文长度
    //   [OUT] phKey 返回会话密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：权限要求：需要用户权限
    /**************************************************************************/
    ULONG DEVAPI SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgID, BYTE *pbWrapedData, ULONG ulWrapedLen, HANDLE *phKey);
    /**************************************************************************/
    //   函数名称：SKF_SetSymmKey
    //   函数功能：明文导入会话密钥并返回密钥句柄
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] pbKey 指向会话密钥值的缓冲区，缓冲区的大小应不小于相应对称算法的密钥长度
    //   [IN] ulAlgID 会话密钥算法标识
    //   [OUT] phKey 返回会话密钥句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev, BYTE *pbKey, ULONG ulAlgID, HANDLE *phKey);
    /**************************************************************************/
    //   函数名称：SKF_EncryptInit
    //   函数功能：数据加密初始化。设置数据加密的算法相关参数
    //   函数参数：
    //   [IN] hKey 加密密钥句柄
    //   [IN] EncryptParam 分组密码算法相关参数：初始向量、初始向量长度、填充方法、反馈值的位长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);
    /**************************************************************************/
    //   函数名称：SKF_Encrypt
    //   函数功能：单组数据加密，在调用SKF_Encrypt之前，必须调用SKF_EncryptInit初始化加密操作
    //   函数参数：
    //   [IN] hKey 加密密钥句柄
    //   [IN] pbData 待加密数据
    //   [IN] ulDataLen 待加密数据长度
    //   [OUT] pbEncryptedData 加密后的数据缓冲区指针，可以为NULL，用于获得加密后数据长度
    //   [IN/OUT] pulEncryptedLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE *pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
    /**************************************************************************/
    //   函数名称：SKF_EncryptUpdate
    //   函数功能：分组数据加密
    //  			在调用SKF_EncryptUpdate之前，必须调用SKF_EncryptInit初始化加密操作
    //  			在调用SKF_EncryptUpdate之后，必须调用SKF_EncryptFinal结束加密操作
    //   函数参数：
    //   [IN] hKey 加密密钥句柄
    //   [IN] pbData 待加密数据
    //   [IN] ulDataLen 待加密数据长度
    //   [OUT] pbEncryptedData 加密后的数据缓冲区指针，不可以为NULL
    //   [IN/OUT] pulEncryptedLen 输入时表示结果数据缓冲区长度，输出时表示实际返回加密密文数据长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE *pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);
    /**************************************************************************/
    //   函数名称：SKF_EncryptFinal
    //   函数功能：结束多个分组数据的加密，返回剩余加密结果。
    //  			先调用SKF_EncryptInit初始化加密操作，再调用SKF_EncryptUpdate对多个分组数据进行加密，
    //  			最后调用SKF_EncryptFinal结束多个分组数据的加密
    //   函数参数：
    //   [IN] hKey 加密密钥句柄
    //   [OUT] pbEncryptedData 加密后的数据缓冲区指针，可以为NULL，用于获得剩余加密后数据长度
    //   [IN/OUT] pulEncryptedLen 输入时表示结果数据缓冲区长度，输出时表示实际返回加密密文数据长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey, BYTE *pbEncryptedData, ULONG *pulEncryptedDataLen);
    
    /**************************************************************************/
    //   函数名称：SKF_DecryptInit
    //   函数功能：数据解密初始化。设置解密密钥相关参数
    //   函数参数：
    //   [IN] hKey 解密密钥句柄
    //   [IN] DecryptParam 分组密码算法相关参数：初始向量、初始向量长度、填充方法、反馈值的位长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);
    /**************************************************************************/
    //   函数名称：SKF_Decrypt
    //   函数功能：单组数据解密，在调用SKF_Decrypt之前，必须调用SKF_DecryptInit初始化解密操作
    //   函数参数：
    //   [IN] hKey 解密密钥句柄
    //   [IN] pbEncryptedData 待解密数据
    //   [IN] ulEncryptedLen 待解密数据长度
    //   [OUT] pbData 解密后的数据缓冲区指针，可以为NULL，用于获得解密后的数据长度
    //   [IN/OUT] pulDataLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE *pbData, ULONG *pulDataLen);
    /**************************************************************************/
    //   函数名称：SKF_DecryptUpdate
    //   函数功能：分组数据解密
    //  			在调用SKF_DecryptUpdate之前，必须调用SKF_DecryptInit初始化解密操作
    //  			在调用SKF_DecryptUpdate之后，必须调用SKF_DecryptFinal结束解密操作
    //   函数参数：
    //   [IN] hKey 解密密钥句柄
    //   [IN] pbEncryptedData 待解密数据
    //   [IN] ulEncryptedLen 待解密数据长度
    //   [OUT] pbData 解密后的数据缓冲区指针，不可以为NULL
    //   [IN/OUT] pulDataLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey,BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE *pbData, ULONG *pulDataLen);
    /**************************************************************************/
    //   函数名称：SKF_DecryptFinal
    //   函数功能：结束多个分组数据的解密，返回剩余解密结果。
    //  			先调用SKF_DecryptInit初始化解密操作，再调用SKF_DecryptUpdate对多个分组数据进行解密，
    //  			最后调用SKF_DecryptFinal结束多个分组数据的解密
    //   函数参数：
    //   [IN] hKey 解密密钥句柄
    //   [OUT] pbDecryptedData 解密后的数据缓冲区指针，可以为NULL，用于获得剩余解密后数据长度
    //   [IN/OUT] pulDecryptedDataLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey,BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen);
    
    /**************************************************************************/
    //   函数名称：SKF_DigestInit
    //   函数功能：初始化密码杂凑计算操作，指定计算密码杂凑的算法
    //   函数参数：
    //   [IN] hDev 设备句柄
    //   [IN] ulAlgID 密码杂凑算法标识
    //   [IN] pPubKey 签名者公钥。当alAlgID为SGD_SM3时有效
    //   [IN] pucID 签名者的ID值，当alAlgID为SGD_SM3时有效。
    //   [IN] ulIDLen 签名者ID的长度，当alAlgID为SGD_SM3时有效。
    //   [OUT] phHash 返回消息鉴别码对象句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：当ulAlgID为SGD_SM3且ulIDLen不为0的情况下pPubKey、pucID有效，执行SM2算法签名预处理1操作。
    //  		计算过程遵循《GT/M 0009》。
    /**************************************************************************/
    ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, 
    							unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);
    /**************************************************************************/
    //   函数名称：SKF_Digest
    //   函数功能：对单一分组的消息进行密码杂凑计算，在调用SKF_Digest之前，必须调用SKF_DigestInit初始化密码杂凑操作
    //   函数参数：
    //   [IN] hHash 密码杂凑对象句柄
    //   [IN] pbData 指向消息数据的缓冲区
    //   [IN] ulDataLen 消息数据的长度
    //   [OUT] pbHashData 密码杂凑数据缓冲区指针，当此参数为NULL时，由pulHashLen返回密码杂凑结果的长度
    //   [IN/OUT] pulHashLen 输入时表示结果数据缓冲区长度，输出时表示结果数据实际长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_Digest (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);
    /**************************************************************************/
    //   函数名称：SKF_DigestUpdate
    //   函数功能：对多个分组的消息进行密码杂凑计算
    //  			在调用SKF_DigestUpdate之前，必须调用SKF_DigestInit初始化密码杂凑操作
    //  			在调用SKF_DigestUpdate之后，必须调用SKF_DigestFinal结束密码杂凑操作
    //   函数参数：
    //   [IN] hHash 密码杂凑对象句柄
    //   [IN] pbData 指向消息数据的缓冲区
    //   [IN] ulDataLen 消息数据的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_DigestUpdate (HANDLE hHash, BYTE *pbData, ULONG ulDataLen);
    /**************************************************************************/
    //   函数名称：SKF_DigestFinal
    //   函数功能：结束多个分组消息的密码杂凑计算操作，将密码杂凑结果保存到指定的缓冲区。
    //  			先调用SKF_DigestInit初始化密码杂凑操作，再调用SKF_DigestUpdate对多个分组数据进行密码杂凑，
    //  			最后调用SKF_DigestFinal结束多个分组数据的密码杂凑并输出杂凑值
    //   函数参数：
    //   [IN] hHash 密码杂凑对象句柄
    //   [OUT] pHashData 返回的密码杂凑结果缓冲区指针，如果此参数NULL时，由pulHashLen返回杂凑结果的长度
    //   [IN/OUT] pulHashLen 输入时表示杂凑结果缓冲区的长度，输出时表示密码杂凑结果的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_DigestFinal (HANDLE hHash, BYTE *pHashData, ULONG *pulHashLen);
    
    /**************************************************************************/
    //   函数名称：SKF_MacInit
    //   函数功能：初始化消息鉴别码计算操作。设置数据加密的算法相关参数
    //   函数参数：
    //   [IN] hKey 加密密钥句柄
    //   [IN] pMacParam 消息认证计算相关参数：初始向量、初始向量长度、填充方法
    //   [OUT] phMac 返回消息鉴别码对象句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：消息鉴别码计算采用分组加密算法的CBC模式，将加密结果的最后一块作为计算结果。
    /**************************************************************************/
    ULONG DEVAPI SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM *pMacParam, HANDLE *phMac);
    /**************************************************************************/
    //   函数名称：SKF_Mac
    //   函数功能：计算单一分组数据的消息鉴别码，在调用SKF_Mac之前，必须调用SKF_MacInit初始化加密操作
    //   函数参数：
    //   [IN] hMac 消息鉴别码句柄
    //   [IN] pbData 指向待计算数据的缓冲区
    //   [IN] ulDataLen 待计算数据的长度
    //   [OUT] pbMacData 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
    //   [IN/OUT] pulMacLen 输入时表示pbMacData缓冲区的长度，输出时表示Mac结果的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE *pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);
    /**************************************************************************/
    //   函数名称：SKF_MacUpdate
    //   函数功能：计算多个分组数据的消息鉴别码
    //  			在调用SKF_MacUpdate之前，必须调用SKF_MacInit初始化消息鉴别码操作
    //  			在调用SKF_MacUpdate之后，必须调用SKF_MacFinal结束消息鉴别码操作
    //   函数参数：
    //   [IN] hKey 解密密钥句柄
    //   [IN] pbData 指向待计算数据的缓冲区
    //   [IN] ulDataLen 待计算数据的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE *pbData, ULONG ulDataLen);
    /**************************************************************************/
    //   函数名称：SKF_MacFinal
    //   函数功能：结束多个分组数据的消息鉴别码计算操作
    //  			先调用SKF_MacInit初始化消息鉴别码操作，再调用SKF_MacUpdate对多个分组数据进行消息鉴别码计算，
    //  			最后调用SKF_MacFinal结束多个分组数据的消息鉴别码计算
    //   函数参数：
    //   [IN] hMac 消息鉴别码句柄
    //   [OUT] pbMacData 指向计算后的Mac结果，如果此参数为NULL时，由pulMacLen返回计算后Mac结果的长度
    //   [IN/OUT] pulMacDataLen 输入时表示pbMacData缓冲区的长度，输出时表示Mac结果的长度
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_MacFinal(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);
    /**************************************************************************/
    //   函数名称：SKF_CloseHandle
    //   函数功能：关闭会话密钥、密码杂凑对象、消息鉴别码对象、ECC密钥协商等句柄
    //   函数参数：
    //   [IN] hHandle 要关闭的对象句柄
    //   返回值：SAR_OK:成功；其他：参见错误码定义
    //   备注：
    /**************************************************************************/
    ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle);   
	
#ifdef __cplusplus
}
#endif

#endif