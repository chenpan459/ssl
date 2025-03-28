#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#if 0
static int my_engine_init(ENGINE *e) {
    printf("rf Engine Initialized\n");
    return 1;  // 成功返回 1
}

static int my_engine_finish(ENGINE *e) {
    printf("tf Engine Finished\n");
    return 1;
}

static int my_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                           RSA *rsa, int padding) {
    printf("Using my custom RSA hardware engine for encryption.\n");
    // 这里调用你的硬件 API 进行 RSA 计算
    return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())(flen, from, to, rsa, padding);
}

static RSA_METHOD *my_rsa_method = NULL;

static int bind_rsa(ENGINE *e) {
     printf("======bind_rsa.===========\n");
    my_rsa_method = RSA_meth_new("rf RSA Engine", 0);
    RSA_meth_set_priv_enc(my_rsa_method, my_rsa_priv_enc);
    return ENGINE_set_RSA(e, my_rsa_method);
}

static int bind_helper(ENGINE *e, const char *id) {
    printf("======bind_helper.===========\n");
    if (!ENGINE_set_id(e, "tf_engine") ||
        !ENGINE_set_name(e, "tf Custom Hardware Engine") ||
        !ENGINE_set_init_function(e, my_engine_init) ||
        !ENGINE_set_finish_function(e, my_engine_finish) ||
        !bind_rsa(e)) {
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
IMPLEMENT_DYNAMIC_CHECK_FN()

#endif

/*
 * by_skf_engine.c
 *
 *  Created on: 2024年11月5日
 *      Author: root
 */

#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/types.h>


//#include "engine_skf.h"
//#ifndef DEBUG

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include "./skf_by/base_type.h"
#include "./skf_by/skf_type.h"
#include "./skf_by/SKF.h"
//#define BY_SKF_GX 1
#define BY_SKF_YXD   1
//#define BY_SKF_WXT   1


#define TRACE_INFO(fmt, ...) \
	{printf("[INFO]%s,%s,%d: "fmt"\n", __FILE__,__func__, __LINE__, ##__VA_ARGS__);}

#define TRACE_WARN(fmt, ...) \
	{printf("[WARN]%s,%d: "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__);}

#define TRACE_ERRO(fmt, ...)  \
	{printf("[ERRO]%s,%d: "fmt"\n", __FILE__, __LINE__, ##__VA_ARGS__);}
	


#if BY_SKF_GX
    #define BY_SKF_LIB_PATH "/root/4119/tf_skf/libSKF_by_gx.so"
#elif BY_SKF_YXD
//#include "../3rd/skf_by/SKFError.h"
//#include "../3rd/skf_by/SKFInterface.h"
    #define BY_SKF_LIB_PATH "/root/4119/tf_skf/libSKF_by_ydx.so"
#else
//#include "../3rd/skf_by/skf_wxd.h"
//#include "../3rd/skf_by/CommonType.h"
    #define BY_SKF_LIB_PATH "/root/4119/tf_skf/libSKF_by_wxt.so"
#endif	
	
//
//#else
//
//#define TRACE_INFO(fmt, ...)
//#define TRACE_WARN(fmt, ...)
//#define TRACE_ERRO(fmt, ...)
//
//#endif
//#define dotest_sm4 1


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


#define SGD_HANDLE HANDLE
#define SGD_RV int

#define ENGINE_ID "skf_engine"
#define ENGINE_NAME "bangyan skf engine"
#define ECB_GROUP_SIZE 16
#define CBC_GROUP_SIZE 32

#define  HT_ENC 1
#define  HT_DEC 0

#if 1

#define DEF_CONTAINER_NAME	"def_cont"
#define DEF_APP_NAME	"def_app"

PSKF_FUNCLIST FunctionList;

SGD_HANDLE hDevice = NULL;
HANDLE happ = NULL;
HANDLE hcont = NULL;

void skf_print_devinfo(DEVINFO *info) {
	printf("Version: major=%u, minor=%u \n", info->Version.major,
			info->Version.minor);
	printf("Manufacturer: %s \n", info->Manufacturer);
	printf("Issuer : %s \n", info->Issuer);
	printf("Label : %s \n", info->Label);
	printf("SerialNumber : %s \n", info->SerialNumber);
	printf("HWVersion: major=%u, minor=%u \n", info->HWVersion.major,
			info->HWVersion.minor);
	printf("FirmwareVersion: major=%u, minor=%u \n",
			info->FirmwareVersion.major, info->FirmwareVersion.minor);
	printf("AlgSymCap :%d \n", info->AlgSymCap);
	printf("AlgAsymCap :%d,\n", info->AlgAsymCap);
	printf("AlgHashCap :%d,\n", info->AlgHashCap);
	printf("DevAuthAlgId :%d,\n", info->DevAuthAlgId);
	printf("TotalSpace:%d \n", info->TotalSpace);
	printf("FreeSpace:%d \n", info->FreeSpace);
	printf("MaxECCBufferSize:%d \n", info->MaxEccBufferSize);
	printf("MaxBufferSize:%d \n", info->MaxBufferSize);
}

static int __test_sm1_ecb_ex(SGD_HANDLE hDevice) {
	int ret = 0;
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;
	BLOCKCIPHERPARAM bp;
	//UCHAR enc_data[1024] = { 0 };
	UCHAR *enc_data = malloc(1024);
	ULONG enc_len = 0, enc_final_len = 0, tmp_enc_len = 0;
	//UCHAR dec_data[1024] = { 0 };
	UCHAR *dec_data = malloc(1024);
	ULONG dec_len = 0, dec_final_len = 0, tmp_dec_len = 0;

	unsigned char pbKeyValue[16] = { 0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73,
			0x86, 0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26 };
	unsigned char pbPlainText[16] = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
			0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	unsigned char pbCipherText[16] = { 0x6d, 0x7f, 0x45, 0xb0, 0x8b, 0xc4, 0xd9,
			0x66, 0x44, 0x4c, 0x86, 0xc2, 0xb0, 0x7d, 0x29, 0x93 };

	unsigned int uiLength = sizeof(pbCipherText);
	memset(&bp, 0, sizeof(bp));

	// SM1 ECB ENC

	//printf("FunctionList->SKF_WaitForDevEvent 0x%0x\n",FunctionList->SKF_WaitForDevEvent);
	printf("FunctionList->SKF_CloseHandle 0x%0x\n",FunctionList->SKF_CloseHandle);
	printf("FunctionList->SKF_SetSymmKey 0x%0x\n",FunctionList->SKF_SetSymmKey);
	//printf("SKF_SetSymmKey 0x%0x\n",SKF_SetSymmKey);
	printf("FunctionList->SKF_EncryptInit 0x%0x\n",FunctionList->SKF_EncryptInit);
	
	
	rv = FunctionList->SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SM1_ECB, &hKey);
//	printf("abc FunctionList->SKF_SetSymmKey  0x%0x\n",FunctionList->SKF_SetSymmKey);
//	printf("abc FunctionList->SKF_EncryptInit 0x%0x\n",FunctionList->SKF_EncryptInit);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_SetSymmKey error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_SetSymmKey");
	printf("SGD_SM1_ECB:%#x\n", SGD_SM1_ECB);

	TRACE_INFO("start SKF_EncryptInit");
	rv = FunctionList->SKF_EncryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptInit SM1 ECB error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_EncryptInit");

	TRACE_INFO("start SKF_Encrypt");
	int i = 0;
	int loop = sizeof(pbPlainText) / ECB_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_enc_len = ECB_GROUP_SIZE;
		rv = FunctionList->SKF_EncryptUpdate(hKey,
				(BYTE*) (pbPlainText + (i * ECB_GROUP_SIZE)), ECB_GROUP_SIZE,
				(enc_data + (i * ECB_GROUP_SIZE)), &tmp_enc_len);
//		rv = SKF_Encrypt(hKey, (BYTE *)pbPlainText, ECB_GROUP_SIZE, enc_data, &tmp_enc_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_EncryptUpdate SM1 ECB error: %08X", rv);
			goto DONE;
		}
		enc_len += tmp_enc_len;
	}

	rv = FunctionList->SKF_EncryptFinal(hKey, (BYTE*) (enc_data + enc_len), &enc_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptFinal SM1 ECB error: %08X", rv);
		goto DONE;
	}
	enc_len += enc_final_len;
	TRACE_INFO("end SKF_Encrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!\n");
		rv = -1;
		goto DONE;
	}

	// SM1 ECB DEC
	memset(&bp, 0, sizeof(bp));
	TRACE_INFO("start SKF_DecryptInit");
	rv = FunctionList->SKF_DecryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptInit SM1 ECB error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_DecryptInit");

	TRACE_INFO("start SKF_Decrypt");
	i = 0;
	loop = enc_len / ECB_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_dec_len = ECB_GROUP_SIZE;
		rv = FunctionList->SKF_DecryptUpdate(hKey, (BYTE*) (enc_data + (i * ECB_GROUP_SIZE)),
				ECB_GROUP_SIZE, (dec_data + (i * ECB_GROUP_SIZE)),
				&tmp_dec_len);
//		rv = SKF_Decrypt(hKey, (BYTE *)enc_data, ECB_GROUP_SIZE, dec_data, &tmp_dec_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_DecryptUpdate SM1 ECB error: %08X", rv);
			goto DONE;
		}
		dec_len += tmp_dec_len;
	}

	rv = FunctionList->SKF_DecryptFinal(hKey, (BYTE*) (dec_data + dec_len), &dec_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptFinal SM1 ECB error: %08X", rv);
		goto DONE;
	}
	dec_len += dec_final_len;
	TRACE_INFO("end SKF_Decrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!");
		rv = -1;
		goto DONE;
	}

	if (enc_len != dec_len || memcmp(pbPlainText, dec_data, enc_len)) {
		TRACE_ERRO("enc and dec data is not same!");
		ret = -2;
		goto DONE;
	} else {
		TRACE_ERRO("SM1_ECB enc and dec succ!");
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}
#if 1
static int __test_sm1_cbc_ex(SGD_HANDLE hDevice) {
	int ret = 0;
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;
	BLOCKCIPHERPARAM bp;
	UCHAR enc_data[1024] = { 0 };
	ULONG enc_len = 0, enc_final_len = 0, tmp_enc_len = 0;
	UCHAR dec_data[1024] = { 0 };
	ULONG dec_len = 0, dec_final_len = 0, tmp_dec_len = 0;

	unsigned char pbKeyValue[16] = { 0x40, 0xbb, 0x12, 0xdd, 0x6a, 0x82, 0x73,
			0x86, 0x7f, 0x35, 0x29, 0xd3, 0x54, 0xb4, 0xa0, 0x26 };
	unsigned char pbIV[16] = { 0xe8, 0x3d, 0x17, 0x15, 0xac, 0xf3, 0x48, 0x63,
			0xac, 0xeb, 0x93, 0xe0, 0xe5, 0xab, 0x8b, 0x90 };
	unsigned char pbPlainText[32] = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
			0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
			0xdd, 0xee, 0xff };
	unsigned char pbCipherText[32] = { 0x3a, 0x70, 0xb5, 0xd4, 0x9a, 0x78, 0x2c,
			0x07, 0x2d, 0xe1, 0x13, 0x43, 0x81, 0x9e, 0xc6, 0x59, 0xf8, 0xfc,
			0x7a, 0xf0, 0x5e, 0x7c, 0x6d, 0xfb, 0x5f, 0x81, 0x09, 0x0f, 0x0d,
			0x87, 0x91, 0xb2 };

	unsigned char pbTempIV[16] = { 0 };
	unsigned int uiLength = sizeof(pbCipherText);

	memcpy(pbTempIV, pbIV, sizeof(pbIV));
	memset(&bp, 0, sizeof(bp));
	bp.IVLen = sizeof(pbTempIV);
	if (bp.IVLen > 0) {
		if (!pbTempIV) {
			printf("sym cbc mode, but iv is null\n");
			ret = -1;
			goto DONE;
		}

		memcpy(bp.IV, pbTempIV, bp.IVLen);
	}

	// SM1 CBC ENC
	TRACE_INFO("start SKF_SetSymmKey");
	//rv = SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SM1_CBC, &hKey);
	rv = FunctionList->SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SM1_CBC, &hKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_SetSymmKey error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_SetSymmKey");
	printf("SGD_SM1_CBC:%#x\n", SGD_SM1_CBC);

	TRACE_INFO("start SKF_EncryptInit");
	rv = FunctionList->SKF_EncryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptInit SM1 CBC error: %0168X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_EncryptInit");

	TRACE_INFO("start SKF_Encrypt");
	int i = 0;
	int loop = sizeof(pbPlainText) / CBC_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_enc_len = CBC_GROUP_SIZE;
		rv = FunctionList->SKF_EncryptUpdate(hKey,
				(BYTE*) (pbPlainText + (i * CBC_GROUP_SIZE)), CBC_GROUP_SIZE,
				(enc_data + (i * CBC_GROUP_SIZE)), &tmp_enc_len);
//		rv = SKF_Encrypt(hKey, (BYTE *)pbPlainText, CBC_GROUP_SIZE, enc_data, &tmp_enc_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_EncryptUpdate SM1 CBC error: %08X", rv);
			goto DONE;
		}
		enc_len += tmp_enc_len;
	}

	rv = FunctionList->SKF_EncryptFinal(hKey, (BYTE*) (enc_data + enc_len), &enc_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptFinal SM1 CBC error: %08X", rv);
		goto DONE;
	}
	enc_len += enc_final_len;
	TRACE_INFO("end SKF_Encrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!\n");
		rv = -1;
		goto DONE;
	}

	// SM1 CBC DEC
	memcpy(pbTempIV, pbIV, sizeof(pbIV));
	memset(&bp, 0, sizeof(bp));
	bp.IVLen = sizeof(pbTempIV);
	if (bp.IVLen > 0) {
		if (!pbTempIV) {
			printf("sym cbc mode, but iv is null\n");
			ret = -1;
			goto DONE;
		}

		memcpy(bp.IV, pbTempIV, bp.IVLen);
	}
	TRACE_INFO("start SKF_DecryptInit");
	rv = FunctionList->SKF_DecryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptInit SM1 CBC error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_DecryptInit");

	TRACE_INFO("start SKF_Decrypt");
	i = 0;
	loop = enc_len / CBC_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_dec_len = CBC_GROUP_SIZE;
		rv = FunctionList->SKF_DecryptUpdate(hKey, (BYTE*) (enc_data + (i * CBC_GROUP_SIZE)),
				CBC_GROUP_SIZE, (dec_data + (i * CBC_GROUP_SIZE)),
				&tmp_dec_len);
//		rv = SKF_Decrypt(hKey, (BYTE *)enc_data, CBC_GROUP_SIZE, dec_data, &tmp_dec_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_DecryptUpdate SM1 CBC error: %08X", rv);
			goto DONE;
		}
		dec_len += tmp_dec_len;
	}

	rv = FunctionList->SKF_DecryptFinal(hKey, (BYTE*) (dec_data + dec_len), &dec_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptFinal SM1 CBC error: %08X", rv);
		goto DONE;
	}
	dec_len += dec_final_len;
	TRACE_INFO("end SKF_Decrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!");
		rv = -1;
		goto DONE;
	}

	if (enc_len != dec_len || memcmp(pbPlainText, dec_data, enc_len)) {
		TRACE_ERRO("enc and dec data is not same!");
		ret = -2;
		goto DONE;
	} else {
		TRACE_ERRO("SM1 CBC enc and dec succ!");
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}

static int __test_sm4_ecb_ex(SGD_HANDLE hDevice) {
	int ret = 0;
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;
	BLOCKCIPHERPARAM bp;
	UCHAR enc_data[1024] = { 0 };
	ULONG enc_len = 0, enc_final_len = 0, tmp_enc_len = 0;
	UCHAR dec_data[1024] = { 0 };
	ULONG dec_len = 0, dec_final_len = 0, tmp_dec_len = 0;

	unsigned char pbKeyValue[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
			0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char pbPlainText[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
			0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char pbCipherText[16] = { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96,
			0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46 };

	unsigned int uiLength = sizeof(pbCipherText);
	memset(&bp, 0, sizeof(bp));

	// SM4 ECB ENC
	TRACE_INFO("start SKF_SetSymmKey");
	//rv = SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SMS4_ECB, &hKey);
	rv = FunctionList->SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SMS4_ECB, &hKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_SetSymmKey error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_SetSymmKey");
	printf("SGD_SMS4_ECB:%#x\n", SGD_SMS4_ECB);

	TRACE_INFO("start SKF_EncryptInit");
	rv = FunctionList->SKF_EncryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptInit SM4 ECB error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_EncryptInit");

	TRACE_INFO("start SKF_Encrypt");
	int i = 0;
	int loop = sizeof(pbPlainText) / ECB_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_enc_len = ECB_GROUP_SIZE;
		rv = FunctionList->SKF_EncryptUpdate(hKey,
				(BYTE*) (pbPlainText + (i * ECB_GROUP_SIZE)), ECB_GROUP_SIZE,
				(enc_data + (i * ECB_GROUP_SIZE)), &tmp_enc_len);
//		rv = SKF_Encrypt(hKey, (BYTE *)pbPlainText, ECB_GROUP_SIZE, enc_data, &tmp_enc_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_EncryptUpdate SM4 ECB error: %08X", rv);
			goto DONE;
		}
		enc_len += tmp_enc_len;
	}

	rv = FunctionList->SKF_EncryptFinal(hKey, (BYTE*) (enc_data + enc_len), &enc_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptFinal SM4 ECB error: %08X", rv);
		goto DONE;
	}
	enc_len += enc_final_len;
	TRACE_INFO("end SKF_Encrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!\n");
		rv = -1;
		goto DONE;
	}

	// SM4 ECB DEC
	memset(&bp, 0, sizeof(bp));
	TRACE_INFO("start SKF_DecryptInit");
	rv = FunctionList->SKF_DecryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptInit SM4 ECB error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_DecryptInit");

	TRACE_INFO("start SKF_Decrypt");
	i = 0;
	loop = enc_len / ECB_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_dec_len = ECB_GROUP_SIZE;
		rv = FunctionList->SKF_DecryptUpdate(hKey, (BYTE*) (enc_data + (i * ECB_GROUP_SIZE)),
				ECB_GROUP_SIZE, (dec_data + (i * ECB_GROUP_SIZE)),
				&tmp_dec_len);
//		rv = SKF_Decrypt(hKey, (BYTE *)enc_data, ECB_GROUP_SIZE, dec_data, &tmp_dec_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_DecryptUpdate SM4 ECB error: %08X", rv);
			goto DONE;
		}
		dec_len += tmp_dec_len;
	}

	rv = FunctionList->SKF_DecryptFinal(hKey, (BYTE*) (dec_data + dec_len), &dec_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptFinal SM4 ECB error: %08X", rv);
		goto DONE;
	}
	dec_len += dec_final_len;
	TRACE_INFO("end SKF_Decrypt");


	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!");
		rv = -1;
		goto DONE;
	}

	if (enc_len != dec_len || memcmp(pbPlainText, dec_data, enc_len)) {
		TRACE_ERRO("enc and dec data is not same!");
		ret = -2;
		goto DONE;
	} else {
		TRACE_ERRO("SM4_ECB enc and dec succ!");
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}

static int __test_sm4_cbc_ex(SGD_HANDLE hDevice) {
	int ret = 0;
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;
	BLOCKCIPHERPARAM bp;
	UCHAR enc_data[1024] = { 0 };
	ULONG enc_len = 0, enc_final_len = 0, tmp_enc_len = 0;
	UCHAR dec_data[1024] = { 0 };
	ULONG dec_len = 0, dec_final_len = 0, tmp_dec_len = 0;

	unsigned char pbKeyValue[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
			0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char pbIV[16] = { 0xeb, 0xee, 0xc5, 0x68, 0x58, 0xe6, 0x04, 0xd8,
			0x32, 0x7b, 0x9b, 0x3c, 0x10, 0xc9, 0x0c, 0xa7 };
	unsigned char pbPlainText[32] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
			0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x29, 0xbe,
			0xe1, 0xd6, 0x52, 0x49, 0xf1, 0xe9, 0xb3, 0xdb, 0x87, 0x3e, 0x24,
			0x0d, 0x06, 0x47 };
	unsigned char pbCipherText[32] = { 0x3f, 0x1e, 0x73, 0xc3, 0xdf, 0xd5, 0xa1,
			0x32, 0x88, 0x2f, 0xe6, 0x9d, 0x99, 0x6c, 0xde, 0x93, 0x54, 0x99,
			0x09, 0x5d, 0xde, 0x68, 0x99, 0x5b, 0x4d, 0x70, 0xf2, 0x30, 0x9f,
			0x2e, 0xf1, 0xb7 };

	unsigned char pbTempIV[16] = { 0 };
	unsigned int uiLength = sizeof(pbCipherText);

	memcpy(pbTempIV, pbIV, sizeof(pbIV));
	memset(&bp, 0, sizeof(bp));
	bp.IVLen = sizeof(pbTempIV);
	if (bp.IVLen > 0) {
		if (!pbTempIV) {
			printf("sym cbc mode, but iv is null\n");
			ret = -1;
			goto DONE;
		}

		memcpy(bp.IV, pbTempIV, bp.IVLen);
	}

	// SM4 CBC ENC
	TRACE_INFO("start SKF_SetSymmKey");
	//rv = SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SMS4_CBC, &hKey);
	rv = FunctionList->SKF_SetSymmKey(hDevice, pbKeyValue, SGD_SMS4_CBC, &hKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_SetSymmKey error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_SetSymmKey");
	printf("SGD_SMS4_CBC:%#x\n", SGD_SMS4_CBC);

	TRACE_INFO("start SKF_EncryptInit");
	rv = FunctionList->SKF_EncryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptInit SM4 CBC error: %0168X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_EncryptInit");

	TRACE_INFO("start SKF_Encrypt");
	int i = 0;
	int loop = sizeof(pbPlainText) / CBC_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_enc_len = CBC_GROUP_SIZE;
		rv = FunctionList->SKF_EncryptUpdate(hKey,
				(BYTE*) (pbPlainText + (i * CBC_GROUP_SIZE)), CBC_GROUP_SIZE,
				(enc_data + (i * CBC_GROUP_SIZE)), &tmp_enc_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_EncryptUpdate SM4 CBC error: %08X", rv);
			goto DONE;
		}
		enc_len += tmp_enc_len;
	}

	rv = FunctionList->SKF_EncryptFinal(hKey, (BYTE*) (enc_data + enc_len), &enc_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_EncryptFinal SM4 CBC error: %08X", rv);
		goto DONE;
	}
	enc_len += enc_final_len;
	TRACE_INFO("end SKF_Encrypt");

	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!\n");
		rv = -1;
		goto DONE;
	}

	// SM4 CBC DEC
	memcpy(pbTempIV, pbIV, sizeof(pbIV));
	memset(&bp, 0, sizeof(bp));
	bp.IVLen = sizeof(pbTempIV);
	if (bp.IVLen > 0) {
		if (!pbTempIV) {
			printf("sym cbc mode, but iv is null\n");
			ret = -1;
			goto DONE;
		}

		memcpy(bp.IV, pbTempIV, bp.IVLen);
	}
	TRACE_INFO("start SKF_DecryptInit");
	rv = FunctionList->SKF_DecryptInit(hKey, bp);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptInit SM4 CBC error: %08X", rv);
		goto DONE;
	}
	TRACE_INFO("end SKF_DecryptInit");

	TRACE_INFO("start SKF_Decrypt");
	i = 0;
	loop = enc_len / CBC_GROUP_SIZE;
	for (; i < loop; i++) {
		tmp_dec_len = CBC_GROUP_SIZE;
		rv = FunctionList->SKF_DecryptUpdate(hKey, (BYTE*) (enc_data + (i * CBC_GROUP_SIZE)),
				CBC_GROUP_SIZE, (dec_data + (i * CBC_GROUP_SIZE)),
				&tmp_dec_len);
		if (rv != SAR_OK) {
			TRACE_ERRO("SKF_DecryptUpdate SM4 CBC error: %08X", rv);
			goto DONE;
		}
		dec_len += tmp_dec_len;
	}

	rv = FunctionList->SKF_DecryptFinal(hKey, (BYTE*) (dec_data + dec_len), &dec_final_len);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DecryptFinal SM4 CBC error: %08X", rv);
		goto DONE;
	}
	dec_len += dec_final_len;
	TRACE_INFO("end SKF_Decrypt");

	if (enc_data && enc_len > 0
			&& (enc_len != uiLength || memcmp(pbCipherText, enc_data, enc_len))) {
		TRACE_ERRO("enc and pbCipherText data is not same!");
		rv = -1;
		goto DONE;
	}

	if (enc_len != dec_len || memcmp(pbPlainText, dec_data, enc_len)) {
		TRACE_ERRO("enc and dec data is not same!");
		ret = -2;
		goto DONE;
	} else {
		TRACE_ERRO("SM4 CBC enc and dec succ!");
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}

static int __test_sm3_hash_ex(SGD_HANDLE hDevice) {
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;

	unsigned char ucStdData[] = { 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
			0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
			0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
			0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
			0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
			0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
			0x63, 0x64 };
	unsigned char ucStdHash[] = { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8,
			0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb,
			0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c,
			0x0c, 0x57, 0x32 };
	unsigned char ucHash[32] = { 0 };
	unsigned int uiLength = sizeof(ucHash);

	printf("SGD_SM3:%#x\n", SGD_SM3);

	rv = FunctionList->SKF_DigestInit(hDevice, SGD_SM3, NULL, NULL, 0, &hKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DigestInit error: %08X", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_DigestUpdate(hKey, ucStdData, sizeof(ucStdData));
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_HashUpdate error: %08X", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_DigestFinal(hKey, ucHash, &uiLength);
	if (rv != SAR_OK) {
		TRACE_ERRO("SDF_HashFinal error: %08X", rv);
		goto DONE;
	}

	if (uiLength != sizeof(ucHash)
			|| memcmp(ucStdHash, ucHash, uiLength) != 0) {
		TRACE_ERRO("SM3 hash failed");
		rv = -1;
		goto DONE;
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}

static int __do_sm2_hash_ex(SGD_HANDLE hDevice, unsigned char *pucData,
		unsigned int uiDataLen, ECCPUBLICKEYBLOB *pstPubKey,
		unsigned char *pucHash, unsigned int *puiLength) {
	unsigned char ucUserID[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	SGD_HANDLE hKey = NULL;
	SGD_RV rv;

	rv = FunctionList->SKF_DigestInit(hDevice, SGD_SM3, pstPubKey, ucUserID, sizeof(ucUserID),
			&hKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DigestInit error: %08X", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_DigestUpdate(hKey, pucData, uiDataLen);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DigestUpdate error: %08X", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_DigestFinal(hKey, pucHash, puiLength);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_DigestFinal error: %08X", rv);
		goto DONE;
	}

	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	return rv;
}

static int __test_sm2_sign_ex(SGD_HANDLE hDevice) {
	unsigned char pbMessage[] = "message digest";
	/*
	 ECCrefPrivateKey stStdPriKey = {256,
	 {0x39,0x45,0x20,0x8f,0x7b,0x21,0x44,0xb1,0x3f,0x36,0xe3,0x8a,0xc6,0xd3,0x9f,0x95,
	 0x88,0x93,0x93,0x69,0x28,0x60,0xb5,0x1a,0x4a,0xfb,0x81,0xef,0x4d,0xf7,0xc5,0xb8}};
	 */
#ifdef SGD_MAX_ECC_BITS_256
	ECCrefPublicKey stStdPubKey = {256,
		{0x09,0xf9,0xdf,0x31,0x1E,0x54,0x21,0xA1,0x50,0xdd,0x7d,0x16,0x1e,0x4b,0xc5,0xc6,
		 0x72,0x17,0x9f,0xad,0x18,0x33,0xfc,0x07,0x6b,0xb0,0x8f,0xf3,0x56,0xf3,0x50,0x20},
		{0xcc,0xea,0x49,0x0c,0xe2,0x67,0x75,0xa5,0x2d,0xc6,0xea,0x71,0x8c,0xc1,0xaa,0x60,
		 0x0a,0xed,0x05,0xfb,0xf3,0x5e,0x08,0x4a,0x66,0x32,0xf6,0x07,0x2d,0xa9,0xad,0x13}};

	ECCSignature stStdSignature = {{0xf5,0xa0,0x3b,0x06,0x48,0xd2,0xc4,0x63,0x0e,0xea,0xc5,0x13,0xe1,0xbb,0x81,0xa1,
					0x59,0x44,0xda,0x38,0x27,0xd5,0xb7,0x41,0x43,0xac,0x7e,0xac,0xee,0xe7,0x20,0xb3},
				       {0xb1,0xb6,0xaa,0x29,0xdf,0x21,0x2f,0xd8,0x76,0x31,0x82,0xbc,0x0d,0x42,0x1c,0xa1,
					0xbb,0x90,0x38,0xfd,0x1f,0x7f,0x42,0xd4,0x84,0x0b,0x69,0xc4,0x85,0xbb,0xc1,0xaa}};
#else
	ECCPUBLICKEYBLOB stStdPubKey = { 256, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x09, 0xf9, 0xdf, 0x31, 0x1E, 0x54, 0x21,
			0xA1, 0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 0xc6, 0x72, 0x17,
			0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07, 0x6b, 0xb0, 0x8f, 0xf3, 0x56,
			0xf3, 0x50, 0x20 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5,
			0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa, 0x60, 0x0a, 0xed, 0x05,
			0xfb, 0xf3, 0x5e, 0x08, 0x4a, 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9,
			0xad, 0x13 } };

	ECCSIGNATUREBLOB stStdSignature = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xf5, 0xa0, 0x3b, 0x06, 0x48, 0xd2, 0xc4,
			0x63, 0x0e, 0xea, 0xc5, 0x13, 0xe1, 0xbb, 0x81, 0xa1, 0x59, 0x44,
			0xda, 0x38, 0x27, 0xd5, 0xb7, 0x41, 0x43, 0xac, 0x7e, 0xac, 0xee,
			0xe7, 0x20, 0xb3 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0xb1, 0xb6, 0xaa, 0x29, 0xdf, 0x21, 0x2f, 0xd8,
			0x76, 0x31, 0x82, 0xbc, 0x0d, 0x42, 0x1c, 0xa1, 0xbb, 0x90, 0x38,
			0xfd, 0x1f, 0x7f, 0x42, 0xd4, 0x84, 0x0b, 0x69, 0xc4, 0x85, 0xbb,
			0xc1, 0xaa } };
#endif
	unsigned char ucStdSM2Hash[] = { 0xf0, 0xb4, 0x3e, 0x94, 0xba, 0x45, 0xac,
			0xca, 0xac, 0xe6, 0x92, 0xed, 0x53, 0x43, 0x82, 0xeb, 0x17, 0xe6,
			0xab, 0x5a, 0x19, 0xce, 0x7b, 0x31, 0xf4, 0x48, 0x6f, 0xdf, 0xc0,
			0xd2, 0x86, 0x40 };
	SGD_RV rv;
	unsigned int uiLength = 32;
	unsigned char ucSM2Hash[32] = { 0 };

	ECCPUBLICKEYBLOB stPubKey;
	ECCPRIVATEKEYBLOB stPriKey;
	ECCSIGNATUREBLOB stSignature;

	// SM2 sign & verify
	rv = __do_sm2_hash_ex(hDevice, pbMessage, strlen((char*) pbMessage),
			&stStdPubKey, ucSM2Hash, &uiLength);
	if (rv != SAR_OK)
		goto DONE;

	if (uiLength != sizeof(ucSM2Hash)
			|| memcmp(ucStdSM2Hash, ucSM2Hash, uiLength) != 0) {
		TRACE_ERRO("SM2 hash failed");
		rv = -1;
		goto DONE;
	}
	rv = FunctionList->SKF_ECCVerify(hDevice, &stStdPubKey, ucSM2Hash, sizeof(ucSM2Hash),
			&stStdSignature);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_ECCVerify error: %08X", rv);
		goto DONE;
	}

	int flag = SGD_SM2_1;
	rv = FunctionList->SKF_GenECCKeyPair(hcont, flag, &stPubKey);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_GenECCKeyPair error: %08X", rv);
		goto DONE;
	}

	rv = __do_sm2_hash_ex(hDevice, pbMessage, strlen((char*) pbMessage),
			&stPubKey, ucSM2Hash, &uiLength);
	if (rv != SAR_OK)
		goto DONE;

	memset(&stSignature, 0, sizeof(stSignature));
	rv = FunctionList->SKF_ECCSignData(hcont, ucSM2Hash, uiLength, &stSignature);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_ECCSignData error: %08X", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_ECCVerify(hDevice, &stPubKey, ucSM2Hash, uiLength, &stSignature);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_ECCVerify error: %08X", rv);
		goto DONE;
	}

	DONE: return rv;
}

static BYTE bEccPrikey[] = { 0xB1, 0xE7, 0xFD, 0xCB, 0x32, 0x12, 0x1C, 0x67,
		0x3A, 0xB7, 0x99, 0xE5, 0xED, 0x7B, 0xD7, 0x86, 0x60, 0xA3, 0xA1, 0x54,
		0x30, 0x55, 0xDB, 0x4A, 0x0D, 0x94, 0xD0, 0xEF, 0xB6, 0x98, 0x56, 0x73 };
static BYTE bEccPubkey[] = { 0xF0, 0x80, 0x36, 0x1D, 0x43, 0xE6, 0x5B, 0x47,
		0xE8, 0xF0, 0xD2, 0xC1, 0x5E, 0x99, 0x98, 0x5E, 0xD7, 0x86, 0xED, 0x29,
		0x30, 0x8D, 0xFF, 0xAB, 0xB5, 0xF0, 0x43, 0x21, 0x6A, 0xD6, 0x87, 0xC2,
		0x50, 0x73, 0x3E, 0x09, 0xE0, 0x1A, 0x48, 0xF3, 0xBA, 0xA5, 0xCD, 0x7E,
		0x90, 0x35, 0xFD, 0x76, 0x6C, 0xEB, 0x7B, 0xFD, 0x4D, 0x23, 0x48, 0xA2,
		0x66, 0x94, 0x2D, 0xBC, 0x10, 0xE4, 0x84, 0x56 };

static int __test_sm2_enc_ex(SGD_HANDLE hDevice) {
	unsigned char pbPlainText[256] = { 0 };
	unsigned char pbCipherText[256] = { 0 };
	unsigned char pbDataOut[256] = { 0 };
	ECCCIPHERBLOB *pstCipher;
	ECCPUBLICKEYBLOB stPubKey;
	ECCPRIVATEKEYBLOB stPriKey;
	SGD_RV rv;
	int flag = SGD_SM2_1;
	printf("SGD_SM2_1:%#x\n", flag);
	unsigned int uiLength = sizeof(pbDataOut);
	memset(pbPlainText, 'A', 256);

	int inlen = sizeof(pbPlainText);
	int declen = sizeof(pbDataOut);
	stPubKey.BitLen = 256;
	memcpy(stPubKey.XCoordinate + sizeof(stPubKey.XCoordinate) - 32, bEccPubkey,
			32);
	memcpy(stPubKey.YCoordinate + sizeof(stPubKey.YCoordinate) - 32,
			bEccPubkey + 32, 32);
	stPriKey.BitLen = 256;
	memcpy(
			stPriKey.PrivateKey + sizeof(stPriKey.PrivateKey)
					- sizeof(bEccPrikey), bEccPrikey, sizeof(bEccPrikey));

	pstCipher = malloc(sizeof(ECCCIPHERBLOB) + inlen);
	if (!pstCipher) {
		TRACE_ERRO("malloc error!");
		goto DONE;
	}

	rv = FunctionList->SKF_ExtECCEncrypt(hDevice, &stPubKey, pbPlainText, inlen, pstCipher);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_ExtECCEncrypt ERROR, errno[0x%08x]\n", rv);
		goto DONE;
	}

	rv = FunctionList->SKF_ExtECCDecrypt(hDevice, &stPriKey, pstCipher, pbDataOut, &declen);
	if (rv != SAR_OK) {
		TRACE_ERRO("SKF_ExtECCDecrypt ERROR, errno[0x%08x]\n", rv);
		goto DONE;
	}

	if (declen != inlen || memcmp(pbPlainText, pbDataOut, inlen)) {
		TRACE_ERRO("ecc plain text && dec text compare ERROR\n");
		goto DONE;
	}

	DONE: if (pstCipher)
		free(pstCipher);
	return rv;
}
#endif
#if 1

#define BY_SKF_DLSYM_ERR(funx)  \
        if (funx == NULL)  { \
                printf("Dlsym Error:%s.\n", dlerror()); \
                return 0;  } \
                
                
                
                        
int load_library()
{
 	int ret = 0;
	void * lib_handle = NULL;
	char  path[128] = {0};

	P_SKF_GetFuncList get_func_list;

    //getcwd(path, sizeof(path));
    //printf("load_library() 1 path: %s \n", path);
    //strcat(path, "/libskf.so");
    //printf("load_library() 2 path: %s \n", path);
   // memset(path,0,sizeof(path));
   // printf("load_library() 3 path: %s \n", path);
        memcpy(path, BY_SKF_LIB_PATH,strlen(BY_SKF_LIB_PATH));
        printf("load_library() 4 path: %s \n", path);
	lib_handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_DEEPBIND);
	//lib_handle = dlopen(path, RTLD_NOW );
	if (!lib_handle)
	{
		printf("Open Error:%s.\n", dlerror());
		return 0;
	}
	
	
	
#if BY_SKF_GX

        get_func_list = dlsym(lib_handle, "SKF_GetFuncList");
        if (get_func_list == NULL)
        {
                printf("Dlsym Error:%s.\n", dlerror());
                return 0;
        }
        ret = get_func_list(&FunctionList);
        if (ret)
        {
                printf("fnGetList ERROR 0x%x", ret);
                return ret;
        }
#else
 printf("222222222222222222222222222\r\n");
       FunctionList = (PSKF_FUNCLIST)malloc(sizeof(SKF_FUNCLIST));
            
       FunctionList->SKF_WaitForDevEvent = dlsym(lib_handle, "SKF_WaitForDevEvent");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_WaitForDevEvent );
            #if 1
       FunctionList->SKF_CancelWaitForDevEvent = dlsym(lib_handle, "SKF_CancelWaitForDevEvent");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CancelWaitForDevEvent );
		
       FunctionList->SKF_EnumDev = dlsym(lib_handle, "SKF_EnumDev");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EnumDev );
	
       FunctionList->SKF_ConnectDev = dlsym(lib_handle, "SKF_ConnectDev");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ConnectDev );
	
       FunctionList->SKF_DisConnectDev = dlsym(lib_handle, "SKF_DisConnectDev");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DisConnectDev );
	
       FunctionList->SKF_GetDevState = dlsym(lib_handle, "SKF_GetDevState");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GetDevState );

	
       FunctionList->SKF_SetLabel = dlsym(lib_handle, "SKF_SetLabel");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_SetLabel );
	
       FunctionList->SKF_GetDevInfo = dlsym(lib_handle, "SKF_GetDevInfo");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GetDevInfo );

       FunctionList->SKF_LockDev = dlsym(lib_handle, "SKF_LockDev");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_LockDev );
	
       FunctionList->SKF_UnlockDev = dlsym(lib_handle, "SKF_UnlockDev");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_UnlockDev );

       FunctionList->SKF_Transmit = dlsym(lib_handle, "SKF_Transmit");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_Transmit );
	
	
       FunctionList->SKF_ChangeDevAuthKey = dlsym(lib_handle, "SKF_ChangeDevAuthKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ChangeDevAuthKey );	

	
	     FunctionList->SKF_DevAuth = dlsym(lib_handle, "SKF_DevAuth");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DevAuth );

	     FunctionList->SKF_ChangePIN = dlsym(lib_handle, "SKF_ChangePIN");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ChangePIN );

	     FunctionList->SKF_GetPINInfo = dlsym(lib_handle, "SKF_GetPINInfo");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GetPINInfo );

	     FunctionList->SKF_VerifyPIN = dlsym(lib_handle, "SKF_VerifyPIN");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_VerifyPIN );

	     FunctionList->SKF_UnblockPIN = dlsym(lib_handle, "SKF_UnblockPIN");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_UnblockPIN );

	     FunctionList->SKF_ClearSecureState = dlsym(lib_handle, "SKF_ClearSecureState");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ClearSecureState );


     FunctionList->SKF_CreateApplication = dlsym(lib_handle, "SKF_CreateApplication");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CreateApplication );

	     FunctionList->SKF_EnumApplication = dlsym(lib_handle, "SKF_EnumApplication");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EnumApplication );

       FunctionList->SKF_DeleteApplication = dlsym(lib_handle, "SKF_DeleteApplication");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DeleteApplication );

	     FunctionList->SKF_OpenApplication = dlsym(lib_handle, "SKF_OpenApplication");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_OpenApplication );
	
	     FunctionList->SKF_CloseApplication = dlsym(lib_handle, "SKF_CloseApplication");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CloseApplication );
	

       FunctionList->SKF_CreateFile = dlsym(lib_handle, "SKF_CreateFile");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CreateFile );

	     FunctionList->SKF_DeleteFile = dlsym(lib_handle, "SKF_DeleteFile");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DeleteFile );

	     FunctionList->SKF_EnumFiles = dlsym(lib_handle, "SKF_EnumFiles");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EnumFiles );

	     FunctionList->SKF_GetFileInfo = dlsym(lib_handle, "SKF_GetFileInfo");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GetFileInfo );

	     FunctionList->SKF_ReadFile = dlsym(lib_handle, "SKF_ReadFile");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ReadFile );
	
	     FunctionList->SKF_WriteFile = dlsym(lib_handle, "SKF_WriteFile");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_WriteFile );


     FunctionList->SKF_CreateContainer = dlsym(lib_handle, "SKF_CreateContainer");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CreateContainer );

	     FunctionList->SKF_DeleteContainer = dlsym(lib_handle, "SKF_DeleteContainer");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DeleteContainer );

	     FunctionList->SKF_OpenContainer = dlsym(lib_handle, "SKF_OpenContainer");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_OpenContainer );

	     FunctionList->SKF_CloseContainer = dlsym(lib_handle, "SKF_CloseContainer");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CloseContainer );

	     FunctionList->SKF_EnumContainer = dlsym(lib_handle, "SKF_EnumContainer");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EnumContainer );

	     FunctionList->SKF_GetContainerType = dlsym(lib_handle, "SKF_GetContainerType");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GetContainerType );

	     FunctionList->SKF_ImportCertificate = dlsym(lib_handle, "SKF_ImportCertificate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ImportCertificate );

	     FunctionList->SKF_ExportCertificate = dlsym(lib_handle, "SKF_ExportCertificate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExportCertificate );


     FunctionList->SKF_GenRandom = dlsym(lib_handle, "SKF_GenRandom");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenRandom );

	     FunctionList->SKF_GenExtRSAKey = dlsym(lib_handle, "SKF_GenExtRSAKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenExtRSAKey );

	     FunctionList->SKF_GenRSAKeyPair = dlsym(lib_handle, "SKF_GenRSAKeyPair");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenRSAKeyPair );

	     FunctionList->SKF_ImportRSAKeyPair = dlsym(lib_handle, "SKF_ImportRSAKeyPair");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ImportRSAKeyPair );

	     FunctionList->SKF_RSASignData = dlsym(lib_handle, "SKF_RSASignData");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_RSASignData );

	     FunctionList->SKF_RSAVerify = dlsym(lib_handle, "SKF_RSAVerify");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_RSAVerify );

	     FunctionList->SKF_RSAExportSessionKey = dlsym(lib_handle, "SKF_RSAExportSessionKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_RSAExportSessionKey );

	     FunctionList->SKF_ExtRSAPubKeyOperation = dlsym(lib_handle, "SKF_ExtRSAPubKeyOperation");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtRSAPubKeyOperation );
	
	     FunctionList->SKF_ExtRSAPriKeyOperation = dlsym(lib_handle, "SKF_ExtRSAPriKeyOperation");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtRSAPriKeyOperation );

	     FunctionList->SKF_GenECCKeyPair = dlsym(lib_handle, "SKF_GenECCKeyPair");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenECCKeyPair );
	
	     FunctionList->SKF_ImportECCKeyPair = dlsym(lib_handle, "SKF_ImportECCKeyPair");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ImportECCKeyPair );
	
	     FunctionList->SKF_ECCSignData = dlsym(lib_handle, "SKF_ECCSignData");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ECCSignData );
	
	     FunctionList->SKF_ECCVerify = dlsym(lib_handle, "SKF_ECCVerify");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ECCVerify );

	     FunctionList->SKF_ECCExportSessionKey = dlsym(lib_handle, "SKF_ECCExportSessionKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ECCExportSessionKey );

	     FunctionList->SKF_ExtECCEncrypt = dlsym(lib_handle, "SKF_ExtECCEncrypt");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtECCEncrypt );
	
	     FunctionList->SKF_ExtECCDecrypt = dlsym(lib_handle, "SKF_ExtECCDecrypt");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtECCDecrypt );

	     FunctionList->SKF_ExtECCSign = dlsym(lib_handle, "SKF_ExtECCSign");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtECCSign );
	
	     FunctionList->SKF_ExtECCVerify = dlsym(lib_handle, "SKF_ExtECCVerify");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExtECCVerify );
	
	     FunctionList->SKF_GenerateAgreementDataWithECC = dlsym(lib_handle, "SKF_GenerateAgreementDataWithECC");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenerateAgreementDataWithECC );

	     FunctionList->SKF_GenerateAgreementDataAndKeyWithECC = dlsym(lib_handle, "SKF_GenerateAgreementDataAndKeyWithECC");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenerateAgreementDataAndKeyWithECC );

	     FunctionList->SKF_GenerateKeyWithECC = dlsym(lib_handle, "SKF_GenerateKeyWithECC");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_GenerateKeyWithECC );
	
	     FunctionList->SKF_ExportPublicKey = dlsym(lib_handle, "SKF_ExportPublicKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ExportPublicKey );
	
       FunctionList->SKF_ImportSessionKey = dlsym(lib_handle, "SKF_ImportSessionKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_ImportSessionKey );


	
      FunctionList->SKF_SetSymmKey = dlsym(lib_handle, "SKF_SetSymmKey");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_SetSymmKey );

	    FunctionList->SKF_EncryptInit = dlsym(lib_handle, "SKF_EncryptInit");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EncryptInit );


	    FunctionList->SKF_EncryptUpdate = dlsym(lib_handle, "SKF_EncryptUpdate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EncryptUpdate );


	    FunctionList->SKF_EncryptFinal = dlsym(lib_handle, "SKF_EncryptFinal");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_EncryptFinal );

	    FunctionList->SKF_Encrypt = dlsym(lib_handle, "SKF_Encrypt");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_Encrypt );

	    FunctionList->SKF_DecryptInit = dlsym(lib_handle, "SKF_DecryptInit");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DecryptInit );

	    FunctionList->SKF_DecryptUpdate = dlsym(lib_handle, "SKF_DecryptUpdate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DecryptUpdate );

	    FunctionList->SKF_DecryptFinal = dlsym(lib_handle, "SKF_DecryptFinal");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DecryptFinal );

	    FunctionList->SKF_Decrypt = dlsym(lib_handle, "SKF_Decrypt");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_Decrypt );

	    FunctionList->SKF_DigestInit = dlsym(lib_handle, "SKF_DigestInit");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DigestInit );

	    FunctionList->SKF_DigestUpdate = dlsym(lib_handle, "SKF_DigestUpdate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DigestUpdate );

	    FunctionList->SKF_DigestFinal = dlsym(lib_handle, "SKF_DigestFinal");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_DigestFinal );

	    FunctionList->SKF_Digest = dlsym(lib_handle, "SKF_Digest");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_Digest );

	    FunctionList->SKF_MacInit = dlsym(lib_handle, "SKF_MacInit");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_MacInit );

	    FunctionList->SKF_MacUpdate = dlsym(lib_handle, "SKF_MacUpdate");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_MacUpdate );

	    FunctionList->SKF_MacFinal = dlsym(lib_handle, "SKF_MacFinal");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_MacFinal );

	    FunctionList->SKF_Mac = dlsym(lib_handle, "SKF_Mac");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_Mac );

	    FunctionList->SKF_CloseHandle = dlsym(lib_handle, "SKF_CloseHandle");
       BY_SKF_DLSYM_ERR(FunctionList->SKF_CloseHandle );
#endif     
          
        
#endif        
   

   
        FunctionList->SKF_SetSymmKey=NULL;
        FunctionList->SKF_SetSymmKey = dlsym(lib_handle, "SKF_SetSymmKey");
        if (FunctionList->SKF_SetSymmKey == NULL)
        {
                printf("Dlsym Error:%s.\n", dlerror());
                return 0;
        }
        
        FunctionList->SKF_ECCVerify=NULL;
        FunctionList->SKF_ECCVerify = dlsym(lib_handle, "SKF_ECCVerify");
        if (FunctionList->SKF_ECCVerify == NULL)
        {
                printf("Dlsym Error:%s.\n", dlerror());
                return 0;
        }
        
        FunctionList->SKF_GenECCKeyPair=NULL;
        FunctionList->SKF_GenECCKeyPair = dlsym(lib_handle, "SKF_GenECCKeyPair");
        if (FunctionList->SKF_GenECCKeyPair == NULL)
        {
                printf("Dlsym Error:%s.\n", dlerror());
                return 0;
        }
        

        return ret;
}
#endif


int test() {

	SGD_RV rv;
	char szDevName[256] = { 0 };
	ULONG ulDevNameLen = 256;
	DEVINFO info = { 0 };
	BYTE pbRandom[32] = { 0 };
	char szAppName[256] = { 0 };
	ULONG ulAppNameLen = 256;
	char szContName[256] = { 0 };
	ULONG ulContName = 256;
	
	ULONG ulRetryCount = 0;
	
	char *dev_auth_key = "1234567812345678";
	BYTE szEncryptedData[256] = { 0 };
	ULONG ulEncryptedDataLen = 256;
	BLOCKCIPHERPARAM bp = { 0 };
	
	#if BY_SKF_GX
	char *pAdminPin = "111111";
	char *pUserPin = "111111";
	 
	#elif BY_SKF_WXT
	 char *pAdminPin = "111111";
	 char *pUserPin = "111111";
	
	#else 
	char *pAdminPin = "88888888";
	char *pUserPin = "88888888";
	#endif 
	
#if 1
	int ret = 0;
	ret = load_library();
        if (ret) {
    	   printf("load_library() failed: %#x\n", ret);
    	    return ret;
	}
        printf("\n load_library() success: %#x\n", ret);

	TRACE_INFO("start SKF_EnumDev");
	if ((rv = FunctionList->SKF_EnumDev(TRUE, szDevName, &ulDevNameLen)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumDev error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumDev szDevName=%s",szDevName);

	TRACE_INFO("start SKF_ConnectDev");
	if ((rv = FunctionList->SKF_ConnectDev(szDevName, &hDevice)) != SAR_OK) {
		TRACE_ERRO("SKF_ConnectDev error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_ConnectDev");

	memset(&info, 0, sizeof(info));

	TRACE_INFO("start SKF_GetDevInfo");
	if ((rv = FunctionList->SKF_GetDevInfo(hDevice, &info)) != SAR_OK) {
		TRACE_ERRO("SKF_GetDevInfo error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GetDevInfo");

	skf_print_devinfo(&info);

	TRACE_INFO("start SKF_GenRandom");
	if ((rv = FunctionList->SKF_GenRandom(hDevice, pbRandom, 8)) != SAR_OK) {
		TRACE_ERRO("SKF_GenRandom error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GenRandom");
       #if 1
	TRACE_INFO("start SKF_EnumApplication");
	if ((rv = FunctionList->SKF_EnumApplication(hDevice, szAppName, &ulAppNameLen)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumApplication error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumApplication");

	TRACE_INFO("start SKF_OpenApplication");
	if ((rv = FunctionList->SKF_OpenApplication(hDevice, szAppName, &happ)) != SAR_OK) {
		TRACE_ERRO("SKF_OpenApplication error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_OpenApplication");

	ULONG pulMaxRetryCount, pulRemainRetryCount = 0;
	BOOL pbDefaultPin = 0;
	TRACE_INFO("start SKF_GetPINInfo User");
	if ((rv = FunctionList->SKF_GetPINInfo(happ, USER_TYPE, &pulMaxRetryCount,
			&pulRemainRetryCount, &pbDefaultPin)) != SAR_OK) {
		TRACE_ERRO("SKF_GetPINInfo User error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GetPINInfo User");

	TRACE_INFO("start SKF_VerifyPIN User");
	if ((rv = FunctionList->SKF_VerifyPIN(happ, USER_TYPE, pUserPin, &ulRetryCount)) != SAR_OK) {
		TRACE_ERRO("SKF_VerifyPIN User error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_VerifyPIN User");

	TRACE_INFO("start SKF_EnumContainer");
	if ((rv = FunctionList->SKF_EnumContainer(happ, szContName, &ulContName)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumContainer error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumContainer");

	if (szContName[0] == '\0') {
		TRACE_INFO("SKF_EnumContainer in NULL!");
		TRACE_INFO("start SKF_CreateContainer");
		if ((rv = FunctionList->SKF_CreateContainer(happ, DEF_CONTAINER_NAME, &hcont))
				!= SAR_OK) {
			TRACE_ERRO("SKF_CreateContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_CreateContainer");

		TRACE_INFO("start SKF_OpenContainer");
		if ((rv = FunctionList->SKF_OpenContainer(happ, DEF_CONTAINER_NAME, &hcont)) != SAR_OK) {
			TRACE_ERRO("SKF_OpenContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_OpenContainer");
	} else {
		TRACE_INFO("start SKF_OpenContainer");
		if ((rv = FunctionList->SKF_OpenContainer(happ, szContName, &hcont)) != SAR_OK) {
			TRACE_ERRO("SKF_OpenContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_OpenContainer");
	}
	printf("FunctionList->SKF_OpenContainer 0x%0x\n",FunctionList->SKF_OpenContainer);
	
	#endif
#else
	TRACE_INFO("start SKF_EnumDev");
	printf("start SKF_EnumDev\r\n");
	if ((rv = SKF_EnumDev(TRUE, szDevName, &ulDevNameLen)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumDev error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumDev");
	printf("end SKF_EnumDev szDevName=%s\r\n",szDevName);

	TRACE_INFO("start SKF_ConnectDev");
	if ((rv = SKF_ConnectDev(szDevName, &hDevice)) != SAR_OK) {
		TRACE_ERRO("SKF_ConnectDev error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_ConnectDev");
	printf("end SKF_ConnectDev\r\n");

	memset(&info, 0, sizeof(info));

	TRACE_INFO("start SKF_GetDevInfo");
	if ((rv = SKF_GetDevInfo(hDevice, &info)) != SAR_OK) {
		TRACE_ERRO("SKF_GetDevInfo error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GetDevInfo");

	skf_print_devinfo(&info);

	TRACE_INFO("start SKF_GenRandom");
	if ((rv = SKF_GenRandom(hDevice, pbRandom, 8)) != SAR_OK) {
		TRACE_ERRO("SKF_GenRandom error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GenRandom");
#if 0
	TRACE_INFO("start SKF_EnumApplication");
	if ((rv = SKF_EnumApplication(hDevice, szAppName, &ulAppNameLen)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumApplication error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumApplication");

	TRACE_INFO("start SKF_OpenApplication");
	if ((rv = SKF_OpenApplication(hDevice, szAppName, &happ)) != SAR_OK) {
		TRACE_ERRO("SKF_OpenApplication error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_OpenApplication");

	ULONG pulMaxRetryCount, pulRemainRetryCount = 0;
	BOOL pbDefaultPin = 0;
	TRACE_INFO("start SKF_GetPINInfo User");
	if ((rv = SKF_GetPINInfo(happ, USER_TYPE, &pulMaxRetryCount,
			&pulRemainRetryCount, &pbDefaultPin)) != SAR_OK) {
		TRACE_ERRO("SKF_GetPINInfo User error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_GetPINInfo User");

	TRACE_INFO("start SKF_VerifyPIN User");
	if ((rv = SKF_VerifyPIN(happ, USER_TYPE, pUserPin, &ulRetryCount)) != SAR_OK) {
		TRACE_ERRO("SKF_VerifyPIN User error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_VerifyPIN User");

	TRACE_INFO("start SKF_EnumContainer");
	if ((rv = SKF_EnumContainer(happ, szContName, &ulContName)) != SAR_OK) {
		TRACE_ERRO("SKF_EnumContainer error: %08X", rv);
		return -1;
	}
	TRACE_INFO("end SKF_EnumContainer");

	if (szContName[0] == '\0') {
		TRACE_INFO("SKF_EnumContainer in NULL!");
		TRACE_INFO("start SKF_CreateContainer");
		if ((rv = SKF_CreateContainer(happ, DEF_CONTAINER_NAME, &hcont))
				!= SAR_OK) {
			TRACE_ERRO("SKF_CreateContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_CreateContainer");

		TRACE_INFO("start SKF_OpenContainer");
		if ((rv = SKF_OpenContainer(happ, DEF_CONTAINER_NAME, &hcont)) != SAR_OK) {
			TRACE_ERRO("SKF_OpenContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_OpenContainer");
	} else {
		TRACE_INFO("start SKF_OpenContainer");
		if ((rv = SKF_OpenContainer(happ, szContName, &hcont)) != SAR_OK) {
			TRACE_ERRO("SKF_OpenContainer error: %08X", rv);
			return -1;
		}
		TRACE_INFO("end SKF_OpenContainer");
	}
	//printf("FunctionList->SKF_OpenContainer 0x%0x\n",FunctionList->SKF_OpenContainer);
#endif

#endif


	if (__test_sm1_ecb_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm1 ecb failed!\n");
	else
		fprintf(stderr, "test sm1 ecb ok!\n");
	

	if (__test_sm1_cbc_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm1 cbc failed!\n");
	else
		fprintf(stderr, "test sm1 cbc ok!\n");
		

	if (__test_sm4_ecb_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm4 ecb failed!\n");
	else
		fprintf(stderr, "test sm4 ecb ok!\n");
		

	if (__test_sm4_cbc_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm4 cbc failed!\n");
	else
		fprintf(stderr, "test sm4 cbc ok!\n");


	if (__test_sm3_hash_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm3 hash failed!\n");
	else
		fprintf(stderr, "test sm3 hash ok!\n");

	if (__test_sm2_sign_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm2 sign failed!\n");
	else
		fprintf(stderr, "test sm2 sign ok!\n");
#if 0
	if (__test_sm2_enc_ex(hDevice) != SAR_OK)
		fprintf(stderr, "test sm2 enc failed!\n");
	else
		fprintf(stderr, "test sm2 enc ok!\n");
		
#endif

	if (hcont != NULL)
		FunctionList->SKF_CloseContainer(hcont);
//	if (happ != NULL)
//		SKF_CloseApplication(happ);
//	if (hDevice != NULL)
//		SKF_DisConnectDev(hDevice);
	return 0;
}
#endif

static int eng_skf_init(ENGINE *e) {
	TRACE_INFO();
	return 1;
}

static int eng_skf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {
	TRACE_INFO();
	return 0;
}

static int eng_skf_finish(ENGINE *e) {
	TRACE_INFO();
	return 1;
}

static int eng_skf_destroy(ENGINE *e) {
	TRACE_INFO();	
	return 1;
}
struct eng_xd_data {
	int enc;
	unsigned char pbKeyValue[16];
	unsigned char pbIV[16];
	SGD_HANDLE hKey;
};

//sm4_cbc
static int eng_sm4_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc) {
	//TRACE_INFO();
    struct eng_xd_data *p = (struct eng_xd_data*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!p) {
        printf("获取 cipher_data 失败\n");
        return;
    }        
	//struct eng_xd_data *p = (struct eng_xd_data*) ctx->cipher_data;
	char key2[16] = { 1 };
	int ret;
	int i;
	p->enc = enc;
	for (i = 0; i < 16; i++) {
		p->pbKeyValue[i] = key[i];
		p->pbIV[i] = iv[i];
	}
	return 1;
}
static int eng_sm4_done(EVP_CIPHER_CTX *ctx) {
	//TRACE_INFO();
	//struct eng_xd_data *p = (struct eng_xd_data*) ctx->cipher_data;
     struct eng_xd_data *p = (struct eng_xd_data*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!p) {
        printf("获取 cipher_data 失败\n");
        return;
    }   
	memset(p->pbKeyValue, 0, 16);
	memset(p->pbIV, 0, 16);
	p->enc = -1;
	return 1;
}
static int eng_sm4_cmd(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, unsigned int inl) {
	//TRACE_INFO();
	//struct eng_xd_data *p = (struct eng_xd_data*) ctx->cipher_data;
     struct eng_xd_data *p = (struct eng_xd_data*) EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!p) {
        printf("获取 cipher_data 失败\n");
        return;
    }   

	int ret = 0;
	BLOCKCIPHERPARAM bp;
	ULONG enc_len = 0, enc_final_len = 0, tmp_enc_len = 0;
	ULONG dec_len = 0, dec_final_len = 0, tmp_dec_len = 0;

	UCHAR pbTempIV[16] = { 0 };
	unsigned int uiLength = inl;

	memcpy(pbTempIV, p->pbIV, sizeof(p->pbIV));
	memset(&bp, 0, sizeof(bp));
	bp.IVLen = 16;
	if (bp.IVLen > 0) {
		if (!pbTempIV) {
			printf("sym cbc mode, but iv is null\n");
			ret = -1;
			goto DONE;
		}

		memcpy(bp.IV, pbTempIV, bp.IVLen);
	}

	int loop = inl / CBC_GROUP_SIZE;
#ifdef dotest_sm4
	sm4_context sm4_ctx={0};
	UCHAR in_txt[8192] = { 0 };
	UCHAR out_txt[8192] = { 0 };
	memcpy(in_txt, in, uiLength);
	if(p->enc == HT_ENC){
		sm4_setkey_enc(&sm4_ctx,p->pbKeyValue);
		sm4_crypt_cbc(&sm4_ctx,p->enc,inl,pbTempIV,in_txt,out_txt);
		dump_hex("SMS4  ENC",out_txt,inl);
	}else{
		sm4_context sm4_ctx={0};
		sm4_setkey_dec(&sm4_ctx,p->pbKeyValue);
		sm4_crypt_cbc(&sm4_ctx,p->enc,inl,pbTempIV,in_txt,out_txt);
		dump_hex("SMS4 DEC",out_txt,inl);
	}
//	memcpy(bp.IV, pbTempIV, bp.IVLen);
#endif

	//int rv = SKF_SetSymmKey(hDevice, p->pbKeyValue, SGD_SMS4_CBC, &p->hKey);
	int rv = FunctionList->SKF_SetSymmKey(hDevice, p->pbKeyValue, SGD_SMS4_CBC, &p->hKey);
	if (rv != SAR_OK) {
		printf("SKF_SetSymmKey error: %08X\n", rv);
		goto DONE;
	}
	SGD_HANDLE hKey = p->hKey;
	int i = 0;
	if (p->enc == HT_ENC) {
		rv = FunctionList->SKF_EncryptInit(hKey, bp);
		if (rv != SAR_OK) {
			printf("SKF_EncryptInit SM4 CBC error: %0168X\n", rv);
			goto DONE;
		}
		for (; i < loop+1; i++) {
			tmp_enc_len = CBC_GROUP_SIZE;
			rv = FunctionList->SKF_EncryptUpdate(hKey,
					(BYTE*) (in + (i * CBC_GROUP_SIZE)), CBC_GROUP_SIZE,
					(out + (i * CBC_GROUP_SIZE)), &tmp_enc_len);

			if (rv != SAR_OK) {
				printf("SKF_EncryptUpdate SM4 CBC error: %08X\n", rv);
				goto DONE;
			}
			enc_len += tmp_enc_len;
		}

		rv = FunctionList->SKF_EncryptFinal(hKey, (BYTE*) (out + enc_len),
				&enc_final_len);
		enc_len += enc_final_len;
//		memcpy(out + inl - bp.IVLen, pbTempIV, bp.IVLen);
#ifdef dotest_sm4
		dump_hex("SMS4 TF ENC",out,inl);
#endif
		if (rv != SAR_OK) {
			printf("SKF_EncryptFinal SM4 CBC error: %08X\n", rv);
			goto DONE;
		}
	}else{
		rv = FunctionList->SKF_DecryptInit(hKey, bp);
		if (rv != SAR_OK) {
			printf("SKF_DecryptInit SM4 CBC error: %0168X\n", rv);
			goto DONE;
		}
		i = 0;
		for (; i < loop+1; i++) {
			tmp_dec_len = CBC_GROUP_SIZE;
			rv = FunctionList->SKF_DecryptUpdate(hKey,(BYTE*) (in + (i * CBC_GROUP_SIZE)), CBC_GROUP_SIZE,
					(out + (i * CBC_GROUP_SIZE)), &tmp_enc_len);
			if (rv != SAR_OK) {
				printf("SKF_DecryptUpdate SM4 CBC error: %08X\n", rv);
				goto DONE;
			}
			dec_len += tmp_dec_len;
		}

		rv = FunctionList->SKF_DecryptFinal(hKey, (BYTE*) (out + dec_len), &dec_final_len);
//		memcpy(out + inl - bp.IVLen, pbTempIV, bp.IVLen);
#ifdef dotest_sm4
		dump_hex("SMS4 TF DEC",out,inl);
#endif
		if (rv != SAR_OK) {
			printf("SKF_DecryptFinal SM4 CBC error: %08X\n", rv);
			goto DONE;
		}
	}
	DONE: if (hKey)
		FunctionList->SKF_CloseHandle(hKey);
	p->hKey = NULL;
	return (!rv);
}

#if 0
static const EVP_CIPHER eng_xd_sm4_cipher = { NID_sm4_cbc, 16, 16, 16,
EVP_CIPH_CBC_MODE, eng_sm4_init, eng_sm4_cmd, eng_sm4_done,
		sizeof(struct eng_xd_data),
		NULL,
		NULL,
		NULL };

static const ENGINE_CMD_DEFN eng_skf_cmd_defns[] = { { 0, NULL, NULL, 0 }, };

static int eng_xd_cipher_nids[] = { 945, 0 };

static int eng_skf_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
		const int **nids, int nid) {
	int ok = 1;
	if (!cipher) {
		*nids = eng_xd_cipher_nids;
		return 2;
	}
	switch (nid) {
	case NID_sm4_cbc:
		*cipher = &eng_xd_sm4_cipher;
		break;

	default:
		ok = 0;
		*cipher = NULL;
		break;
	}
	return ok;
}
#else


static int eng_sm4_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    TRACE_INFO();
    struct eng_xd_data *cipher_ctx = (struct eng_xd_data*) EVP_CIPHER_CTX_get_cipher_data(ctx);
	//struct cipher_ctx *cipher_ctx =(struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    ///EVP_CIPHER_CTX *to_ctx = (EVP_CIPHER_CTX *)p2;
    //struct cipher_ctx *to_cipher_ctx;

	if (cipher_ctx == NULL){
				cipher_ctx = malloc(sizeof(struct eng_xd_data));
				TRACE_INFO("cipher_ctx == NULL");
				
	}
    switch (type) {

		case EVP_CTRL_COPY:
		        TRACE_INFO();        
				return 1;
			
			/* when copying the context, a new session needs to be initialized */
		/*   to_cipher_ctx =
				(struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(to_ctx);
		// memset(&to_cipher_ctx->sess, 0, sizeof(to_cipher_ctx->sess));
			return eng_sm4_init(to_ctx, (void *)cipher_ctx->key, EVP_CIPHER_CTX_iv(ctx),COP_ENCRYPT);
	*/
		case EVP_CTRL_INIT:
		    TRACE_INFO();
		//  memset(&cipher_ctx->sess, 0, sizeof(cipher_ctx->sess));
			return 1;

		default:
			break;
    }
    TRACE_INFO();
    return 1;

   
}



static EVP_CIPHER *_hidden=NULL;
static const EVP_CIPHER *eng_xd_sm4_cipher(int nid)
{
   
   TRACE_INFO("nid=%d",nid);
    if (_hidden == NULL
        && ((_hidden =EVP_CIPHER_meth_new(nid,16,16)) == NULL
        || !EVP_CIPHER_meth_set_iv_length(_hidden, 16)
        || !EVP_CIPHER_meth_set_flags(_hidden,NID_sm4_cbc )
        || !EVP_CIPHER_meth_set_init(_hidden, eng_sm4_init)
        || !EVP_CIPHER_meth_set_do_cipher(_hidden,eng_sm4_cmd)
        || !EVP_CIPHER_meth_set_cleanup(_hidden, eng_sm4_done)
        || !EVP_CIPHER_meth_set_impl_ctx_size(_hidden, sizeof(struct eng_xd_data))
		|| !EVP_CIPHER_meth_set_ctrl(_hidden,eng_sm4_ctrl)
	
		
       )) {
		TRACE_INFO();
        EVP_CIPHER_meth_free(_hidden);
        _hidden= NULL;
    }
    return _hidden;
}

static const ENGINE_CMD_DEFN eng_skf_cmd_defns[] = { { 0, NULL, NULL, 0 }, };
/*static int ossltest_cipher_nids[] = {
    NID_aes_128_cbc, NID_aes_128_gcm,
    NID_aes_128_cbc_hmac_sha1, 0
};**/
static int eng_xd_cipher_nids[] = { NID_sm4_cbc, 0 };
static int eng_skf_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
		const int **nids, int nid) {
			TRACE_INFO("nid=%d",nid);
			
	int ok = 1;
	if (!cipher) {
		*nids = eng_xd_cipher_nids;
		TRACE_INFO();
		return 2;
	}
	TRACE_INFO();
	switch (nid) {
		case NID_sm4_cbc:
		TRACE_INFO();
			*cipher = eng_xd_sm4_cipher(nid);
			break;

		default:
			ok = 0;
			*cipher = NULL;
			TRACE_INFO();
			break;
	}
	return ok;
}
#endif


static int __bind_engine(ENGINE *e, const char *id) {

	test();
	if (!ENGINE_set_id(e, ENGINE_ID) || !ENGINE_set_name(e, ENGINE_NAME)
			|| !ENGINE_set_init_function(e, eng_skf_init)
			|| !ENGINE_set_ctrl_function(e, eng_skf_ctrl)
			|| !ENGINE_set_finish_function(e, eng_skf_finish)
			|| !ENGINE_set_destroy_function(e, eng_skf_destroy)	
			|| !ENGINE_set_ciphers(e, eng_skf_ciphers))
		return 0;
		TRACE_INFO("*******4*********success**********");
	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(__bind_engine)
IMPLEMENT_DYNAMIC_CHECK_FN()

