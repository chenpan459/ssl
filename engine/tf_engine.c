#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

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
    my_rsa_method = RSA_meth_new("rf RSA Engine", 0);
    RSA_meth_set_priv_enc(my_rsa_method, my_rsa_priv_enc);
    return ENGINE_set_RSA(e, my_rsa_method);
}

static int bind_helper(ENGINE *e, const char *id) {
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

