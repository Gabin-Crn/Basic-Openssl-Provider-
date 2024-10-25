#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>

#define DBG_PRINT(...) fprintf(stderr, __VA_ARGS__)

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    OSSL_LIB_CTX *libctx;
};

static void provider_ctx_free(struct provider_ctx_st *ctx);

typedef struct {
    EVP_CIPHER_CTX *cipher_ctx;
} MYPROV_CIPHER_CTX;

static OSSL_FUNC_provider_teardown_fn aes_prov_teardown;
static OSSL_FUNC_provider_query_operation_fn aes_prov_query;
static OSSL_FUNC_provider_gettable_params_fn aes_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn aes_prov_get_params;

static OSSL_FUNC_cipher_newctx_fn aes256cbc_newctx;
static OSSL_FUNC_cipher_freectx_fn aes256cbc_freectx;
static OSSL_FUNC_cipher_update_fn aes256cbc_update;
static OSSL_FUNC_cipher_final_fn aes256cbc_final;
static OSSL_FUNC_cipher_get_params_fn aes256cbc_get_params;

static void *aes256cbc_newctx(void *provctx) {
    MYPROV_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof(MYPROV_CIPHER_CTX));
    if (ctx == NULL) {
        return NULL; 
    }
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    return ctx;
}

int aes256cbc_encrypt_init(void *ctx, const unsigned char *key, const unsigned char *iv) {    
    MYPROV_CIPHER_CTX *myctx = (MYPROV_CIPHER_CTX *)ctx;
    if (!EVP_EncryptInit_ex(myctx->cipher_ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return 0;
    
    return 1;
}

static int aes256cbc_update(void *ctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl) {
    MYPROV_CIPHER_CTX *myctx = (MYPROV_CIPHER_CTX *)ctx;

    unsigned char *shifted_in = OPENSSL_malloc(inl);
    if (shifted_in == NULL) 
        return 0;

    for (size_t i = 0; i < inl; i++) {
        shifted_in[i] = in[i] >> 1; // Décalage de 1 bit
    }

    int ret = EVP_EncryptUpdate(myctx->cipher_ctx, out, (int *)outl, shifted_in, (int)inl);
    OPENSSL_free(shifted_in);
    return ret;
}    

static int aes256cbc_final(void *ctx, unsigned char *out, size_t *outl, size_t outsize) {
    MYPROV_CIPHER_CTX *myctx = (MYPROV_CIPHER_CTX *)ctx;
    return EVP_EncryptFinal_ex(myctx->cipher_ctx, out, (int *)outl);
}

static void aes256cbc_freectx(void *ctx) {
    MYPROV_CIPHER_CTX *myctx = (MYPROV_CIPHER_CTX *)ctx;
    EVP_CIPHER_CTX_free(myctx->cipher_ctx);
    OPENSSL_free(myctx);
}

// Implementing OSSL_FUNC_cipher_get_params function
static int aes256cbc_get_params(OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32)) // AES-256 key length is 32 bytes
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) // IV length for AES-256-CBC is 16 bytes
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) // Block size for AES is 16 bytes
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_FLAGS);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1)) // CBC mode
        return 0;

    return 1;
}

const OSSL_DISPATCH aes256cbc_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))aes256cbc_newctx }, 
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))aes256cbc_encrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))aes256cbc_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))aes256cbc_final },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))aes256cbc_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))aes256cbc_get_params }, // Register get_params function
    {0, NULL}
};

const OSSL_ALGORITHM aes256cbc_algorithms[] = {
    { "AES-256-CBC", "provider=cipherprovider", aes256cbc_functions },
    { NULL, NULL, NULL }
};

const OSSL_ALGORITHM *query_operation(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_CIPHER:
            return aes256cbc_algorithms;
    }
    return NULL;
}

static void aes_prov_teardown(void *provctx) {
    struct provider_ctx_st *pctx = (struct provider_ctx_st *)provctx;

    DBG_PRINT("enter %s\n", __func__);
    if (pctx != NULL) {
        OSSL_LIB_CTX_free(pctx->libctx);
        provider_ctx_free(pctx);
    }
}

static const OSSL_PARAM aes_prov_param_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *aes_prov_gettable_params(void *provctx) {
    return aes_prov_param_types;
}

static int aes_prov_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "AES Provider"))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "rc0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static void provider_ctx_free(struct provider_ctx_st *ctx) {
    OPENSSL_free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *handle, OSSL_LIB_CTX *libctx) {
    struct provider_ctx_st *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL) {
        ctx->core_handle = handle;
        ctx->libctx = libctx;
    }

    return ctx;
}

static const OSSL_DISPATCH aes_prov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))aes_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))query_operation }, 
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))aes_prov_get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))aes_prov_gettable_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) {
    OSSL_LIB_CTX *libctx = NULL;

    if ((libctx = OSSL_LIB_CTX_new()) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    *provctx = provider_ctx_new(handle, libctx);
    if (*provctx == NULL) {
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    *out = aes_prov_dispatch;
    return 1;
}
