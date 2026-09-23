/*
 * Demonstrates the streaming sign/verify difference between ML-DSA and SLH-DSA.
 *
 * ML-DSA registers OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE/FINAL in its
 * dispatch table (ml_dsa_sig.c:480-482), so streaming works.
 *
 * SLH-DSA does NOT register these (slh_dsa_sig.c:352-377), so streaming fails.
 *
 * There are two streaming APIs in OpenSSL:
 *
 * 1. Old API: EVP_DigestSignUpdate / EVP_DigestSignFinal
 *    Checks signature->digest_sign_update (OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE).
 *    Neither ML-DSA nor SLH-DSA registers this, so it fails for BOTH.
 *    See m_sigver.c:352-355.
 *
 * 2. New API: EVP_PKEY_sign_message_update / EVP_PKEY_sign_message_final
 *    Checks signature->sign_message_update (OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE).
 *    ML-DSA registers this -> works.
 *    SLH-DSA does not -> fails.
 *    See signature.c:939-942.
 *
 * Build:
 *   cc -o streaming_sign streaming_sign.c \
 *      -I/path/to/openssl/include -L/path/to/openssl/lib \
 *      -lcrypto -Wl,-rpath,/path/to/openssl/lib
 *
 * Requires OpenSSL 3.5 or later.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void print_openssl_errors(void)
{
    unsigned long err;

    while ((err = ERR_get_error()) != 0)
        fprintf(stderr, "  OpenSSL error: %s\n", ERR_error_string(err, NULL));
}

/*
 * Try streaming sign with the OLD API:
 *   EVP_DigestSignInit -> EVP_DigestSignUpdate -> EVP_DigestSignFinal
 *
 * This checks signature->digest_sign_update (m_sigver.c:352).
 * Neither ML-DSA nor SLH-DSA registers OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
 * so this fails for both.
 */
static int try_old_streaming_api(EVP_PKEY *pkey, const char *alg_name)
{
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[65536];
    size_t siglen = sizeof(sig);
    const unsigned char msg[] = "Hello, streaming world!";
    int ret = 0;

    printf("  Old API (EVP_DigestSignUpdate): ");

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto err;

    /* EVP_DigestSignInit -> do_sigver_init (m_sigver.c:32) */
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        printf("FAIL (EVP_DigestSignInit)\n");
        goto err;
    }

    /*
     * EVP_DigestSignUpdate (m_sigver.c:328)
     *   -> checks signature->digest_sign_update (m_sigver.c:352)
     *   -> if NULL: ERR_raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED) (m_sigver.c:353)
     */
    if (EVP_DigestSignUpdate(mdctx, msg, sizeof(msg) - 1) <= 0) {
        printf("FAIL (EVP_DigestSignUpdate) - digest_sign_update is NULL\n");
        print_openssl_errors();
        goto cleanup;
    }

    if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
        printf("FAIL (EVP_DigestSignFinal)\n");
        goto err;
    }

    printf("OK (sig=%zu bytes)\n", siglen);
    ret = 1;
    goto cleanup;

err:
    print_openssl_errors();
cleanup:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/*
 * Try streaming sign with the NEW API:
 *   EVP_PKEY_sign_message_init -> EVP_PKEY_sign_message_update
 *     -> EVP_PKEY_sign_message_final
 *
 * This checks signature->sign_message_update (signature.c:939).
 * ML-DSA registers OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE -> works.
 * SLH-DSA does not -> fails.
 */
static int try_new_streaming_api(EVP_PKEY *pkey, const char *alg_name)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char sig[65536];
    size_t siglen = sizeof(sig);
    const unsigned char msg[] = "Hello, streaming world!";
    OSSL_PARAM params[2];
    int ret = 0;

    printf("  New API (EVP_PKEY_sign_message_update): ");

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (pctx == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_end();

    /* EVP_PKEY_sign_message_init (signature.c:879) */
    if (EVP_PKEY_sign_message_init(pctx, NULL, params) <= 0) {
        printf("FAIL (EVP_PKEY_sign_message_init)\n");
        goto err;
    }

    /*
     * EVP_PKEY_sign_message_update (signature.c:920)
     *   -> checks signature->sign_message_update (signature.c:939)
     *   -> if NULL: ERR_raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED) (signature.c:940)
     */
    if (EVP_PKEY_sign_message_update(pctx, msg, sizeof(msg) - 1) <= 0) {
        printf("FAIL (EVP_PKEY_sign_message_update) - sign_message_update is NULL\n");
        print_openssl_errors();
        goto cleanup;
    }

    /* EVP_PKEY_sign_message_final (signature.c:952) */
    if (EVP_PKEY_sign_message_final(pctx, sig, &siglen) <= 0) {
        printf("FAIL (EVP_PKEY_sign_message_final)\n");
        goto err;
    }

    printf("OK (sig=%zu bytes)\n", siglen);
    ret = 1;
    goto cleanup;

err:
    print_openssl_errors();
cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
 * One-shot sign with EVP_DigestSign for reference (works for both).
 */
static int try_oneshot_api(EVP_PKEY *pkey, const char *alg_name)
{
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[65536];
    size_t siglen = sizeof(sig);
    const unsigned char msg[] = "Hello, streaming world!";
    int ret = 0;

    printf("  One-shot  (EVP_DigestSign):             ");

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
        goto err;

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        printf("FAIL (EVP_DigestSignInit)\n");
        goto err;
    }

    /*
     * EVP_DigestSign (m_sigver.c:452)
     *   -> checks signature->digest_sign (m_sigver.c:473)
     *   -> Both ML-DSA and SLH-DSA register OSSL_FUNC_SIGNATURE_DIGEST_SIGN
     */
    if (EVP_DigestSign(mdctx, sig, &siglen, msg, sizeof(msg) - 1) <= 0) {
        printf("FAIL (EVP_DigestSign)\n");
        goto err;
    }

    printf("OK (sig=%zu bytes)\n", siglen);
    ret = 1;
    goto cleanup;

err:
    print_openssl_errors();
cleanup:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

static void test_algorithm(const char *alg_name)
{
    EVP_PKEY *pkey;

    printf("=== %s ===\n", alg_name);

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg_name);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to generate %s key\n", alg_name);
        print_openssl_errors();
        return;
    }

    try_oneshot_api(pkey, alg_name);
    try_old_streaming_api(pkey, alg_name);
    try_new_streaming_api(pkey, alg_name);

    EVP_PKEY_free(pkey);
    printf("\n");
}

int main(void)
{
    printf("OpenSSL version: %s\n\n", OpenSSL_version(OPENSSL_VERSION));

    printf("Dispatch table entries in OpenSSL providers:\n");
    printf("  ML-DSA:  SIGN_MESSAGE_UPDATE registered (ml_dsa_sig.c:480)\n");
    printf("  SLH-DSA: SIGN_MESSAGE_UPDATE NOT registered (slh_dsa_sig.c:352-377)\n");
    printf("  Neither registers DIGEST_SIGN_UPDATE.\n\n");

    test_algorithm("ML-DSA-44");
    test_algorithm("SLH-DSA-SHA2-128f");

    return 0;
}
