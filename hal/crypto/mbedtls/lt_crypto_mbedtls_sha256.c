/**
 * @file lt_crypto_mbedtls_sha256.c
 * @author Tropic Square s.r.o.
 *
 * @license For the license see file LICENSE.txt file in the root directory of this source tree.
 */
#ifdef USE_MBEDTLS_CRYPTO

#include <stdint.h>
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

void lt_sha256_init(void *ctx)
{
    mbedtls_sha256_context *_ctx = (mbedtls_sha256_context*)(ctx);
    mbedtls_sha256_init(_ctx);
}

void lt_sha256_start(void *ctx)
{
    mbedtls_sha256_context *_ctx = (mbedtls_sha256_context*)(ctx);
    mbedtls_sha256_starts(_ctx, 0);
}

void lt_sha256_update(void *ctx, const uint8_t *input, size_t len)
{
    mbedtls_sha256_context *_ctx = (mbedtls_sha256_context*)(ctx);
    mbedtls_sha256_update(_ctx, input, len);
}

void lt_sha256_finish(void * ctx, uint8_t *output)
{
    mbedtls_sha256_context *_ctx = (mbedtls_sha256_context*)(ctx);
    mbedtls_sha256_free(_ctx);
}

void lt_hmac_sha256( const uint8_t *key, size_t keylen,
                          const uint8_t *input, size_t ilen,
                          uint8_t *output )
{
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, keylen, input, ilen, output);    
}
#endif
