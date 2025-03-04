/**
 * @file lt_crypto_mbedtls_x25519.c
 * @author Tropic Square s.r.o.
 *
 * @license For the license see file LICENSE.txt file in the root directory of this source tree.
 */
#define USE_MBEDTLS_CRYPTO
#ifdef USE_MBEDTLS_CRYPTO

#include <stdint.h>
#include "libtropic.h"
#include "mbedtls/ecp.h"

void mbedtls_ecp_decompress(const uint8_t *input_point, mbedtls_ecp_point *output_point) {
    int ret;
    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n);

    // x <= input
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&x, input_point, 32));

    // r = x
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&r, &x));

    // r = x + 486662
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&r, &r, 486662));

    // r = x^2 + 486662x
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

    // r = x^3 + 486662x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

    // r = x^3 + 486662x^2 + x
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &x));

    // Calculate square root of r over finite field P:
    //   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

    // r ^ ((P + 1) / 4) (mod p)
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

    // Select solution that has the correct "sign" (equals odd/even solution in finite group)
    if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
        // r = p - r
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
    }

    // y => output
    ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&n);

    return(ret);
}

void lt_X25519_calc_shared_secret(lt_handle_t *h, const uint8_t *priv, const uint8_t *pub, uint8_t *secret)
{
    mbedtls_ecp_point  pub_jacob, mul_result;
	uint8_t           *priv_clamp = {0};
    mbedtls_ecp_group  curve25519;
    mbedtls_mpi        multiplier;

    mbedtls_ecp_group_load(&curve25519, MBEDTLS_ECP_DP_CURVE25519);
    
    mbedtls_ecp_decompress(priv, &pub_jacob);
    
	for (size_t i = 0; i < 32; ++i) {
        priv_clamp[i] = priv[i];
    }
	priv_clamp[0]  &= 0xf8;
	priv_clamp[31] &= 0x7f;
	priv_clamp[31] |= 0x40;

    mbedtls_mpi_read_binary_le(&multiplier, priv_clamp, 32);

    mbedtls_ecp_mul(&curve25519, &mul_result, &multiplier, &pub_jacob, lt_random_get, h);

    for (size_t i = 0; i < 32; i++) {
        mbedtls_mpi_write_binary_le(&mul_result.private_X, secret, 32);
    }
}

void lt_X25519_calc_public_key(lt_handle_t *h, const uint8_t *sk, uint8_t *pk)
{

}

#endif
