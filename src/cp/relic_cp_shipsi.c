/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of protocols for size-hiding private set intersection.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Domain separation tag for hashing set elements to primes.
 */
#define SHIPSI_TAG		"RELIC-SHIPSI"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_shipsi_gen(bn_t g, crt_t crt, size_t bits) {
	int result = RLC_OK;

	RLC_TRY {
		/* Generate different primes p and q. */
		do {
			bn_gen_prime(crt->p, bits / 2);
			bn_gen_prime(crt->q, bits / 2);
		} while (bn_cmp(crt->p, crt->q) == RLC_EQ);

		/* Swap p and q so that p is smaller. */
		if (bn_cmp(crt->p, crt->q) != RLC_LT) {
			bn_swap(crt->p, crt->q);
		}

		/* n = pq. */
		bn_mul(crt->n, crt->p, crt->q);

		do {
			bn_rand_mod(g, crt->n);
			bn_gcd(crt->qi, g, crt->n);
		} while (bn_cmp_dig(crt->qi, 1) != RLC_EQ);

		/* phi(n) = (p - 1)(q - 1). */
		bn_sub_dig(crt->dp, crt->p, 1);
		bn_sub_dig(crt->dq, crt->q, 1);
		bn_mod_inv(crt->qi, crt->q, crt->p);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	return result;
}

int cp_shipsi_ask(bn_t d, bn_t r, bn_t p[], const bn_t g, const bn_t n,
		const bn_t x[], size_t m) {
	int result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	size_t i;
	uint8_t bin[RLC_CEIL(RLC_BN_BITS, 8)];

	/* Elements are encoded as non-negative integers of RLC_BN_BITS bits. */
	for (i = 0; i < m; i++) {
		if (bn_sign(x[i]) == RLC_NEG || bn_bits(x[i]) > RLC_BN_BITS) {
			return RLC_ERR;
		}
	}

	/* Compute R = g^r mod N. */
	bn_rand_mod(r, n);
	bn_mxp(d, g, r, n);

	/* Now hash all x_i and accmulate on R. */
	for (i = 0; i < m; i++) {
		bn_write_bin(bin, len, x[i]);
		/* Primes of 2 * CP_STAT_SEC bits avoid accidental collisions. */
		if (bn_map_prime(p[i], NULL, bin, len, 2 * CP_STAT_SEC, 0,
				(const uint8_t *)SHIPSI_TAG, strlen(SHIPSI_TAG)) != RLC_OK) {
			result = RLC_ERR;
			break;
		}
		bn_mxp(d, d, p[i], n);
	}

	return result;
}

int cp_shipsi_ans(bn_t t[], bn_t u, bn_t d, const bn_t g, const crt_t crt,
		const bn_t y[], size_t n) {
	int result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	size_t j;
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	uint_t *shuffle = RLC_ALLOCA(uint_t, n);
	bn_t p, q;

	/* Elements are encoded as non-negative integers of RLC_BN_BITS bits. */
	for (j = 0; j < n; j++) {
		if (bn_sign(y[j]) == RLC_NEG || bn_bits(y[j]) > RLC_BN_BITS) {
			RLC_FREE(shuffle);
			return RLC_ERR;
		}
	}

	if (shuffle == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(p);
	bn_null(q);

	RLC_TRY {
		bn_new(p);
		bn_new(q);

		util_perm(shuffle, n);

		bn_rand_mod(u, crt->n);
		for (j = 0; j < n; j++) {
			bn_write_bin(bin, len, y[shuffle[j]]);
			if (bn_map_prime(p, NULL, bin, len, 2 * CP_STAT_SEC, 0,
					(const uint8_t *)SHIPSI_TAG, strlen(SHIPSI_TAG))
					!= RLC_OK) {
				RLC_THROW(ERR_NO_VALID);
			}

			bn_mod_inv(q, p, crt->dq);
			bn_mul(q, q, u);
			bn_mod(q, q, crt->dq);

			bn_mod_inv(p, p, crt->dp);
			bn_mul(p, p, u);
			bn_mod(p, p, crt->dp);

			bn_mxp_crt(t[j], d, p, q, crt, 0);
			/* Send only a hash of the tag, or the receiver could test any
			 * guess against it, and not only its own elements. */
			bn_write_bin(bin, len, t[j]);
			md_map(h, bin, len);
			bn_read_bin(t[j], h, RLC_MD_LEN);
		}

		bn_mod(p, u, crt->dp);
		bn_mod(q, u, crt->dq);

		bn_mxp_crt(u, g, p, q, crt, 0);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(q);
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_shipsi_int(bn_t z[], size_t *len, const bn_t r, const bn_t p[],
		const bn_t n, const bn_t x[], size_t m, const bn_t t[], const bn_t u,
		size_t l) {
	int result = RLC_OK;
	size_t i, j, k;
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	bn_t e, f;

	bn_null(e);
	bn_null(f);

	RLC_TRY {
		bn_new(e);
		bn_new(f);

		*len = 0;
		if (m > 0) {
			bn_mxp(f, u, r, n);
			for (k = 0; k < m; k++) {
				bn_copy(e, f);
				for (i = 0; i < m; i++) {
					if (i != k) {
						bn_mxp(e, e, p[i], n);
					}
				}
				/* Compare with the hashes of the tags sent by the sender. */
				bn_write_bin(bin, sizeof(bin), e);
				md_map(h, bin, sizeof(bin));
				bn_read_bin(e, h, RLC_MD_LEN);
				for (j = 0; j < l; j++) {
					if (bn_cmp(e, t[j]) == RLC_EQ) {
						/* Report each element once, so that len <= m. */
						bn_copy(z[*len], x[k]);
						(*len)++;
						break;
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(e);
		bn_free(f);
	}
	return result;
}
