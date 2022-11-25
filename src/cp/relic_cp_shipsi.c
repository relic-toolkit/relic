/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Statistical security determining collision probability.
 */
#define STAT_SEC	(40)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_shipsi_gen(bn_t g, crt_t crt, size_t bits) {
	/* Generate different primes p and q. */
	do {
		bn_gen_prime(crt->p, bits / 2);
		bn_gen_prime(crt->q, bits / 2);
	} while (bn_cmp(crt->p, crt->q) == RLC_EQ);

	/* Swap p and q so that p is smaller. */
	if (bn_cmp(crt->p, crt->q) != RLC_LT) {
		bn_copy(g, crt->p);
		bn_copy(crt->p, crt->q);
		bn_copy(crt->q, g);
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

	return RLC_OK;
}

int cp_shipsi_ask(bn_t d, bn_t r, bn_t p[], const bn_t g, const bn_t n,
		const bn_t x[], size_t m) {
	int i, result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];

	/* Compute R = g^r mod N. */
	bn_rand_mod(r, n);
	bn_mxp(d, g, r, n);

	/* Now hash all x_i and accmulate on R. */
	for (i = 0; i < m; i++) {
		bn_write_bin(bin, len, x[i]);
		md_map(h, bin, len);
		bn_read_bin(p[i], h, 2 * STAT_SEC / 8);
		if (bn_is_even(p[i])) {
			bn_add_dig(p[i], p[i], 1);
		}
		do {
			bn_add_dig(p[i], p[i], 2);
		} while (!bn_is_prime(p[i]));
		bn_mxp(d, d, p[i], n);
	}

	return result;
}

int cp_shipsi_ans(bn_t t[], bn_t u, bn_t d, const bn_t g, const crt_t crt,
		const bn_t y[], size_t n) {
	int j, result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	unsigned int *shuffle = RLC_ALLOCA(unsigned int, n);
	bn_t p, q;

	bn_null(p);
	bn_null(q);

	RLC_TRY {
		bn_new(p);
		bn_new(q);
		if (shuffle == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		util_perm(shuffle, n);

		bn_rand_mod(u, crt->n);
		for (j = 0; j < n; j++) {
			bn_write_bin(bin, len, y[shuffle[j]]);
			md_map(h, bin, len);
			bn_read_bin(p, h, 2 * STAT_SEC / 8);
			if (bn_is_even(p)) {
				bn_add_dig(p, p, 1);
			}
			do {
				bn_add_dig(p, p, 2);
			} while (!bn_is_prime(p));

#if !defined(CP_CRT)
			bn_mul(q, crt->dp, crt->dq);
			bn_mod_inv(p, p, q);
			bn_mul(p, p, u);
			bn_mod(p, p, q);
			bn_mxp(t[j], d, p, crt->n);
#else
			bn_mod_inv(q, p, crt->dq);
			bn_mul(q, q, u);
			bn_mod(q, q, crt->dq);

			bn_mod_inv(p, p, crt->dp);
			bn_mul(p, p, u);
			bn_mod(p, p, crt->dp);

			bn_mxp_crt(t[j], d, p, q, crt, 0);
#endif /* CP_CRT */
		}

#if !defined(CP_CRT)
		bn_mxp(u, g, u, crt->n);
#else
		bn_mod(p, u, crt->dp);
		bn_mod(q, u, crt->dq);

		bn_mxp_crt(u, g, p, q, crt, 0);
#endif
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
	int i, j, k, result = RLC_OK;
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
				for (j = 0; j < l; j++) {
					if (bn_cmp(e, t[j]) == RLC_EQ) {
						bn_copy(z[*len], x[k]);
						(*len)++;
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
