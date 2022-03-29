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
/* Public definitions                                                         */
/*============================================================================*/

int cp_shipsi_gen(bn_t g, crt_t crt, int bits) {
	/* Generate different primes p and q. */
	do {
		bn_gen_prime_safep(crt->p, bits / 2);
		bn_gen_prime_safep(crt->q, bits / 2);
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

int cp_shipsi_ask(bn_t d, bn_t r, bn_t g, bn_t n, bn_t x[], int m) {
	int i, result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* Compute R = g^r mod N for random r mod N^2. */
		bn_rand_mod(r, n);
		bn_rand_mod(t, n);
		bn_mul(r, r, t);
		bn_mxp(d, g, r, n);

		/* Now hash all x_i and accmulate on R. */
		for (i = 0; i < m; i++) {
			bn_write_bin(bin, len, x[i]);
			md_map(h, bin, len);
			bn_read_bin(t, h, RLC_MD_LEN);
			if (bn_is_even(t)) {
				bn_add_dig(t, t, 1);
			}
			bn_mxp(d, d, t, n);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(t);
	}

	return result;
}

int cp_shipsi_ans(bn_t t[], bn_t u, bn_t d, bn_t g, crt_t crt, bn_t y[], int n) {
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
			bn_read_bin(p, h, RLC_MD_LEN);
			if (bn_is_even(p)) {
				bn_add_dig(p, p, 1);
			}

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
		bn_mxp(u, g, u, crt->n);
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

int cp_shipsi_int(bn_t z[], int *len, bn_t r, bn_t n, bn_t x[], int m,
		bn_t t[], bn_t u, int l) {
	int i, j, k, result = RLC_OK, size = RLC_CEIL(RLC_BN_BITS, 8);
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	bn_t *hs = RLC_ALLOCA(bn_t, m);
	bn_t e, f;

	bn_null(e);
	bn_null(f);

	RLC_TRY {
		bn_new(e);
		bn_new(f);
		if (hs == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			bn_null(hs[i]);
			bn_new(hs[i]);
		}

		for (i = 0; i < m; i++) {
			bn_write_bin(bin, size, x[i]);
			md_map(h, bin, size);
			bn_read_bin(hs[i], h, RLC_MD_LEN);
			if (bn_is_even(hs[i])) {
				bn_add_dig(hs[i], hs[i], 1);
			}
		}

		*len = 0;
		if (m > 0) {
			bn_mxp(f, u, r, n);
			for (j = 0; j < l; j++) {
				for (k = 0; k < m; k++) {
					bn_copy(e, f);
					for (i = 0; i < m; i++) {
						if (i != k) {
							bn_mxp(e, e, hs[i], n);
						}
					}
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
		for (i = 0; i < m; i++) {
			bn_free(hs[i]);
		}
		bn_free(e);
		bn_free(f);
		RLC_FREE(hs);
	}
	return result;
}
