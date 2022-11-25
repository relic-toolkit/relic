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
 * Implementation of protocols for laconic private set intersection.
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
#define STAT_SEC	40

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_rsapsi_gen(bn_t g, bn_t n, size_t bits) {
	bn_t p, q;

	bn_null(p);
	bn_null(q);

	RLC_TRY {
		bn_new(p);
		bn_new(q);

		/* Generate different primes p and q. */
		do {
			bn_gen_prime(p, bits / 2);
			bn_gen_prime(q, bits / 2);
		} while (bn_cmp(p, q) == RLC_EQ);

		/* n = pq. */
		bn_mul(n, p, q);

		do {
			bn_rand_mod(g, n);
			bn_gcd(p, g, n);
		} while (bn_cmp_dig(p, 1) != RLC_EQ);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(q);
	}

	return RLC_OK;
}

int cp_rsapsi_ask(bn_t d, bn_t r, bn_t p[], const bn_t g, const bn_t n,
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

int cp_rsapsi_ans(bn_t t[], bn_t u[], const bn_t d, const bn_t g, const bn_t n,
		const bn_t y[], size_t l) {
	int j, result = RLC_OK, len = RLC_CEIL(RLC_BN_BITS, 8);
	uint8_t h[RLC_MD_LEN], bin[RLC_CEIL(RLC_BN_BITS, 8)];
	unsigned int *shuffle = RLC_ALLOCA(unsigned int, l);
	bn_t p;

	bn_null(p);

	RLC_TRY {
		bn_new(p);
		if (shuffle == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		util_perm(shuffle, l);

		for (j = 0; j < l; j++) {
			bn_write_bin(bin, len, y[shuffle[j]]);
			md_map(h, bin, len);
			bn_read_bin(p, h, 2 * STAT_SEC / 8);
			if (bn_is_even(p)) {
				bn_add_dig(p, p, 1);
			}
			do {
				bn_add_dig(p, p, 2);
			} while (!bn_is_prime(p));
			bn_mxp(p, g, p, n);
			bn_rand_mod(t[j], n);
			bn_mxp(u[j], p, t[j], n);
			bn_mxp(t[j], d, t[j], n);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_rsapsi_int(bn_t z[], size_t *len, const bn_t r, const bn_t p[],
		const bn_t n, const bn_t x[], size_t m, const bn_t t[], const bn_t u[],
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
			for (j = 0; j < l; j++) {
				bn_mxp(f, u[j], r, n);
				for (k = 0; k < m; k++) {
					bn_copy(e, f);
					for (i = 0; i < m; i++) {
						if (i != k) {
							bn_mxp(e, e, p[i], n);
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
		bn_free(e);
		bn_free(f);
	}
	return result;
}
