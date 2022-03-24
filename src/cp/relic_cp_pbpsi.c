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
 * Implementation of pairing-based laconic private set intersection protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_pbpsi_gen(bn_t sk, g1_t ss, g2_t s[], int m) {
	int i, result = RLC_OK;
	bn_t q;

	bn_null(q);

	RLC_TRY {
		bn_new(q);

		pc_get_ord(q);
		bn_rand_mod(sk, q);
		g1_mul_gen(ss, sk);

		g2_get_gen(s[0]);
		for (i = 1; i <= m; i++) {
			g2_mul(s[i], s[i - 1], sk);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
	}
	return result;
}

int cp_pbpsi_ask(g2_t d, bn_t r, bn_t x[], g2_t s[], int m) {
	int i, result = RLC_OK;
	bn_t q, *p = RLC_ALLOCA(bn_t, m + 1);

	bn_null(q);

	RLC_TRY {
		bn_new(q);
		if (p == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i <= m; i++) {
			bn_null(p[i]);
			bn_new(p[i]);
		}

		pc_get_ord(q);
		bn_rand_mod(r, q);
		if (m == 0) {
			g2_mul_gen(d, r);
		} else {
			bn_lag(p, x, q, m);
			g2_mul_sim_lot(d, s, p, m + 1);
			g2_mul(d, d, r);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		for (i = 0; i <= m; i++) {
			bn_free(p[i]);
		}
		RLC_FREE(p);
	}
	return result;
}

int cp_pbpsi_ans(gt_t t[], g1_t u[], g1_t ss, g2_t d, bn_t y[], int n) {
	int j, result = RLC_OK;
	bn_t q, tj;
	g1_t g1;
	g2_t g2;
	unsigned int *shuffle = RLC_ALLOCA(unsigned int, n);

	bn_null(q);
	bn_null(tj);
	g1_null(g1);
	g2_null(g2);

	RLC_TRY {
		bn_new(q);
		bn_new(tj);
		g1_new(g1);
		g2_new(g2);
		if (shuffle == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		util_perm(shuffle, n);

		pc_get_ord(q);
		g2_get_gen(g2);
		for (j = 0; j < n; j++) {
			bn_rand_mod(tj, q);
			g1_mul_gen(g1, tj);
			pc_map(t[j], g1, d);
			g1_mul_gen(u[j], y[shuffle[j]]);
			g1_sub(u[j], ss, u[j]);
			g1_mul(u[j], u[j], tj);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(tj);
		g1_free(g1);
		g1_free(g2);
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_pbpsi_int(bn_t z[], int *len, bn_t sk, g2_t d, bn_t x[], int m,
		gt_t t[], g1_t u[], int n) {
	int j, k, result = RLC_OK;
	bn_t q, *i = RLC_ALLOCA(bn_t, m);
	g2_t c;
	gt_t e;

	bn_null(q);
	g2_null(c);
	gt_null(e);

	RLC_TRY {
		bn_new(q);
		for (j = 0; j < m; j++) {
			bn_null(i[j]);
			bn_new(i[j]);
		}
		g2_new(c);
		gt_new(e);

		*len = 0;
		if (m > 0) {
			pc_get_ord(q);
			for (k = 0; k < m; k++) {
				bn_sub(i[k], sk, x[k]);
				bn_mod(i[k], i[k], q);
			}
			bn_mod_inv_sim(i, i, q, m);
			for (k = 0; k < m; k++) {
				g2_mul(c, d, i[k]);
				for (j = 0; j < n; j++) {
					pc_map(e, u[j], c);
					if (gt_cmp(e, t[j]) == RLC_EQ && !gt_is_unity(e)) {
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
		bn_free(q);
		for (j = 0; j < m; j++) {
			bn_free(i[j]);
		}
		g2_free(c);
		gt_free(e);
		RLC_FREE(i);
	}
	return result;
}
