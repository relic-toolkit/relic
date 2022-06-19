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

int cp_pbpsi_gen(bn_t sk, g1_t ss, g2_t s[], size_t m) {
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

int cp_pbpsi_ask(g2_t d[], bn_t r, const bn_t x[], const g2_t s[], size_t m) {
	int i, result = RLC_OK;
	bn_t t, q, *p = RLC_ALLOCA(bn_t, m + 1), *_x = RLC_ALLOCA(bn_t, m + 1)

	bn_null(q);
	bn_null(t);

	RLC_TRY {
		bn_new(q);
		bn_new(t);
		if (p == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i <= m; i++) {
			bn_null(p[i]);
			bn_new(p[i]);
			bn_null(_x[i]);
			bn_new(_x[i]);
		}

		pc_get_ord(q);
		bn_rand_mod(r, q);
		if (m == 0) {
			g2_mul_gen(d[0], r);
		} else {
			bn_lag(p, x, q, m);
			g2_mul_sim_lot(d[0], s, p, m + 1);
			g2_mul(d[0], d[0], r);
			for (i = 0; i < m; i++) {
				bn_copy(_x[i], x[i]);
			}
			for (i = 0; i < m; i++) {
				bn_copy(t, _x[i]);
				bn_copy(_x[i], _x[m - 1]);
				bn_lag(p, _x, q, m - 1);
				g2_mul_sim_lot(d[i + 1], s, p, m);
				g2_mul(d[i + 1], d[i + 1], r);
				bn_copy(_x[i], t);
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(t);
		for (i = 0; i <= m; i++) {
			bn_free(p[i]);
			bn_free(_x[i]);
		}
		RLC_FREE(p);
	}
	return result;
}

int cp_pbpsi_ans(gt_t t[], g1_t u[], const g1_t ss, const g2_t d,
		const bn_t y[], size_t n) {
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
		g2_free(g2);
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_pbpsi_int(bn_t z[], size_t *len, const g2_t d[], const bn_t x[],
		size_t m, const gt_t t[], const g1_t u[], size_t n) {
	int j, k, result = RLC_OK;
	gt_t e;

	gt_null(e);

	RLC_TRY {
		gt_new(e);

		*len = 0;
		if (m > 0) {
			for (k = 0; k < m; k++) {
				for (j = 0; j < n; j++) {
					pc_map(e, u[j], d[k + 1]);
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
		gt_free(e);
	}
	return result;
}
