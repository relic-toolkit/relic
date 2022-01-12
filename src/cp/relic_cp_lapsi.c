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
/* Public definitions                                                         */
/*============================================================================*/

int cp_lapsi_gen(bn_t sk, g2_t ss, g1_t s[], int m) {
	int i, result = RLC_OK;
	bn_t q;

	bn_null(q);

	RLC_TRY {
		bn_new(q);

		pc_get_ord(q);
		bn_rand_mod(sk, q);
		g2_mul_gen(ss, sk);

		g1_get_gen(s[0]);
		for (i = 1; i <= m; i++) {
			g1_mul(s[i], s[i - 1], sk);
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

int cp_lapsi_ask(g1_t d, bn_t r, bn_t x[], g1_t s[], int m) {
	int i, j, result = RLC_OK;
	bn_t q, *p = RLC_ALLOCA(bn_t, m + 1), *_p = RLC_ALLOCA(bn_t, m + 1);

	bn_null(q);

	RLC_TRY {
		bn_new(q);
		for (i = 0; i <= m; i++) {
			bn_null(p[i]);
			bn_null(_p[i]);
			bn_new(p[i]);
			bn_new(_p[i]);
		}

		pc_get_ord(q);
		bn_rand_mod(r, q);
		if (m == 0) {
			g1_mul_gen(d, r);
		} else {
			bn_set_dig(p[0], 1);
			for (i = 0; i < m; i++) {
				bn_zero(_p[0]);
				for (j = 0; j <= i; j++) {
					bn_copy(_p[j + 1], p[j]);
				}
				for (j = 0; j <= i; j++) {
					bn_mul(p[j], p[j], x[i]);
					bn_mod(p[j], p[j], q);
					bn_sub(p[j], _p[j], p[j]);
					bn_mod(p[j], p[j], q);
				}
				bn_copy(p[j], _p[j]);
			}
			g1_mul_sim_lot(d, s, p, m + 1);
			g1_mul(d, d, r);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		for (i = 0; i <= m; i++) {
			bn_free(p[i]);
			bn_free(_p[i]);
		}
		RLC_FREE(p);
		RLC_FREE(_p);
	}
	return result;
}

int cp_lapsi_ans(gt_t t[], g2_t u[], g1_t d, g2_t ss, bn_t y[], int n) {
	int j, result = RLC_OK;
	bn_t q, tj;
	g1_t g1;
	g2_t g2;

	bn_null(q);
	bn_null(tj);
	g1_null(g1);
	g2_null(g2);

	RLC_TRY {
		bn_new(q);
		bn_new(tj);
		g1_new(g1);
		g2_new(g2);

		pc_get_ord(q);
		g2_get_gen(g2);
		for (j = 0; j < n; j++) {
			bn_rand_mod(tj, q);
			g1_mul(g1, d, tj);
			pc_map(t[j], g1, g2);
			g2_mul_gen(u[j], y[j]);
			g2_sub(u[j], ss, u[j]);
			g2_norm(u[j], u[j]);
			g2_mul(u[j], u[j], tj);
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
	}
	return result;
}

int cp_lapsi_int(bn_t z[], int *len, bn_t sk, g1_t d, bn_t x[], int m,
		gt_t t[], g2_t u[], int n) {
	int j, k, result = RLC_OK;
	bn_t i, q;
	g1_t c;
	gt_t e;

	bn_null(i);
	bn_null(q);
	g1_null(c);
	gt_null(e);

	RLC_TRY {
		bn_new(i);
		bn_new(q);
		g1_new(c);
		gt_new(e);

		*len = 0;
		if (m > 0) {
			pc_get_ord(q);
			for (k = 0; k < m; k++) {
				bn_sub(i, sk, x[k]);
				bn_mod(i, i, q);
				bn_mod_inv(i, i, q);
				g1_mul(c, d, i);
				for (j = 0; j < n; j++) {
					pc_map(e, c, u[j]);
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
		bn_free(i);
		bn_free(q);
		g1_free(c);
		gt_free(e);
	}
	return result;
}
