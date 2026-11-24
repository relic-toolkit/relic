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
 * Implementation of pairing-based laconic private set intersection protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_pbpsi_gen(bn_t sk, g1_t ss, g2_t *s, size_t m) {
	int result = RLC_OK;
	size_t i;
	bn_t q;

	bn_null(q);

	RLC_TRY {
		bn_new(q);

		pc_get_ord(q);
		bn_rand_mod(sk, q);
		g1_mul_gen(ss, sk);

		g2_get_gen(s[0]);
		for (i = 1; i <= m; i++) {
			g2_mul_sec(s[i], s[i - 1], sk);
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

int cp_pbpsi_ask(g2_t *d, bn_t r, const bn_t *x, const g2_t *s, size_t m) {
	int result = RLC_OK;
	size_t i, k;
	bn_t q, *p = RLC_ALLOCA(bn_t, m + 1), *c = RLC_ALLOCA(bn_t, m + 1);

	bn_null(q);
	for (i = 0; i <= m; i++) {
		bn_null(p[i]);
		bn_null(c[i]);
	}

	RLC_TRY {
		bn_new(q);
		for (i = 0; i <= m; i++) {
			bn_new(p[i]);
			bn_new(c[i]);
		}

		pc_get_ord(q);
		bn_rand_mod(r, q);
		if (m == 0) {
			g2_mul_gen(d[0], r);
		} else {
			/* Scale the coefficients of P(X) by r instead of the results. */
			bn_lag(p, x, q, m);
			for (i = 0; i <= m; i++) {
				bn_mul(p[i], p[i], r);
				bn_mod(p[i], p[i], q);
			}
			g2_mul_sim_lot(d[0], s, p, m + 1);
			/*
			 * Divide r * P(X) by (X - x_k) synthetically, which takes O(m)
			 * operations instead of the O(m^2) to interpolate the quotient
			 * again from the other m - 1 roots.
			 */
			for (k = 0; k < m; k++) {
				bn_copy(c[m - 1], p[m]);
				for (i = m - 1; i > 0; i--) {
					bn_mul(c[i - 1], c[i], x[k]);
					bn_add(c[i - 1], c[i - 1], p[i]);
					bn_mod(c[i - 1], c[i - 1], q);
				}
				g2_mul_sim_lot(d[k + 1], s, c, m);
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		for (i = 0; i <= m; i++) {
			bn_free(p[i]);
			bn_free(c[i]);
		}
		RLC_FREE(p);
		RLC_FREE(c);
	}
	return result;
}

int cp_pbpsi_ans(gt_t *t, g1_t *u, const g1_t ss, const g2_t d,
		const bn_t *y, size_t n) {
	int result = RLC_OK;
	size_t i, j;
	bn_t q, tj, k;
	g1_t g1, tab[RLC_G1_TABLE];
	gt_t e;
	uint_t *shuffle = RLC_ALLOCA(uint_t, n);

	bn_null(q);
	bn_null(tj);
	bn_null(k);
	g1_null(g1);
	gt_null(e);
	for (i = 0; i < RLC_G1_TABLE; i++) {
		g1_null(tab[i]);
	}

	RLC_TRY {
		bn_new(q);
		bn_new(tj);
		bn_new(k);
		g1_new(g1);
		gt_new(e);
		for (i = 0; i < RLC_G1_TABLE; i++) {
			g1_new(tab[i]);
		}

		util_perm(shuffle, n);

		/* The same ss is multiplied for every element, so precompute it. */
		g1_mul_pre(tab, ss);

		/* e(tj * G_1, d) = e(G_1, d)^tj, so pair only once. */
		g1_get_gen(g1);
		pc_map(e, g1, d);

		pc_get_ord(q);
		for (j = 0; j < n; j++) {
			bn_rand_mod(tj, q);
			/* The exponent is secret, so exponentiate in constant time. */
			gt_exp_sec(t[j], e, tj);
			/* u_j = tj * (ss - y_j * G_1), with both bases fixed. */
			bn_mul(k, tj, y[shuffle[j]]);
			bn_mod(k, k, q);
			g1_mul_gen(u[j], k);
			g1_mul_fix(g1, (const g1_t *)tab, tj);
			g1_sub(u[j], g1, u[j]);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(tj);
		bn_free(k);
		g1_free(g1);
		gt_free(e);
		for (i = 0; i < RLC_G1_TABLE; i++) {
			g1_free(tab[i]);
		}
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_pbpsi_int(bn_t *z, size_t *len, const g2_t *d, const bn_t *x,
		size_t m, const gt_t *t, const g1_t *u, size_t n) {
	int result = RLC_OK;
	size_t j, k;
	gt_t e;
#ifdef RLC_PC_FIX
	size_t i;
	RLC_CAT(RLC_PC_FIELD, t) tab[RLC_PC_TABLE];

	for (i = 0; i < RLC_PC_TABLE; i++) {
		RLC_CAT(RLC_PC_FIELD, null)(tab[i]);
	}
#endif

	gt_null(e);

	RLC_TRY {
		gt_new(e);
#ifdef RLC_PC_FIX
		for (i = 0; i < RLC_PC_TABLE; i++) {
			RLC_CAT(RLC_PC_FIELD, new)(tab[i]);
		}
#endif

		*len = 0;
		if (m > 0) {
			for (k = 0; k < m; k++) {
#ifdef RLC_PC_FIX
				/* Each d_{k+1} is paired n times, so precompute its lines. */
				pc_map_pre(tab, d[k + 1]);
#endif
				for (j = 0; j < n; j++) {
#ifdef RLC_PC_FIX
					pc_map_fix(e, u[j], tab);
#else
					pc_map(e, u[j], d[k + 1]);
#endif
					if (gt_cmp(e, t[j]) == RLC_EQ && !gt_is_unity(e)) {
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
		gt_free(e);
#ifdef RLC_PC_FIX
		for (i = 0; i < RLC_PC_TABLE; i++) {
			RLC_CAT(RLC_PC_FIELD, free)(tab[i]);
		}
#endif
	}
	return result;
}
