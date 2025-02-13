/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of pairing batch delegation protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Statistical distance 1/2^\sigma between sampling and uniform distribution.
 */
#define RAND_DIST		40

/**
 * Bound \tau on how many elements the adversary can store.
 */
#define BND_STORE		72

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_pdbat_gen(g1_t u, g2_t v, gt_t e) {
	g1_rand(u);
	g2_rand(v);
	pc_map(e, u, v);
	return RLC_OK;
}

int cp_pdbat_ask(bn_t *l, bn_t *b, g1_t *z, g2_t c, const g1_t u, const g2_t v,
		const g1_t *p, const g2_t *q, size_t m) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		for (size_t i = 0; i < m; i++) {
			bn_rand_mod(l[i], n);
			bn_rand(b[i], RLC_POS, pc_param_level());
			g1_mul_sim(z[i], p[i], b[i], u, l[i]);
		}
		g2_mul_sim_lot(c, q, l, m);
		g2_sub(c, c, v);
		g2_norm(c, c);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_pdbat_ans(gt_t *w, const g1_t *z, const g2_t i, const g1_t u,
		const g1_t *p, const g2_t *q, size_t m) {
	g1_t *_p = (g1_t *)RLC_ALLOCA(g1_t, m + 1);
	g2_t *_q = (g2_t *)RLC_ALLOCA(g2_t, m + 1);
	int result = RLC_OK;

	RLC_TRY {
		for (size_t i = 0; i <= m; i++) {	
			g1_null(_p[i]);
			g2_null(_q[i]);
			g1_new(_p[i]);
			g2_new(_q[i]);
			g1_copy(_p[i], z[i]);
			g2_copy(_q[i], q[i]);
		}
		g1_neg(_p[m], u);
		g2_copy(_q[m], i);
		pc_map_sim(w[0], _p, _q, m + 1);
		for (size_t i = 0; i < m; i++) {
			pc_map(w[i + 1], p[i], q[i]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		for (size_t i = 0; i <= m; i++) {	
			g1_free(_p[i]);
			g2_free(_1[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
	}

	return result;
}

int cp_pdbat_ver(gt_t *rs, const gt_t *w, const bn_t *b, const gt_t e,
		size_t m) {
	gt_t t, u;
	int result = 1;

	gt_null(t);
	gt_null(u);

	RLC_TRY {
		gt_new(t);
		gt_new(u);

		gt_set_unity(u);
		result &= gt_is_valid(w[0]);
		for (size_t i = 0; i < m; i++) {
			result &= gt_is_valid(w[i + 1]);
			gt_exp(t, w[i + 1], b[i]);
			gt_mul(u, u, t);
			gt_copy(rs[i], w[i + 1]);
		}
		gt_mul(u, u, e);

		result &= (gt_cmp(u, w[0]) == RLC_EQ);
		if (!result) {
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(rs[i]);
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		gt_free(t);
		gt_free(u);
	}

	return result;
}

int cp_mvbat_gen(bn_t *l, g2_t r, g2_t *rs, size_t m) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		g2_rand(r);
		for (size_t i = 0; i < m; i++) {
			bn_rand_mod(l[i], n);
			g2_mul(rs[i], r, l[i]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_mvbat_ask(bn_t *b, g2_t *qs, const g2_t *rs, const g1_t *p,
		const g2_t *q, size_t m) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);

		for (size_t i = 0; i < m; i++) {
			bn_rand(b[i], RLC_POS, RAND_DIST);
			g2_mul(qs[i], q[i], b[i]);
			g2_add(qs[i], qs[i], rs[i]);
		}
		g2_norm_sim(qs, qs, m);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_mvbat_ans(gt_t *as, gt_t *bs, const g2_t *qs, const g1_t *p,
		const g2_t *q, size_t m) {
	
	for (size_t i = 0; i < m; i++) {
		pc_map(as[i], p[i], q[i]);
		pc_map(bs[i], p[i], qs[i]);
	}

	return RLC_OK;
}

int cp_mvbat_ver(gt_t *rs, const gt_t *as, const gt_t *bs, const bn_t *b,
		const bn_t *l, const g2_t r, const g1_t *p, size_t m) {
	g1_t u;
	gt_t v, w, alpha;
	int result = 1;

	g1_null(u);
	gt_null(v);
	gt_null(w);
	gt_null(alpha);

	RLC_TRY {
		g1_new(t);
		g1_new(u);
		gt_new(v);
		gt_new(w);
		gt_new(alpha);

		for (size_t i = 0; i < m; i++) {
			result &= gt_is_valid(as[i]);
			result &= gt_is_valid(bs[i]);
		}

		gt_set_unity(v);
		g1_mul_sim_lot(u, p, l, m);
		pc_map(alpha, u, r);
		for (size_t i = 0; i < m; i++) {
			gt_mul(v, v, bs[i]);
			gt_exp(w, as[i], b[i]);
			gt_mul(alpha, alpha, w);
			gt_copy(rs[i], as[i]);
		}

		result &= (gt_cmp(v, alpha) == RLC_EQ);
		if (!result) {
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(rs[i]);
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		g1_free(u);
		gt_free(v);
		gt_free(w);
		gt_free(alpha);
	}

	return result;
}

int cp_ambat_gen(bn_t s, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		pc_get_ord(n);
		bn_rand_mod(s, n);
		gt_exp_gen(e, s);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_ambat_ask(bn_t *r, g1_t *c, g1_t x, g2_t y, g2_t d, g1_t u, g2_t v,
		const bn_t s, const gt_t e, const g1_t *p, const g2_t *q, size_t m) {
	bn_t n, t, z;
	g1_t w1;
	g2_t w2;
	int result = RLC_OK;
	size_t eps = RAND_DIST/2 + BND_STORE - 1;

	bn_null(n);
	bn_null(t);
	g1_null(w1);
	g2_null(w2);

	RLC_TRY {
		bn_new(n);
		bn_new(t);
		bn_new(z);
		g1_new(w1);
		g2_new(w2);

		pc_get_ord(n);
		/* Sample r from Z_q* and compute U = [z]P. */
		bn_rand_mod(z, n);
		g1_mul_gen(u, z);
		/* Compute V = [s/z]Q. */
		bn_mod_inv(t, z, n);
		bn_mul(t, t, s);
		bn_mod(t, t, n);
		g2_mul_gen(v, t);

		if (m == 1) {
			g1_copy(c[0], p[0]);
			g1_sub(x, u, p[0]);
			g1_mul(x, x, t);
			if (ep_curve_is_pairf() == EP_BN || ep_curve_embed() <= 2) {
				bn_rand(r[0], RLC_POS, eps);
			} else {
				bn_rand_frb(r[0], &(core_get()->par), n, eps);
			}
			g2_rand(w2);
			g2_mul(d, q[0], r[0]);
			g2_add(d, d, w2);
			g2_sub(y, v, w2);
			g2_norm(y, y);
		} else {
			g1_rand(w1);
			g1_sub(x, u, w1);
			g1_norm(x, x);
			g2_copy(d, q[0]);
			for (size_t j = 1; j < m; j++) {
				g2_add(d, d, q[j]);
			}
			g2_sub(y, v, d);
			g2_mul(y, y, z);

			for (size_t i = 0; i < m; i++) {
				if (ep_curve_is_pairf() == EP_BN || ep_curve_embed() <= 2) {
					bn_rand(r[i], RLC_POS, eps);
				} else {
					bn_rand_frb(r[i], &(core_get()->par), n, eps);
				}
				g1_mul(c[i], p[i], r[i]);
				g1_add(c[i], c[i], w1);
				result &= (g1_is_infty(p[i]) == 0);
				result &= (g2_is_infty(q[i]) == 0);
				result &= (g1_is_infty(c[i]) == 0);
			}
			g1_norm_sim(c, c, m);
		}
		g2_norm(d, d);

		result &= (g1_is_infty(x) == 0);
		result &= (g2_is_infty(y) == 0);
		result &= (g2_is_infty(d) == 0);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(t);
		bn_free(z);
		g1_free(w1);
		g2_free(w2);
	}
	return result;
}

int cp_ambat_ans(gt_t *gs, const g1_t *c, const g1_t x, const g2_t y,
		const g2_t d, const g1_t *p, const g2_t *q, size_t m) {
	g1_t ps[3];
	g2_t qs[3];
	gt_t g;
	int result = RLC_OK;

	gt_null(g);

	RLC_TRY {
		for (size_t i = 0; i < 3; i++) {
			g1_null(ps[i]);
			g2_null(qs[i]);
			g1_new(ps[i]);
			g2_new(qs[i]);
		}
		gt_new(g);

		if (m == 1) {
			g1_copy(ps[0], p[0]);
			g2_copy(qs[0], d);
			g1_copy(ps[1], c[0]);
			g2_copy(qs[1], y);
			g1_copy(ps[2], x);
			g2_get_gen(qs[2]);
			pc_map(gs[0], p[0], q[0]);
			pc_map_sim(gs[1], ps, qs, 3);
		} else {
			for (size_t i = 0; i < m; i++) {
				pc_map(gs[i], p[i], q[i]);
			}

			g1_copy(ps[0], x);
			g2_copy(qs[0], d);
			g1_get_gen(ps[1]);
			g2_copy(qs[1], y);
			
			pc_map_sim(g, c, q, m);
			pc_map_sim(gs[m], ps, qs, 2);
			gt_mul(gs[m], gs[m], g);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		for (size_t i = 0; i < 3; i++) {
			g1_free(ps[i]);
			g2_free(qs[i]);
		}
		gt_free(g);
	}
	return result;
}

int cp_ambat_ver(gt_t *gs, const bn_t *c, const gt_t e, size_t m) {
	int result = 1;
	gt_t t, u;

	gt_null(t);
	gt_null(u);

	RLC_TRY {
		gt_new(t);
		gt_new(u);

		gt_set_unity(t);
		for (size_t i = 0; i < m; i++) {
			gt_exp(u, gs[i], c[i]);
			gt_mul(t, t, u);
			result &= gt_is_valid(gs[i]);
		}
		gt_mul(t, t, e);
		result &= (gt_cmp(t, gs[m]) == RLC_EQ);

		if (!result) {
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(gs[i]);
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
		gt_free(u);
	}
	return result;
}
