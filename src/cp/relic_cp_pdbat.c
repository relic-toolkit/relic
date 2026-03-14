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
 * Implementation of batch pairing delegation protocols.
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
 * Bound \tau on how many elements the adversary can compute.
 */
#define BND_TIME		70

/**
 * Generates a challenge for batch pairing delegation protocols.
 * 
 * @param[out] r		- the resulting challenge.
 * @param[in] n			- the group order.
 * @param[in] bits		- the length of the challenge in bits.
 */
static void cp_pdbat_sample(bn_t r, const bn_t n, size_t bits) {
	if (ep_curve_is_pairf() == EP_BN || ep_curve_embed() <= 2) {
		bn_rand(r, RLC_POS, bits);
	} else {
		bn_rand_frb(r, &(core_get()->par), n, bits);
	}
}

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
			bn_rand(b[i], RLC_POS, RAND_DIST);
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
		for (size_t i = 0; i < m; i++) {	
			g1_null(_p[i]);
			g2_null(_q[i]);
			g1_new(_p[i]);
			g2_new(_q[i]);
			g1_copy(_p[i], z[i]);
			g2_copy(_q[i], q[i]);
		}
		g1_null(_p[m]);
		g1_new(_p[m]);
		g2_null(_q[m]);
		g2_new(_q[m]);
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
			g2_free(_q[i]);
		}
		g1_free(_p[m]);
		g2_free(_q[m]);
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

int cp_amore_gen(bn_t s, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		pc_get_ord(n);
		bn_rand_mod(s, n);
		gt_exp_gen(e, s);
		gt_inv(e, e);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_amore_ask(bn_t *r, g1_t *c, g1_t x, g2_t y, g2_t d, const bn_t s,
		const g1_t *p, const g2_t *q, size_t m) {
	bn_t n, t, z;
	g1_t w, u;
	g2_t v;
	int result = RLC_OK;
	size_t eps = (RAND_DIST - 1)/2 + BND_TIME;

	bn_null(n);
	bn_null(t);
	bn_null(z);
	g1_null(u);
	g1_null(w);
	g2_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(t);
		bn_new(z);
		g1_new(u);
		g1_new(w);
		g2_new(v);

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
			g1_add(c[0], p[0], u);
			g1_mul(c[0], c[0], t);
			g1_neg(c[0], c[0]);
			cp_pdbat_sample(r[0], n, eps);
			g2_mul(d, q[0], r[0]);
			g2_sub(d, v, d);
		} else {
			g1_rand(w);
			g1_sub(x, u, w);
			g1_norm(x, x);
			g2_copy(d, q[0]);
			for (size_t j = 1; j < m; j++) {
				g2_add(d, d, q[j]);
			}
			g2_sub(y, v, d);
			g2_mul(y, y, z);

			for (size_t i = 0; i < m; i++) {
				cp_pdbat_sample(r[i], n, eps);
				g1_mul(c[i], p[i], r[i]);
				g1_add(c[i], c[i], w);
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
		g1_free(u);
		g1_free(w);
		g2_free(v);
	}
	return result;
}

int cp_amore_ans(gt_t *gs, const g1_t *c, const g1_t x, const g2_t y,
		const g2_t d, const g1_t *p, const g2_t *q, size_t m) {
	g1_t ps[2];
	g2_t qs[2];
	gt_t g;
	int result = RLC_OK;

	gt_null(g);

	RLC_TRY {
		for (size_t i = 0; i < 2; i++) {
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
			g2_get_gen(qs[1]);
			pc_map(gs[0], p[0], q[0]);
			pc_map_sim(gs[1], ps, qs, 2);
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
			gt_inv(gs[m], gs[m]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		for (size_t i = 0; i < 2; i++) {
			g1_free(ps[i]);
			g2_free(qs[i]);
		}
		gt_free(g);
	}
	return result;
}

int cp_amore_ver(gt_t *gs, const bn_t *r, const gt_t e, size_t m) {
	int result = 1;
	gt_t t, u;

	gt_null(t);
	gt_null(u);

	RLC_TRY {
		gt_new(t);
		gt_new(u);

		gt_copy(t, gs[m]);
		for (size_t i = 0; i < m; i++) {
			gt_exp(u, gs[i], r[i]);
			gt_mul(t, t, u);
			result &= gt_is_valid(gs[i]);
		}
		result &= (gt_cmp(t, e) == RLC_EQ);

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

int cp_amprv_ask(bn_t *r, bn_t *w, g1_t *c, g2_t *d, g1_t *x, g2_t y, g2_t z,
		const bn_t s, const g1_t *p, const g2_t *q, int prv,
		size_t m) {
	bn_t n, *t = (bn_t *)RLC_ALLOCA(bn_t, 2 * m);
	g1_t u, g;
	g2_t v;
	int result = RLC_OK;
	size_t eps = ep_param_level();

	bn_null(n);
	g1_null(u);
	g1_null(g);
	g2_null(v);

	if (prv == 0) {
		return cp_amore_ask(r, c, x[0], y, d[0], s, p, q, m);
	}

	RLC_TRY {
		bn_new(n);
		g1_new(u);
		g1_new(g);
		g2_new(v);
		for (size_t i = 0; i < 2 * m; i++) {
			bn_null(t[i]);
			bn_new(t[i]);
		}

		pc_get_ord(n);
		/* Sample r from Z_q* and compute U = [u]P. */
		bn_rand_mod(w[0], n);
		g1_mul_gen(u, w[0]);
		/* Compute V = [s/u]Q. */
		bn_mod_inv(t[0], w[0], n);
		bn_mul(t[0], t[0], s);
		bn_mod(t[0], t[0], n);
		g2_mul_gen(v, t[0]);

		g2_set_infty(y);
		if (m == 1) {
			if (prv == 1) {
				/* w is a copy of s/u here. */
				bn_copy(w[0], t[0]);
			}
			cp_pdbat_sample(r[0], n, eps);
			cp_pdbat_sample(t[0], n, eps);
		} else {
			do {
				g1_rand(g);
			} while(g1_is_infty(g));
		}

		switch (prv) {
			case 1:
				if (m == 1) {
					g1_copy(c[0], p[0]);
					g1_sub(x[0], u, p[0]);
					g1_mul(x[0], x[0], t[0]);
					g2_sub(z, v, q[0]);
					g2_norm(z, z);
					bn_copy(t[1], r[0]);
					bn_mod_inv_sim(t, t, n, 2);
					g2_mul(d[0], q[0], t[1]);
					bn_mul(w[0], w[0], t[0]);
					bn_mod(w[0], w[0], n);
				} else {
					for (size_t i = 0; i < m; i++) {
						cp_pdbat_sample(r[i], n, eps);
						cp_pdbat_sample(t[i], n, eps);
						g1_copy(c[i], p[i]);
						g2_mul(d[i], q[i], t[i]);
						g2_add(y, y, d[i]);
						bn_copy(t[m + i], r[i]);
					}
					g2_norm(y, y);
					g2_sub(z, y, v);
					g2_mul(z, z, w[0]);
					bn_mod_inv_sim(t, t, n, 2 * m);
					for (size_t i = 0; i < m; i++) {
						g1_mul(x[i], p[i], t[i]);
						g1_add(x[i], x[i], g);
						bn_mul(w[i], t[i], t[m + i]);
						bn_mod(w[i], w[i], n);
						if (g1_is_infty(x[i])) {
							result = RLC_ERR;
						}
					}
				}
				break;
			case 2:
				if (m == 1) {
					g2_copy(d[0], q[0]);
					g1_sub(x[0], u, p[0]);
					g1_norm(x[0], x[0]);
					g2_sub(z, v, q[0]);
					g2_mul(z, z, t[0]);
					bn_copy(t[1], r[0]);
					bn_mod_inv_sim(t, t, n, 2);
					bn_mul(w[0], w[0], t[0]);
					bn_mod(w[0], w[0], n);
					g2_copy(y, d[0]);
					g1_mul(c[0], p[0], t[1]);
				} else {
					for (size_t i = 0; i < m; i++) {
						cp_pdbat_sample(r[i], n, eps);
						g1_mul(c[i], p[i], r[i]);
						g2_copy(d[i], q[i]);
						g1_add(x[i], p[i], g);
						g2_add(y, y, d[i]);
					}
					g1_norm_sim(x, x, m);
					g2_norm(y, y);
					g2_sub(z, y, v);
					g2_mul(z, z, w[0]);
					bn_mod_inv_sim(r, r, n, m);
				}
				break;
			case 3:
				if (m == 1) {
					g2_mul(d[0], q[0], t[0]);
					g2_sub(z, v, q[0]);
					g2_mul(z, z, r[0]);
					bn_copy(t[1], r[0]);
					bn_mod_inv_sim(t, t, n, 2);
					bn_mul(w[0], w[0], t[1]);
					bn_mod(w[0], w[0], n);
					g1_sub(x[0], u, p[0]);
					g1_mul(x[0], x[0], t[0]);
					g2_copy(y, d[0]);
					bn_mul(t[0], t[0], t[1]);
					bn_mod(t[0], t[0], n);
					g1_mul(c[0], p[0], t[0]);
				} else {
					for (size_t i = 0; i < m; i++) {
						cp_pdbat_sample(r[i], n, eps);
						g2_mul(d[i], q[i], t[0]);
						g2_add(y, y, d[i]);
						bn_copy(t[i + 1], r[i]);
					}
					g2_norm(y, y);
					g2_sub(z, y, v);
					g2_mul(z, z, w[0]);
					bn_mod_inv_sim(t, t, n, m + 1);
					for (size_t i = 0; i < m; i++) {
						g1_mul(x[i], p[i], t[0]);
						g1_add(x[i], x[i], g);
						bn_mul(w[i], t[0], t[i + 1]);
						bn_mod(w[i], w[i], n);
						g1_mul(c[i], p[i], w[i]);
						if (g1_is_infty(x[i])) {
							result = RLC_ERR;
						}
					}
				}
				break;
		}

		if (m > 1) {
			g1_sub(x[m], g, u);
			g1_norm(x[m], x[m]);
			if (g1_is_infty(x[m]) || g2_is_infty(y) || g2_is_infty(z)) {
				result = RLC_ERR;
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		g1_free(u);
		g1_free(g);
		g2_free(v);
		for (size_t i = 0; i < 2 * m; i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
	}
	return result;
}

int cp_amprv_ans(gt_t *gs, const bn_t *w, const g1_t *c, const g2_t *d,
		const g1_t *x, const g2_t y, const g2_t z, const g1_t *p, const g2_t *q,
		int prv, size_t m) {
	g1_t *ps = (g1_t *)RLC_ALLOCA(g1_t, m + 2);
	g2_t *qs = (g2_t *)RLC_ALLOCA(g2_t, m + 2);
	int result = RLC_OK;

	if (prv == 0) {
		RLC_FREE(ps);
		RLC_FREE(qs);
		return cp_amore_ans(gs, c, x[0], y, d[0], p, q, m);
	}

	RLC_TRY {
		for (size_t i = 0; i < m + 2; i++) {
			g1_null(ps[i]);
			g2_null(qs[i]);
			g1_new(ps[i]);
			g2_new(qs[i]);
		}

		switch (prv) {
			case 1:
				if (m == 1) {
					g2_mul_gen(qs[0], w[0]);
					g1_copy(ps[1], p[0]);
				} else {
					for (size_t i = 0; i < m; i++) {
						g1_mul(ps[i], p[i], w[i]);
						pc_map(gs[i], ps[i], d[i]);
						g1_neg(ps[i], x[i]);
						g2_copy(qs[i], d[i]);
					}
				}
				break;
			case 2:
			case 3:
				if (m == 1) {
					g2_copy(qs[0], y);
					g1_mul_gen(ps[1], w[0]);
				} else {
					for (size_t i = 0; i < m; i++) {
						pc_map(gs[i], c[i], d[i]);
						g1_neg(ps[i], x[i]);
						g2_copy(qs[i], d[i]);
					}
				}
				break;
		}

		if (m == 1) {
			g1_copy(ps[0], x[0]);
			g2_copy(qs[1], z);
			pc_map(gs[0], c[0], d[0]);
			pc_map_sim(gs[1], ps, qs, 2);
		} else {
			g1_copy(ps[m], x[m]);
			g2_copy(qs[m], y);
			g1_get_gen(ps[m + 1]);
			g2_copy(qs[m + 1], z);
			pc_map_sim(gs[m], ps, qs, m + 2);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		for (size_t i = 0; i < m + 2; i++) {
			g1_free(ps[i]);
			g2_free(qs[i]);
		}
		RLC_FREE(ps);
		RLC_FREE(qs);
	}
	return result;
}

int cp_amprv_ver(gt_t *gs, const bn_t *r, const gt_t e, int prv, size_t m) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		if (prv == 0) {
			result = cp_amore_ver(gs, r, e, m);
		} else {
			gt_copy(t, gs[m]);
			for (size_t i = 0; i < m; i++) {
				result &= gt_is_valid(gs[i]);
				gt_exp(gs[i], gs[i], r[i]);
				gt_mul(t, t, gs[i]);
			}
			if (m == 1) {
				/* Invert t to compensate for the sign difference in s
					* between the single and batched versions. */
				gt_inv(t, t);
			}
			result &= (gt_cmp(t, e) == RLC_EQ);

			if (!result) {
				for (size_t i = 0; i < m; i++) {
					gt_set_unity(gs[i]);
				}
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}
