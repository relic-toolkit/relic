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
 * Implementation of pairing delegation protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Statistical distance 1/2^\lambda between sampling and uniform distribution.
 */
#define RAND_DIST		40

/**
 * Statistical distance 1/2^\lambda between sampling and uniform distribution.
 */
#define BND_STORE		72

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_pdpub_gen(bn_t c, bn_t r, g1_t u1, g2_t u2, g2_t v2, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		/* Generate random c, U1, U2, r. */
		pc_get_ord(n);
		bn_rand(c, RLC_POS, RAND_DIST);
		g1_rand(u1);
		bn_rand_mod(r, n);
		g2_rand(u2);
		/* Compute gamma = e(U1, U2) and V2 = [1/r2]U2. */
		bn_mod_inv(n, r, n);
		g2_mul(v2, u2, n);
		pc_map(e, u1, u2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_pdpub_ask(g1_t v1, g2_t w2, const g1_t p, const g2_t q, const bn_t c,
		const bn_t r, const g1_t u1, const g2_t u2, const g2_t v2) {
	int result = RLC_OK;

	/* Compute V1 = [r](P - U1). */
	g1_sub(v1, p, u1);
	g1_mul(v1, v1, r);
	/* Compute W2 = [c]Q + U2. */
	g2_mul(w2, q, c);
	g2_add(w2, w2, u2);

	return result;
}

int cp_pdpub_ans(gt_t g[3], const g1_t p, const g2_t q, const g1_t v1,
		const g2_t v2, const g2_t w2) {
	int result = RLC_OK;
	pc_map(g[0], p, q);
	pc_map(g[1], p, w2);
	pc_map(g[2], v1, v2);
	return result;
}

int cp_pdpub_ver(gt_t r, const gt_t g[3], const bn_t c, const gt_t e) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result &= gt_is_valid(g[0]);
		result &= gt_is_valid(g[2]);

		gt_exp(t, g[0], c);
		gt_mul(t, t, g[2]);
		gt_mul(t, t, e);

		if (!result || gt_cmp(t, g[1]) != RLC_EQ) {
			gt_set_unity(r);
		} else {
			gt_copy(r, g[0]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_pdprv_gen(bn_t c, bn_t r[3], g1_t u1[2], g2_t u2[2], g2_t v2[4],
		gt_t e[2]) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(r[2], n);
		bn_rand(c, RLC_POS, RAND_DIST);
		for (int i = 0; i < 2; i++) {
			/* Generate random c, r, Ui. */
			g1_rand(u1[i]);
			bn_rand_mod(r[i], n);
			g2_rand(u2[i]);
			/* Compute gamma = e(U1, U2) and V2 = [1/r2]U2. */
			pc_get_ord(n);
			bn_mod_inv(n, r[i], n);
			g2_mul(v2[i], u2[i], n);
			pc_map(e[i], u1[i], u2[i]);
		}
		g2_mul(v2[2], u2[0], r[2]);
		g2_neg(v2[2], v2[2]);
		g2_mul(v2[3], u2[1], r[2]);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_pdprv_ask(g1_t v1[3], g2_t w2[4], const g1_t p, const g2_t q,
		const bn_t c, const bn_t r[3], const g1_t u1[2], const g2_t u2[2],
		const g2_t v2[4]) {
	int result = RLC_OK;
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_mod_inv(n, r[2], n);
		g1_mul(v1[2], p, n);
		for (int i = 0; i < 2; i++) {
			/* Compute V1 = [r](A - Ui). */
			g1_sub(v1[i], p, u1[i]);
			g1_mul(v1[i], v1[i], r[i]);
		}
		g2_mul(w2[0], q, r[2]);
		g2_add(w2[2], w2[0], v2[2]);
		g2_mul(w2[3], w2[0], c);
		g2_add(w2[3], w2[3], v2[3]);
		g2_copy(w2[0], v2[0]);
		g2_copy(w2[1], v2[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_pdprv_ans(gt_t g[4], const g1_t v1[3], const g2_t w2[4]) {
	int result = RLC_OK;
	pc_map(g[0], v1[0], w2[0]);
	pc_map(g[1], v1[1], w2[1]);
	pc_map(g[2], v1[2], w2[2]);
	pc_map(g[3], v1[2], w2[3]);
	return result;
}

int cp_pdprv_ver(gt_t r, const gt_t g[4], const bn_t c, const gt_t e[2]) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result &= gt_is_valid(g[0]);
		result &= gt_is_valid(g[1]);
		result &= gt_is_valid(g[2]);

		gt_mul(t, g[0], g[2]);
		gt_mul(r, t, e[0]);
		gt_exp(t, r, c);
		gt_mul(t, t, g[1]);
		gt_mul(t, t, e[1]);

		if (!result || gt_cmp(t, g[3]) != RLC_EQ) {
			gt_set_unity(r);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_lvpub_gen(bn_t c, bn_t r, g1_t u1, g2_t u2, g2_t v2, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		/* Generate random c, U1, r, U2. */
		pc_get_ord(n);
		g1_rand(u1);
		bn_rand_mod(r, n);
		g2_rand(u2);
		bn_rand(c, RLC_POS, RAND_DIST);
		/* Compute gamma = e(U1, U2) and V2 = [1/r2]U2. */
		bn_mod_inv(n, r, n);
		g2_mul(v2, u2, n);
		pc_map(e, u1, u2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_lvpub_ask(g1_t v1, g2_t w2, const bn_t c, const g1_t p, const g2_t q,
		const bn_t r, const g1_t u1, const g2_t u2, const g2_t v2) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		/* Sample random c. */
		pc_get_ord(n);
		/* Compute V1 = [r](P - U1). */
		g1_sub(v1, p, u1);
		g1_mul(v1, v1, r);
		/* Compute W2 = [c]Q + U_2. */
		g2_mul(w2, q, c);
		g2_add(w2, w2, u2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_lvpub_ans(gt_t g[2], const g1_t p, const g2_t q, const g1_t v1,
		const g2_t v2, const g2_t w2) {
	int result = RLC_OK;
	g1_t _p[2];
	g2_t _q[2];

	g1_null(_p[0]);
	g1_null(_p[1]);
	g2_null(_q[0]);
	g2_null(_q[1]);

	RLC_TRY {
		g1_new(_p[0]);
		g1_new(_p[1]);
		g2_new(_q[0]);
		g2_new(_q[1]);

		g1_copy(_p[0], p);
		g1_copy(_p[1], v1);
		g2_copy(_q[0], w2);
		g2_neg(_q[1], v2);
		pc_map_sim(g[1], _p, _q, 2);
		pc_map(g[0], p, q);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		g1_free(_p[0]);
		g1_free(_p[1]);
		g2_free(_q[0]);
		g2_free(_q[1]);
	}

	return result;
}

int cp_lvpub_ver(gt_t r, const gt_t g[2], const bn_t c, const gt_t e) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result &= gt_is_valid(g[0]);

		gt_exp(t, g[0], c);
		gt_inv(t, t);
		gt_mul(t, t, g[1]);

		if (!result || gt_cmp(t, e) != RLC_EQ) {
			gt_set_unity(r);
		} else {
			gt_copy(r, g[0]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_lvprv_gen(bn_t c, bn_t r[3], g1_t u1[2], g2_t u2[2], g2_t v2[4],
		gt_t e[2]) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand(c, RLC_POS, RAND_DIST);
		bn_rand_mod(r[2], n);
		for (int i = 0; i < 2; i++) {
			/* Generate random c, r, Ui. */
			g1_rand(u1[i]);
			bn_rand_mod(r[i], n);
			g2_rand(u2[i]);
			/* Compute gamma = e(U1, U2) and V2 = [1/r2]U2. */
			pc_get_ord(n);
			bn_mod_inv(n, r[i], n);
			g2_mul(v2[i], u2[i], n);
			pc_map(e[i], u1[i], u2[i]);
		}
		g2_mul(v2[2], u2[0], r[2]);
		g2_neg(v2[2], v2[2]);
		g2_mul(v2[3], u2[1], r[2]);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_lvprv_ask(g1_t v1[3], g2_t w2[4], const bn_t c, const g1_t p,
		const g2_t q, const bn_t r[3], const g1_t u1[2], const g2_t u2[2],
		const g2_t v2[4]) {
	int result = RLC_OK;
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_mod_inv(n, r[2], n);
		g1_mul(v1[2], p, n);
		for (int i = 0; i < 2; i++) {
			/* Compute V1 = [r](A - Ui). */
			g1_sub(v1[i], p, u1[i]);
			g1_mul(v1[i], v1[i], r[i]);
		}
		g2_mul(w2[0], q, r[2]);
		g2_add(w2[2], w2[0], v2[2]);
		g2_mul(w2[3], w2[0], c);
		g2_add(w2[3], w2[3], v2[3]);
		g2_copy(w2[0], v2[0]);
		g2_copy(w2[1], v2[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_lvprv_ans(gt_t g[4], const g1_t v1[3], const g2_t w2[4]) {
	int result = RLC_OK;
	g1_t _p[2];
	g2_t _q[2];

	g1_null(_p[0]);
	g1_null(_p[1]);
	g2_null(_q[0]);
	g2_null(_q[1]);

	RLC_TRY {
		g1_new(_p[0]);
		g1_new(_p[1]);
		g2_new(_q[0]);
		g2_new(_q[1]);

		g1_copy(_p[0], v1[0]);
		g1_copy(_p[1], v1[2]);
		g2_copy(_q[0], w2[0]);
		g2_copy(_q[1], w2[2]);
		pc_map_sim(g[0], _p, _q, 2);
		pc_map(g[1], v1[1], w2[1]);
		pc_map(g[2], v1[2], w2[3]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		g1_free(_p[0]);
		g1_free(_p[1]);
		g2_free(_q[0]);
		g2_free(_q[1]);
	}
	return result;
}

int cp_lvprv_ver(gt_t r, const gt_t g[4], const bn_t c, const gt_t e[2]) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result &= gt_is_valid(g[0]);
		result &= gt_is_valid(g[1]);

		gt_mul(r, g[0], e[0]);
		gt_exp(t, r, c);
		gt_mul(t, t, g[1]);
		gt_mul(t, t, e[1]);

		if (!result || gt_cmp(t, g[2]) != RLC_EQ) {
			gt_set_unity(r);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_amore_gen(bn_t c, bn_t r, bn_t d, g1_t u, g2_t v, bn_t x, gt_t e,
		int first, int longc, int priva, int privb) {
	bn_t n, u1, u2;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		bn_new(u1);
		bn_new(u2);

		pc_get_ord(n);
		if (first) {
			/* Generate random U1, U2, x, c. */
			bn_rand_mod(x, n);
			bn_rand_mod(u1, n);
			bn_mod_inv(u2, u1, n);
			bn_mul(u2, u2, x);
			bn_mod(u2, u2, n);
			g1_mul_gen(u, u1);
			g2_mul_gen(v, u2);
			/* Compute gamma = e(U1, U2). */
#if FP_PRIME < 1536
			gt_get_gen(e);
			gt_exp(e, e, x);
#else
			pc_map(e, u, v);
#endif
			if (longc) {
				if (ep_curve_is_pairf() == EP_BN) {
					bn_rand(c, RLC_POS, RAND_DIST + BND_STORE);
				} else {
					bn_rand_frb(c, &(core_get()->par), n, RAND_DIST + BND_STORE);
				}
			} else {
				if (ep_curve_is_pairf() == EP_BN) {
					bn_rand(c, RLC_POS, RAND_DIST);
				} else {
					bn_rand_frb(c, &(core_get()->par), n, RAND_DIST);
				}
			}
		} else {
			bn_rand_mod(u1, n);
			bn_mod_inv(u2, u1, n);
			bn_mul(u2, u2, x);
			bn_mod(u2, u2, n);
			g1_mul_gen(u, u1);
			g2_mul_gen(v, u2);
			if (ep_curve_is_pairf() == EP_BN) {
				bn_rand(c, RLC_POS, RAND_DIST + BND_STORE);
			} else {
				bn_rand_frb(c, &(core_get()->par), n, RAND_DIST + BND_STORE);
			}
		}

		bn_rand_mod(r, n);
		if (priva && !privb) {
			/* Compute d = (xu)/r mod q. */
			bn_mul(d, r, u2);
			bn_mod(d, d, n);
			bn_copy(u2, x);
		} else if (priva && privb) {
			/* Compute d = x/(rcu) mod q. */
			bn_mul(d, r, c);
			bn_mod(d, d, n);
		} else {
			/* Compute d = x/(ru) mod q. */
			bn_copy(d, r);
		}
		bn_mod_inv(d, d, n);
		bn_mul(d, d, u2);
		bn_mod(d, d, n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u1);
		bn_free(u2);
	}
	return result;
}

int cp_amore_ask(g1_t a1, g2_t b1, g1_t a2, g2_t b2, const bn_t c, const bn_t r,
		const bn_t d, const g1_t p, const g2_t q, const g1_t u, const g2_t v,
		int priva, int privb) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		if (!priva && !privb) {
			g1_copy(a1, p);
			g2_copy(b1, q);
			g1_sub(a2, u, p);
			g1_mul(a2, a2, r);
			g2_mul(b2, q, c);
			g2_sub(b2, v, b2);
		} else if (priva && privb) {
			g2_mul(b1, q, c);
			bn_mod_inv(n, c, n);
			g1_mul(a1, p, n);
			g1_sub(a2, u, p);
			g1_mul(a2, a2, r);
			g2_sub(b2, v, q);
		} else if (privb) {
			g1_copy(a1, p);
			g1_sub(a2, u, p);
			g1_mul(a2, a2, r);
			bn_mod_inv(n, c, n);
			g2_mul(b1, q, n);
			g2_sub(b2, v, q);
		} else if (priva) {
			bn_mod_inv(n, c, n);
			g1_mul(a1, p, n);
			g1_sub(a2, u, p);
			g2_copy(b1, q);
			g2_sub(b2, v, q);
			g2_mul(b2, b2, r);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_amore_ans(gt_t g[2], const bn_t d, const g1_t a1, const g2_t b1,
		const g1_t a2, const g2_t b2, int priva, int privb) {
	int result = RLC_OK;
	g1_t _p[2];
	g2_t _q[2];

	g1_null(_p[0]);
	g1_null(_p[1]);
	g2_null(_q[0]);
	g2_null(_q[1]);

	RLC_TRY {
		g1_new(_p[0]);
		g1_new(_p[1]);
		g2_new(_q[0]);
		g2_new(_q[1]);

		pc_map(g[0], a1, b1);
		if (priva && !privb) {
			g1_copy(_p[0], a2);
			g1_mul_gen(_p[1], d);
			g2_copy(_q[0], b1);
			g2_copy(_q[1], b2);
			pc_map_sim(g[1], _p, _q, 2);
		} else {
			g1_copy(_p[0], a1);
			g1_copy(_p[1], a2);
			g2_copy(_q[0], b2);
			g2_mul_gen(_q[1], d);
			pc_map_sim(g[1], _p, _q, 2);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		g1_free(_p[0]);
		g1_free(_p[1]);
		g2_free(_q[0]);
		g2_free(_q[1]);
	}

	return result;
}

int cp_amore_ver(gt_t r, const gt_t g[2], const bn_t c, const gt_t e,
		int priva, int privb) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result &= gt_is_valid(g[0]);

		if (priva && privb) {
			gt_exp(t, g[1], c);
			gt_mul(t, t, g[0]);
			gt_copy(r, g[0]);
		} else if (!priva && !privb) {
			gt_exp(t, g[0], c);
			gt_mul(t, t, g[1]);
			gt_copy(r, g[0]);
		} else {
			gt_exp(r, g[0], c);
			gt_mul(t, r, g[1]);
		}
		if (!result || gt_cmp(e, t) != RLC_EQ) {
			gt_set_unity(r);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_amprd_gen(bn_t *ls, g2_t *rs, bn_t c, bn_t r, bn_t d, g1_t u, g2_t v,
		bn_t x, gt_t e, size_t m) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		g2_rand(rs[0]);

		if (ep_curve_is_pairf() == EP_BN) {
			bn_rand(ls[0], RLC_POS, RAND_DIST);
		} else {
			bn_rand_frb(ls[0], &(core_get()->par), n, RAND_DIST);
		}
		for (size_t i = 0; i < m; i++) {
			if (ep_curve_is_pairf() == EP_BN) {
				bn_rand(ls[i + 1], RLC_POS, RAND_DIST + BND_STORE);
			} else {
				bn_rand_frb(ls[i + 1], &(core_get()->par), n, RAND_DIST + BND_STORE);
			}
			g2_mul(rs[i + 1], rs[0], ls[i + 1]);
		}
		cp_amore_gen(c, r, d, u, v, x, e, 1, 1, 0, 1);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_amprd_ask(g2_t *ds, g1_t a1, g2_t b1, g1_t a2, g2_t b2, const bn_t c,
		const bn_t r, const bn_t d, const g1_t *p, const g2_t *q, const g1_t u,
		const g2_t v, const bn_t *ls, const g2_t *rs, size_t m) {
	g1_t a, t;
	int result = RLC_OK;

	g1_null(a);
	g1_null(t);

	RLC_TRY {
		g1_new(t);

		g1_set_infty(a);
		for (size_t i = 0; i < m; i++) {
			g1_mul(t, p[i], ls[i + 1]);
			g1_add(a, a, t);
			g2_mul(ds[i], q[i], ls[0]);
			g2_add(ds[i], ds[i], rs[i + 1]);
			g2_norm(ds[i], ds[i]);
		}
		g1_norm(a, a);
		cp_amore_ask(a1, b1, a2, b2, c, r, d, a, rs[0], u, v, 0, 1);
	} RLC_CATCH_ANY {
		g1_free(a);
		g1_free(t);
	}

	return result;
}

int cp_amprd_ans(gt_t g[4], const g2_t *ds, const bn_t d, const g1_t a1,
		const g2_t b1, const g1_t a2, const g2_t b2, const g1_t *p,
		const g2_t *q, size_t m) {
	pc_map_sim(g[2], p, ds, m);
	pc_map_sim(g[3], p, q, m);
	cp_amore_ans(g, d, a1, b1, a2, b2, 0, 1);
	return RLC_OK;
}

int cp_amprd_ver(gt_t r, const gt_t g[4], const bn_t l, const bn_t c,
		const gt_t e) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);
		
		result = cp_amore_ver(r, g, c, e, 0, 1);
		result &= gt_is_valid(g[3]);

		gt_exp(t, g[3], l);
		gt_mul(t, t, r);
		gt_copy(r, g[3]);

		if (!result || gt_cmp(g[2], t) != RLC_EQ) {
			gt_set_unity(r);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}