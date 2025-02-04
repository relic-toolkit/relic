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
			result = 0;
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
			result = 0;
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
			result = 0;
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
			result = 0;
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

int cp_amore_gen(bn_t x, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		pc_get_ord(n);
		bn_rand_mod(x, n);

		gt_get_gen(e);
		gt_exp(e, e, x);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_amore_ask(bn_t d, g1_t a1, g2_t b1, g1_t a2, g2_t b2, bn_t c, bn_t r,
		const bn_t x, const g1_t p, const g2_t q, int priva, int privb) {
	bn_t n, t;
	g1_t u;
	g2_t v;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);
	g1_null(u);
	g2_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(t);
		g1_new(u);
		g2_new(v);

		pc_get_ord(n);
		bn_rand_mod(t, n);
		/* d = x/u here. */
		bn_mod_inv(d, t, n);
		bn_mul(d, d, x);
		bn_mod(d, d, n);
		g1_mul_gen(u, t);
		g2_mul_gen(v, d);

		if (ep_curve_is_pairf() == EP_BN || ep_curve_embed() <= 2) {
			bn_rand(c, RLC_POS, RAND_DIST/2 + BND_STORE - 1);
		} else {
			bn_rand_frb(c, &(core_get()->par), n, RAND_DIST/2 + BND_STORE - 1);
		}

		bn_rand_mod(r, n);
		if (priva && !privb) {
			/* In this case, make d = u. */
			bn_copy(d, t);
		}

		if (priva && privb) {
			/* Compute t = 1/(rc) mod q, so d/t = x/(rcu) mod q.  */
			bn_mul(t, r, c);
			bn_mod(t, t, n);
		} else {
			/* Compute t = 1/r mod q. */			
			bn_copy(t, r);
		}
		if (priva || privb) {
			bn_mod_inv(t, t, n);
			bn_mul(d, d, t);
			bn_mod(d, d, n);
		}

		if (!priva && !privb) {
			g1_copy(a1, p);
			g2_copy(b1, q);
			g1_sub(a2, u, p);
			g1_mul(a2, a2, d);
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
		bn_free(t);
		g1_free(u);
		g2_free(v);
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
		} else if (!priva && !privb) {
			g1_copy(_p[0], a1);
			g1_copy(_p[1], a2);
			g2_copy(_q[0], b2);
			g2_get_gen(_q[1]);
		} else {
			g1_copy(_p[0], a1);
			g1_copy(_p[1], a2);
			g2_copy(_q[0], b2);
			g2_mul_gen(_q[1], d);
		}
		pc_map_sim(g[1], _p, _q, 2);
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
			result = 0;
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
	g1_t t, u;
	gt_t v, w, alpha;
	int result = 1;

	g1_null(t);
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

		g1_set_infty(u);
		gt_set_unity(v);
		for (size_t i = 0; i < m; i++) {
			g1_mul(t, p[i], l[i]);
			g1_add(u, u, t);
			gt_mul(v, v, bs[i]);
		}
		g1_norm(u, u);
		pc_map(alpha, u, r);
		for (size_t i = 0; i < m; i++) {
			gt_exp(w, as[i], b[i]);
			gt_mul(alpha, alpha, w);
			gt_copy(rs[i], as[i]);
		}

		if (!result || (gt_cmp(v, alpha) != RLC_EQ)) {
			result = 0;
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(rs[i]);
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		g1_free(t);
		g1_free(u);
		gt_free(v);
		gt_free(w);
		gt_free(alpha);
	}

	return result;
}

int cp_ambat_gen(bn_t r, g1_t u, g2_t v, g1_t w, gt_t e) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		pc_get_ord(n);
		bn_rand_mod(r, n);
		bn_rand_mod(t, n);

		g1_mul_gen(u, r);
		g2_mul_gen(v, t);
		g1_rand(w);

		bn_mul(t, t, r);
		bn_mod(t, t, n);
		gt_get_gen(e);
		gt_exp(e, e, t);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
		bn_free(t);
	}
	return result;
}

int cp_ambat_ask(bn_t *ls, g1_t *rs, g1_t a, g2_t b, g2_t d, const bn_t r,
		const g1_t u, const g2_t v, const g1_t w, const gt_t e, const g1_t *p,
		const g2_t *q, size_t m) {
	bn_t n;
	int result = RLC_OK;
	size_t eps = RAND_DIST/2 + BND_STORE - 1;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		g2_copy(d, q[0]);
		for (size_t j = 1; j < m; j++) {
			g2_add(d, d, q[j]);
		}
		g2_norm(d, d);

		for (size_t i = 0; i < m; i++) {
			if (ep_curve_is_pairf() == EP_BN || ep_curve_embed() <= 2) {
				bn_rand(ls[i], RLC_POS, eps);
			} else {
				bn_rand_frb(ls[i], &(core_get()->par), n, eps);
			}
			g1_mul(rs[i], p[i], ls[i]);
			g1_add(rs[i], rs[i], w);
		}
		g1_norm_sim(rs, rs, m);

		g1_sub(a, u, w);
		g1_norm(a, a);

		g2_sub(b, v, d);
		g2_norm(b, b);
		g2_mul(b, b, r);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_ambat_ans(gt_t *gs, const g1_t *rs, const g1_t a, const g2_t b,
		const g2_t d, const g1_t *p, const g2_t *q, size_t m) {
	g1_t ps[2];
	g2_t qs[2];
	gt_t g;
	int result = RLC_OK;

	g1_null(ps[0]);
	g1_null(ps[1]);
	g2_null(qs[0]);
	g2_null(qs[1]);
	gt_null(g);

	RLC_TRY {
		g1_new(ps[0]);
		g1_new(ps[1]);
		g2_new(qs[0]);
		g2_new(qs[1]);
		gt_new(g);

		for (size_t i = 0; i < m; i++) {
			pc_map(gs[i], p[i], q[i]);
		}

		g1_copy(ps[0], a);
		g2_copy(qs[0], d);
		g1_get_gen(ps[1]);
		g2_copy(qs[1], b);
		
		pc_map_sim(gs[m], ps, qs, 2);
		pc_map_sim(g, rs, q, m);
		gt_mul(gs[m], gs[m], g);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		g1_free(ps[0]);
		g1_free(ps[1]);
		g2_free(qs[0]);
		g2_free(qs[1]);
		gt_free(g);
	}
	return result;
}

int cp_ambat_ver(gt_t *gs, const bn_t *ls, const gt_t e, size_t m) {
	int result = 1;
	gt_t t, u;

	gt_null(t);
	gt_null(u);

	RLC_TRY {
		gt_new(t);
		gt_new(u);

		gt_set_unity(t);
		for (size_t i = 0; i < m; i++) {
			gt_exp(u, gs[i], ls[i]);
			gt_mul(t, t, u);
		}
		gt_mul(t, t, e);
		result &= (gt_cmp(t, gs[m]) == RLC_EQ);
		result &= gt_is_valid(gs[m]);

		if (!result) {
			result = 0;
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
