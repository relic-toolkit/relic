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

int cp_cades_ask(bn_t t, g1_t t1, g2_t t2, gt_t e, const g1_t p,
		const g2_t q) {
	bn_t x1, x2, n;
	g1_t a1;
	g2_t a2;
	int result = RLC_OK;

	bn_null(n);
	bn_null(x1);
	bn_null(x2);
	g1_null(a1);
	g2_null(a2);

	RLC_TRY {
		bn_new(n);
		bn_new(x1);
		bn_new(x2);
		g1_new(a1);
		g2_new(a2);

		pc_get_ord(n);
		bn_rand_mod(x1, n);
		bn_rand_mod(x2, n);
		g1_mul_gen(a1, x1);
		g2_mul_gen(a2, x2);

		bn_mul(t, x1, x2);
		bn_mod(t, t, n);
		gt_exp_gen(e, t);
		bn_mod_inv(t, t, n);

		bn_mod_inv(x2, x2, n);
		bn_mod_inv(x1, x1, n);
		g1_mul(t1, p, x2);
		g1_add(t1, t1, a1);
		g1_norm(t1, t1);
		g2_mul(t2, q, x1);
		g2_add(t2, t2, a2);
		g2_norm(t2, t2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(x1);
		bn_free(x2);
		g1_free(a1);
		g2_free(a2);
	}
	return result;
}

int cp_cades_ans(gt_t g[2], const g1_t t1, const g2_t t2, const g1_t p,
		const g2_t q) {
	g1_t ps[3];
	g2_t qs[3];
	int result = RLC_OK;

	RLC_TRY {
		for (size_t i = 0; i < 3; i++) {
			g1_null(ps[i]);
			g2_null(qs[i]);
			g1_new(ps[i]);
			g2_new(qs[i]);
		}

		g1_copy(ps[0], t1);
		g1_get_gen(ps[1]);
		g1_neg(ps[2], p);
		g2_copy(qs[0], t2);
		g2_neg(qs[1], q);
		g2_get_gen(qs[2]);
		pc_map_sim(g[0], ps, qs, 3);

		pc_map(g[1], p, q);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		for (size_t i = 0; i < 3; i++) {
			g1_free(ps[i]);
			g2_free(qs[i]);
		}
	}
	return result;
}

int cp_cades_ver(gt_t r, const gt_t g[2], const bn_t t, const gt_t e) {
	int result = 1;

	result &= gt_is_valid(g[1]);
	gt_exp(r, g[1], t);
	gt_mul(r, r, e);
	result &= (gt_cmp(g[0], r) == RLC_EQ);

	gt_copy(r, g[1]);

	if (!result) {
		gt_set_unity(r);
	}
	return result;
}

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

		result &= (gt_cmp(t, g[1]) == RLC_EQ);
		gt_copy(r, g[0]);
		if (!result) {
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

		result &= (gt_cmp(t, g[3]) == RLC_EQ);
		if (!result) {
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

		result &= (gt_cmp(t, e) == RLC_EQ);
		if (!result) {
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

		result &= (gt_cmp(t, g[2]) == RLC_EQ);
		if (!result) {
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
