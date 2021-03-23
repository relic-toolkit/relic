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
/* Public definitions                                                         */
/*============================================================================*/

int cp_pcdel_gen(bn_t c, bn_t r, g1_t u1, g2_t u2, g2_t v2, gt_t e) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		/* Generate random c, U1, r, U2. */
		pc_get_ord(n);
		bn_rand(c, RLC_POS, pc_param_level());
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

int cp_pcdel_ask(g1_t v1, g2_t w2, g1_t p, g2_t q, bn_t c, bn_t r, g1_t u1, g2_t u2, g2_t v2) {
	int result = RLC_OK;

	/* Compute V1 = [r](P - U1). */
	g1_sub(v1, p, u1);
	g1_mul(v1, v1, r);
	/* Compute W2 = [c]Q + U2. */
	g2_mul(w2, q, c);
	g2_add(w2, w2, u2);

	return result;
}

int cp_pcdel_ans(gt_t g[3], g1_t p, g2_t q, g1_t v1, g2_t v2, g2_t w2) {
	int result = RLC_OK;
	pc_map(g[0], p, q);
	pc_map(g[1], p, w2);
	pc_map(g[2], v1, v2);
	return result;
}

int cp_pcdel_ver(gt_t r, gt_t g[3], bn_t c, gt_t e) {
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

int cp_amore_gen(bn_t r, g1_t u1, g2_t u2, g2_t v2, gt_t e) {
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

int cp_amore_ask(bn_t c, g1_t v1, g2_t w2, g1_t p, g2_t q, bn_t r, g1_t u1, g2_t u2, g2_t v2) {
	int result = RLC_OK;

	/* Sample random c. */
	bn_rand(c, RLC_POS, pc_param_level());
	/* Compute V1 = [r](P - U1). */
	g1_sub(v1, p, u1);
	g1_mul(v1, v1, r);
	/* Compute W2 = [c]Q + U_2. */
	g2_mul(w2, q, c);
	g2_add(w2, w2, u2);

	return result;
}

int cp_amore_ans(gt_t g[2], g1_t p, g2_t q, g1_t v1, g2_t v2, g2_t w2) {
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

int cp_amore_ver(gt_t r, gt_t g[2], bn_t c, gt_t e) {
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
