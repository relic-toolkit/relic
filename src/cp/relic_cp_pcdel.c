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
		int first, int priva, int privb) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		pc_get_ord(n);
		if (first) {
			/* Generate random U1, U2, x, c. */
			bn_rand_mod(x, n);
			bn_rand_mod(t, n);
			bn_mod_inv(d, t, n);
			bn_mul(d, d, x);
			bn_mod(d, d, n);
			g1_mul_gen(u, t);
			g2_mul_gen(v, d);
			/* Compute gamma = e(U1, U2). */
#if FP_PRIME < 1536
			gt_get_gen(e);
			gt_exp(e, e, x);
#else
			pc_map(e, u, v);
#endif
		} else {
			bn_rand_mod(t, n);
			/* d = x/u here. */
			bn_mod_inv(d, t, n);
			bn_mul(d, d, x);
			bn_mod(d, d, n);
			g1_mul_gen(u, t);
			g2_mul_gen(v, d);
		}

		if (ep_curve_is_pairf() == EP_BN) {
			bn_rand(c, RLC_POS, RAND_DIST);
		} else {
			bn_rand_frb(c, &(core_get()->par), n, RAND_DIST/2 + BND_STORE);
		}

		bn_rand_mod(r, n);
		if (priva && !privb) {
			/* In this case, make d = u. */
			bn_copy(d, t);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(t);
	}
	return result;
}

int cp_amore_ask(bn_t d, g1_t a1, g2_t b1, g1_t a2, g2_t b2, const bn_t c,
		const bn_t r, const g1_t p, const g2_t q, const g1_t u, const g2_t v,
		int priva, int privb) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		pc_get_ord(n);
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
		} else if (!priva && !privb) {
			g1_copy(_p[0], a1);
			g1_copy(_p[1], a2);
			g2_copy(_q[0], b2);
			g2_get_gen(_q[1]);
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

int cp_mvbat_gen(bn_t r, g1_t *x, size_t m) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(r, n);
		for (size_t i = 0; i < m; i++) {
			g1_rand(x[i]);
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_mvbat_ask(g1_t p0, g1_t *ps, g2_t q0, gt_t *e, const bn_t r,
		const g1_t *p, const g2_t q, const g1_t *x, size_t m) {
	bn_t prime, n;
	g1_t t, u;
	int result = RLC_OK;

	bn_null(n);
	bn_null(prime);
	g1_null(t);
	g1_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(prime);
		g1_new(t);
		g1_new(u);

		pc_get_ord(n);
		dv_copy(prime->dp, fp_prime_get(), RLC_FP_DIGS);
		prime->sign = RLC_POS;
		prime->used = RLC_FP_DIGS;
		bn_mod(prime, prime, n);

		g1_rand(p0);
		bn_mod_inv(n, r, n);
		g2_mul(q0, q, n);

		pc_map(e[0], p0, q0);
		for (size_t i = 0; i < m; i++) {
			pc_map(e[i + 1], x[i], q0);
			gt_inv(e[i + 1], e[i + 1]);
			g1_mul(t, p[i], r);
			g1_add(ps[i], x[i], t);
		}
		g1_norm_sim(ps, ps, m);

		g1_set_infty(u);
		for (size_t i = 0; i < pc_param_level() - 2; i++) {
			uint_t j = i % RLC_MIN(m, pc_param_level());
			g1_mul_dig(t, ps[j], j);
			g1_add(u, u, t);
		}
		g1_norm(u, u);
		g1_mul(u, u, prime);
		g1_add(p0, p0, u);
		g1_norm(p0, p0);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
		bn_free(prime);
		g1_free(t);
		g1_free(u);
	}

	return result;
}

int cp_mvbat_ans(gt_t *as, const g1_t p0, const g1_t *ps, const g2_t q0,
		size_t m) {
	pc_map(as[0], p0, q0);
	for (size_t i = 0; i < m; i++) {
		pc_map(as[i + 1], ps[i], q0);
	}

	return RLC_OK;
}

int cp_mvbat_ver(gt_t *rs, const gt_t *as, const gt_t *e, size_t m) {
	gt_t t, alpha;
	int result = 1;

	gt_null(t);
	gt_null(alpha);

	RLC_TRY {
		gt_new(t);
		gt_new(alpha);

		for (size_t i = 0; i <= m; i++) {
			result &= gt_is_valid(as[i]);
		}

		gt_copy(alpha, e[0]);
		for (size_t i = 1; i <= pc_param_level() - 2; i++) {
			uint_t j = i % RLC_MIN(m, pc_param_level());
			gt_exp_dig(t, as[j + 1], j);
			gt_frb(t, t, 1);
			gt_mul(alpha, alpha, t);
		}
		for (size_t i = 0; i < m; i++) {
			gt_mul(rs[i], as[i + 1], e[i + 1]);
		}

		if (!result || (gt_cmp(alpha, as[0]) != RLC_EQ)) {
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(rs[i]);
			}
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		gt_free(t);
		gt_free(alpha);
	}

	return result;
}


int cp_ambat_gen(bn_t r, g1_t u, g2_t v, gt_t e) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		pc_get_ord(n);
		bn_rand_mod(r, n);
		g2_mul_gen(v, r);

		bn_rand_mod(t, n);
		g1_mul_gen(u, t);

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

int cp_ambat_ask(bn_t *ls, g2_t *rs, g1_t a, g2_t b, const bn_t r, 
		const g1_t *p, const g2_t q, const g1_t u, const g2_t v, const gt_t e,
		uint_t longc, size_t m) {
	bn_t n, *t = RLC_ALLOCA(bn_t, m);
	size_t eps, len;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		eps = gt_size_bin(e, 1) / g2_size_bin(q, 1);
		if (longc) {
			len = 2 * (pc_param_level() - eps);
		} else {
			len = RAND_DIST/2 + BND_STORE + eps;
		}

		for (size_t i = 0; i < m; i++) {
			bn_null(t[i]);
			bn_new(t[i]);

			if (ep_curve_is_pairf() == EP_BN) {
				bn_rand(ls[i], RLC_POS, len);
			} else {
				bn_rand_frb(ls[i], &(core_get()->par), n, len);
			}
		}

		g1_set_infty(a);
		bn_mod_inv_sim(t, ls, n, m);
		for (size_t i = 0; i < m; i++) {
			g1_add(a, a, p[i]);
			g2_mul(rs[i], q, t[i]);
		}

		g1_sub(a, u, a);
		g1_norm(a, a);
		g1_mul(a, a, r);
		g2_sub(b, v, q);
		g2_norm(b, b);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
		for (size_t i = 0; i < m; i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
	}

	return result;
}

int cp_ambat_ans(gt_t *gs, const g2_t *rs, const g1_t a, const g2_t b, 
		const g1_t *p, size_t m) {
	g1_t ps[2];
	g2_t qs[2];
	int result = RLC_OK;

	g1_null(ps[0]);
	g1_null(ps[1]);
	g2_null(qs[0]);
	g2_null(qs[1]);

	RLC_TRY {
		g1_new(ps[0]);
		g1_new(ps[1]);
		g2_new(qs[0]);
		g2_new(qs[1]);

		g1_set_infty(ps[0]);
		for (size_t i = 0; i < m; i++) {
			g1_add(ps[0], ps[0], p[i]);
			pc_map(gs[i], p[i], rs[i]);
		}
		g1_norm(ps[0], ps[0]);
		g2_copy(qs[0], b);
		g1_copy(ps[1], a);
		g2_get_gen(qs[1]);
		
		pc_map_sim(gs[m], ps, qs, 2);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		g1_free(ps[0]);
		g1_free(ps[1]);
		g2_free(qs[0]);
		g2_free(qs[1]);
	}

	return result;
}

int cp_ambat_ver(gt_t *es, const gt_t *gs, const bn_t *ls, const gt_t e,
		size_t m) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);
		gt_set_unity(t);
		for (size_t i = 0; i < m; i++) {
			result &= gt_is_valid(gs[i]);
			gt_exp(es[i], gs[i], ls[i]);
			gt_mul(t, t, es[i]);
		}
		gt_mul(t, t, gs[m]);
		if (!result || gt_cmp(e, t) != RLC_EQ) {
			for (size_t i = 0; i < m; i++) {
				gt_set_unity(es[i]);
			}
			result = 0;
		}
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(t);
	}
	return result;
}

int cp_amprd_gen(bn_t *ls, g2_t *rs, g2_t r, bn_t c, g1_t u, g2_t v, gt_t e, 
		size_t l, size_t m) {
	bn_t n, xi;
	int result = RLC_OK;
	size_t i, j, eps, bound = RLC_MIN(l * m, pc_param_level() - RAND_DIST);
	int8_t naf[RLC_FP_BITS + 1];

	bn_null(n);
	bn_null(xi);

	RLC_TRY {
		bn_new(n);
		bn_new(xi);

		pc_get_ord(n);
		g2_rand(r);

		cp_ambat_gen(c, u, v, e);
		eps = gt_size_bin(e, 1) / g2_size_bin(rs[0], 1);

		for (i = 0; i < bound; i++) {
			if (ep_curve_is_pairf() == EP_BN) {
				bn_rand(ls[i], RLC_POS, eps + BND_STORE - RAND_DIST/2);
			} else {
				bn_rand_frb(ls[i], &(core_get()->par), n, eps + BND_STORE - RAND_DIST/2);
			}
			g2_mul(rs[i], r, ls[i]);
		}
		for (; i < 0; i++) {
			/* Case 2 is too slow in practice, so move directly to case 3. */
			bn_rand(xi, RLC_POS, pc_param_level() - RAND_DIST);
			l = RLC_FP_BITS + 1;
			bn_rec_naf(naf, &l, xi, 2);
			bn_zero(ls[i + 1]);
			g2_set_infty(rs[i + 1]);
			for (j = 0; j < l; j++) {
				if (naf[j] > 0) {
					bn_add(ls[i], ls[i], ls[j]);
					g2_add(rs[i], rs[i], rs[j]);
				}
				if (naf[j] < 0) {
					bn_sub(ls[i], ls[i], ls[j]);
					g2_sub(rs[i], rs[i], rs[j]);
				}
			}
			bn_mod(ls[i], ls[i], n);
		}
		for (; i < l * m; i++) {
			bn_zero(ls[i]);
			g2_set_infty(rs[i]);
			for (j = 0; j < bound/3; j++) {
				size_t index;
				rand_bytes((unsigned char *)&index, sizeof(size_t));
				index = index % i;
				bn_add(ls[i], ls[i], ls[index]);
				g2_add(rs[i], rs[i], rs[index]);
			}
			bn_mod(ls[i], ls[i], n);
		}
		if (l * m != bound) {
			g2_norm_sim(rs + bound + 1,  rs + bound + 1, l * m - bound - 1);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(xi);
	}
	return result;
}

int cp_amprd_ask(bn_t *ks, g2_t *ds, bn_t *cs, g1_t *fs, g2_t *bs, g1_t a,
		g2_t b, const bn_t *ls, const g2_t *rs, const g2_t r, const bn_t c,
		const g1_t *p, const g2_t *q, const g1_t u, const g2_t v, const gt_t e,
		size_t l, size_t m) {
	bn_t n;
	g1_t t;
	int result = RLC_OK;

	bn_null(n);
	g1_null(t);

	RLC_TRY {
		bn_new(n);
		g1_new(t);

		pc_get_ord(n);
		for (size_t j = 0; j < l; j++) {
			if (ep_curve_is_pairf() == EP_BN) {
				bn_rand(ks[j], RLC_POS, RAND_DIST);
			} else {
				bn_rand_frb(ks[j], &(core_get()->par), n, RAND_DIST);
			}
			g1_set_infty(fs[j]);
			for (size_t i = 0; i < m; i++) {
				g1_mul(t, p[j * m + i], ls[j * m + i]);
				g1_add(fs[j], fs[j], t);
				g2_mul(ds[j * m + i], q[j * m + i], ks[j]);
				g2_add(ds[j * m + i], ds[j * m + i], rs[j * m + i]);
			}
		}
		g2_norm_sim(ds, ds, l * m);
		g1_norm_sim(fs, fs, l);
		cp_ambat_ask(cs, bs, a, b, c, fs, r, u, v, e, 1, l);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		bn_free(n);
		g1_free(t);
	}

	return result;
}

int cp_amprd_ans(gt_t *gs, const g2_t *ds, const g1_t *fs, const g2_t *bs,
		const g1_t a, const g2_t b, const g1_t *p, const g2_t *q,
		size_t l, size_t m) {
	cp_ambat_ans(gs, bs, a, b, fs, l);
	for (size_t i = 0; i < l; i++) {
		pc_map_sim(gs[l+i*2+1], p + i * m, ds + i * m, m);
		pc_map_sim(gs[l+i*2+2], p + i * m, q + i * m, m);		
	}
	return RLC_OK;
}

int cp_amprd_ver(gt_t *ts, const gt_t *gs, const bn_t *ks, const bn_t *cs,
		const gt_t e, size_t l) {
	int result = 1;
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		result = cp_ambat_ver(ts, gs, cs, e, l);
		for (size_t i = 0; i < l; i++) {
			result &= !gt_is_unity(ts[i]);
			result &= gt_is_valid(gs[l+i+2]);
			gt_exp(t, gs[l+i*2+2], ks[i]);
			gt_mul(t, t, ts[i]);
			gt_copy(ts[i], gs[l+i*2+2]);
			result &= (gt_cmp(gs[l+i*2+1], t) == RLC_EQ);
		}

		if (!result) {
			for (size_t i = 0; i < l; i++) {
				gt_set_unity(ts[i]);
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
