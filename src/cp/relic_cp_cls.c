/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2018 RELIC Authors
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
 * Implementation of the Camenisch-Lysyanskaya signature protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Reads a message as an integer modulo n, accepting only messages that are not
 * longer than n and smaller than n, so that each integer has a single encoding.
 *
 * @param[out] m			- the integer, or zero if the message is rejected.
 * @param[in] msg			- the message.
 * @param[in] len			- the length of the message in bytes.
 * @param[in] n				- the modulus.
 * @return 1 if the message is accepted, 0 otherwise.
 */
static int cls_read(bn_t m, const uint8_t *msg, size_t len, const bn_t n) {
	bn_zero(m);
	if (len > bn_size_bin(n)) {
		return 0;
	}
	bn_read_bin(m, msg, len);
	if (bn_cmp(m, n) != RLC_LT) {
		bn_zero(m);
		return 0;
	}
	return 1;
}

/**
 * Checks that e(p, q) = e(s, g), or that e(p, q)e(-s, g) = 1, where g is the
 * generator of G_2.
 *
 * @param[in] p				- the G_1 element of the first pairing.
 * @param[in] q				- the G_2 element of the first pairing.
 * @param[in] s				- the G_1 element of the second pairing.
 * @return 1 if the pairings are equal, 0 otherwise.
 */
static int cls_pair(const g1_t p, const g2_t q, const g1_t s) {
	g1_t t[1], u;
	g2_t r[1];
	gt_t e;
	int result = 0;

	g1_null(t[0]);
	g1_null(u);
	g2_null(r[0]);
	gt_null(e);

	RLC_TRY {
		g1_new(t[0]);
		g1_new(u);
		g2_new(r[0]);
		gt_new(e);

		g1_copy(t[0], p);
		g1_neg(u, s);
		g2_copy(r[0], q);
		pc_map_sim_gen(e, t, r, 1, u);
		result = gt_is_unity(e);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(t[0]);
		g1_free(u);
		g2_free(r[0]);
		gt_free(e);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_cls_gen(bn_t r, bn_t s, g2_t x, g2_t y) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(r, n);
		bn_rand_mod(s, n);
		g2_mul_gen(x, r);
		g2_mul_gen(y, s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_cls_sig(g1_t a, g1_t b, g1_t c, const uint8_t *msg, size_t len,
		const bn_t r, const bn_t s) {
	bn_t m, n;
	int result = RLC_OK;

	bn_null(m);
	bn_null(n);

	RLC_TRY {
		bn_new(m);
		bn_new(n);

		g1_rand(a);
		pc_get_ord(n);
		bn_mul(m, r, s);
		bn_mod(m, m, n);
		g1_mul_sec(b, a, s);
		if (!cls_read(m, msg, len, n)) {
			RLC_THROW(ERR_NO_VALID);
		}
		bn_mul(m, m, s);
		bn_mod(m, m, n);
		bn_mul(m, m, r);
		bn_mod(m, m, n);
		bn_add(m, m, r);
		bn_mod(m, m, n);
		g1_mul_sec(c, a, m);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(n);
	}
	return result;
}

int cp_cls_ver(const g1_t a, const g1_t b, const g1_t c, const uint8_t *msg,
		size_t len, const g2_t x, const g2_t y) {
	g1_t p;
	bn_t m, n;
	int result = 0;

	g1_null(p);
	bn_null(m);
	bn_null(n);

	RLC_TRY {
		g1_new(p);
		bn_new(m);
		bn_new(n);

		pc_get_ord(n);
		if (g1_is_valid(a) && g1_is_valid(b) && g1_is_valid(c) &&
				cls_read(m, msg, len, n)) {
			g1_mul(p, b, m);
			g1_add(p, p, a);
			g1_norm(p, p);
			/* Check that e(a, Y) = e(b, g) and e(a + [m]b, X) = e(c, g). */
			result = cls_pair(a, y, b) && cls_pair(p, x, c);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(p);
		bn_free(m);
		bn_free(n);
	}
	return result;
}

int cp_cli_gen(bn_t t, bn_t u, bn_t v, g2_t x, g2_t y, g2_t z) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(t, n);
		bn_rand_mod(u, n);
		bn_rand_mod(v, n);
		g2_mul_gen(x, t);
		g2_mul_gen(y, u);
		g2_mul_gen(z, v);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_cli_sig(g1_t a, g1_t A, g1_t b, g1_t B, g1_t c, const uint8_t *msg,
		size_t len, const bn_t r, const bn_t t, const bn_t u, const bn_t v) {
	bn_t m, n;
	int result = RLC_OK;

	bn_null(m);
	bn_null(n);

	RLC_TRY {
		bn_new(m);
		bn_new(n);

		/* Choose random a in G1. */
		g1_rand(a);
		/* Compute A = a^z, B = A^y. */
		g1_mul_sec(A, a, v);
		g1_mul_sec(b, a, u);
		g1_mul_sec(B, A, u);
		/* Compute c = A^(xyr) = B^{xr}. */
		pc_get_ord(n);
		bn_mul(m, t, r);
		bn_mod(m, m, n);
		g1_mul_sec(b, B, m);
		/* Compute c = a^{x+xym}A^(xyr). */
		if (!cls_read(m, msg, len, n)) {
			RLC_THROW(ERR_NO_VALID);
		}
		bn_mul(m, m, t);
		bn_mod(m, m, n);
		bn_mul(m, m, u);
		bn_mod(m, m, n);
		bn_add(m, m, t);
		bn_mod(m, m, n);
		g1_mul_sec(c, a, m);
		g1_add(c, c, b);
		g1_norm(c, c);
		/* Compute b = a^y. */
		g1_mul_sec(b, a, u);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(n);
	}
	return result;
}

int cp_cli_ver(g1_t a, g1_t A, g1_t b, g1_t B, g1_t c, const uint8_t *msg,
		size_t len, const bn_t r, const g2_t x, const g2_t y, const g2_t z) {
	g1_t p;
	bn_t m, n;
	int result = 0;

	g1_null(p);
	bn_null(m);
	bn_null(n);

	RLC_TRY {
		g1_new(p);
		bn_new(m);
		bn_new(n);

		pc_get_ord(n);
		if (g1_is_valid(a) && g1_is_valid(A) && g1_is_valid(b) &&
				g1_is_valid(B) && g1_is_valid(c) && cls_read(m, msg, len, n)) {
			g1_mul_sim(p, b, m, B, r);
			g1_add(p, p, a);
			g1_norm(p, p);
			/* Check that e(a, Z) = e(A, g), e(a, Y) = e(b, g), e(A, Y) = e(B, g)
			 * and e(a + [m]b + [r]B, X) = e(c, g). */
			result = cls_pair(a, z, A) && cls_pair(a, y, b) &&
					cls_pair(A, y, B) && cls_pair(p, x, c);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(p);
		bn_free(m);
		bn_free(n);
	}
	return result;
}

int cp_clb_gen(bn_t t, bn_t u, bn_t v[], g2_t x, g2_t y, g2_t z[], size_t l) {
	bn_t n;
	int result = RLC_OK;
	size_t i;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(t, n);
		bn_rand_mod(u, n);
		g2_mul_gen(x, t);
		g2_mul_gen(y, u);
		for (i = 1; i < l; i++) {
			bn_rand_mod(v[i - 1], n);
			g2_mul_gen(z[i - 1], v[i - 1]);
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

int cp_clb_sig(g1_t a, g1_t A[], g1_t b, g1_t B[], g1_t c, const uint8_t *ms[],
		const size_t ls[], const bn_t t, const bn_t u, const bn_t v[],
		size_t l) {
	bn_t m, n;
	int result = RLC_OK;
	size_t i;

	bn_null(m);
	bn_null(n);

	RLC_TRY {
		bn_new(m);
		bn_new(n);

		/* Choose random a in G1. */
		g1_rand(a);
		/* Compute A_i = a^z_i, B_i = A_i^y. */
		for (i = 1; i < l; i++) {
			g1_mul_sec(A[i - 1], a, v[i - 1]);
			g1_mul_sec(B[i - 1], A[i - 1], u);
		}
		/* Compute c = a^(x+xym_0)\prod A_i^(xym_i) = B_i^(xm_i). */
		pc_get_ord(n);
		if (!cls_read(m, ms[0], ls[0], n)) {
			RLC_THROW(ERR_NO_VALID);
		}
		bn_mul(m, m, t);
		bn_mod(m, m, n);
		bn_mul(m, m, u);
		bn_add(m, m, t);
		bn_mod(m, m, n);
		g1_mul_sec(c, a, m);
		/* This can be made faster with more interleaving. */
		for (i = 1; i < l; i++) {
			if (!cls_read(m, ms[i], ls[i], n)) {
				RLC_THROW(ERR_NO_VALID);
			}
			bn_mul(m, m, t);
			bn_mod(m, m, n);
			g1_mul_sec(b, B[i - 1], m);
			g1_add(c, c, b);
		}
		g1_norm(c, c);
		/* Compute b = a^y. */
		g1_mul_sec(b, a, u);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(n);
	}
	return result;
}

int cp_clb_ver(const g1_t a, const g1_t A[], const g1_t b, const g1_t B[],
		const g1_t c, const uint8_t *ms[], const size_t ls[], const g2_t x,
		const g2_t y, const g2_t z[], size_t l) {
	g1_t p, t;
	bn_t m, n;
	int result = 0;
	size_t i;

	g1_null(p);
	g1_null(t);
	bn_null(m);
	bn_null(n);

	RLC_TRY {
		g1_new(p);
		g1_new(t);
		bn_new(m);
		bn_new(n);

		pc_get_ord(n);
		/* Check that e(a, Y) = e(b, g). */
		result = g1_is_valid(a) && g1_is_valid(b) && g1_is_valid(c) &&
				cls_read(m, ms[0], ls[0], n) && cls_pair(a, y, b);
		g1_mul(p, b, m);
		g1_add(p, p, a);
		for (i = 1; result && i < l; i++) {
			/* Check that e(a, Z_i) = e(A_i, g) and e(A_i, Y) = e(B_i, g). */
			result = g1_is_valid(A[i - 1]) && g1_is_valid(B[i - 1]) &&
					cls_read(m, ms[i], ls[i], n) &&
					cls_pair(a, z[i - 1], A[i - 1]) &&
					cls_pair(A[i - 1], y, B[i - 1]);
			g1_mul(t, B[i - 1], m);
			g1_add(p, p, t);
		}
		if (result) {
			/* Check that e(a + [m_0]b + \sum [m_i]B_i, X) = e(c, g). */
			g1_norm(p, p);
			result = cls_pair(p, x, c);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(p);
		g1_free(t);
		bn_free(m);
		bn_free(n);
	}
	return result;
}
