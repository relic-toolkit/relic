/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of exponentiation in pairing groups.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Apply Frobenius endomorphism in different pairing-friendly curve families.
 *
 * @param[in] c			- the result.
 * @param[in] a			- the extension field element to exponentiate.
 */
static void gt_psi(gt_t c, const gt_t a) {
	gt_t b;

	gt_null(b);

	RLC_TRY {
		gt_new(b);

		switch (ep_curve_is_pairf()) {
			case EP_K16:
				/* u = (2*p^5 - p) mod r */
				gt_frb(b, a, 1);
				gt_frb(c, b, 4);
				gt_sqr(c, c);
				gt_inv(b, b);
				gt_mul(c, c, b);
				break;
			case EP_N16:
				/* u = -p^5 mod r */
				gt_frb(c, a, 5);
				gt_inv(c, c);
				break;
			case EP_SG18:
				/* -3*u = (2*p^2 - p^5) mod r */
				gt_frb(b, a, 5);
				gt_inv(b, b);
				gt_frb(c, a, 2);
				gt_sqr(c, c);
				gt_mul(c, c, b);
				break;
			case EP_K18:
				/* For KSS18, we have that x = p^4 - 3*p = (p^3 - 3)p mod n. */
				gt_sqr(b, a);
				gt_mul(b, b, a);
				gt_frb(c, a, 3);
				gt_inv(b, b);
				gt_mul(c, c, b);
				gt_frb(c, c, 1);
				break;
			case EP_FM18:
				/* For FM18, we have that u = (p^4-p) mod r. */
				gt_frb(b, a, 3);
				gt_inv(b, b);
				gt_mul(c, a, b);
				gt_frb(c, c, 1);
				gt_inv(c, c);
				break;
			default:
				gt_frb(c, a, 1);
				break;
		}	
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(b);
	}
}

/**
 * Size of a precomputation table using the double-table comb method.
 */
#define RLC_GT_TABLE		(1 << (RLC_WIDTH - 2))

/**
 * Exponentiates an element from G_T in constant time.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] f				- the maximum Frobenius power.
 */
void gt_exp_imp(gt_t c, const gt_t a, const bn_t b, size_t f) {
	int8_t c0, n0, *reg  = RLC_ALLOCA(int8_t, f * (RLC_FP_BITS + 1));
	int8_t *e = RLC_ALLOCA(int8_t, f), *s = RLC_ALLOCA(int8_t, f);
	gt_t q, w, *t = RLC_ALLOCA(gt_t, f * RLC_GT_TABLE);
	bn_t n, u, *_b = RLC_ALLOCA(bn_t, f);
	size_t l, len, *_l = RLC_ALLOCA(size_t, f);

	if (reg == NULL || e == NULL || t == NULL || _b == NULL || _l == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_is_zero(b)) {
		RLC_FREE(reg);
		RLC_FREE(e);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		return gt_set_unity(c);
	}

	bn_null(n);
	bn_null(u);
	gt_null(q);
	gt_null(w);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		gt_new(q);
		gt_new(w);
		for (size_t i = 0; i < f; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_null(t[i * RLC_GT_TABLE + j]);
				gt_new(t[i * RLC_GT_TABLE + j]);
			}
		}

		fp_prime_get_par(u);
		if (ep_curve_is_pairf() == EP_SG18) {
			/* Compute base -3*u for the recoding below. */
			bn_dbl(n, u);
			bn_add(u, u, n);
			bn_neg(u, u);
		}
		gt_get_ord(n);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, f, _b[0], u, n, ep_curve_is_pairf() == EP_BN);

		l = 0;
		len = bn_bits(u) + (ep_curve_is_pairf() == EP_BN);
		gt_copy(t[0], a);
		for (size_t i = 0; i < f; i++) {
			s[i] = bn_sign(_b[i]);
			bn_abs(_b[i], _b[i]);
			e[i] = bn_is_even(_b[i]);
			_b[i]->dp[0] |= e[i];

			_l[i] = RLC_FP_BITS + 1;
			bn_rec_reg(reg + i * (RLC_FP_BITS + 1), &_l[i], _b[i], len, RLC_WIDTH);
			l = RLC_MAX(l, _l[i]);
			/* Apply Frobenius before flipping sign to build table. */
			if (i > 0) {
				gt_psi(t[i * RLC_GT_TABLE], t[(i - 1) * RLC_GT_TABLE]);
			}
		}

		for (size_t i = 0; i < f; i++) {
			gt_inv(q, t[i * RLC_GT_TABLE]);
			gt_copy_sec(q, t[i * RLC_GT_TABLE], s[i] == RLC_POS);
			if (RLC_WIDTH > 2) {
				gt_sqr(t[i * RLC_GT_TABLE], q);
				gt_mul(t[i * RLC_GT_TABLE + 1], t[i * RLC_GT_TABLE], q);
				for (size_t j = 2; j < RLC_GT_TABLE; j++) {
					gt_mul(t[i * RLC_GT_TABLE + j], t[i * RLC_GT_TABLE + j - 1],
							t[i * (RLC_GT_TABLE)]);
				}
			}
			gt_copy(t[i * RLC_GT_TABLE], q);
		}

		gt_set_unity(c);
		for (int j = l - 1; j >= 0; j--) {
			for (size_t i = 0; i < RLC_WIDTH - 1; i++) {
				gt_sqr(c, c);
			}

			for (size_t i = 0; i < f; i++) {
				n0 = reg[i * (RLC_FP_BITS + 1) + j];
				c0 = (n0 >> 7);
				n0 = ((n0 ^ c0) - c0) >> 1;

				for (size_t m = 0; m < RLC_GT_TABLE; m++) {
					gt_copy_sec(w, t[i * RLC_GT_TABLE + m], m == n0);
				}

				gt_inv(q, w);
				gt_copy_sec(q, w, c0 == 0);
				gt_mul(c, c, q);

			}
		}

		for (size_t i = 0; i < f; i++) {
			/* Tables are built with points already negated, so no need here. */
			gt_inv(q, t[i * RLC_GT_TABLE]);
			gt_mul(q, c, q);
			gt_copy_sec(c, q, e[i]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		gt_free(q);
		gt_free(w);
		for (size_t i = 0; i < f; i++) {
			bn_free(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_free(t[i * RLC_GT_TABLE + j]);
			}
		}
		RLC_FREE(reg);
		RLC_FREE(e);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
	}
}

/**
 * Size of a precomputation table using the double-table comb method.
 */
#define RLC_GT_TABLE		(1 << (RLC_WIDTH - 2))

/**
 * Exponentiates an element from G_T in constant time.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] f				- the maximum Frobenius power.
 */
void gt_exp_gls_imp(gt_t c, const gt_t a, const bn_t b, size_t f) {
	int8_t *naf  = RLC_ALLOCA(int8_t, f * (RLC_FP_BITS + 1));
	int8_t n0, *s = RLC_ALLOCA(int8_t, f);
	gt_t q, *t = RLC_ALLOCA(gt_t, f * RLC_GT_TABLE);
	bn_t n, u, *_b = RLC_ALLOCA(bn_t, f);
	size_t l, *_l = RLC_ALLOCA(size_t, f);

	if (naf == NULL || t == NULL || _b == NULL || _l == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_is_zero(b)) {
		RLC_FREE(naf);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		return gt_set_unity(c);
	}

	bn_null(n);
	bn_null(u);
	gt_null(q);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		gt_new(q);
		for (size_t i = 0; i < f; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_null(t[i * RLC_GT_TABLE + j]);
				gt_new(t[i * RLC_GT_TABLE + j]);
			}
		}

		fp_prime_get_par(u);
		if (ep_curve_is_pairf() == EP_SG18) {
			/* Compute base -3*u for the recoding below. */
			bn_dbl(n, u);
			bn_add(u, u, n);
			bn_neg(u, u);
		}
		gt_get_ord(n);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, f, _b[0], u, n, ep_curve_is_pairf() == EP_BN);

		l = 0;
		gt_copy(t[0], a);
		for (size_t i = 0; i < f; i++) {
			s[i] = bn_sign(_b[i]);
			bn_abs(_b[i], _b[i]);

			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf + i * (RLC_FP_BITS + 1), &_l[i], _b[i], RLC_WIDTH);
			l = RLC_MAX(l, _l[i]);
			/* Apply Frobenius before flipping sign to build table. */
			if (i > 0) {
				gt_psi(t[i * RLC_GT_TABLE], t[(i - 1) * RLC_GT_TABLE]);
			}
		}

		for (size_t i = 0; i < f; i++) {
			gt_inv(q, t[i * RLC_GT_TABLE]);
			gt_copy_sec(q, t[i * RLC_GT_TABLE], s[i] == RLC_POS);
			if (RLC_WIDTH > 2) {
				gt_sqr(t[i * RLC_GT_TABLE], q);
				gt_mul(t[i * RLC_GT_TABLE + 1], t[i * RLC_GT_TABLE], q);
				for (size_t j = 2; j < RLC_GT_TABLE; j++) {
					gt_mul(t[i * RLC_GT_TABLE + j], t[i * RLC_GT_TABLE + j - 1],
							t[i * (RLC_GT_TABLE)]);
				}
			}
			gt_copy(t[i * RLC_GT_TABLE], q);
		}

		gt_set_unity(c);
		for (int j = l - 1; j >= 0; j--) {
			gt_sqr(c, c);

			for (size_t i = 0; i < f; i++) {
				n0 = naf[i * (RLC_FP_BITS + 1) + j];
				if (n0 > 0) {
					gt_mul(c, c, t[i * RLC_GT_TABLE + n0 / 2]);
				}
				if (n0 < 0) {
					gt_inv(q, t[i * RLC_GT_TABLE - n0 / 2]);
					gt_mul(c, c, q);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		gt_free(q);
		for (size_t i = 0; i < f; i++) {
			bn_free(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_free(t[i * RLC_GT_TABLE + j]);
			}
		}
		RLC_FREE(naf);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul(g1_t c, const g1_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g1_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g1_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g1_mul_gen(g1_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul(g2_t c, const g2_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g2_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g2_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul_gen(g2_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp(gt_t c, const gt_t a, const bn_t b) {
	if (bn_bits(b) <= RLC_DIG) {
		gt_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			gt_inv(c, c);
		}
		return;
	}

#if FP_PRIME == 1536 || FP_PRIME == 544
	RLC_CAT(RLC_GT_LOWER, exp_cyc)(c, a, b);
#elif FP_PRIME < 1536
	gt_exp_gls_imp(c, a, b, ep_curve_frdim());
#else
	RLC_CAT(RLC_GT_LOWER, exp)(c, a, b);
#endif
}

void gt_exp_sec(gt_t c, const gt_t a, const bn_t b) {
	if (bn_bits(b) <= RLC_DIG) {
		gt_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			gt_inv(c, c);
		}
		return;
	}

#if FP_PRIME <= 1536
	gt_exp_imp(c, a, b, ep_curve_frdim());
#else
	RLC_CAT(RLC_GT_LOWER, exp_monty)(c, a, b);
#endif
}

void gt_exp_dig(gt_t c, const gt_t a, dig_t b) {
	gt_t s, t;
	bn_t _b;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	if (b == 0) {
		gt_set_unity(c);
		return;
	}

	gt_null(s);
	gt_null(t);
	bn_null(_b);

	RLC_TRY {
		gt_new(s);
		gt_new(t);
		bn_new(_b);

		bn_set_dig(_b, b);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, _b, 2);

		gt_inv(s, a);
		gt_copy(t, a);
		for (int i = l - 2; i >= 0; i--) {
			gt_sqr(t, t);
			u = naf[i];
			if (u > 0) {
				gt_mul(t, t, a);
			} else if (u < 0) {
				gt_mul(t, t, s);
			}
		}

		gt_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(s);
		gt_free(t);
		bn_free(_b);
	}
}

void gt_exp_sim(gt_t e, const gt_t a, const bn_t b, const gt_t c, const bn_t d) {
	bn_t n, _b, _d;
	gt_t t;

	bn_null(n);
	bn_null(_b);
	bn_null(_d);
	gt_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);
		bn_new(_d);
		gt_new(t);

		gt_get_ord(n);
		bn_mod(_b, b, n);
		bn_mod(_d, d, n);

#if FP_PRIME <= 1536
		RLC_CAT(RLC_GT_LOWER, exp_cyc_sim)(e, a, _b, c, _d);
		(void)t;
#else
		gt_exp(t, a, _b);
		gt_exp(e, c, _d);
		gt_mul(e, e, t);
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
		bn_free(_d);
		gt_free(t);
	}
}

void gt_exp_gen(gt_t c, const bn_t b) {
	gt_t g;

	gt_null(g);

	RLC_TRY {
		gt_new(g);

		gt_get_gen(g);
		gt_exp(c, g, b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		gt_free(g);
	}
}
