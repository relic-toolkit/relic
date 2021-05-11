/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
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
 * Implementation of pairing computation utilities.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Internal macro to map GT function to basic FPX implementation. The final
 * exponentiation from the pairing is used to move element to subgroup.
 *
 * @param[out] A 				- the element to assign.
 */
#define gt_rand_imp(A)			RLC_CAT(RLC_GT_LOWER, rand)(A)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void gt_rand(gt_t a) {
	gt_rand_imp(a);
#if FP_PRIME < 1536
#if FP_PRIME == 509
	pp_exp_k24(a, a);
#else
	pp_exp_k12(a, a);
#endif
#else
	pp_exp_k2(a, a);
#endif
}

void gt_get_gen(gt_t g) {
    gt_copy(g, core_get()->gt_g);
}

int g1_is_valid(g1_t a) {
	bn_t n;
	g1_t t, u, v;
	int r = 0;

	if (g1_is_infty(a)) {
		return 0;
	}

	bn_null(n);
	g1_null(t);
	g1_null(u);
	g1_null(v);

	RLC_TRY {
		bn_new(n);
		g1_new(t);
		g1_new(u);
		g1_new(v);

		ep_curve_get_cof(n);
		if (bn_cmp_dig(n, 1) == RLC_EQ) {
			/* If curve has prime order, simpler to check if point on curve. */
			r = g1_on_curve(a);
		} else {
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Faster Subgroup Checks for BLS12-381" by Bowe.
				 * https://eprint.iacr.org/2019/814.pdf */
				case EP_B12:
					/* Check [(z^2−1)](2\psi(P)-P-\psi^2(P)) == [3]\psi^2(P).
					 * Since \psi(P) = [\lambda]P = [z^2 - 1]P, it is the same
					 * as checking \psi(2\psi(P)-P-\psi^2(P)) == [3]\psi^2(P),
					 * or \psi((\psi-1)^2(P)) == [-3]*\psi^2(P). */
					ep_psi(v, a);
					ep_sub(t, v, a);
					ep_psi(u, v);
					ep_psi(v, t);
					ep_sub(v, v, t);
					ep_psi(t, v);
					ep_dbl(v, u);
					ep_add(u, u, v);
					ep_neg(u, u);
					r = ep_on_curve(t) && (ep_cmp(t, u) == RLC_EQ);
					break;
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					g1_copy(u, a);
					for (int i = bn_bits(n) - 2; i >= 0; i--) {
						g1_dbl(u, u);
						if (bn_get_bit(n, i)) {
							g1_add(u, u, a);
						}
					}
					g1_neg(u, u);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		g1_free(t);
		g1_free(u);
		g1_free(v);
	}

	return r;
}

int g2_is_valid(g2_t a) {
#if FP_PRIME >= 1536
	if (pc_map_is_type1()) {
		return g1_is_valid(a);
	}
#else

	if (g2_is_infty(a)) {
		return 0;
	}

	bn_t p, n;
	g2_t u, v;
	int r = 0;

	bn_null(n);
	bn_null(p);
	g2_null(u);
	g2_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		g2_new(u);
		g2_new(v);

		pc_get_ord(n);
		ep_curve_get_cof(p);

		if (bn_cmp_dig(p, 1) == RLC_EQ) {
			/* Trick for curves of prime order or subgroup-secure. */
			bn_mul(n, n, p);
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			/* Compute trace t = p - n + 1. */
			bn_sub(n, p, n);
			bn_add_dig(n, n, 1);
			/* Compute u = a^t. */
			g2_copy(u, a);
			for (int i = bn_bits(n) - 2; i >= 0; i--) {
				g2_dbl(u, u);
				if (bn_get_bit(n, i)) {
					g2_add(u, u, a);
				}
			}
			if (bn_sign(n) == RLC_NEG) {
				g2_neg(u, u);
			}
			/* Compute v = a^(p + 1). */
			g2_frb(v, a, 1);
			g2_add(v, v, a);
			/* Check if a^(p + 1) = a^t. */
			r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
		} else {
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Faster Subgroup Checks for BLS12-381" by Bowe.
				 * https://eprint.iacr.org/2019/814.pdf */
				case EP_B12:
					/* Check [z]psi^3(P) + P == \psi^2(P). */
#if FP_PRIME == 383
					/* Since p mod n = r, we can check instead that
					 * psi^4(P) + P == \psi^2(P). */
					ep2_frb(u, a, 4);
					ep2_add(u, u, a);
					ep2_frb(v, a, 2);
#else
					fp_prime_get_par(n);
					g2_copy(u, a);
					for (int i = bn_bits(n) - 2; i >= 0; i--) {
						g2_dbl(u, u);
						if (bn_get_bit(n, i)) {
							g2_add(u, u, a);
						}
					}
					if (bn_sign(n) == RLC_NEG) {
						g2_neg(u, u);
					}
					g2_frb(u, u, 3);
					g2_frb(v, a, 2);
					g2_add(u, u, a);
#endif
					r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
					break;
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					g2_copy(u, a);
					for (int i = bn_bits(n) - 2; i >= 0; i--) {
						g2_dbl(u, u);
						if (bn_get_bit(n, i)) {
							g2_add(u, u, a);
						}
					}
					g2_neg(u, u);
					r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u);
		g2_free(v);
	}

	return r;
#endif
}

int gt_is_valid(gt_t a) {
	bn_t p, n;
	gt_t u, v;
	int r;

	if (gt_is_unity(a)) {
		return 0;
	}

	bn_null(n);
	bn_null(p);
	gt_null(u);
	gt_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		gt_new(u);
		gt_new(v);

		pc_get_ord(n);
		ep_curve_get_cof(p);

		if (bn_cmp_dig(p, 1) == RLC_EQ) {
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			/* Compute trace t = p - n + 1. */
			bn_sub(n, p, n);
			bn_add_dig(n, n, 1);
			/* Compute u = a^t. */
			gt_exp(u, a, n);
			/* Compute v = a^(p + 1). */
			gt_frb(v, a, 1);
			gt_mul(v, v, a);
#if FP_PRIME == 509
			r = fp24_test_cyc(a) && (gt_cmp(u, v) == RLC_EQ);
#else
			/* Check if a^(p + 1) = a^t. */
			r = fp12_test_cyc(a) && (gt_cmp(u, v) == RLC_EQ);
#endif
		} else {
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Faster Subgroup Checks for BLS12-381" by Bowe.
				 * https://eprint.iacr.org/2019/814.pdf */
				case EP_B12:
#if FP_PRIME == 383
					/* Check [z]psi^3(P) + P == \psi^2(P), or trick from G2. */
					fp12_frb(u, a, 4);
					fp12_mul(u, u, a);
					fp12_frb(v, a, 2);
#else
					fp_prime_get_par(n);
					gt_exp(u, a, n);
					gt_frb(u, u, 3);
					gt_frb(v, a, 2);
					gt_mul(u, u, a);
#endif
#if FP_PRIME == 509
					r = fp24_test_cyc(a) && (gt_cmp(u, v) == RLC_EQ);
#else
					r = fp12_test_cyc(a) && (gt_cmp(u, v) == RLC_EQ);
#endif
					break;
				default:
					/* Common case. */
					bn_sub_dig(n, n, 1);
					gt_copy(u, a);
					for (int i = bn_bits(n) - 2; i >= 0; i--) {
						gt_sqr(u, u);
						if (bn_get_bit(n, i)) {
							gt_mul(u, u, a);
						}
					}
					gt_inv(u, u);
					r = (gt_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		gt_free(u);
		gt_free(v);
	}

	return r;
}
