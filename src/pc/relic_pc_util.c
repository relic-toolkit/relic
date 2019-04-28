/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Internal macro to map GT_T function to basic FPX implementation. The final
 * exponentiation from the pairing is used to move element to subgroup.
 *
 * @param[out] A 				- the element to assign.
 */
#define gt_rand_imp(A)			RLC_CAT(GT_LOWER, rand)(A)

/**
 * Internal macro to power an element from G_T. Computes C = A^B.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the element to exponentiate.
 * @param[in] B				- the integer exponent.
 */
#if FP_PRIME < 1536
#define gt_exp_imp(C, A, B)		RLC_CAT(GT_LOWER, exp_cyc)(C, A, B);
#else
#define gt_exp_imp(C, A, B)		RLC_CAT(GT_LOWER, exp_uni)(C, A, B);
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void gt_rand(gt_t a) {
	gt_rand_imp(a);
#if FP_PRIME < 1536
	pp_exp_k12(a, a);
#else
	pp_exp_k2(a, a);
#endif
}

void gt_get_gen(gt_t g) {
	g1_t g1;
	g2_t g2;

	g1_null(g1);
	g2_null(g2);

	TRY {
		g1_new(g1);
		g2_new(g2);

		g1_get_gen(g1);
		g2_get_gen(g2);

		pc_map(g, g1, g2);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		g1_free(g1);
		g2_free(g2);
	}
}

void gt_exp(gt_t c, gt_t a, bn_t b) {
	bn_t n;

	bn_null(n);

	TRY {
		bn_new(n);

		gt_get_ord(n);
		bn_mod(n, b, n);
		gt_exp_imp(c, a, n);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
	}
}

int g1_is_valid(g1_t a) {
	bn_t n;
	g1_t u;
	int r;

	bn_null(n);
	g1_null(u);

	TRY {
		bn_new(n);
		g1_new(u);

		ep_curve_get_cof(n);
		if (bn_cmp_dig(n, 1) == RLC_EQ) {
			/* If curve has prime order, simpler to check if point on curve. */
			return ep_is_valid(a);
		} else {
			/* Otherwise, check order explicitly. */
			g1_get_ord(n);
			/* Multiply by (n-1)/2 to prevent weird interactions with recoding. */
			bn_sub_dig(n, n, 1);
			bn_hlv(n, n);
			g1_mul(u, a, n);
			g1_dbl(u, u);
			g1_neg(u, u);
			r = (g1_cmp(u, a) == RLC_EQ);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		g1_free(u);
	}

	return r;
}

int g2_is_valid(g2_t a) {
	bn_t p, n;
	g2_t u, v;
	int r;

	bn_null(n);
	bn_null(p);
	g2_null(u);
	g2_null(v);

	TRY {
		bn_new(n);
		bn_new(p);
		g2_new(u);
		g2_new(v);

		g2_get_ord(n);
		ep_curve_get_cof(p);
		bn_mul(n, n, p);
		dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
		p->used = RLC_FP_DIGS;
		p->sign = RLC_POS;
		/* Compute trace t = p - n + 1. */
		bn_sub(n, p, n);
		bn_add_dig(n, n, 1);
		/* Compute u = a^t. */
		g2_mul(u, a, n);
		/* Compute v = a^(p + 1). */
		ep2_frb(v, a, 1);
		g2_add(v, v, a);
		/* Check if a^(p + 1) = a^t. */
		r = (g2_cmp(u, v) == RLC_EQ);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u);
		g2_free(v);
	}

	return r;
}

int gt_is_valid(gt_t a) {
	bn_t p, n;
	gt_t u, v;
	int r;

	bn_null(n);
	bn_null(p);
	gt_null(u);
	gt_null(v);

	TRY {
		bn_new(n);
		bn_new(p);
		gt_new(u);
		gt_new(v);

		gt_get_ord(n);
		dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
		p->used = RLC_FP_DIGS;
		p->sign = RLC_POS;
		/* Compute trace t = p - n + 1. */
		bn_sub(n, p, n);
		bn_add_dig(n, n, 1);
		/* Compute u = a^t. */
		gt_exp(u, a, n);
		/* Compute v = a^(p + 1). */
		fp12_frb(v, a, 1);
		gt_mul(v, v, a);
		/* Check if a^(p + 1) = a^t. */
		r = (gt_cmp(u, v) == RLC_EQ);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(p);
		bn_free(n);
		gt_free(u);
		gt_free(v);
	}

	return r;
}
