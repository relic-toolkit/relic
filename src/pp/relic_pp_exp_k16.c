/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of the final exponentiation for curves of embedding degree 16.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Computes the final exponentiation of a pairing defined over a KSS curve.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
static void pp_exp_kss(fp16_t c, fp16_t a) {
	fp16_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13;
	bn_t x;

	bn_null(x);
	fp16_null(t0);
	fp16_null(t1);
	fp16_null(t2);
	fp16_null(t3);
	fp16_null(t4);
	fp16_null(t5);
	fp16_null(t6);
	fp16_null(t7);
	fp16_null(t8);
	fp16_null(t9);
	fp16_null(t10);
	fp16_null(t11);
	fp16_null(t12);
	fp16_null(t13);

	RLC_TRY {
		bn_new(x);
		fp16_new(t0);
		fp16_new(t1);
		fp16_new(t2);
		fp16_new(t3);
		fp16_new(t4);
		fp16_new(t5);
		fp16_new(t6);
		fp16_new(t7);
		fp16_new(t8);
		fp16_new(t9);
		fp16_new(t10);
		fp16_new(t11);
		fp16_new(t12);
		fp16_new(t13);

		fp_prime_get_par(x);

		/* First, compute m = f^(p^8 - 1). */
		fp16_conv_cyc(c, a);

		/* Now compute m^((p^8 + 1) / r). */
		fp16_sqr_cyc(t0, c);
		fp16_sqr_cyc(t1, t0);

		bn_add_dig(x, x, 1);
		fp16_exp_cyc(t2, c, x);
		fp16_exp_cyc(t3, t2, x);
		fp16_mul(t4, t3, t1);
		bn_sub_dig(x, x, 1);

		fp16_exp_cyc(t5, t4, x);
		fp16_sqr_cyc(t6, t4);
		fp16_sqr_cyc(t6, t6);
		fp16_mul(t6, t6, t4);
		fp16_sqr_cyc(t7, t1);
		fp16_sqr_cyc(t7, t7);
		fp16_sqr_cyc(t7, t7);
		fp16_sqr_cyc(t8, t7);
		fp16_inv_cyc(t9, t1);
		fp16_mul(t9, t7, t9);
		fp16_sqr_cyc(t10, t9);
		fp16_exp_cyc(t11, t5, x);
		fp16_exp_cyc(t12, t11, x);
		fp16_mul(t13, t12, t10);

		fp16_exp_cyc(t9, t13, x);
		fp16_inv_cyc(t2, t9);
		fp16_sqr_cyc(t2, t2);
		fp16_sqr_cyc(t10, t6);
		fp16_sqr_cyc(t10, t10);
		fp16_mul(t10, t10, t6);
		fp16_sqr_cyc(t0, t10);
		fp16_sqr_cyc(t0, t0);
		fp16_mul(t10, t10, t0);
		fp16_inv_cyc(t0, t10);
		fp16_mul(t0, t2, t0);

		fp16_sqr_cyc(t3, t0);
		fp16_sqr_cyc(t2, t2);
		fp16_sqr_cyc(t2, t2);
		fp16_mul(t2, t2, t9);
		fp16_mul(t2, t2, t3);
		fp16_exp_cyc(t3, t9, x);
		fp16_exp_cyc(t6, t3, x);
		fp16_exp_cyc(t7, t6, x);
		fp16_sqr_cyc(t10, t3);

		fp16_sqr_cyc(t9, t5);
		fp16_sqr_cyc(t9, t9);
		fp16_mul(t9, t9, t5);
		fp16_sqr_cyc(t4, t9);
		fp16_sqr_cyc(t4, t4);
		fp16_mul(t9, t4, t9);
		fp16_sqr_cyc(t4, t9);
		fp16_mul(t4, t4, t9);
		fp16_mul(t9, t4, t9);
		fp16_sqr_cyc(t10, t10);
		fp16_mul(c, t10, t4);
		fp16_inv_cyc(c, c);
		fp16_inv_cyc(t3, t3);
		fp16_mul(t3, t3, t10);
		fp16_mul(t3, t3, t9);
		fp16_sqr_cyc(t9, t11);
		fp16_sqr_cyc(t9, t9);
		fp16_mul(t11, t11, t9);
		fp16_sqr_cyc(t9, t11);
		fp16_mul(t4, t9, t6);

		fp16_sqr_cyc(t6, t6);
		fp16_sqr_cyc(t10, t9);
		fp16_sqr_cyc(t10, t10);
		fp16_mul(t9, t9, t10);
		fp16_mul(t9, t9, t11);
		fp16_mul(t9, t9, t6);
		fp16_sqr_cyc(t5, t12);
		fp16_mul(t5, t5, t12);
		fp16_sqr_cyc(t5, t5);
		fp16_sqr_cyc(t5, t5);
		fp16_sqr_cyc(t12, t5);
		fp16_mul(t5, t7, t12);
		fp16_inv_cyc(t5, t5);
		fp16_sqr_cyc(t10, t8);
		fp16_mul(t8, t8, t10);
		fp16_mul(t6, t8, t1);
		fp16_mul(t7, t5, t6);
		fp16_sqr_cyc(t8, t13);
		fp16_mul(t8, t8, t13);
		fp16_sqr_cyc(t8, t8);
		fp16_mul(t8, t8, t13);
		fp16_frb(c, c, 1);
		fp16_frb(t7, t7, 3);
		fp16_frb(t3, t3, 5);
		fp16_frb(t8, t8, 7);
		fp16_mul(t1, c, t7);
		fp16_mul(t1, t1, t3);
		fp16_mul(t1, t1, t8);
		fp16_frb(t0, t0, 2);
		fp16_frb(t4, t4, 4);
		fp16_frb(t2, t2, 6);
		fp16_mul(t2, t2, t0);

		fp16_mul(c, t2, t9);
		fp16_mul(c, c, t1);
		fp16_mul(c, c, t4);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp16_free(t0);
		fp16_free(t1);
		fp16_free(t2);
		fp16_free(t3);
		fp16_free(t4);
		fp16_free(t5);
		fp16_free(t6);
		fp16_free(t7);
		fp16_free(t8);
		fp16_free(t9);
		fp16_free(t10);
		fp16_free(t11);
		fp16_free(t12);
		fp16_free(t13);
	}
}

/**
 * Computes the final exponentiation of a pairing defined over a KSS curve.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
static void pp_exp_new(fp16_t c, fp16_t a) {
	fp16_t t0, t1, t2, t3, t4;
	bn_t x, x_;

	bn_null(x);
	bn_null(x_);
	fp16_null(t0);
	fp16_null(t1);
	fp16_null(t2);
	fp16_null(t3);
	fp16_null(t4);

	RLC_TRY {
		bn_new(x);
		bn_new(x_);
		fp16_new(t0);
		fp16_new(t1);
		fp16_new(t2);
		fp16_new(t3);
		fp16_new(t4);

		fp_prime_get_par(x);

		/* First, compute m = f^(p^8 - 1). */
		fp16_conv_cyc(c, a);

		/* Now compute m^((p^8 + 1) / r). */
		bn_abs(x_, x);

		/* Compute eq t0 = m^(u*p * (1+u*p^3)). */
		fp16_exp_cyc(t0, c, x_);
		fp16_frb(t0, t0, 3);
		fp16_inv_cyc(t1, c);
		if (bn_sign(x) == RLC_POS) {
			fp16_mul(t0, t0, c);
		} else {
			fp16_mul(t0, t0, t1);
		}
		fp16_exp_cyc(t0, t0, x_);
		fp16_frb(t0, t0, 1);

		/* Compute t2 = m^(p^5 + u*(-1 + u^2 * u*p*(1+u*p^3))). */
		fp16_exp_cyc(t2, t0, x_);
		fp16_exp_cyc(t2, t2, x_);
		fp16_mul(t2, t2, t1);
		fp16_exp_cyc(t2, t2, x_);
		if (bn_sign(x) == RLC_NEG) {
			fp16_inv_cyc(t2, t2);
		}
		fp16_frb(t3, c, 5);
		fp16_mul(t2, t2, t3);

		/* Compute t2 = m2^(((u^2 div 4)*(u^3+1)^2 +1) */
		if (bn_is_even(x_)) {
			bn_hlv(x_, x_);
			fp16_exp_cyc(t3, t2, x_);
			fp16_exp_cyc(t3, t3, x_);
			bn_dbl(x_, x_);
			if (bn_sign(x) == RLC_NEG) {
				fp16_inv_cyc(t4, t3);
			} else {
				fp16_copy(t4, t3);
			}
			fp16_exp_cyc(t3, t3, x_);
			fp16_exp_cyc(t3, t3, x_);
			fp16_exp_cyc(t3, t3, x_);
			fp16_mul(t3, t3, t4);
			if (bn_sign(x) == RLC_NEG) {
				fp16_inv_cyc(t4, t3);
			} else {
				fp16_copy(t4, t3);
			}
			fp16_exp_cyc(t3, t3, x_);
			fp16_exp_cyc(t3, t3, x_);
			fp16_exp_cyc(t3, t3, x_);
			fp16_mul(t3, t3, t4);
		} else {
			fp16_exp_cyc(t3, t2, x_);
			fp16_exp_cyc(t3, t3, x_);
			bn_sqr(x, x_);
			bn_mul(x, x, x_);
			bn_add_dig(x, x, 1);
			bn_hlv(x, x);
			bn_abs(x, x);
			fp16_exp_cyc(t3, t3, x);
			fp16_exp_cyc(t3, t3, x);
		}
		fp16_mul(t2, t2, t3);

		/* Compute t2 = (t0 * m2)^((p^2-u^2). */
		fp16_mul(t2, t2, t0);
		fp16_frb(t4, t2, 2);
		fp16_exp_cyc(t2, t2, x_);
		fp16_exp_cyc(t2, t2, x_);
		fp16_inv_cyc(t2, t2);
		fp16_mul(t2, t4, t2);

		fp16_mul(c, c, t2);
		if (!bn_is_even(x_)) {
			fp16_sqr_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(x_);
		fp16_free(t0);
		fp16_free(t1);
		fp16_free(t2);
		fp16_free(t3);
		fp16_free(t4);
	}
}

/**
 * Computes the final exponentiation of a pairing defined over a FM16 curve.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
static void pp_exp_fm16(fp16_t c, fp16_t a) {
	fp16_t t0, t1, t2, t3, t4, t5, t6, t7;
	bn_t x, x_;

	bn_null(x);
	bn_null(x_);
	fp16_null(t0);
	fp16_null(t1);
	fp16_null(t2);
	fp16_null(t3);
	fp16_null(t4);
	fp16_null(t5);
	fp16_null(t6);
	fp16_null(t7);

	RLC_TRY {
		bn_new(x);
		bn_new(x_);
		fp16_new(t0);
		fp16_new(t1);
		fp16_new(t2);
		fp16_new(t3);
		fp16_new(t4);
		fp16_new(t5);
		fp16_new(t6);
		fp16_new(t7);

		fp_prime_get_par(x);

		/* First, compute m = f^(p^8 - 1). */
		fp16_conv_cyc(c, a);

		/* Now compute m^((p^8 + 1) / r). */
		bn_hlv(x_, x);

		fp16_exp_cyc(t1, c, x_);
		fp16_exp_cyc(t1, t1, x_);
		fp16_exp_cyc(t2, t1, x);
		fp16_exp_cyc(t3, t2, x);
		fp16_exp_cyc(t4, t3, x);
		fp16_exp_cyc(t5, t4, x);
		fp16_exp_cyc(t6, t5, x);
		fp16_exp_cyc(t7, t6, x);

		fp16_mul(t0, t1, c);
		fp16_mul(t0, t0, t7);
		fp16_frb(t7, t0, 7);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 6);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 5);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 4);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 3);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 2);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_frb(t1, t0, 1);
		fp16_mul(t7, t7, t1);
		fp16_exp_cyc(t0, t0, x);
		fp16_mul(t7, t7, t0);
		fp16_mul(c, c, t7);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(x_);
		fp16_free(t0);
		fp16_free(t1);
		fp16_free(t2);
		fp16_free(t3);
		fp16_free(t4);
		fp16_free(t5);
		fp16_free(t6);
		fp16_free(t7);
	}
}
 



/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k16(fp16_t c, fp16_t a) {
	switch (ep_curve_is_pairf()) {
		case EP_K16:
			pp_exp_kss(c, a);
			break;
		case EP_N16:
			pp_exp_new(c, a);
			break;
		case EP_FM16:
			pp_exp_fm16(c, a);
			break;
	}
}
