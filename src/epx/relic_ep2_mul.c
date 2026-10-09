/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over
 * a quadratic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"
#include "relic_md.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_GLS_IMP(ep2, 4);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep2, fp2, 4, 1);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep2);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep2, fp2);

#endif /* EP_MUL == LWREG */

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_ENDOM_GLS(ep2, 4);

TMPL_EP_MUL_SIM_PLAIN(ep2);

#endif /* EP_SIM == INTER */

/**
 * Multiplies a point by the cofactor in a Barreto-Naehrig curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep2_mul_cof_bn(ep2_t r, const ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	bn_null(x);

	RLC_TRY {
		ep2_new(t0);
		ep2_new(t1);
		ep2_new(t2);
		bn_new(x);

		fp_prime_get_par(x);

		/* Compute t0 = xP. */
		ep2_mul_basic(t0, p, x);

		/* Compute t1 = \psi(3xP). */
		ep2_dbl(t1, t0);
		ep2_add(t1, t1, t0);
		ep2_norm(t1, t1);
		ep2_frb(t1, t1, 1);

		/* Compute t2 = \psi^3(P) + t0 + t1 + \psi^2(xP). */
		ep2_frb(t2, p, 2);
		ep2_frb(t2, t2, 1);
		ep2_add(t2, t2, t0);
		ep2_add(t2, t2, t1);
		ep2_frb(t1, t0, 2);
		ep2_add(t2, t2, t1);

		ep2_norm(r, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t0);
		ep2_free(t1);
		ep2_free(t2);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Barreto-Lynn-Scott curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep2_mul_cof_b12(ep2_t r, const ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2, t3;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	ep2_null(t3);
	bn_null(x);

	RLC_TRY {
		ep2_new(t0);
		ep2_new(t1);
		ep2_new(t2);
		ep2_new(t3);
		bn_new(x);

		fp_prime_get_par(x);

		/* Compute t0 = xP. */
		ep2_mul_basic(t0, p, x);
		/* Compute t1 = [x^2]P. */
		ep2_mul_basic(t1, t0, x);

		/* t2 = (x^2 - x - 1)P = x^2P - x*P - P. */
		ep2_sub(t2, t1, t0);
		ep2_sub(t2, t2, p);
		/* t3 = \psi(x - 1)P. */
		ep2_sub(t3, t0, p);
		ep2_frb(t3, t3, 1);
		ep2_add(t2, t2, t3);
		/* t3 = \psi^2(2P). */
		ep2_dbl(t3, p);
		ep2_frb(t3, t3, 2);
		ep2_add(t2, t2, t3);
		ep2_norm(r, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t0);
		ep2_free(t1);
		ep2_free(t2);
		ep2_free(t3);
		bn_free(x);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep2);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep2);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep2, fp2);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep2_mul_lwnaf(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep2_mul_gls_imp(r, p, k);
		return;
	}

	ep2_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep2_mul_lwreg(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep2_mul_reg_gls(r, p, k);
		return;
	}

	ep2_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep2);

TMPL_EP_MUL_DIG(ep2);

#if EP_FIX == BASIC || !defined(STRIP)

TMPL_EP_MUL_FIX_BASIC(ep2);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep2);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep2);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

TMPL_EP_MUL_FIX_LWNAF(ep2);

#endif

#if EP_SIM == BASIC || !defined(STRIP)

TMPL_EP_MUL_SIM_BASIC(ep2);

#endif

#if EP_SIM == TRICK || !defined(STRIP)

TMPL_EP_MUL_SIM_TRICK(ep2);

#endif

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_INTER(ep2);

#endif

#if EP_SIM == JOINT || !defined(STRIP)

TMPL_EP_MUL_SIM_JOINT(ep2);

#endif

TMPL_EP_MUL_SIM_GEN(ep2);

TMPL_EP_MUL_SIM_DIG(ep2);

TMPL_EP_MUL_SIM_LOT(ep2, 4);

void ep2_mul_cof(ep2_t r, const ep2_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		switch (ep_curve_is_pairf()) {
			case EP_BN:
				ep2_mul_cof_bn(r, p);
				break;
			case EP_B12:
				ep2_mul_cof_b12(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep2_curve_get_cof(k);
				ep2_mul_big(r, p, k);
				break;
		}		
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
