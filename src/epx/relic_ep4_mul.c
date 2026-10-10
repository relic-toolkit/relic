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
 * Implementation of point multiplication on prime elliptic curves over
 * a quartic extension field.
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

TMPL_EP_MUL_GLS_IMP(ep4, 8);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep4, fp4, 8, 2);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep4);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep4, fp4);

#endif /* EP_MUL == LWREG */

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_ENDOM_GLS(ep4, 8);

TMPL_EP_MUL_SIM_PLAIN(ep4);

#endif /* EP_SIM == INTER */

/**
 * Multiplies a point by the cofactor in a KSS16 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep4_mul_cof_k16(ep4_t r, const ep4_t p) {
	bn_t x;
	ep4_t t0, t1, t2, t3, t4, t5;

	ep4_null(t0);
	ep4_null(t1);
	ep4_null(t2);
	ep4_null(t3);
	ep4_null(t4);
	ep4_null(t5);
	bn_null(x);

	RLC_TRY {
		bn_new(x);
		ep4_new(t0);
		ep4_new(t1);
		ep4_new(t2);
		ep4_new(t3);
		ep4_new(t4);
		ep4_new(t5);

		fp_prime_get_par(x);

		/* [x^3-3*x^2, 3*x^2+11*x, -11*x-7, 2*x^3+14, -2*x^3-4*x^2, 4*x^2-2*x, 2*x+24, x^4+x^3] */
		ep4_mul_basic(t1, p, x);
		ep4_mul_basic(t2, t1, x);
		ep4_mul_basic(t3, t2, x);

		ep4_dbl(t0, t2);
		ep4_add(t2, t2, t0);
		ep4_sub(t5, t3, t2);

		ep4_dbl(t0, t0);
		ep4_dbl(t4, t3);
		ep4_add(t4, t4, t0);
		ep4_frb(t4, t4, 4);
		ep4_sub(t5, t5, t4);

		ep4_sub(t4, t0, t1);
		ep4_sub(t4, t4, t1);
		ep4_frb(t4, t4, 5);
		ep4_add(t5, t5, t4);

		ep4_dbl(t0, t1);
		ep4_mul_dig(t4, p, 24);
		ep4_add(t4, t4, t0);
		ep4_frb(t4, t4, 6);
		ep4_add(t5, t5, t4);

		ep4_mul_dig(t4, t1, 11);
		ep4_mul_dig(t0, p, 7);
		ep4_add(t0, t0, t4);
		ep4_add(t4, t4, t2);
		ep4_frb(t4, t4, 1);
		ep4_add(t5, t5, t4);
		ep4_frb(t4, t0, 2);
		ep4_sub(t5, t5, t4);

		ep4_dbl(t0, t3);
		ep4_mul_dig(t4, p, 14);
		ep4_add(t4, t4, t0);
		ep4_frb(t4, t4, 3);
		ep4_add(t5, t5, t4);

		ep4_mul_basic(t4, t3, x);
		ep4_add(t4, t4, t3);
		ep4_frb(t4, t4, 7);
		ep4_add(t5, t5, t4);

		ep4_norm(r, t5);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep4_free(t0);
		ep4_free(t1);
		ep4_free(t2);
		ep4_free(t3);
		ep4_free(t4);
		ep4_free(t5);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a KSS16 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep4_mul_cof_afg16(ep4_t r, const ep4_t p) {
	bn_t x;
	ep4_t t0, t1, t2, t3, t4, t5;

	ep4_null(t0);
	ep4_null(t1);
	ep4_null(t2);
	ep4_null(t3);
	ep4_null(t4);
	ep4_null(t5);
	bn_null(x);

	RLC_TRY {
		bn_new(x);
		ep4_new(t0);
		ep4_new(t1);
		ep4_new(t2);
		ep4_new(t3);
		ep4_new(t4);
		ep4_new(t5);

		fp_prime_get_par(x);

		/* [2*(1+u^3), -u^3*(1+u^3), -2*u, u*(1+u^3), -u^4*(u^3+1), -2*u^2,  u^2*(1+u^3), 2] */
		ep4_mul_basic(t1, p, x);
		ep4_mul_basic(t2, t1, x);
		ep4_mul_basic(t3, t2, x);

		ep4_frb(t5, p, 7);
		ep4_frb(t4, t1, 2);
		ep4_sub(t5, t5, t4);
		ep4_frb(t4, t2, 5);
		ep4_sub(t5, t5, t4);
		ep4_add(t3, t3, p);
		ep4_add(t5, t5, t3);
		ep4_dbl(t5, t5);

		ep4_mul_basic(t0, t3, x);
		ep4_frb(t4, t0, 3);
		ep4_add(t5, t5, t4);

		ep4_mul_basic(t0, t0, x);
		ep4_frb(t4, t0, 6);
		ep4_add(t5, t5, t4);

		ep4_mul_basic(t0, t0, x);
		ep4_frb(t4, t0, 1);
		ep4_sub(t5, t5, t4);

		ep4_mul_basic(t0, t0, x);
		ep4_frb(t4, t0, 4);
		ep4_sub(t5, t5, t4);

		ep4_norm(r, t5);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep4_free(t0);
		ep4_free(t1);
		ep4_free(t2);
		ep4_free(t3);
		ep4_free(t4);
		ep4_free(t5);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a FM16 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep4_mul_cof_fm16(ep4_t r, const ep4_t p) {
	bn_t x;
	ep4_t t0, t1, t2, t3;

	ep4_null(t0);
	ep4_null(t1);
	ep4_null(t2);
	ep4_null(t3);
	bn_null(x);

	RLC_TRY {
		bn_new(x);
		ep4_new(t0);
		ep4_new(t1);
		ep4_new(t2);
		ep4_new(t3);

		fp_prime_get_par(x);
		if (bn_is_even(x)) {
			bn_hlv(x, x);
		} else {
			RLC_THROW(ERR_NO_VALID);
		}

		/* [1 + u^7/2, u^6/2, u^5/2, u^4/2, u^3(2-u)/2, u^2(2-u)/2, u(2-u)/2, (2-u)/2] */

		/* Compute [1 - u/2]\psi^7(P). */
		ep4_mul_basic(t1, p, x);
		ep4_sub(t0, p, t1);
		ep4_frb(t0, t0, 7);
		bn_dbl(x, x);
		/* Compute [u - u^2/2]\psi^6(P). */
		ep4_mul_basic(t2, t1, x);
		ep4_dbl(t1, t1);
		ep4_sub(t3, t1, t2);
		ep4_frb(t3, t3, 6);
		ep4_add(t0, t0, t3);
		/* Compute [u^2 - u^3/2]\psi^5(P). */
		ep4_mul_basic(t1, t2, x);
		ep4_dbl(t2, t2);
		ep4_sub(t3, t2, t1);
		ep4_frb(t3, t3, 5);
		ep4_add(t0, t0, t3);
		/* Compute [u^3 - u^4/2]\psi^4(P). */
		ep4_mul_basic(t2, t1, x);
		ep4_dbl(t1, t1);
		ep4_sub(t3, t1, t2);
		ep4_frb(t3, t3, 4);
		ep4_add(t0, t0, t3);
		/* Compute [u^4/2]\psi^3(P). */
		ep4_frb(t3, t2, 3);
		ep4_add(t0, t0, t3);
		/* Compute [u^5/2]\psi^2(P). */
		ep4_mul_basic(t2, t2, x);
		ep4_frb(t3, t2, 2);
		ep4_add(t0, t0, t3);
		/* Compute [u^6/2]\psi(P). */
		ep4_mul_basic(t2, t2, x);
		ep4_frb(t3, t2, 1);
		ep4_add(t0, t0, t3);
		/* Compute [1 + u^7/2]P. */
		ep4_mul_basic(t2, t2, x);
		ep4_add(t0, t0, t2);
		ep4_add(t0, t0, p);

		ep4_norm(r, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep4_free(t0);
		ep4_free(t1);
		ep4_free(t2);
		ep4_free(t3);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a BLS24 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep4_mul_cof_b24(ep4_t r, const ep4_t p) {
	bn_t z;
	ep4_t t0, t1, t2, t3;

	ep4_null(t0);
	ep4_null(t1);
	ep4_null(t2);
	ep4_null(t3);
	bn_null(z);

	RLC_TRY {
		bn_new(z);
		ep4_new(t0);
		ep4_new(t1);
		ep4_new(t2);
		ep4_new(t3);

		fp_prime_get_par(z);

		bn_sub_dig(z, z, 1);
		ep4_mul_basic(t0, p, z);
		bn_add_dig(z, z, 1);
		ep4_mul_basic(t1, t0, z);
		ep4_mul_basic(t2, t1, z);
		ep4_mul_basic(t3, t2, z);

		/* Compute t0 = [u - 1]*\psi^3(P). */
		ep4_frb(t0, t0, 3);
		/* Compute t2 = [u^2*(u-1)]\psi(P). */
		ep4_frb(t2, t2, 1);
		/* Compute t1 = [u*(u-1)]\psi^2(P). */
		ep4_frb(t1, t1, 2);
		/* Compute t3 = [u^3(u-1) - 1]P. */
		ep4_sub(t3, t3, p);

		ep4_dbl(r, p);
		ep4_frb(r, r, 4);
		ep4_add(r, r, t0);
		ep4_add(r, r, t1);
		ep4_add(r, r, t2);
		ep4_add(r, r, t3);

		ep4_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep4_free(t0);
		ep4_free(t1);
		ep4_free(t2);
		ep4_free(t3);
		bn_free(z);

	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep4);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep4);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep4, fp4);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep4_mul_lwnaf(ep4_t r, const ep4_t p, const bn_t k) {
	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep4_mul_gls_imp(r, p, k);
		return;
	}

	ep4_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep4_mul_lwreg(ep4_t r, const ep4_t p, const bn_t k) {
	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep4_mul_reg_gls(r, p, k);
		return;
	}

	ep4_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep4);

TMPL_EP_MUL_DIG(ep4);

#if EP_FIX == BASIC || !defined(STRIP)

TMPL_EP_MUL_FIX_BASIC(ep4);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep4);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep4);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

TMPL_EP_MUL_FIX_LWNAF(ep4);

#endif

#if EP_SIM == BASIC || !defined(STRIP)

TMPL_EP_MUL_SIM_BASIC(ep4);

#endif

#if EP_SIM == TRICK || !defined(STRIP)

TMPL_EP_MUL_SIM_TRICK(ep4);

#endif

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_INTER(ep4);

#endif

#if EP_SIM == JOINT || !defined(STRIP)

TMPL_EP_MUL_SIM_JOINT(ep4);

#endif

TMPL_EP_MUL_SIM_GEN(ep4);

TMPL_EP_MUL_SIM_DIG(ep4);

TMPL_EP_MUL_SIM_LOT(ep4, 8);

void ep4_mul_cof(ep4_t r, const ep4_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		switch (ep_curve_is_pairf()) {
			case EP_K16:
				ep4_mul_cof_k16(r, p);
				break;
			case EP_AFG16:
				ep4_mul_cof_afg16(r, p);
				break;
			case EP_FM16:
				ep4_mul_cof_fm16(r, p);
				break;
			case EP_B24:
				ep4_mul_cof_b24(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep4_curve_get_cof(k);
				ep4_mul_big(r, p, k);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
