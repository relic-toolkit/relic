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

/* Defined below by the multiplication template. */
static void ep4_mul_naf_imp(ep4_t r, const ep4_t p, const bn_t k);

/**
 * Multiplies a point by the cofactor in a supersingular curve over Fp^4 with
 * embedding degree 3, which is the hard part c * (p^2 + d^2 - 1) * (p + d) + 1
 * of the final exponentiation of its pairing, for p = d + c * r.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep4_mul_cof_ss3(ep4_t r, const ep4_t p) {
	ep4_t t0, t1, t2;
	bn_t c, d, n;

	ep4_null(t0);
	ep4_null(t1);
	ep4_null(t2);
	bn_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep4_new(t0);
		ep4_new(t1);
		ep4_new(t2);
		bn_new(c);
		bn_new(d);
		bn_new(n);

		fp_prime_get_par(d);
		ep4_curve_get_ord(n);
		bn_read_raw(c, fp_prime_get(), RLC_FP_DIGS);
		bn_sub(c, c, d);
		bn_div(c, c, n);

		/* The endomorphism [p] is defined on the whole curve, but the GLS
		 * decomposition is not, so use w-NAF, which reduces modulo r > c. */
		ep4_mul_naf_imp(t0, p, c);
		/* t0 = [p^2 + d^2 - 1]t0. */
		ep4_frb(t1, t0, 2);
		ep4_mul_dig(t2, t0, d->dp[0]);
		ep4_mul_dig(t2, t2, d->dp[0]);
		ep4_add(t1, t1, t2);
		ep4_sub(t0, t1, t0);
		/* t0 = [p + d]t0. */
		ep4_frb(t1, t0, 1);
		ep4_mul_dig(t2, t0, d->dp[0]);
		ep4_add(t0, t1, t2);
		ep4_add(r, t0, p);
		ep4_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep4_free(t0);
		ep4_free(t1);
		ep4_free(t2);
		bn_free(c);
		bn_free(d);
		bn_free(n);
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

TMPL_EPX_MUL(ep4, fp4, 8, 2, WNAF);

TMPL_EP_MUL_TW_TAB(ep4, fp4);

TMPL_EP_MUL_TW_NAF(ep4, fp4);

TMPL_EP_MUL_TW_REG(ep4, fp4);

TMPL_EP_MUL_TW_GLS(ep4, fp4, 8, 4);

void ep4_mul_cof(ep4_t r, const ep4_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		bn_new(k);

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
			case EP_SS3:
				ep4_mul_cof_ss3(r, p);
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
