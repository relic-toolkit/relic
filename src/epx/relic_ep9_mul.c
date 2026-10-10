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
 * a nonic extension field.
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

TMPL_EP_MUL_GLS_IMP(ep9, 10);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep9, fp9, 10, 2);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep9);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep9, fp9);

#endif /* EP_MUL == LWREG */

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_ENDOM_GLS(ep9, 10);

TMPL_EP_MUL_SIM_PLAIN(ep9);

#endif /* EP_SIM == INTER */

/**
 * Applies the automorphism (x, y) -> (beta * x, y) of an elliptic curve over a
 * nonic extension with a = 0, where beta is a cube root of unity in Fp.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to map.
 */
static void ep9_omega(ep9_t r, const ep9_t p) {
	ep9_copy(r, p);
	for (int i = 0; i < 3; i++) {
		for (int j = 0; j < 3; j++) {
			fp_mul(r->x[i][j], r->x[i][j], ep_curve_get_beta());
		}
	}
}

/**
 * Multiplies a point in an elliptic curve over a nonic extension of an SG54
 * curve by a multiple of the cofactor, writing the short vector found by
 * lattice reduction as a polynomial in u with Horner's rule.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep9_mul_cof_sg54(ep9_t r, const ep9_t p) {
	bn_t x, y;
	ep9_t v[8], s[10], t;

	bn_null(x);
	bn_null(y);
	ep9_null(t);

	RLC_TRY {
		bn_new(x);
		bn_new(y);
		ep9_new(t);
		for (int i = 0; i < 8; i++) {
			ep9_null(v[i]);
			ep9_new(v[i]);
		}
		for (int i = 0; i < 10; i++) {
			ep9_null(s[i]);
			ep9_new(s[i]);
		}

		fp_prime_get_par(x);
		bn_mul_dig(y, x, 3);

		/* Compute v_i = Frob^i(V) for V = Frob(P) - P and 0 <= i < 8. */
		ep9_frb(t, p, 1);
		ep9_sub(v[0], t, p);
		for (int i = 1; i < 8; i++) {
			ep9_frb(v[i], v[i - 1], 1);
		}

		/* Compute the coefficients of u^i, with W(x, y) = (beta * x, y). */
		ep9_omega(t, p);
		ep9_sub(s[9], p, t);
		ep9_omega(s[8], v[0]);
		ep9_omega(t, v[1]);
		ep9_omega(s[7], t);
		ep9_sub(s[7], s[7], t);
		ep9_omega(t, v[2]);
		ep9_omega(s[6], t);
		ep9_neg(s[6], s[6]);
		ep9_omega(t, v[3]);
		ep9_omega(s[5], t);
		ep9_sub(s[5], s[5], v[3]);
		ep9_copy(s[4], v[4]);
		ep9_omega(s[3], v[5]);
		ep9_sub(s[3], s[3], v[5]);
		ep9_omega(s[2], v[6]);
		ep9_neg(s[2], s[2]);
		ep9_omega(s[1], v[7]);
		ep9_omega(t, s[1]);
		ep9_sub(s[1], s[1], t);
		ep9_copy(t, v[0]);
		for (int i = 1; i < 8; i++) {
			ep9_add(t, t, v[i]);
		}
		ep9_omega(t, t);
		ep9_omega(s[0], t);
		ep9_neg(s[0], s[0]);

		/* Horner's rule alternating between u and 3u, from the top. */
		ep9_copy(r, s[9]);
		for (int i = 8; i >= 0; i--) {
			ep9_mul_basic(r, r, (i % 2 == 0 ? x : y));
			ep9_add(r, r, s[i]);
		}
		ep9_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(y);
		ep9_free(t);
		for (int i = 0; i < 8; i++) {
			ep9_free(v[i]);
		}
		for (int i = 0; i < 10; i++) {
			ep9_free(s[i]);
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep9);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep9);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep9, fp9);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep9_mul_lwnaf(ep9_t r, const ep9_t p, const bn_t k) {
	if (bn_is_zero(k) || ep9_is_infty(p)) {
		ep9_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep9_mul_gls_imp(r, p, k);
		return;
	}

	ep9_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep9_mul_lwreg(ep9_t r, const ep9_t p, const bn_t k) {
	if (bn_is_zero(k) || ep9_is_infty(p)) {
		ep9_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep9_mul_reg_gls(r, p, k);
		return;
	}

	ep9_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep9);

TMPL_EP_MUL_DIG(ep9);

#if EP_FIX == BASIC || !defined(STRIP)

TMPL_EP_MUL_FIX_BASIC(ep9);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep9);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep9);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

TMPL_EP_MUL_FIX_LWNAF(ep9);

#endif

#if EP_SIM == BASIC || !defined(STRIP)

TMPL_EP_MUL_SIM_BASIC(ep9);

#endif

#if EP_SIM == TRICK || !defined(STRIP)

TMPL_EP_MUL_SIM_TRICK(ep9);

#endif

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_INTER(ep9);

#endif

#if EP_SIM == JOINT || !defined(STRIP)

TMPL_EP_MUL_SIM_JOINT(ep9);

#endif

TMPL_EP_MUL_SIM_GEN(ep9);

TMPL_EP_MUL_SIM_DIG(ep9);

TMPL_EP_MUL_SIM_LOT(ep9, 10);

void ep9_mul_cof(ep9_t r, const ep9_t p) {
	switch (ep_curve_is_pairf()) {
		case EP_SG54:
			ep9_mul_cof_sg54(r, p);
			break;
		default:
			/* The cofactor is too large to be stored for clearing. */
			RLC_THROW(ERR_NO_VALID);
			break;
	}
}
