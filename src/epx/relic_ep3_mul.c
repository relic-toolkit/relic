/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * a cubic extension field.
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

static void ep3_mul_gls_imp(ep3_t r, const ep3_t p, const bn_t k) {
	size_t l;
	bn_t n, _k[6], u;
	int8_t even, col, sac[6 * (RLC_FP_BITS + 1)];
	ep3_t q[6], t[1 << 5];

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (int i = 0; i < 6; i++) {
			bn_null(_k[i]);
			ep3_null(q[i]);
			bn_new(_k[i]);
			ep3_new(q[i]);
		}
		for (int i = 0; i < (1 << 5); i++) {
			ep3_null(t[i]);
			ep3_new(t[i]);
		}

		fp_prime_get_par(u);
		if (ep_curve_is_pairf() == EP_SG18) {
			/* Compute base -3*u for the recoding below. */
			bn_dbl(n, u);
			bn_add(u, u, n);
			bn_neg(u, u);
		}
		ep3_curve_get_ord(n);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 6, _k[0], u, n, ep_curve_is_pairf() == EP_BN);
		even = bn_is_even(_k[0]);
		bn_add_dig(_k[0], _k[0], even);
		ep3_norm(q[0], p);
		for (size_t i = 1; i < 6; i++) {
			ep3_psi(q[i], q[i - 1]);
		}
		for (size_t i = 0; i < 6; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep3_neg(q[i], q[i]);
			}
			bn_abs(_k[i], _k[i]);
		}

		ep3_copy(t[0], q[0]);
		for (size_t i = 1; i < (1 << 5); i++) {
			l = util_bits_dig(i);
			ep3_add(t[i], t[i ^ (1 << (l - 1))], q[l]);
		}

		l = RLC_FP_BITS + 1;
		bn_rec_sac(sac, &l, _k, u, 1, 6, bn_bits(n), 0);

		ep3_norm_sim(t + 1, t + 1, (1 << 5) - 1);
		fp3_set_dig(r->z, 1);
		fp3_set_dig(q[1]->z, 1);
		r->coord = q[1]->coord = BASIC;

		ep3_set_infty(r);
		for (int j = l - 1; j >= 0; j--) {
			ep3_dbl(r, r);

			col = 0;
			for (int i = 5; i > 0; i--) {
				col <<= 1;
				col += sac[i * l + j];
			}

			if (sac[j]) {
				ep3_sub(r, r, t[col]);
			} else {
				ep3_add(r, r, t[col]);
			}			
		}

		if (even) {
			ep3_sub(r, r, q[0]);
		}

		/* Convert r to affine coordinates. */
		ep3_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (int i = 0; i < 6; i++) {
			bn_free(_k[i]);
			ep3_free(q[i]);
		}
		for (int i = 0; i < (1 << 5); i++) {
			ep3_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep3, fp3, 6, 1);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep3);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep3, fp3);

#endif /* EP_MUL == LWREG */

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_ENDOM_GLS(ep3, 6);

TMPL_EP_MUL_SIM_PLAIN(ep3);

#endif /* EP_SIM == INTER */

/**
 * Multiplies a point by the cofactor in a KSS18 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_k18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4, t5;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	ep3_null(t5);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		ep3_new(t5);
		bn_new(x);

		/* Method from "Faster Hashing to G2" by Laura Fuentes-Castañeda,
		 * Edward Knapp and Francisco Rodríguez-Henríquez.
		. */

		/* Compute multi-addition-subtraction chain \sum \lambda_i \psi^P, where
		 * \lambda_0 = 5u + 18
		 * \lambda_1 = (u^3+3u^2+1)
		 * \lambda_2 = -(3u^2+8*u)
		 * \lambda_3 = (3u+1)
		 * \lambda_4 = -(u^2+2)
		 * \lambda_5 = (u^2+5u)

		 * We will write the subscalars below as vectors for simplicity.
		 */

		fp_prime_get_par(x);

		/* t0 = [u]P, t4 = [u^2]P, later t2 = [u^3]P. */
		ep3_mul_basic(t0, p, x);
		ep3_mul_basic(t4, t0, x);

		/* t1 = [1, 0, -u, 0, 0, 0]. */
		ep3_frb(t1, t0, 2);
		/* t2 = [u, 0, 0, 0, 0, u]. */
		ep3_frb(t2, t1, 3);
		ep3_add(t2, t2, t0);
		/* t3 = [0, 0, 0, -u, 0, 0]. */
		ep3_frb(t3, t1, 1);
		ep3_neg(t1, t1);
		ep3_add(t1, t1, p);
		/* t0 = [u+3, 0, -u, 0, 0, u]. */
		ep3_dbl(t0, p);
		ep3_add(t0, t0, t2);
		ep3_add(t0, t0, t1);

		/* t2 = [0, 0, u^2, 0, 0, 0], t3 = [0, u^2, -u^2, -u, 0, 0]. */
		ep3_frb(t2, t4, 1);
		ep3_add(t3, t3, t2);
		ep3_frb(t2, t2, 1);
		ep3_sub(t3, t3, t2);

		/* t5 = [0, u^3 + 1, 0, 1, -u^2, u^2] */
		ep3_frb(t5, p, 1);
		ep3_frb(t2, t5, 2);
		ep3_add(t5, t5, t2);
		ep3_frb(t2, t4, 4);
		ep3_sub(t5, t5, t2);
		ep3_frb(t2, t2, 1);
		ep3_add(t5, t5, t2);
		ep3_mul_basic(t2, t4, x);
		ep3_frb(t2, t2, 1);
		ep3_add(t5, t5, t2);

		/* t4 = [0, 0, 0, 0, -1, 0], t3 = [1, u^2, -u^2-u, -u, 0, 0]. */
		ep3_frb(t4, p, 4);
		ep3_neg(t4, t4);
		ep3_add(t3, t3, t1);
		/* t4 = [u+3, 0, -u, 0, -1, u]. */
		ep3_add(t4, t4, t0);
		/* t3 = [u+4, u^2, -u^2-2u, -u, -1, u]. */
		ep3_add(t3, t3, t0);
		/* t4 = [2u+7, u^2, -u^2-3u, -u, -1, 2u]. */
		ep3_add(t4, t4, t3);
		/* t3 = [u+4, u^3+u^2+1, -u^2-2u, -u+1, -u^2, u^2+u]. */
		ep3_add(t3, t3, t5);
		/* t4 = [4u+14, 2u^2, -2u^2-6u, -2u, -2, 4u]. */
		ep3_dbl(t4, t4);
		/* r = [5u+18, u^3+3u^2+1, -3u^2-8u, -3u+1, -u^2-2, u^2+5u]. */
		ep3_add(r, t4, t3);
		ep3_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		ep3_free(t5);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Scott-Guillevic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_sg18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		bn_new(x);

		/* Vector computed by Guillevic's MAGMA script:
		[9*u^4-3*u^2+u, 3*u^2-1, -6*u^3 + 2*u, -2*u, 0, 3*u^3-u+1] */
		fp_prime_get_par(x);

		/* t0 = [u]P, t1 = [3u^2]P, t2 = [3u^3]P, t3 = [9u^4]P. */
		ep3_mul_basic(t0, p, x);
		bn_mul_dig(x, x, 3);
		ep3_mul_basic(t1, t0, x);
		bn_div_dig(x, x, 3);
		ep3_mul_basic(t2, t1, x);
		bn_mul_dig(x, x, 3);
		ep3_mul_basic(t3, t2, x);
		ep3_sub(t3, t3, t1);
		ep3_add(t3, t3, t0);

		ep3_sub(t4, t1, p),
		ep3_frb(t4, t4, 1);
		ep3_add(t3, t3, t4);

		ep3_sub(t2, t2, t0);
		ep3_frb(t4, t2, 2);
		ep3_dbl(t4, t4);
		ep3_sub(t3, t3, t4);
		ep3_add(t2, t2, p);
		ep3_frb(t2, t2, 5);
		ep3_add(t3, t3, t2);

		ep3_dbl(t4, t0);
		ep3_frb(t4, t4, 3);
		ep3_sub(r, t3, t4);
		ep3_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Fotiadis-Mardindale curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_fm18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		bn_new(x);

		/* Vector computed by Guillevic's MAGMA script:
		[2*x*(x+2)/3, x^3-(x+2)/3, -2*x^2*(x+2)/3, -x*(x^3+(x+2)/3), 2*(x+2)/3, x^2*(x^3+(x+2)/3)-1] */
		fp_prime_get_par(x);

		/* t0 = [(x+2)/3]P, t1 = [x]P. */
		bn_add_dig(x, x, 2);
		bn_div_dig(x, x, 3);
		ep3_mul_basic(t0, p, x);
		ep3_dbl(t1, t0);
		ep3_add(t1, t1, t0);
		ep3_dbl(t2, p);
		ep3_sub(t1, t1, t2);

		/* Compute t2 = [x*(x+2)/3]P, t1 = [3*x*(x+2)/3-2x]P = [x^2]P. */
		fp_prime_get_par(x);
		ep3_frb(t3, t0, 4);
		ep3_mul_basic(t2, t0, x);
		ep3_add(t3, t3, t2);
		ep3_dbl(t4, t2);
		ep3_add(t4, t4, t2);
		ep3_dbl(t1, t1);
		ep3_sub(t1, t4, t1);
		ep3_norm(t1, t1);
		/* Compute t2 = [x^2*(x+2)/3]P, */
		ep3_mul_basic(t2, t2, x);
		ep3_frb(t4, t2, 2);
		ep3_sub(t3, t3, t4);
		ep3_dbl(t3, t3);
		ep3_mul_basic(t2, t1, x);
		ep3_sub(t4, t2, t0);
		ep3_frb(t4, t4, 1);
		ep3_add(t3, t3, t4);
		ep3_add(t4, t2, t0);
		ep3_norm(t4, t4);
		ep3_mul_basic(t2, t4, x);
		ep3_frb(t4, t2, 3);
		ep3_sub(t3, t3, t4);
		ep3_mul_basic(t2, t2, x);
		ep3_sub(t2, t2, p);
		ep3_frb(t2, t2, 5);
		ep3_add(t3, t3, t2);
		ep3_norm(r, t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		bn_free(x);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep3);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep3);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep3, fp3);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep3_mul_lwnaf(ep3_t r, const ep3_t p, const bn_t k) {
	if (bn_is_zero(k) || ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep3_mul_gls_imp(r, p, k);
		return;
	}

	ep3_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep3_mul_lwreg(ep3_t r, const ep3_t p, const bn_t k) {
	if (bn_is_zero(k) || ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep3_mul_reg_gls(r, p, k);
		return;
	}

	ep3_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep3);

TMPL_EP_MUL_DIG(ep3);

#if EP_FIX == BASIC || !defined(STRIP)

TMPL_EP_MUL_FIX_BASIC(ep3);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep3);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep3);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

TMPL_EP_MUL_FIX_LWNAF(ep3);

#endif

#if EP_SIM == BASIC || !defined(STRIP)

TMPL_EP_MUL_SIM_BASIC(ep3);

#endif

#if EP_SIM == TRICK || !defined(STRIP)

TMPL_EP_MUL_SIM_TRICK(ep3);

#endif

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_INTER(ep3);

#endif

#if EP_SIM == JOINT || !defined(STRIP)

TMPL_EP_MUL_SIM_JOINT(ep3);

#endif

TMPL_EP_MUL_SIM_GEN(ep3);

TMPL_EP_MUL_SIM_DIG(ep3);

TMPL_EP_MUL_SIM_LOT(ep3, 6);

void ep3_mul_cof(ep3_t r, const ep3_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		switch (ep_curve_is_pairf()) {
			case EP_K18:
				ep3_mul_cof_k18(r, p);
				break;
			case EP_SG18:
				ep3_mul_cof_sg18(r, p);
				break;
			case EP_FM18:
				ep3_mul_cof_fm18(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep3_curve_get_cof(k);
				ep3_mul_big(r, p, k);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
