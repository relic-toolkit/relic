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
 * Implementation of fixed point multiplication on a prime elliptic curve over
 * a quadratic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_FIX == LWNAF || !defined(STRIP)

/**
 * Multiplies a binary elliptic curve point by an integer using the w-NAF
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the point to multiply.
 * @param[in] k					- the integer.
 */
static void ep2_mul_fix_plain(ep2_t r, const ep2_t *table, const bn_t k) {
	int8_t naf[2 * RLC_FP_BITS + 1], *t;
	size_t len;
	int n;

	if (bn_is_zero(k)) {
		ep2_set_infty(r);
		return;
	}

	/* Compute the w-TNAF representation of k. */
	len = 2 * RLC_FP_BITS + 1;
	bn_rec_naf(naf, &len, k, RLC_DEPTH);

	t = naf + len - 1;
	ep2_set_infty(r);
	for (int i = len - 1; i >= 0; i--, t--) {
		ep2_dbl(r, r);

		n = *t;
		if (n > 0) {
			ep2_add(r, r, table[n / 2]);
		}
		if (n < 0) {
			ep2_sub(r, r, table[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	ep2_norm(r, r);
	if (bn_sign(k) == RLC_NEG) {
		ep2_neg(r, r);
	}
}

#endif /* EP_FIX == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_FIX == BASIC || !defined(STRIP)

void ep2_mul_pre_basic(ep2_t *t, const ep2_t p) {
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ep2_curve_get_ord(n);

		ep2_copy(t[0], p);
		for (int i = 1; i < bn_bits(n); i++) {
			ep2_dbl(t[i], t[i - 1]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
	}
}

TMPL_EP_MUL_FIX_BASIC(ep2);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep2);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_PRE_COMBD(ep2);

void ep2_mul_fix_combd(ep2_t r, const ep2_t *t, const bn_t k) {
	int i, j, d, e, w0, w1, n0, p0, p1;
	bn_t n, _k;

	if (bn_is_zero(k)) {
		ep2_set_infty(r);
		return;
	}

	bn_null(n);
	bn_null(_k);

	RLC_TRY {
		bn_new(n);
		bn_new(_k);

		ep2_curve_get_ord(n);
		d = bn_bits(n);
		d = ((d % RLC_DEPTH) == 0 ? (d / RLC_DEPTH) : (d / RLC_DEPTH) + 1);
		e = (d % 2 == 0 ? (d / 2) : (d / 2) + 1);

		ep2_set_infty(r);
		bn_mod(_k, k, n);
		n0 = bn_bits(_k);

		p1 = (e - 1) + (RLC_DEPTH - 1) * d;
		for (i = e - 1; i >= 0; i--) {
			ep2_dbl(r, r);

			w0 = 0;
			p0 = p1;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {
				w0 = w0 << 1;
				if (p0 < n0 && bn_get_bit(_k, p0)) {
					w0 = w0 | 1;
				}
			}

			w1 = 0;
			p0 = p1-- + e;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {
				w1 = w1 << 1;
				if (i + e < d && p0 < n0 && bn_get_bit(_k, p0)) {
					w1 = w1 | 1;
				}
			}

			ep2_add(r, r, t[w0]);
			ep2_add(r, r, t[(1 << RLC_DEPTH) + w1]);
		}
		ep2_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(_k);
	}
}

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

void ep2_mul_pre_lwnaf(ep2_t *t, const ep2_t p) {
	ep2_tab(t, p, RLC_DEPTH);
}

void ep2_mul_fix_lwnaf(ep2_t r, const ep2_t *t, const bn_t k) {
	bn_t n, _k;

	if (bn_is_zero(k)) {
		ep2_set_infty(r);
		return;
	}

	bn_null(n);
	bn_null(_k);

	RLC_TRY {
		bn_new(n);
		bn_new(_k);

		ep2_curve_get_ord(n);
		bn_mod(_k, k, n);
		ep2_mul_fix_plain(r, t, _k);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_k);
	}
}

#endif
