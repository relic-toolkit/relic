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
 * Implementation of fixed point multiplication on a prime elliptic curve over
 * a quartic extension field.
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
 * Precomputes a table for a point multiplication on an ordinary curve.
 *
 * @param[out] t				- the destination table.
 * @param[in] p					- the point to multiply.
 */
static void ep4_mul_pre_ordin(ep4_t *t, const ep4_t p) {
	ep4_dbl(t[0], p);
#if defined(EP_MIXED)
	ep4_norm(t[0], t[0]);
#endif

#if RLC_DEPTH > 2
	ep4_add(t[1], t[0], p);
	for (int i = 2; i < (1 << (RLC_DEPTH - 2)); i++) {
		ep4_add(t[i], t[i - 1], t[0]);
	}

#if defined(EP_MIXED)
	for (int i = 1; i < (1 << (RLC_DEPTH - 2)); i++) {
		ep4_norm(t[i], t[i]);
	}
#endif

#endif
	ep4_copy(t[0], p);
}

/**
 * Multiplies a binary elliptic curve point by an integer using the w-NAF
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the point to multiply.
 * @param[in] k					- the integer.
 */
static void ep4_mul_fix_ordin(ep4_t r, const ep4_t *table, const bn_t k) {
	int8_t naf[2 * RLC_FP_BITS + 1], *t;
	size_t len;
	int n;

	if (bn_is_zero(k)) {
		ep4_set_infty(r);
		return;
	}

	/* Compute the w-TNAF representation of k. */
	len = 2 * RLC_FP_BITS + 1;
	bn_rec_naf(naf, &len, k, RLC_DEPTH);

	t = naf + len - 1;
	ep4_set_infty(r);
	for (int i = len - 1; i >= 0; i--, t--) {
		ep4_dbl(r, r);

		n = *t;
		if (n > 0) {
			ep4_add(r, r, table[n / 2]);
		}
		if (n < 0) {
			ep4_sub(r, r, table[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	ep4_norm(r, r);
	if (bn_sign(k) == RLC_NEG) {
		ep4_neg(r, r);
	}
}

#endif /* EP_FIX == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_FIX == BASIC || !defined(STRIP)

void ep4_mul_pre_basic(ep4_t *t, const ep4_t p) {
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ep4_curve_get_ord(n);

		ep4_copy(t[0], p);
		for (int i = 1; i < bn_bits(n); i++) {
			ep4_dbl(t[i], t[i - 1]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
	}
}

TMPL_EP_MUL_FIX_BASIC(ep4);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

TMPL_EP_MUL_COMBS(ep4);

#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep4);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

void ep4_mul_pre_lwnaf(ep4_t *t, const ep4_t p) {
	ep4_mul_pre_ordin(t, p);
}

void ep4_mul_fix_lwnaf(ep4_t r, const ep4_t *t, const bn_t k) {
	ep4_mul_fix_ordin(r, t, k);
}

#endif
