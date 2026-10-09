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
 * Implementation of fixed point multiplication on a prime elliptic curve over
 * a cubic extension field.
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
static void ep3_mul_fix_plain(ep3_t r, const ep3_t *table, const bn_t k) {
	int i, n;
	size_t len;
	int8_t naf[2 * RLC_FP_BITS + 1], *t;

	if (bn_is_zero(k)) {
		ep3_set_infty(r);
		return;
	}

	/* Compute the w-TNAF representation of k. */
	len = 2 * RLC_FP_BITS + 1;
	bn_rec_naf(naf, &len, k, RLC_DEPTH);

	t = naf + len - 1;
	ep3_set_infty(r);
	for (i = len - 1; i >= 0; i--, t--) {
		ep3_dbl(r, r);

		n = *t;
		if (n > 0) {
			ep3_add(r, r, table[n / 2]);
		}
		if (n < 0) {
			ep3_sub(r, r, table[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	ep3_norm(r, r);
	if (bn_sign(k) == RLC_NEG) {
		ep3_neg(r, r);
	}
}

#endif /* EP_FIX == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

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

void ep3_mul_pre_lwnaf(ep3_t *t, const ep3_t p) {
	ep3_tab(t, p, RLC_DEPTH);
}

void ep3_mul_fix_lwnaf(ep3_t r, const ep3_t *t, const bn_t k) {
	bn_t n, _k;

	if (bn_is_zero(k)) {
		ep3_set_infty(r);
		return;
	}

	bn_null(n);
	bn_null(_k);

	RLC_TRY {
		bn_new(n);
		bn_new(_k);

		ep3_curve_get_ord(n);
		bn_mod(_k, k, n);
		ep3_mul_fix_plain(r, t, _k);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_k);
	}
}

#endif
