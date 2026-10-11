/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of fixed point multiplication on binary elliptic curves.
 *
 * @ingroup eb
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies a binary elliptic curve point by an integer using the w-TNAF
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void eb_mul_fix_kbltz(eb_t r, const eb_t *t, const bn_t k) {
	int i, n;
	int8_t u, tnaf[RLC_FB_BITS + 8];
	size_t l;

	if (eb_curve_opt_a() == RLC_ZERO) {
		u = -1;
	} else {
		u = 1;
	}

	/* Compute the w-TNAF representation of k. */
	l = sizeof(tnaf);
	bn_rec_tnaf(tnaf, &l, k, u, RLC_FB_BITS, RLC_DEPTH);

	eb_set_infty(r);
	for (i = l - 1; i >= 0; i--) {
		eb_frb(r, r);

		n = tnaf[i];
		if (n > 0) {
			eb_add(r, r, t[n / 2]);
		}
		if (n < 0) {
			eb_sub(r, r, t[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	eb_norm(r, r);
}

/**
 * Multiplies a binary elliptic curve point by an integer using the w-NAF
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void eb_mul_fix_naf(eb_t r, const eb_t *t, const bn_t k) {
	int i, n;
	int8_t naf[RLC_FB_BITS + 1];
	size_t l;

	/* Compute the w-NAF representation of k. */
	l = RLC_FB_BITS + 1;
	bn_rec_naf(naf, &l, k, RLC_DEPTH);

	eb_set_infty(r);
	for (i = l - 1; i >= 0; i--) {
		eb_dbl(r, r);

		n = naf[i];
		if (n > 0) {
			eb_add(r, r, t[n / 2]);
		}
		if (n < 0) {
			eb_sub(r, r, t[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	eb_norm(r, r);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EC_MUL_FIX_BASIC(eb, plain);

TMPL_EC_MUL_FIX_LWREG(eb, fb, plain, 1, RLC_FB_BITS);

TMPL_EC_MUL_COMBD(eb);

void eb_mul_pre_lwnaf(eb_t *t, const eb_t p) {
	eb_tab(t, p, RLC_DEPTH);
}

void eb_mul_fix_lwnaf(eb_t r, const eb_t *t, const bn_t k) {
	bn_t n, _k;

	bn_null_all(n, _k);

	RLC_TRY {
		bn_new_all(n, _k);

		/* Reduce the scalar here to simplify the static functions. */
		eb_curve_get_ord(n);
		bn_mod(_k, k, n);

		if (eb_curve_is_kbltz()) {
			eb_mul_fix_kbltz(r, t, _k);
		} else {
			eb_mul_fix_naf(r, t, _k);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k);
	}
}
