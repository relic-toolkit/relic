/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the low-level prime field shifting in a Residue Number
 * System.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Converts an element of the Residue Number System to an integer, by the
 * Chinese Remainder Theorem in the first base, and applies a function to it.
 */
static void rns_int(dig_t *c, const dig_t *a, void (*f)(bn_t, uint_t),
		uint_t bits) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		fp_rns_back(t, a);
		f(t, bits);
		fp_rns_conv(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
}

/**
 * Halves an integer, rounding towards minus infinity, for rns_int().
 */
static void rns_rsh(bn_t t, uint_t bits) {
	if (bn_sign(t) == RLC_NEG) {
		bn_neg(t, t);
		bn_add_dig(t, t, ((dig_t)1 << bits) - 1);
		bn_rsh(t, t, bits);
		bn_neg(t, t);
	} else {
		bn_rsh(t, t, bits);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_lsh1_low(dig_t *c, const dig_t *a) {
	RLC_RNS_MAP(c, RLC_RNS_ADD(a[_i], a[_i], _m[_i]));
	return 0;
}

dig_t fp_lshb_low(dig_t *c, const dig_t *a, uint_t bits) {
	RLC_RNS_MAP(c, rns_mul(a[_i], RLC_RNS_SCL((dig_t)1 << bits, _i), _m[_i], _u[_i]));
	return 0;
}

dig_t fp_rsh1_low(dig_t *c, const dig_t *a) {
	rns_int(c, a, rns_rsh, 1);
	return 0;
}

dig_t fp_rshb_low(dig_t *c, const dig_t *a, uint_t bits) {
	rns_int(c, a, rns_rsh, bits);
	return 0;
}

#endif /* FP_RDC == FP_RENUS */
