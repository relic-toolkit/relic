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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"
#include "relic_util.h"

#if FP_PRIME != 255 || FP_RDC == MONTY
#error "This backend only implements the Curve25519 prime without Montgomery form"
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void _fp_mulm_low(dig_t *tmp, const dig_t *f1, dig_t *out, const dig_t *f2);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit) {
	return mpn_addmul_1(c, a, RLC_FP_DIGS, digit);
}

void fp_mul1_low(dig_t *c, const dig_t *a, dig_t digit) {
	dig_t r0, r1, t;

	/* Fold the top digit of a * digit with 2^256 = 38 mod p, keeping the
	 * result below 2^256 like the other functions in this backend. */
	t = bn_mul1_low(c, a, digit, RLC_FP_DIGS);
	RLC_MUL_DIG(r1, r0, t, 38);
	c[0] += r0;
	t = (c[0] < r0);
	c[1] += t;
	t = (c[1] < t);
	c[1] += r1;
	t += (c[1] < r1);
	for (size_t i = 2; i < RLC_FP_DIGS; i++) {
		c[i] += t;
		t = (c[i] < t);
	}
	/* A carry out is worth another 38, and the sum is then small enough
	 * for the addition to stop at the second digit. */
	r0 = 38 * t;
	c[0] += r0;
	c[1] += (c[0] < r0);
}

void fp_muln_low(dig_t *c, const dig_t *a, const dig_t *b) {
	mpn_mul_n(c, a, b, RLC_FP_DIGS);
}

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	rlc_align dig_t t[2 * RLC_FP_DIGS];
	_fp_mulm_low(t, a, c, b);
}
