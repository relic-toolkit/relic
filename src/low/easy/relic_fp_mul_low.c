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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup fp
 */

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit) {
	dig_t _c, r0, r1, carry = 0;
	for (size_t i = 0; i < RLC_FP_DIGS; i++, a++, c++) {
		/* Multiply the digit *a by d and accumulate with the previous
		 * result in the same columns and the propagated carry. */
		RLC_MUL_DIG(r1, r0, *a, digit);
		_c = r0 + carry;
		carry = r1 + (_c < carry);
		/* Increment the column and assign the result. */
		*c = *c + _c;
		/* Update the carry. */
		carry += (*c < _c);
	}
	return carry;
}

void fp_mul1_low(dig_t *c, const dig_t *a, dig_t digit) {
	const dig_t *p = fp_prime_get();
	dig_t h, l, m, q, u, v, d[RLC_FP_DIGS + 1], r[RLC_FP_DIGS + 1];
	dig_t t[RLC_FP_DIGS + 1];
	size_t s, j, b;

	d[RLC_FP_DIGS] = bn_mul1_low(d, a, digit, RLC_FP_DIGS);

	/* With d = a * digit below 2^(RLC_DIG - 1) * p, the digit
	 * floor(d / 2^(|p| - 1)), times floor(2^(|p| + RLC_DIG - 1) / p) and
	 * divided by 2^RLC_DIG, is at most 2 below floor(d / p). */
	s = (RLC_FP_DIGS - 1) * RLC_DIG + util_bits_dig(p[RLC_FP_DIGS - 1]) - 1;
	j = s >> RLC_DIG_LOG;
	b = s % RLC_DIG;
	q = d[j] >> b;
	if (b > 0) {
		q |= d[j + 1] << (RLC_DIG - b);
	}
	RLC_MUL_DIG(q, l, q, *fp_prime_get_rdc1());

	/* r = d - q * p is below 3p. */
	m = u = 0;
	for (size_t i = 0; i < RLC_FP_DIGS; i++) {
		RLC_MUL_DIG(h, l, q, p[i]);
		l += m;
		h += (l < m);
		v = d[i] - l;
		m = h + (d[i] < l);
		r[i] = v - u;
		u = (v < u);
	}
	r[RLC_FP_DIGS] = d[RLC_FP_DIGS] - m - u;

	/* Subtract p twice in constant time, keeping the nonnegative results. */
	for (int k = 0; k < 2; k++) {
		u = 0;
		for (size_t i = 0; i < RLC_FP_DIGS; i++) {
			v = r[i] - p[i];
			t[i] = v - u;
			u = (r[i] < p[i]) | (v < u);
		}
		t[RLC_FP_DIGS] = r[RLC_FP_DIGS] - u;
		m = (t[RLC_FP_DIGS] >> (RLC_DIG - 1)) - 1;
		for (size_t i = 0; i <= RLC_FP_DIGS; i++) {
			r[i] ^= (r[i] ^ t[i]) & m;
		}
	}
	dv_copy(c, r, RLC_FP_DIGS);
}

void fp_muln_low(dig_t *c, const dig_t *a, const dig_t *b) {
	size_t i, j;
	const dig_t *tmpa, *tmpb;
	dig_t r0, r1, r2;

	r0 = r1 = r2 = 0;
	for (i = 0; i < RLC_FP_DIGS; i++, c++) {
		tmpa = a;
		tmpb = b + i;
		for (j = 0; j <= i; j++, tmpa++, tmpb--) {
			RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
		}
		*c = r0;
		r0 = r1;
		r1 = r2;
		r2 = 0;
	}
	for (i = 0; i < RLC_FP_DIGS; i++, c++) {
		tmpa = a + i + 1;
		tmpb = b + (RLC_FP_DIGS - 1);
		for (j = 0; j < RLC_FP_DIGS - (i + 1); j++, tmpa++, tmpb--) {
			RLC_COMBA_STEP_MUL(r2, r1, r0, *tmpa, *tmpb);
		}
		*c = r0;
		r0 = r1;
		r1 = r2;
		r2 = 0;
	}
}

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	rlc_align dig_t t[2 * RLC_FP_DIGS];

	fp_muln_low(t, a, b);
	fp_rdc(c, t);
}
