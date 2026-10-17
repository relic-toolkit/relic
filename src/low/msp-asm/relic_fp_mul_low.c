/*
 * Copyright 2007-2009 RELIC Project
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file.
 *
 * RELIC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup bn
 */

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit) {
	int i;
	dig_t carry;
	dbl_t r;

	carry = 0;
	for (i = 0; i < RLC_FP_DIGS; i++, a++, c++) {
		/* Multiply the digit *tmpa by b and accumulate with the previous
		 * result in the same columns and the propagated carry. */
		r = (dbl_t)(*c) + (dbl_t)(*a) * (dbl_t)(digit) + (dbl_t)(carry);
		/* Increment the column and assign the result. */
		*c = (dig_t)r;
		/* Update the carry. */
		carry = (dig_t)(r >> (dbl_t)RLC_DIG);
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

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	rlc_align dig_t t[2 * RLC_FP_DIGS];

	fp_muln_low(t, a, b);
	fp_rdc(c, t);
}
