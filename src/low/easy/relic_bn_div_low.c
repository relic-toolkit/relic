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
 * Implementation of the low-level multiple precision integer division
 * functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_divn_low(dig_t *c, dig_t *d, const dig_t *a, size_t sa, const dig_t *b,
		size_t sb) {
	int norm, i, n, t, sd;
	dig_t carry, t1[3], t2[3];
	/* Make backup copies of operands and adjust pointers. */
	dig_t *x = RLC_ALLOCA(dig_t, sa + 1), *y = RLC_ALLOCA(dig_t, sa + 1);

	dv_copy(x, a, sa);
	dv_copy(y, b, sb);
	x[sa] = y[sb] = 0;

	dv_zero(c, sa + 1);
	/* Normalize x and y so that the leading digit of y is bigger than
	 * 2^(RLC_DIG-1). */
	norm = util_bits_dig(y[sb - 1]) % RLC_DIG;

	if (norm < (int)(RLC_DIG - 1)) {
		norm = (RLC_DIG - 1) - norm;
		carry = bn_lshb_low(x, x, sa, norm);
		if (carry) {
			x[sa++] = carry;
		}
		carry = bn_lshb_low(y, y, sb, norm);
		if (carry) {
			y[sb++] = carry;
		}
	} else {
		norm = 0;
	}

	n = sa - 1;
	t = sb - 1;

	/* Shift y so that the most significant digit of y is aligned with the
	 * most significant digit of x. */
	dv_lshd(y, y, sb + (n - t), (n - t));

	/* Find the most significant digit of the quotient. */
	while (dv_cmp(x, y, sa) != RLC_LT) {
		c[n - t]++;
		bn_subn_low(x, x, y, sa);
	}

	/* Shift y back. */
	dv_rshd(y, y, sb + (n - t), (n - t));

	/* Find the remaining digits. */
	for (i = n; i >= (t + 1); i--) {
		if (i > sa) {
			continue;
		}

		if (x[i] == y[t]) {
			c[i - t - 1] = RLC_MASK(RLC_DIG);
		} else {
			RLC_DIV_DIG(c[i - t - 1], carry, x[i], x[i - 1], y[t]);
		}

		c[i - t - 1]++;
		do {
			c[i - t - 1]--;
			t1[0] = (t - 1 < 0) ? 0 : y[t - 1];
			t1[1] = y[t];

			carry = bn_mul1_low(t1, t1, c[i - t - 1], 2);
			t1[2] = carry;

			t2[0] = (i - 2 < 0) ? 0 : x[i - 2];
			t2[1] = (i - 1 < 0) ? 0 : x[i - 1];
			t2[2] = x[i];
		} while (dv_cmp(t1, t2, 3) == RLC_GT);

		carry = bn_mul1_low(d, y, c[i - t - 1], sb);
		sd = sb;
		if (carry) {
			d[sd++] = carry;
		}

		carry = bn_subn_low(x + (i - t - 1), x + (i - t - 1), d, sd);
		sd += (i - t - 1);
		if (sa > sd) {
			carry = bn_sub1_low(x + sd, x + sd, carry, sa - sd);
		}

		if (carry) {
			sd = sb + (i - t - 1);
			carry = bn_addn_low(x + (i - t - 1), x + (i - t - 1), y, sb);
			carry = bn_add1_low(x + sd, x + sd, carry, sa - sd);
			c[i - t - 1]--;
		}
	}
	/* Remainder should be not be longer than the divisor. */
	bn_rshb_low(d, x, sb, norm);
	RLC_FREE(x);
	RLC_FREE(y);
}

void bn_div1_low(dig_t *c, dig_t *d, const dig_t *a, dig_t b, size_t size) {
	dig_t q, r, w = 0;

	for (int i = size - 1; i >= 0; i--) {
		RLC_DIV_DIG(q, r, w, a[i], b);
		c[i] = q;
		w = r;
	}
	*d = (dig_t)w;
}
