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
 * Implementation of the multiple precision integer recoding functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Returns a maximum of eight contiguous bits from a multiple precision integer.
 *
 * @param[in] a				- the multiple precision integer.
 * @param[in] from			- the first bit position.
 * @param[in] to			- the last bit position, inclusive.
 * @return the bits in the chosen positions.
 */
static char get_bits(const bn_t a, size_t from, size_t to) {
	int f, t;
	dig_t mf, mt;

	RLC_RIP(from, f, from);
	RLC_RIP(to, t, to);

	if (f == t) {
		/* Same digit. */

		mf = RLC_MASK(from);
		if (to + 1 >= RLC_DIG) {
			mt = RLC_DMASK;
		} else {
			mt = RLC_MASK(to + 1);
		}

		mf = mf ^ mt;

		return ((a->dp[f] & (mf)) >> from);
	} else {
		mf = RLC_MASK(RLC_DIG - from) << from;
		mt = RLC_MASK(to + 1);

		return ((a->dp[f] & mf) >> from) |
				((a->dp[t] & mt) << (RLC_DIG - from));
	}
}

/**
 * Tau-adic halving step shared by the TNAF recoders: (r0, r1) <- (r1 + u *
 * r0/2, -r0/2), using tmp as scratch for r0/2.
 */
static void tnaf_hlv(bn_t r0, bn_t r1, bn_t tmp, int8_t u) {
	bn_hlv(tmp, r0);
	if (u == -1) {
		bn_sub(r0, r1, tmp);
	} else {
		bn_add(r0, r1, tmp);
	}
	bn_copy(r1, tmp);
	r1->sign = tmp->sign ^ 1;
}

/**
 * Constant C for the partial reduction modulo (t^m - 1)/(t - 1).
 */
#define MOD_C		8

/**
 * Constant 2^C.
 */
#define MOD_2TC		(1 << MOD_C)

/**
 * Mask to calculate reduction modulo 2^C.
 */
#define MOD_CMASK	(MOD_2TC - 1)

/**
 * Digits g + h * tau of the tau-adic recodings in Z[w], where w is a primitive
 * cube root of unity and tau = 1 - w. Digit 6 * i + u is the unit
 * (-1)^(u / 3) * w^(u % 3) times the i-th base digit, among 1, 2, 1 + tau,
 * 1 - 2 * tau, 2 + tau and 1 + 2 * tau.
 */
static const int8_t tw_g[36] = {
	1, 1, -2, -1, -1, 2, 2, 2, -4, -2, -2, 4,
	1, 4, -5, -1, -4, 5, 1, -5, 4, -1, 5, -4,
	2, 5, -7, -2, -5, 7, 1, 7, -8, -1, -7, 8
};

static const int8_t tw_h[36] = {
	0, -1, 1, 0, 1, -1, 0, -2, 2, 0, 2, -2,
	1, -3, 2, -1, 3, -2, -2, 3, -1, 2, -3, 1,
	1, -4, 3, -1, 4, -3, 2, -5, 3, -2, 5, -3
};

/**
 * Digit of the width-3 tau-NAF for the residues (g mod 9, h mod 3) of a
 * remainder g + h * tau not divisible by tau, using the first three bases.
 */
static const int8_t tw_naf[27] = {
	0, 0, 0, 0, 12, 1, 6, 7, 5,
	0, 0, 0, 13, 11, 14, 16, 17, 8,
	0, 0, 0, 9, 2, 10, 3, 4, 15
};

/**
 * Digit of the regular recoding for the residues (g mod 9, h mod 9) of a
 * remainder g + h * tau not divisible by tau, and the digit itself, in rows
 * for g mod 9 in 1, 2, 4, 5, 7, 8. It is congruent to the remainder modulo
 * tau^3 but not modulo tau^4, so the next remainder is not divisible by tau
 * either.
 */
static const int8_t tw_reg[54] = {
	32, 18, 1, 0, 12, 1, 0, 12, 30,
	26, 7, 5, 6, 7, 5, 6, 24, 34,
	13, 11, 20, 13, 11, 14, 19, 28, 14,
	16, 17, 25, 22, 17, 8, 16, 23, 8,
	29, 31, 27, 9, 2, 10, 9, 2, 10,
	35, 33, 15, 3, 4, 15, 3, 4, 21
};

static const int8_t tw_reg_g[54] = {
	-8, 1, 1, 1, 1, 1, 1, 1, 1,
	-7, 2, 2, 2, 2, 2, 2, 2, -7,
	4, 4, 4, 4, 4, -5, -5, -5, -5,
	-4, 5, 5, 5, 5, -4, -4, -4, -4,
	7, 7, -2, -2, -2, -2, -2, -2, -2,
	8, -1, -1, -1, -1, -1, -1, -1, -1
};

static const int8_t tw_reg_h[54] = {
	3, -2, -1, 0, 1, -1, 0, 1, 2,
	3, -2, -1, 0, -2, -1, 0, 1, 5,
	-3, -2, -1, -3, -2, 2, 3, 4, 2,
	3, -2, -4, -3, -2, 2, 3, 1, 2,
	-3, -5, -1, 0, 1, 2, 0, 1, 2,
	-3, -2, -1, 0, 1, -1, 0, 1, 2
};

/**
 * Reduces modulo 9, in constant time, an integer of s digits in two's
 * complement representation. The weight 2^(i * RLC_DIG) of the i-th digit
 * modulo 9 has period 3 in i for every digit size.
 */
static int tw_mod9(const dig_t *a, size_t s) {
	const dig_t d = (RLC_DMASK % 9 + 1) % 9, w[3] = { 1, d, d * d % 9 };
	dig_t r = 0;

	for (size_t i = 0; i < s; i++) {
		r += (a[i] % 9) * w[i % 3];
	}
	/* Subtract 2^(s * RLC_DIG) for negative integers. */
	r += (a[s - 1] >> (RLC_DIG - 1)) * (9 - w[s % 3]);
	return r % 9;
}

/**
 * Subtracts the digit g + h * tau from a + b * tau.
 */
static void tw_sub(dig_t *a, dig_t *b, int g, int h, size_t s) {
	dig_t c0 = 0, c1 = 0, t, u, x = (dig_t)g, y = (dig_t)h;

	for (size_t i = 0; i < s; i++) {
		t = a[i] - x;
		u = (a[i] < x);
		a[i] = t - c0;
		c0 = u | (t < c0);
		t = b[i] - y;
		u = (b[i] < y);
		b[i] = t - c1;
		c1 = u | (t < c1);
		/* Sign-extend the digit. */
		x = -(dig_t)(g < 0);
		y = -(dig_t)(h < 0);
	}
}

/**
 * Divides a + b * tau by tau, computing (a + b) - (a / 3) * tau when a is a
 * multiple of 3. All the steps go from the least significant digit up: the
 * exact division by 3 multiplies each digit of a, minus the borrow, by the
 * inverse of 3 modulo 2^RLC_DIG.
 */
static void tw_div(dig_t *a, dig_t *b, size_t s) {
	const dig_t e = RLC_DMASK / 3 * 2 + 1;
	dig_t c = 0, n = 1, r = 0, h, l, q, t;

	for (size_t i = 0; i < s; i++) {
		q = (a[i] - r) * e;
		RLC_MUL_DIG(h, l, q, 3);
		r = h + (a[i] < r);
		t = a[i] + c;
		c = (t < c);
		t += b[i];
		c += (t < b[i]);
		a[i] = t;
		b[i] = ~q + n;
		n = (b[i] < n);
	}
	(void)l;
}

/**
 * Divides a + b * tau by tau^3 = 6 * tau - 9, computing (a + 2b) / 3 -
 * ((2a + 3b) / 9) * tau when a is a multiple of 9 and b of 3, in a single pass
 * from the least significant digit up as above.
 */
static void tw_div3(dig_t *a, dig_t *b, size_t s) {
	const dig_t e = RLC_DMASK / 3 * 2 + 1, f = e * e;
	dig_t c0 = 0, c1 = 0, c2 = 0, n = 1, r0 = 0, r1 = 0, h, l, t, u, v;

	for (size_t i = 0; i < s; i++) {
		/* t = a + b, u = a + 2b and v = 2a + 3b. */
		t = a[i] + c0;
		c0 = (t < c0);
		t += b[i];
		c0 += (t < b[i]);
		u = t + c1;
		c1 = (u < c1);
		u += b[i];
		c1 += (u < b[i]);
		v = u + c2;
		c2 = (v < c2);
		v += t;
		c2 += (v < t);
		a[i] = (u - r0) * e;
		RLC_MUL_DIG(h, l, a[i], 3);
		r0 = h + (u < r0);
		t = (v - r1) * f;
		RLC_MUL_DIG(h, l, t, 9);
		r1 = h + (v < r1);
		b[i] = ~t + n;
		n = (b[i] < n);
	}
	(void)l;
}

/**
 * Converts u + v * w to a + b * tau = (u + v) - v * tau, in two's complement
 * representation with s digits.
 */
static void tw_set(dig_t *a, dig_t *b, const bn_t u, const bn_t v, size_t s) {
	dv_zero(a, s);
	dv_zero(b, s);
	dv_copy(a, u->dp, RLC_MIN(u->used, s));
	dv_copy(b, v->dp, RLC_MIN(v->used, s));
	bn_sneg_low(a, a, bn_sign(u), s);
	bn_sneg_low(b, b, bn_sign(v), s);
	bn_addn_low(a, a, b, s);
	bn_sneg_low(b, b, 1, s);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_rec_win(uint8_t *win, size_t *len, const bn_t k, size_t w) {
	size_t i, j, l;

	l = bn_bits(k);

	/* Zero still takes one window. */
	if (*len < (l == 0 ? 1 : RLC_CEIL(l, w))) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	memset(win, 0, *len);

	j = 0;
	if (l == 0) {
		win[j++] = 0;
	} else {
		for (i = 0; i + w < l; i += w) {
			win[j++] = get_bits(k, i, i + w - 1);
		}
		win[j++] = get_bits(k, i, l - 1);
	}
	*len = j;
}

void bn_rec_slw(uint8_t *win, size_t *len, const bn_t k, size_t w) {
	int i, j, s;
	size_t l;

	l = bn_bits(k);

	if (*len < l) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	memset(win, 0, *len);

	i = l - 1;
	j = 0;
	while (i >= 0) {
		if (!bn_get_bit(k, i)) {
			i--;
			win[j++] = 0;
		} else {
			s = RLC_MAX(i - w + 1, 0);
			while (!bn_get_bit(k, s)) {
				s++;
			}
			win[j++] = get_bits(k, s, i);
			i = s - 1;
		}
	}
	*len = j;
}

void bn_rec_naf(int8_t *naf, size_t *len, const bn_t k, size_t w) {
	int i, l;
	bn_t t;
	dig_t t0, mask;
	int8_t u_i;

	if (*len < (bn_bits(k) + 1)) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		bn_abs(t, k);

		mask = RLC_MASK(w);
		l = (1 << w);

		memset(naf, 0, *len);

		i = 0;
		while (!bn_is_zero(t)) {
			if (!bn_is_even(t)) {
				bn_get_dig(&t0, t);
				u_i = t0 & mask;
				if (u_i > l / 2) {
					u_i = (int8_t)(u_i - l);
				}
				bn_sub_dis(t, t, u_i);
				*naf = u_i;
			} else {
				*naf = 0;
			}
			bn_hlv(t, t);
			i++;
			naf++;
		}
		*len = i;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

void bn_rec_tnaf_get(uint8_t *t, int8_t *beta, int8_t *gama, int8_t u,
		size_t w) {
	if (u == -1) {
		switch (w) {
			case 2:
			case 3:
				*t = 2;
				break;
			case 4:
				*t = 10;
				break;
			case 5:
			case 6:
				*t = 26;
				break;
			case 7:
			case 8:
				*t = 90;
				break;
		}
	} else {
		switch (w) {
			case 2:
				*t = 2;
				break;
			case 3:
			case 4:
			case 5:
				*t = 6;
				break;
			case 6:
			case 7:
				*t = 38;
				break;
			case 8:
				*t = 166;
				break;
		}
	}

	beta[0] = 1;
	gama[0] = 0;

	if (w >= 3) {
		beta[1] = 1;
		gama[1] = (int8_t)-u;
	}

	if (w >= 4) {
		beta[1] = -3;
		beta[2] = -1;
		beta[3] = 1;
		gama[1] = gama[2] = gama[3] = (int8_t)u;
	}

	if (w >= 5) {
		beta[4] = -3;
		beta[5] = -1;
		beta[6] = beta[7] = 1;
		gama[4] = gama[5] = gama[6] = (int8_t)(2 * u);
		gama[7] = (int8_t)(-3 * u);
	}

	if (w >= 6) {
		beta[1] = beta[8] = beta[14] = 3;
		beta[2] = beta[9] = beta[15] = 5;
		beta[3] = -5;
		beta[4] = beta[10] = beta[11] = -3;
		beta[5] = beta[12] = -1;
		beta[6] = beta[7] = beta[13] = 1;
		gama[1] = gama[2] = 0;
		gama[3] = gama[4] = gama[5] = gama[6] = (int8_t)(2 * u);
		gama[7] = gama[8] = gama[9] = (int8_t)(-3 * u);
		gama[10] = (int8_t)(4 * u);
		gama[11] = gama[12] = gama[13] = (int8_t)(-u);
		gama[14] = gama[15] = (int8_t)(-u);
	}

	if (w >= 7) {
		beta[3] = beta[22] = beta[29] = 7;
		beta[4] = beta[16] = beta[23] = -5;
		beta[5] = beta[10] = beta[17] = beta[24] = -3;
		beta[6] = beta[11] = beta[18] = beta[25] = beta[30] = -1;
		beta[7] = beta[12] = beta[14] = beta[19] = beta[26] = beta[31] = 1;
		beta[8] = beta[13] = beta[20] = beta[27] = 3;
		beta[9] = beta[21] = beta[28] = 5;
		beta[15] = -7;
		gama[3] = 0;
		gama[4] = gama[5] = gama[6] = (int8_t)(-3 * u);
		gama[11] = gama[12] = gama[13] = (int8_t)(4 * u);
		gama[14] = (int8_t)(-6 * u);
		gama[15] = gama[16] = gama[17] = gama[18] = (int8_t)u;
		gama[19] = gama[20] = gama[21] = gama[22] = (int8_t)u;
		gama[23] = gama[24] = gama[25] = gama[26] = (int8_t)(-2 * u);
		gama[27] = gama[28] = gama[29] = (int8_t)(-2 * u);
		gama[30] = gama[31] = (int8_t)(5 * u);
	}

	if (w == 8) {
		beta[10] = beta[17] = beta[48] = beta[55] = beta[62] = 7;
		beta[11] = beta[18] = beta[49] = beta[56] = beta[63] = 9;
		beta[12] = beta[22] = beta[29] = -3;
		beta[36] = beta[43] = beta[50] = -3;
		beta[13] = beta[23] = beta[30] = beta[37] = -1;
		beta[44] = beta[51] = beta[58] = -1;
		beta[14] = beta[24] = beta[31] = beta[38] = 1;
		beta[45] = beta[52] = beta[59] = 1;
		beta[15] = beta[32] = beta[39] = beta[46] = beta[53] = beta[60] = 3;
		beta[16] = beta[40] = beta[47] = beta[54] = beta[61] = 5;
		beta[19] = beta[57] = 11;
		beta[20] = beta[27] = beta[34] = beta[41] = -7;
		beta[21] = beta[28] = beta[35] = beta[42] = -5;
		beta[25] = -11;
		beta[26] = beta[33] = -9;
		gama[10] = gama[11] = (int8_t)(-3 * u);
		gama[12] = gama[13] = gama[14] = gama[15] = (int8_t)(-6 * u);
		gama[16] = gama[17] = gama[18] = gama[19] = (int8_t)(-6 * u);
		gama[20] = gama[21] = gama[22] = (int8_t)(8 * u);
		gama[23] = gama[24] = (int8_t)(8 * u);
		gama[25] = gama[26] = gama[27] = gama[28] = (int8_t)(5 * u);
		gama[29] = gama[30] = gama[31] = gama[32] = (int8_t)(5 * u);
		gama[33] = gama[34] = gama[35] = gama[36] = (int8_t)(2 * u);
		gama[37] = gama[38] = gama[39] = gama[40] = (int8_t)(2 * u);
		gama[41] = gama[42] = gama[43] = gama[44] = (int8_t)(-1 * u);
		gama[45] = gama[46] = gama[47] = gama[48] = (int8_t)(-1 * u);
		gama[49] = (int8_t)(-1 * u);
		gama[50] = gama[51] = gama[52] = gama[53] = (int8_t)(-4 * u);
		gama[54] = gama[55] = gama[56] = gama[57] = (int8_t)(-4 * u);
		gama[58] = gama[59] = gama[60] = (int8_t)(-7 * u);
		gama[61] = gama[62] = gama[63] = (int8_t)(-7 * u);
	}
}

void bn_rec_tnaf_mod(bn_t r0, bn_t r1, const bn_t k, int u, size_t m) {
	bn_t t, t0, t1, t2, t3;

	bn_null_all(t, t0, t1, t2, t3);

	RLC_TRY {
		bn_new_all(t, t0, t1, t2, t3);

		/* (a0, a1) = (1, 0). */
		bn_set_dig(t0, 1);
		bn_zero(t1);
		/* (b0, b1) = (0, 0). */
		bn_zero(t2);
		bn_zero(t3);
		/* (r0, r1) = (k, 0). */
		bn_abs(r0, k);
		bn_zero(r1);

		for (size_t i = 0; i < m; i++) {
			if (!bn_is_even(r0)) {
				/* r0 = r0 - 1. */
				bn_sub_dig(r0, r0, 1);
				/* (b0, b1) = (b0 + a0, b1 + a1). */
				bn_add(t2, t2, t0);
				bn_add(t3, t3, t1);
			}

			bn_hlv(t, r0);
			/* r0 = r1 + mu * r0 / 2. */
			if (u == -1) {
				bn_sub(r0, r1, t);
			} else {
				bn_add(r0, r1, t);
			}
			/* r1 = - r0 / 2. */
			bn_neg(r1, t);

			bn_dbl(t, t1);
			/* a1 = a0 + mu * a1. */
			if (u == -1) {
				bn_sub(t1, t0, t1);
			} else {
				bn_add(t1, t0, t1);
			}
			/* a0 = - 2 * a1. */
			bn_neg(t0, t);
		}

		/* r0 = r0 + b0, r1 = r1 + b1. */
		bn_add(r0, r0, t2);
		bn_add(r1, r1, t3);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(t, t0, t1, t2, t3);
	}
}

void bn_rec_tnaf(int8_t *tnaf, size_t *len, const bn_t k, int8_t u, size_t m,
		size_t w) {
	int i, l;
	bn_t tmp, r0, r1;
	int8_t beta[64], gama[64];
	uint8_t t_w;
	dig_t t0, t1, mask;
	int s, t, u_i;

	bn_null_all(r0, r1, tmp);

	/* The expansion can be longer than k, so the writes are checked below. */
	if (*len < (bn_bits(k) + 1)) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	RLC_TRY {
		bn_new_all(r0, r1, tmp);

		memset(tnaf, 0, *len);

		bn_rec_tnaf_get(&t_w, beta, gama, u, w);
		bn_abs(tmp, k);
		bn_rec_tnaf_mod(r0, r1, tmp, u, m);

		mask = RLC_MASK(w);
		l = 1 << w;

		i = 0;
		while (!bn_is_zero(r0) || !bn_is_zero(r1)) {
			while ((r0->dp[0] & 1) == 0) {
				if (i < (int)*len) {
					tnaf[i] = 0;
				}
				i++;
				tnaf_hlv(r0, r1, tmp, u);
			}
			/* If r0 is odd. */
			if (w == 2) {
				t0 = r0->dp[0];
				if (bn_sign(r0) == RLC_NEG) {
					t0 = l - t0;
				}
				t1 = r1->dp[0];
				if (bn_sign(r1) == RLC_NEG) {
					t1 = l - t1;
				}
				u_i = 2 - ((t0 - 2 * t1) & mask);
				if (i < (int)*len) {
					tnaf[i] = u_i;
				}
				i++;
				bn_sub_dis(r0, r0, u_i);
			} else {
				/* t0 = r0 mod_s 2^w. */
				t0 = r0->dp[0];
				if (bn_sign(r0) == RLC_NEG) {
					t0 = l - t0;
				}
				/* t1 = r1 mod_s 2^w. */
				t1 = r1->dp[0];
				if (bn_sign(r1) == RLC_NEG) {
					t1 = l - t1;
				}
				/* u = r0 + r1 * (t_w) mod_s 2^w. */
				u_i = (t0 + t_w * t1) & mask;

				if (u_i >= (l / 2)) {
					/* If u < 0, s = -1 and u = -u. */
					u_i = (int8_t)(u_i - l);
					if (i < (int)*len) {
						tnaf[i] = u_i;
					}
					i++;
					u_i = (int8_t)(-u_i >> 1);
					t = -beta[u_i];
					s = -gama[u_i];
				} else {
					/* If u > 0, s = 1. */
					if (i < (int)*len) {
						tnaf[i] = u_i;
					}
					i++;
					u_i = (int8_t)(u_i >> 1);
					t = beta[u_i];
					s = gama[u_i];
				}
				/* r0 = r0 - s * beta_u. */
				bn_sub_dis(r0, r0, t);
				/* r1 = r1 - s * gama_u. */
				bn_sub_dis(r1, r1, s);
			}
			tnaf_hlv(r0, r1, tmp, u);
		}
		if (i > (int)*len) {
			*len = 0;
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			*len = i;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(r0, r1, tmp);
	}
}

void bn_rec_rtnaf(int8_t *tnaf, size_t *len, const bn_t k, int8_t u, size_t m,
		size_t w) {
	int i, l;
	bn_t tmp, r0, r1;
	int8_t beta[64], gama[64];
	uint8_t t_w;
	dig_t t0, t1, mask;
	int s, t, u_i;

	bn_null_all(r0, r1, tmp);

	/* The expansion has l digits and at most two more for the remainder. */
	l = RLC_CEIL(m + 2, (w - 1));
	if (*len < (size_t)l + 2) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	RLC_TRY {
		bn_new_all(r0, r1, tmp);

		memset(tnaf, 0, *len);

		bn_rec_tnaf_get(&t_w, beta, gama, u, w);
		bn_abs(tmp, k);
		bn_rec_tnaf_mod(r0, r1, tmp, u, m);
		mask = RLC_MASK(w);

		/* The regular recoding needs r0 odd, and also r1 odd if w = 2. */
		i = 0;
		if (bn_is_even(r0) || (w == 2 && bn_is_even(r1))) {
			*len = 0;
			RLC_THROW(ERR_NO_VALID);
			l = -2;
		}
		while (i < l) {
			/* If r0 is odd. */
			if (w == 2) {
				t0 = r0->dp[0];
				if (bn_sign(r0) == RLC_NEG) {
					t0 = (1 << w) - t0;
				}
				t1 = r1->dp[0];
				if (bn_sign(r1) == RLC_NEG) {
					t1 = (1 << w) - t1;
				}
				u_i = ((t0 - 2 * t1) & mask) - 2;
				tnaf[i++] = u_i;
				bn_sub_dis(r0, r0, u_i);
			} else {
				/* t0 = r0 mod_s 2^w. */
				t0 = r0->dp[0];
				if (bn_sign(r0) == RLC_NEG) {
					t0 = (1 << w) - t0;
				}
				/* t1 = r1 mod_s 2^w. */
				t1 = r1->dp[0];
				if (bn_sign(r1) == RLC_NEG) {
					t1 = (1 << w) - t1;
				}
				/* u = r0 + r1 * (t_w) mod_s 2^w. */
				u_i = ((t0 + t_w * t1) & mask) - (1 << (w - 1));
				if (u_i < 0) {
					/* If u < 0, s = -1 and u = -u. */
					tnaf[i++] = u_i;
					u_i = (int8_t)(-u_i >> 1);
					t = -beta[u_i];
					s = -gama[u_i];
				} else {
					/* If u > 0, s = 1. */
					tnaf[i++] = u_i;
					u_i = (int8_t)(u_i >> 1);
					t = beta[u_i];
					s = gama[u_i];
				}
				/* r0 = r0 - s * beta_u. */
				bn_sub_dis(r0, r0, t);
				/* r1 = r1 - s * gama_u. */
				bn_sub_dis(r1, r1, s);
			}
			for (size_t j = 0; j < (w - 1); j++) {
				tnaf_hlv(r0, r1, tmp, u);
			}
		}
		s = r0->dp[0];
		t = r1->dp[0];
		if (bn_sign(r0) == RLC_NEG) {
			s = -s;
		}
		if (bn_sign(r1) == RLC_NEG) {
			t = -t;
		}
		if (l < 0) {
			/* Nothing was written for an invalid input. */
		} else if (s != 0 && t != 0) {
			for (int j = 0; j < (1 << (w - 2)); j++) {
				if (beta[j] == s && gama[j] == t) {
					tnaf[i++] = 2 * j + 1;
					break;
				}
			}
			for (int j = 0; j < (1 << (w - 2)); j++) {
				if (beta[j] == -s && gama[j] == -t) {
					tnaf[i++] = -(2 * j + 1);
					break;
				}
			}
		} else {
			if (t != 0) {
				tnaf[i++] = t;
			} else {
				tnaf[i++] = s;
			}
		}
		if (l >= 0) {
			*len = i;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(r0, r1, tmp);
	}
}

void bn_rec_reg(int8_t *naf, size_t *len, const bn_t k, size_t n, size_t w) {
	/* Leave some room in case n and w do not align perfectly. */
	size_t i, l = RLC_CEIL(n, w - 1), d = RLC_CEIL(l * (w - 1), RLC_DIG);
	dig_t mask = RLC_MASK(w), *t = (dig_t *)RLC_ALLOCA(dig_t, d);
	int8_t u_i;

	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (*len <= l) {
		*len = 0;
		RLC_FREE(t);
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	/* The l digits cover l * (w - 1) bits, so larger k cannot be recoded. */
	if (bn_bits(k) > l * (w - 1)) {
		*len = 0;
		RLC_FREE(t);
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	memset(naf, 0, *len);
	dv_zero(t, d);
	dv_copy(t, k->dp, k->used);

	i = 0;
	if (w == 2) {
		for (i = 0; i < l; i++) {
			u_i = (t[0] & mask) - 2;
			t[0] -= u_i;
			naf[i] = u_i;
			bn_rsh1_low(t, t, d);
		}
		naf[i] = t[0];
	} else {
		for (i = 0; i < l; i++) {
			u_i = (t[0] & mask) - (1 << (w - 1));
			t[0] -= u_i;
			naf[i] = u_i;
			bn_rshb_low(t, t, d, w - 1);
		}
		naf[i] = t[0];
	}
	*len = l + 1;
	RLC_FREE(t);
}

void bn_rec_jsf(int8_t *jsf, size_t *len, const bn_t k, const bn_t l) {
	bn_t n0, n1;
	dig_t l0, l1;
	int8_t u0, u1, d0, d1;
	int i, j, offset;

	/* Both rows have max(bits(k), bits(l)) + 1 digits. */
	if (*len < 2 * (RLC_MAX(bn_bits(k), bn_bits(l)) + 1)) {
		*len = 0;
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	bn_null_all(n0, n1);

	RLC_TRY {
		bn_new_all(n0, n1);

		bn_abs(n0, k);
		bn_abs(n1, l);

		i = bn_bits(k);
		j = bn_bits(l);
		offset = RLC_MAX(i, j) + 1;

		memset(jsf, 0, *len);

		i = 0;
		d0 = d1 = 0;
		while (!(bn_is_zero(n0) && d0 == 0) || !(bn_is_zero(n1) && d1 == 0)) {
			bn_get_dig(&l0, n0);
			bn_get_dig(&l1, n1);
			/* For reduction modulo 8. */
			l0 = (l0 + d0) & RLC_MASK(3);
			l1 = (l1 + d1) & RLC_MASK(3);

			if (l0 % 2 == 0) {
				u0 = 0;
			} else {
				u0 = 2 - (l0 & RLC_MASK(2));
				if ((l0 == 3 || l0 == 5) && ((l1 & RLC_MASK(2)) == 2)) {
					u0 = (int8_t)-u0;
				}
			}
			jsf[i] = u0;
			if (l1 % 2 == 0) {
				u1 = 0;
			} else {
				u1 = 2 - (l1 & RLC_MASK(2));
				if ((l1 == 3 || l1 == 5) && ((l0 & RLC_MASK(2)) == 2)) {
					u1 = (int8_t)-u1;
				}
			}
			jsf[i + offset] = u1;

			if (d0 + d0 == 1 + u0) {
				d0 = (int8_t)(1 - d0);
			}
			if (d1 + d1 == 1 + u1) {
				d1 = (int8_t)(1 - d1);
			}

			i++;
			bn_hlv(n0, n0);
			bn_hlv(n1, n1);
		}
		*len = i;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n0, n1);
	}
}

void bn_rec_glv(bn_t k0, bn_t k1, const bn_t k, const bn_t n, const bn_st *v1,
		const bn_st *v2) {
	size_t bits = bn_bits(n), d = bits >> RLC_DIG_LOG, b = bits % RLC_DIG;
	dig_t r, b1[2 * RLC_FP_DIGS + 1] = { 0 }, b2[2 * RLC_FP_DIGS + 1] = { 0 };
	dig_t _k[2 * RLC_FP_DIGS + 1] = { 0 }, _v[2 * RLC_FP_DIGS] = { 0 };

	/* Constant-time, except for the first scalar copy. */

	/* The subscalars are computed in full double precision. */
	bn_grow(k0, 2 * RLC_FP_DIGS + 1);
	bn_grow(k1, 2 * RLC_FP_DIGS + 1);

	/* b1 = (k * v10) >> (bits + 1). */
	dv_copy(_k, k->dp, k->used);
	dv_copy(_v, v1[0].dp, v1[0].used);
	bn_muln_low(b1, _k, _v, RLC_FP_DIGS);
	r = (b1[d] >> b) & (dig_t)1;
	dv_rshd(b1, b1, 2 * RLC_FP_DIGS + 1, d);
	bn_rshb_low(b1, b1, 2 * RLC_FP_DIGS + 1, b);
	bn_rsh1_low(b1, b1, 2 * RLC_FP_DIGS + 1);
	bn_add1_low(b1, b1, r, 2 * RLC_FP_DIGS + 1);

	/* b2 = (k * v20) >> (bits + 1). */
	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, v2[0].dp, v2[0].used);
	bn_muln_low(b2, _k, _v, RLC_FP_DIGS);
	r = (b2[d] >> b) & (dig_t)1;
	dv_rshd(b2, b2, 2 * RLC_FP_DIGS + 1, d);
	bn_rshb_low(b2, b2, 2 * RLC_FP_DIGS + 1, b);
	bn_rsh1_low(b2, b2, 2 * RLC_FP_DIGS + 1);
	bn_add1_low(b2, b2, r, 2 * RLC_FP_DIGS + 1);

	/* k0 = b1 * v11 */
	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, v1[1].dp, v1[1].used);
	bn_muln_low(k0->dp, b1, _v, RLC_FP_DIGS);
	k0->dp[2 * RLC_FP_DIGS] = 0;
	k0->sign = v1[0].sign ^ v1[1].sign;

	/* k1 = b2 * v21 */
	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, v2[1].dp, v2[1].used);
	bn_muln_low(k1->dp, b2, _v, RLC_FP_DIGS);
	k1->dp[2 * RLC_FP_DIGS] = 0;
	k1->sign = v2[0].sign ^ v2[1].sign;

	/* k0 = k - k0 - k1. */
	bn_sneg_low(k0->dp, k0->dp, k0->sign ^ 1, 2 * RLC_FP_DIGS + 1);
	bn_sneg_low(k1->dp, k1->dp, k1->sign ^ 1, 2 * RLC_FP_DIGS + 1);
	bn_addn_low(k0->dp, k0->dp, k1->dp, 2 * RLC_FP_DIGS + 1);
	bn_addn_low(k0->dp, k0->dp, _k, 2 * RLC_FP_DIGS + 1);
	k0->sign = k0->dp[2 * RLC_FP_DIGS] & 1;
	bn_sneg_low(k0->dp, k0->dp, k0->sign, 2 * RLC_FP_DIGS + 1);
	k0->used = 2 * RLC_FP_DIGS;
	bn_trim(k0);

	/* k1 = 0 - b1 * v21 - b2 * v21. */
	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, v1[2].dp, v1[2].used);
	bn_muln_low(k1->dp, b1, _v, RLC_FP_DIGS);
	k1->dp[2 * RLC_FP_DIGS] = 0;
	k1->sign = v1[0].sign ^ v1[2].sign;

	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, v2[2].dp, v2[2].used);
	bn_muln_low(_k, b2, _v, RLC_FP_DIGS);
	_k[2 * RLC_FP_DIGS] = 0;
	r = v2[0].sign ^ v2[2].sign;

	bn_sneg_low(_k, _k, r ^ 1, 2 * RLC_FP_DIGS + 1);
	bn_sneg_low(k1->dp, k1->dp, k1->sign ^ 1, 2 * RLC_FP_DIGS + 1);
	bn_addn_low(k1->dp, k1->dp, _k, 2 * RLC_FP_DIGS + 1);
	k1->sign = k1->dp[2 * RLC_FP_DIGS] & 1;
	bn_sneg_low(k1->dp, k1->dp, k1->sign, 2 * RLC_FP_DIGS + 1);
	k1->used = 2 * RLC_FP_DIGS;
	bn_trim(k1);
}

void bn_rec_sac(int8_t *b, size_t *len, const bn_t *k, const bn_t u, size_t c,
		size_t m, size_t n, int cof) {
	/* Assume k0 is the sign-aligner. */
	bn_t *t = (bn_t *)RLC_ALLOCA(bn_t, m);
	size_t l = RLC_CEIL(n, c * m) + 1;
	int8_t bji;

	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (*len <= l) {
		*len = 0;
		RLC_FREE(t);
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	for (size_t i = 0; i < m; i++) {
		bn_null(t[i]);
	}

	RLC_TRY {
		for (size_t i = 0; i < m; i++) {
			bn_new(t[i]);
		}

		l = RLC_MAX(l, bn_bits(u) + 1);
		for (size_t i = 0; i < m; i++) {
			bn_copy(t[i], k[i]);
			/* The current basis for some curves might be one bit longer. */
			if (cof) {
				l = RLC_MAX(l, bn_bits(t[i]) + 1);
			}
		}
		/* The rows may have grown past the capacity checked above. */
		if (*len < l) {
			*len = 0;
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			memset(b, 0, *len);

			b[l - 1] = 0;
			for (size_t i = 0; i < l - 1; i++) {
				b[i] = 1 - bn_get_bit(k[0], i + 1);
			}
			for (size_t j = 1; j < m; j++) {
				for (size_t i = 0; i < l - 1; i++) {
					bji = bn_get_bit(t[j], 0);
					b[j * l + i] = bji;
					bn_hlv(t[j], t[j]);
					bn_add_dig(t[j], t[j], bji & b[i]);
				}
				b[j * l + l - 1] = bn_get_bit(t[j], 0);
			}
			*len = l;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (size_t i = 0; i < m; i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
	}
}

void bn_rec_frb(bn_t *ki, int sub, const bn_t k, const bn_t x, const bn_t n,
		int cof) {
	int i, sk, sx;
	size_t l;
	bn_t u[4], v[4];

	for (i = 0; i < 4; i++) {
		bn_null(u[i]);
		bn_null(v[i]);
	}

	RLC_TRY {
		for (i = 0; i < 4; i++) {
			bn_new(u[i]);
			bn_new(v[i]);
		}

		if (cof == 0) {
			bn_abs(v[0], k);
			bn_abs(u[0], x);

			sk = bn_sign(k);
			sx = bn_sign(x);

			for (i = 0; i < sub; i++) {
				bn_mod(ki[i], v[0], u[0]);
				bn_div(v[0], v[0], u[0]);
				if ((sx == RLC_NEG) && (i % 2 != 0)) {
					bn_neg(ki[i], ki[i]);
				}
				if (sk == RLC_NEG) {
					bn_neg(ki[i], ki[i]);
				}
			}
		} else {
			bn_copy(v[1], x);
			bn_copy(v[2], x);
			bn_copy(v[3], x);

			/* t = 2x^2. */
			bn_sqr(u[3], x);
			bn_dbl(u[3], u[3]);

			/* v0 = 2x^2 + 3x + 1. */
			bn_mul_dig(v[0], x, 3);
			bn_add_dig(v[0], v[0], 1);
			bn_add(v[0], v[0], u[3]);

			/* v3 = -(2x^2 + x). */
			bn_add(v[3], v[3], u[3]);
			bn_neg(v[3], v[3]);

			/* v1 = 12x^3 + 8x^2 + x, v2 = 6x^3 + 4x^2 + x. */
			bn_dbl(u[3], u[3]);
			bn_add(v[2], v[2], u[3]);
			bn_dbl(u[3], u[3]);
			bn_add(v[1], v[1], u[3]);
			bn_rsh(u[3], u[3], 2);
			bn_mul(u[3], u[3], x);
			bn_mul_dig(u[3], u[3], 3);
			bn_add(v[2], v[2], u[3]);
			bn_dbl(u[3], u[3]);
			bn_add(v[1], v[1], u[3]);

			for (i = 0; i < 4; i++) {
				bn_mul(v[i], v[i], k);
				bn_div(v[i], v[i], n);
				if (bn_sign(v[i]) == RLC_NEG) {
					bn_add_dig(v[i], v[i], 1);
				}
			}

			/* u0 = x + 1, u1 = 2x + 1, u2 = 2x, u3 = x - 1. */
			bn_dbl(u[2], x);
			bn_add_dig(u[1], u[2], 1);
			bn_sub_dig(u[3], x, 1);
			bn_add_dig(u[0], x, 1);
			bn_copy(ki[0], k);
			bn_zero(ki[1]);
			bn_zero(ki[2]);
			bn_zero(ki[3]);
			for (i = 0; i < 4; i++) {
				bn_mul(u[i], u[i], v[i]);
				bn_mod(u[i], u[i], n);
				bn_add(ki[0], ki[0], n);
				bn_sub(ki[0], ki[0], u[i]);
				bn_mod(ki[0], ki[0], n);
			}

			/* u0 = x, u1 = -x, u2 = 2x + 1, u3 = 4x + 2. */
			bn_copy(u[0], x);
			bn_neg(u[1], x);
			bn_dbl(u[2], x);
			bn_add_dig(u[2], u[2], 1);
			bn_dbl(u[3], u[2]);
			for (i = 0; i < 4; i++) {
				bn_mul(u[i], u[i], v[i]);
				bn_mod(u[i], u[i], n);
				bn_add(ki[1], ki[1], n);
				bn_sub(ki[1], ki[1], u[i]);
				bn_mod(ki[1], ki[1], n);
			}

			/* u0 = x, u1 = -(x + 1), u2 = 2x + 1, u3 = -(2x - 1). */
			bn_copy(u[0], x);
			bn_add_dig(u[1], x, 1);
			bn_neg(u[1], u[1]);
			bn_dbl(u[2], x);
			bn_add_dig(u[2], u[2], 1);
			bn_sub_dig(u[3], u[2], 2);
			bn_neg(u[3], u[3]);
			for (i = 0; i < 4; i++) {
				bn_mul(u[i], u[i], v[i]);
				bn_mod(u[i], u[i], n);
				bn_add(ki[2], ki[2], n);
				bn_sub(ki[2], ki[2], u[i]);
				bn_mod(ki[2], ki[2], n);
			}

			/* u0 = -2x, u1 = -x, u2 = 2x + 1, u3 = x - 1. */
			bn_dbl(u[0], x);
			bn_neg(u[0], u[0]);
			bn_dbl(u[2], x);
			bn_add_dig(u[2], u[2], 1);
			bn_sub_dig(u[3], x, 1);
			bn_neg(u[1], x);
			for (i = 0; i < 4; i++) {
				bn_mul(u[i], u[i], v[i]);
				bn_mod(u[i], u[i], n);
				bn_add(ki[3], ki[3], n);
				bn_sub(ki[3], ki[3], u[i]);
				bn_mod(ki[3], ki[3], n);
			}

			for (i = 0; i < 4; i++) {
				l = bn_bits(ki[i]);
				bn_sub(ki[i], n, ki[i]);
				if (bn_bits(ki[i]) > l) {
					bn_sub(ki[i], ki[i], n);
					ki[i]->sign = RLC_POS;
				} else {
					ki[i]->sign = RLC_NEG;
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (i = 0; i < 4; i++) {
			bn_free(u[i]);
			bn_free(v[i]);
		}
	}
}

void bn_rec_etnaf(int8_t *naf, size_t *len, const bn_t u, const bn_t v) {
	/* One digit more absorbs the growth of the remainders. */
	size_t l, s = RLC_MAX(u->used, v->used) + 1;
	dig_t a[RLC_BN_DIGS + 1], b[RLC_BN_DIGS + 1], z;
	int d;

	if (s > RLC_BN_DIGS + 1) {
		RLC_THROW(ERR_NO_PRECI);
		return;
	}

	tw_set(a, b, u, v, s);
	for (l = 0; ; l++) {
		z = 0;
		for (size_t i = 0; i < s; i++) {
			z |= a[i] | b[i];
		}
		if (z == 0) {
			break;
		}
		if (l + 3 > *len) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
		d = tw_mod9(a, s);
		if (d % 3 == 0) {
			naf[l] = 0;
			tw_div(a, b, s);
		} else {
			/* A digit is followed by two zeros. */
			d = tw_naf[3 * d + tw_mod9(b, s) % 3];
			tw_sub(a, b, tw_g[d], tw_h[d], s);
			naf[l] = d + 1;
			naf[l + 1] = naf[l + 2] = 0;
			l += 2;
			tw_div3(a, b, s);
		}
	}
	while (l > 0 && naf[l - 1] == 0) {
		l--;
	}
	*len = l;
}

void bn_rec_retnaf(int8_t *reg, int8_t *c, size_t len, const bn_t u,
		const bn_t v) {
	/* The remainders have absolute value below 27^(len/2) * 2 and their
	 * coordinates grow by a few bits in the divisions. */
	size_t s = RLC_MAX(RLC_CEIL(12 * len / 5 + 8, RLC_DIG),
			RLC_MAX(u->used, v->used) + 1);
	dig_t a[RLC_BN_DIGS + 1], b[RLC_BN_DIGS + 1];
	int d, e, g, h;

	if (s > RLC_BN_DIGS + 1) {
		RLC_THROW(ERR_NO_PRECI);
		return;
	}

	tw_set(a, b, u, v, s);
	/* Make a + b * tau not divisible by tau. */
	*c = (tw_mod9(a, s) % 3 == 0);
	tw_sub(a, b, -(int)*c, 0, s);
	for (size_t i = 0; i < len; i++) {
		e = tw_mod9(a, s);
		e = 9 * (e - e / 3 - 1) + tw_mod9(b, s);
		d = g = h = 0;
		for (int j = 0; j < 54; j++) {
			d |= tw_reg[j] & -(j == e);
			g |= tw_reg_g[j] & -(j == e);
			h |= tw_reg_h[j] & -(j == e);
		}
		reg[i] = d;
		tw_sub(a, b, g, h, s);
		tw_div3(a, b, s);
	}
	/* The remainder is a unit, the top digit. */
	d = 0;
	for (int j = 0; j < 6; j++) {
		d |= j & -((a[0] == (dig_t)tw_g[j]) & (b[0] == (dig_t)tw_h[j]));
	}
	reg[len] = d;
}
