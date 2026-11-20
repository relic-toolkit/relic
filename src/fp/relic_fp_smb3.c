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
 * Implementation of the cubic residue symbol for prime fields.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fp_smb_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Number of digits of the coordinates of the Eisenstein integers, in two's
 * complement: a few bits more than the square root of p.
 */
#define FP_CUB_DIGS		RLC_CEIL(RLC_FP_BITS / 2 + 6, RLC_DIG)

/**
 * Iterations per jump, which need residues modulo FP_CUB_JM = 3^(FP_CUB_JK +
 * 2): the most for which these residues and the entries of the matrices fit in
 * a digit, with FP_CUB_JM below 2^(RLC_DIG - 2), and the iterations stay below
 * 2^63. FP_CUB_JMI = -FP_CUB_JM^-1 mod 2^RLC_DIG, FP_CUB_JR1 = 2^RLC_DIG mod
 * FP_CUB_JM and FP_CUB_JR2 = 2^(2 * RLC_DIG) mod FP_CUB_JM are for the
 * Montgomery reduction.
 */
#if RLC_DIG == 8
#define FP_CUB_JK		1
#define FP_CUB_JM		((dig_t)27)
#define FP_CUB_JMI		((dig_t)0xed)
#define FP_CUB_JR1		((dig_t)13)
#define FP_CUB_JR2		((dig_t)7)
#elif RLC_DIG == 16
#define FP_CUB_JK		6
#define FP_CUB_JM		((dig_t)6561)
#define FP_CUB_JMI		((dig_t)0xf59f)
#define FP_CUB_JR1		((dig_t)6487)
#define FP_CUB_JR2		((dig_t)5476)
#elif RLC_DIG == 32
#define FP_CUB_JK		16
#define FP_CUB_JM		((dig_t)387420489)
#define FP_CUB_JMI		((dig_t)0xe1d9cf07)
#define FP_CUB_JR1		((dig_t)33341917)
#define FP_CUB_JR2		((dig_t)94494328)
#else
#define FP_CUB_JK		36
#define FP_CUB_JM		((dig_t)1350851717672992089)
#define FP_CUB_JMI		((dig_t)0xf5942fe5e5698517)
#define FP_CUB_JR1		((dig_t)885671743960654459)
#define FP_CUB_JR2		((dig_t)792073204337213275)
#endif

/**
 * Number of iterations of the constant-time symbol, B >= 1.112 log2(p) + 15.12
 * from a convex-hull bound as in safegcd-bounds for |f|, |g| <= sqrt(p), within
 * two iterations of the hull for primes of 128 to 690 bits and with its slope
 * beyond, as tools/relic-smb-hull.py computes and checks.
 */
#define FP_CUB_ITER		RLC_CEIL(FP_PRIME * 139 + 1890, 125)

/**
 * Table of what an iteration does for g = x + y * w, 7 bits per pair 3 * (x mod
 * 3) + (y mod 3): bit 0 if 1 - w divides g, and otherwise the unit u = a + b *
 * w = (+/-) w^-j that makes g primary, with j in bits 1-2, a + 1 in bits 3-4
 * and b + 1 in bits 5-6.
 */
#define FP_CUB_TAB		((uint64_t)0xc62c18cc400a931)

/**
 * Inverse of 3 modulo 2^64.
 */
#define FP_CUB_I3		((uint64_t)0xAAAAAAAAAAAAAAAB)

/**
 * Computes c = (s0 * f0 + s1 * f1 + s2 * g0 + s3 * g1) / d for the coordinates
 * f0, f1, g0, g1 in w of len digits in two's complement, signed digits s_i and
 * an odd digit d dividing the combination, in one pass from the lowest digit:
 * the combination accumulates in a signed double digit, whose digits are
 * divided exactly as they come, with the inverse of d modulo 2^RLC_DIG and the
 * high half of each quotient digit times d as the borrow into the next.
 *
 * @param[out] c			- the result.
 * @param[in] w				- the coordinates.
 * @param[in] s				- the factors.
 * @param[in] d				- the divisor.
 * @param[in] inv			- the inverse of d modulo 2^RLC_DIG.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_comb(dig_t *c, dig_t w[4][FP_CUB_DIGS],
		const dis_t s[4], dig_t d, dig_t inv, size_t len) {
	dig_t lo = 0, hi = 0, b = 0, q, u, v;

	for (size_t j = 0; j < len; j++) {
		/* The top digits need no sign correction, as only the result
		 * modulo 2^(RLC_DIG * len) matters. */
		for (int i = 0; i < 4; i++) {
			RLC_MAC_DIG(hi, lo, s[i], w[i][j], 0);
		}
		u = lo - b;
		b = (lo < b);
		q = RLC_MLO_DIG(u, inv);
		c[j] = q;
		RLC_MUL_DIG(v, u, q, d);
		b += v;
		lo = hi;
		hi = -RLC_SIGN(hi);
	}
}

/**
 * Applies the rows (A, B) and (C, D) over Z[w] of h combined iterations to
 * f = w[0] + w[1] * w and g = w[2] + w[3] * w, computing
 * f' = (A f + B g) / (-3w)^h and g' = (C f + D g) / (-3w)^h into c: the entries
 * times (-w)^-h give four combinations of the coordinates, divided by 3^h.
 *
 * @param[out] c			- the coordinates of f' and g'.
 * @param[in] w				- the coordinates of f and g.
 * @param[in] r				- the rows A, B, C and D, as coordinate pairs.
 * @param[in] h				- the number of iterations.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_apply(dig_t c[4][FP_CUB_DIGS],
		dig_t w[4][FP_CUB_DIGS], const int64_t r[4][2], int h, size_t len) {
	int64_t e[4][2], t;
	dis_t s[4][4];
	dig_t p = 1, pi = 1;

	/* Multiply the entries by (-w)^-h, a power of 1 + w, with
	 * (a + b * w)(1 + w) = (a - b) + a * w. */
	for (int k = 0; k < 4; k++) {
		e[k][0] = r[k][0];
		e[k][1] = r[k][1];
		for (int j = 0; j < h % 6; j++) {
			t = e[k][0] - e[k][1];
			e[k][1] = e[k][0];
			e[k][0] = t;
		}
	}
	/* (m0 + m1 * w)(x + y * w) = (m0 * x - m1 * y) +
	 * (m1 * x + (m0 - m1) * y) * w, for (m, n) = (A, B) and (C, D). */
	for (int k = 0; k < 4; k += 2) {
		s[k][0] = (dis_t)e[k][0];
		s[k][1] = (dis_t)-e[k][1];
		s[k][2] = (dis_t)e[k + 1][0];
		s[k][3] = (dis_t)-e[k + 1][1];
		s[k + 1][0] = (dis_t)e[k][1];
		s[k + 1][1] = (dis_t)(e[k][0] - e[k][1]);
		s[k + 1][2] = (dis_t)e[k + 1][1];
		s[k + 1][3] = (dis_t)(e[k + 1][0] - e[k + 1][1]);
	}
	/* 3^h and its inverse, by squaring and multiplying. */
	for (int j = 5; j >= 0; j--) {
		p *= p;
		pi = RLC_MLO_DIG(pi, pi);
		if ((h >> j) & 1) {
			p *= 3;
			pi = RLC_MLO_DIG(pi, (dig_t)FP_CUB_I3);
		}
	}
	for (int k = 0; k < 4; k++) {
		smb3_comb(c[k], w, s[k], p, pi, len);
	}
}

/**
 * Reduces an integer of len digits in two's complement modulo FP_CUB_JM by
 * Montgomery reduction of each digit a_j times 2^(RLC_DIG * (j + 1)), a power
 * that the reduction of its product with FP_CUB_JR2 updates.
 *
 * @param[in] a				- the integer.
 * @param[in] len			- the number of digits.
 * @return the residue.
 */
static inline dig_t smb3_modj(const dig_t *a, size_t len) {
	const dig_t m = FP_CUB_JM;
	dig_t r = 0, p = FP_CUB_JR1, q = 0, h, l, t, s;

	for (size_t j = 0; j < len; j++) {
		/* Corrections masked by the sign of the difference, as compilers may
		 * turn comparisons into branches. */
		RLC_MUL_DIG(h, l, a[j], p);
		RLC_MUL_DIG(t, s, RLC_MLO_DIG(l, FP_CUB_JMI), m);
		(void)s;
		t += h + (l != 0) - m;
		t += m & (dig_t)((dis_t)t >> (RLC_DIG - 1));
		r += t - m;
		r += m & (dig_t)((dis_t)r >> (RLC_DIG - 1));
		/* The next power, p * 2^RLC_DIG mod m. */
		q = p;
		RLC_MUL_DIG(h, l, p, FP_CUB_JR2);
		RLC_MUL_DIG(t, s, RLC_MLO_DIG(l, FP_CUB_JMI), m);
		p = h + t + (l != 0) - m;
		p += m & (dig_t)((dis_t)p >> (RLC_DIG - 1));
	}
	/* A negative integer is its digits minus 2^(RLC_DIG * len) = q mod m;
	 * no division, as some processors divide in variable time. */
	r += (m - q) & -(a[len - 1] >> (RLC_DIG - 1));
	r -= m;
	r += m & (dig_t)((dis_t)r >> (RLC_DIG - 1));
	return r;
}

/**
 * Reduces an integer of len digits in two's complement modulo 9, in variable
 * time.
 *
 * @param[in] a				- the integer.
 * @param[in] len			- the number of digits.
 * @return the residue.
 */
static int smb3_mod9(const dig_t *a, size_t len) {
	const unsigned b = (unsigned)(RLC_DMASK % 9 + 1) % 9;
	unsigned r = 0, w = 1;

	for (size_t j = 0; j < len; j++) {
		r += (unsigned)(a[j] % 9) * w;
		w = w * b % 9;
	}
	/* A negative integer is its digits minus 2^(RLC_DIG * len) = w mod 9. */
	r += (9 - w) * (unsigned)(a[len - 1] >> (RLC_DIG - 1));
	return (int)(r % 9);
}

/**
 * Reduces a signed integer below 2^61 in absolute value modulo 3, adding 3^39
 * to make it nonnegative. With digits of 16 bits or less, whose processors
 * would divide with a library call, it sums chunks of 16, 8, 4 and 2 bits
 * instead, as 2^(2i) = 1 mod 3, and maps the final sum, at most 5, to its
 * residue.
 *
 * @param[in] a				- the integer.
 * @return the residue in {0, 1, 2}.
 */
static int64_t smb3_c3(uint64_t a) {
#if RLC_DIG >= 32
	return (a + (uint64_t)4052555153018976267) % 3;
#else
	uint32_t x;

	a += (uint64_t)4052555153018976267;
	x = (uint32_t)(a >> 48) + (uint32_t)((a >> 32) & 0xFFFF) +
			(uint32_t)((a >> 16) & 0xFFFF) + (uint32_t)(a & 0xFFFF);
	x = (x >> 16) + ((x >> 8) & 0xFF) + (x & 0xFF);
	x = (x >> 8) + ((x >> 4) & 0xF) + (x & 0xF);
	x = (x >> 4) + ((x >> 2) & 3) + (x & 3);
	x = (x >> 2) + (x & 3);
	return x - 3 * ((x + 1) >> 2);
#endif
}

/**
 * Runs len <= FP_CUB_JK / 2 combined iterations on the residues of f and g in
 * constant time, with the rows (A, B) and (C, D) over Z[w] such that (-3w)^len
 * * (f', g') = (A f + B g, C f + D g). An iteration divides g by 1 - w if it
 * can, and otherwise makes g primary with a unit u and replaces it by (u * g -
 * f) / (1 - w)^2, after swapping f and u * g if delta > 0. The entries grow by
 * at most 3 per iteration, so their coordinates stay below 2^31 and are packed
 * in pairs of 32 bits; f and g do not grow, so theirs stay below 2 * FP_CUB_JM
 * / sqrt(3).
 *
 * @param[out] r			- the rows A, B, C and D, as coordinate pairs.
 * @param[in,out] f			- the residues of f.
 * @param[in,out] g			- the residues of g.
 * @param[in,out] mk		- m and k modulo 3, for f = (3m - 1) + 3k * w.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] len			- the number of iterations.
 */
static void smb3_jhalf(int64_t r[4][2], uint64_t f[2], uint64_t g[2],
		int64_t mk[2], int64_t *d, int64_t *e, int len) {
	/* Values in two's complement modulo 2^64, where exact divisions by 3 are
	 * multiplications by its inverse, and the results of inexact ones are
	 * never selected; the masks are signed, and so are delta and m, k. */
	const uint64_t i3 = FP_CUB_I3;
	uint64_t f0 = f[0], f1 = f[1], g0 = g[0], g1 = g[1], h0, h1, q0, q1;
	int64_t m = mk[0], k = mk[1], tab, dv, sw, ua, ub, j, mu, ku;
	/* The rows as packed coordinates, starting from the identity:
	 * p = ((A.x, B.x), (A.y, B.y), (C.x, D.x), (C.y, D.y)). */
	uint64_t p[4] = { 1, 0, (uint64_t)1 << 32, 0 }, tx, ty, ux, uy;
	/* Local copies, which stay in registers. */
	int64_t dl = *d, el = *e;

	for (; len > 0; len--) {
		/* What to do from g mod 3, with u = 1 for a division. A shift by a
		 * secret amount takes constant time. */
		tab = (int64_t)((FP_CUB_TAB >> (7 * (3 * smb3_c3(g0) +
				smb3_c3(g1)))) & 127);
		dv = -(tab & 1);
		j = (tab >> 1) & 3;
		ua = ((tab >> 3) & 3) - 1;
		ub = (tab >> 5) - 1;
		sw = ~dv & -(int64_t)(dl > 0);
		/* u * g = (a x - b y) + (a y + b (x - y)) w for g = x + y w and
		 * u = a + b w, and u * (C, D) on the packed row. */
		tx = ua * g0 - ub * g1;
		g1 = ua * g1 + ub * (g0 - g1);
		g0 = tx;
		tx = ua * p[2] - ub * p[3];
		ty = ua * p[3] + ub * (p[2] - p[3]);
		mu = smb3_c3((g0 + 1) * i3);
		ku = smb3_c3(g1 * i3);
		/* The exponent, modulo 3: 2m for a division, or j(m + k) for the
		 * unit and 4m = m for (1 - w)^2, with the m of u * g after a swap. */
		el += (2 * m & dv) | ((j * (m + k) + m + ((mu - m) & sw)) & ~dv);
		/* The new delta: d + 2, d + 4, or 4 - d after a swap. */
		dl += 4 - (2 * dl & sw) - (2 & dv);
		/* The new f and g: g / (1 - w), or (u * g - f) / (1 - w)^2. */
		h0 = g0 - (f0 & ~dv);
		h1 = g1 - (f1 & ~dv);
		q0 = (2 * h0 - h1) * i3;
		q1 = (h0 + h1) * i3;
		h0 = (2 * q0 - q1) * i3;
		h1 = (q0 + q1) * i3;
		f0 += (g0 - f0) & sw;
		f1 += (g1 - f1) & sw;
		m += (mu - m) & sw;
		k += (ku - k) & sw;
		g0 = h0 ^ ((h0 ^ q0) & dv);
		g1 = h1 ^ ((h1 ^ q1) & dv);
		/* The rows, over a denominator times (1 - w)^2 = -3w per iteration:
		 * that of f is (A, B), or u * (C, D) after a swap, times (1 - w)^2,
		 * and that of g is u * (C, D) - (A, B), or (C, D) times 1 - w for a
		 * division. */
		ux = tx - p[0];
		uy = ty - p[1];
		p[0] += ux & sw;
		p[1] += uy & sw;
		tx = 3 * p[1];
		p[1] = 3 * (p[1] - p[0]);
		p[0] = tx;
		tx = ux ^ ((ux ^ (p[2] + p[3])) & dv);
		p[3] = uy ^ ((uy ^ (2 * p[3] - p[2])) & dv);
		p[2] = tx;
	}
	f[0] = f0;
	f[1] = f1;
	g[0] = g0;
	g[1] = g1;
	mk[0] = m;
	mk[1] = k;
	*d = dl;
	*e = el;
	/* Unpack the signed entries, the high one with the borrow of the low one,
	 * into the rows (A, B) and (C, D). */
	for (int i = 0; i < 4; i++) {
		r[i & 2][i & 1] = (int64_t)(p[i] << 32) >> 32;
		r[(i & 2) + 1][i & 1] = (int64_t)(p[i] - (uint64_t)r[i & 2][i & 1]) >> 32;
	}
}

/**
 * Computes one jump of n <= FP_CUB_JK iterations on f = w[0] + w[1] * w and g =
 * w[2] + w[3] * w: two halves on their residues give the rows (A, B) and (C, D)
 * with (-3w)^n * (f', g') = (A f + B g, C f + D g), which are applied to f and
 * g in len digits.
 *
 * @param[out] c			- the coordinates of f' and g'.
 * @param[in] w				- the coordinates of f and g.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] n				- the number of iterations.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_jump(dig_t c[4][FP_CUB_DIGS],
		dig_t w[4][FP_CUB_DIGS], int64_t *d, int64_t *e, int n, size_t len) {
	uint64_t f[2], g[2];
	int64_t mk[2], s[4][2], t[4][2], r[4][2];

	f[0] = smb3_modj(w[0], len);
	f[1] = smb3_modj(w[1], len);
	g[0] = smb3_modj(w[2], len);
	g[1] = smb3_modj(w[3], len);
	/* For f = (3m - 1) + 3k * w, m and k modulo 3. */
	mk[0] = smb3_c3((f[0] + 1) * FP_CUB_I3);
	mk[1] = smb3_c3(f[1] * FP_CUB_I3);
	smb3_jhalf(s, f, g, mk, d, e, n / 2);
	smb3_jhalf(t, f, g, mk, d, e, n - n / 2);
	/* The second matrix times the first, entry by entry, with
	 * (a0 + a1 * w)(x0 + x1 * w) = (a0 x0 - a1 x1) + (a0 x1 + a1 x0 - a1 x1) w. */
	for (int i = 0; i < 4; i++) {
		const int64_t *a = t[i & 2], *b = t[(i & 2) + 1];
		const int64_t *x = s[i & 1], *y = s[(i & 1) + 2];
		r[i][0] = a[0] * x[0] - a[1] * x[1] + b[0] * y[0] - b[1] * y[1];
		r[i][1] = a[0] * x[1] + a[1] * x[0] - a[1] * x[1] +
				b[0] * y[1] + b[1] * y[0] - b[1] * y[1];
	}
	smb3_apply(c, w, r, n, len);
}


/**
 * Reduces an exponent of the cubic symbol modulo 3, nonnegative after adding 3.
 */
#define SMB3_MOD(E)		smb3_c3((uint64_t)((E) + 3))

TMPL_FP_SMB(smb3, FP_CUB_DIGS, FP_CUB_ITER, cub, 1, SMB3_MOD)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb3_basic(const fp_t a) {
	fp_t t, u;
	int r = -1;

	fp_null(t);
	fp_null(u);

	/* For p = 2 mod 3 every element is a cube, and zero has no symbol. */
	if (fp_prime_get_mod18() % 3 == 2) {
		return -fp_is_zero(a);
	}

	RLC_TRY {
		fp_new(t);
		fp_new(u);

		/* By Euler's criterion, a^((p - 1)/3) = z^k, and 0 for zero. */
		fp_exp(t, a, &(core_get()->over3));
		/* k from which of 1, z and z^2 is the power, with dv_equ_sec() 0 if
		 * equal and RLC_NE = 2 otherwise, without branches, on the reduced
		 * values, as some backends keep elements below a multiple of p. */
		fp_norm(t, t);
		fp_set_dig(u, 1);
		fp_norm(u, u);
		r += 1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1);
		dv_copy(u, fp_prime_get_cub(), RLC_FP_DIGS);
		fp_norm(u, u);
		r += 2 * (1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1));
		fp_sqr(u, u);
		fp_norm(u, u);
		r += 3 * (1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
		fp_free(u);
	}
	return r;
}

int fp_smb3_binar(const fp_t a) {
	dig_t w[4][FP_CUB_DIGS], c[4][FP_CUB_DIGS], z;
	int64_t x[4], nf, ng, e = 0, tab, dv, sw, j, ua, ub, mf, kf;
	const dig_t i3 = (dig_t)FP_CUB_I3;
	size_t len = FP_CUB_DIGS, l;

	if (fp_is_zero(a)) {
		return -1;
	}
	if (fp_prime_get_mod18() % 3 == 2) {
		return 0;
	}

	smb3_init(w, a);
	/* For f = (3m - 1) + 3k * w, m and k modulo 3. */
	mf = (smb3_mod9(w[0], len) + 1) % 9 / 3;
	kf = smb3_mod9(w[1], len) / 3;
	while (1) {
		z = 0;
		for (l = 0; l < len; l++) {
			z |= w[2][l] | w[3][l];
		}
		if (z == 0) {
			break;
		}
		tab = (int64_t)((FP_CUB_TAB >> (7 * (3 * (smb3_mod9(w[2], len) % 3) +
				smb3_mod9(w[3], len) % 3))) & 127);
		dv = tab & 1;
		j = (tab >> 1) & 3;
		ua = ((tab >> 3) & 3) - 1;
		ub = (tab >> 5) - 1;
		sw = 0;
		if (dv) {
			/* g / (1 - w) = ((2x - y) + (x + y) * w) / 3 for g = x + y * w,
			 * and (1 - w) gives w^(2m). */
			const dis_t s0[4] = { 0, 0, 2, -1 }, s1[4] = { 0, 0, 1, 1 };

			smb3_comb(c[2], w, s0, 3, i3, len);
			smb3_comb(c[3], w, s1, 3, i3, len);
			e += 2 * mf;
		} else {
			/* The factors of (u * g - f) / (1 - w)^2, and of u * g. */
			const dis_t s0[4] = { -1, 1, (dis_t)(ua - ub), (dis_t)-ua };
			const dis_t s1[4] = { -1, 0, (dis_t)ua, (dis_t)-ub };
			const dis_t s2[4] = { 0, 0, (dis_t)ua, (dis_t)-ub };
			const dis_t s3[4] = { 0, 0, (dis_t)ub, (dis_t)(ua - ub) };

			/* u = +/- w^-j gives w^(j(m + k)). */
			e += j * (mf + kf);
			/* Compare N(u * g) = N(g) with N(f), from the bits of the
			 * coordinates below their top one. */
			smb3_top(x, w, len);
			nf = x[0] * x[0] - x[0] * x[1] + x[1] * x[1];
			ng = x[2] * x[2] - x[2] * x[3] + x[3] * x[3];
			/* (u * g - f) / (1 - w)^2 = ((x - y) + x * w) / 3 for
			 * x + y * w = u * g - f, which replaces the one with the larger
			 * norm, and f becomes u * g if that is f, by reciprocity. */
			smb3_comb(c[2], w, s0, 3, i3, len);
			smb3_comb(c[3], w, s1, 3, i3, len);
			sw = (ng < nf);
			if (sw) {
				smb3_comb(c[0], w, s2, 1, 1, len);
				smb3_comb(c[1], w, s3, 1, 1, len);
			}
		}
		/* f only changes after a swap. */
		for (int i = (sw ? 0 : 2); i < 4; i++) {
			dv_copy(w[i], c[i], len);
		}
		if (sw) {
			mf = (smb3_mod9(w[0], len) + 1) % 9 / 3;
			kf = smb3_mod9(w[1], len) / 3;
		}
		/* (1 - w)^2 gives w^(4m) = w^m, with the m of the new f. */
		if (!dv) {
			e += mf;
		}
		len = smb3_shrink(w, len);
	}
	/* g is now 0 and f the unit -1, so the symbol is w^e, divided by that
	 * of R in Montgomery form. */
	return (int)((e + 3 - core_get()->cub_r) % 3);
}

int fp_smb3_divst(const fp_t a) {
	if (fp_prime_get_mod18() % 3 == 2) {
		return -fp_is_zero(a);
	}
	return smb3_symbol(a, 1, 1);
}

int fp_smb3_jmpds(const fp_t a) {
	if (fp_prime_get_mod18() % 3 == 2) {
		return -fp_is_zero(a);
	}
	return smb3_symbol(a, 1, FP_CUB_JK);
}

int fp_smb3_jmpvt(const fp_t a) {
	if (fp_prime_get_mod18() % 3 == 2) {
		return -fp_is_zero(a);
	}
	return smb3_symbol(a, 0, FP_CUB_JK);
}

#if FP_SMB == FP_LOWER

int fp_smb3_lower(const fp_t a) {
	return fp_smb3_low(a);
}

#endif
