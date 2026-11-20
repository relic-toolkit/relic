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
 * beyond, as tools/relic-cub-hull.py computes and checks.
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
 * Divides an integer of len digits in two's complement exactly by an odd digit,
 * from the lowest digit with the inverse modulo 2^RLC_DIG, the high half of
 * each product being the borrow into the next: two products per digit and no
 * division.
 *
 * @param[out] c			- the quotient.
 * @param[in] a				- the integer, a multiple of d.
 * @param[in] d				- the odd divisor.
 * @param[in] inv			- the inverse of d modulo 2^RLC_DIG.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_divd(dig_t *c, const dig_t *a, dig_t d, dig_t inv,
		size_t len) {
	dig_t b = 0, h, l, q;

	for (size_t j = 0; j < len; j++) {
		l = a[j] - b;
		b = (a[j] < b);
		q = RLC_MLO_DIG(l, inv);
		c[j] = q;
		/* The borrow is the high digit of d * q, the low one being l. */
		RLC_MUL_DIG(h, l, q, d);
		b += h;
	}
}

/**
 * Computes c = s0 * a0 + s1 * a1 + s2 * a2 + s3 * a3 for integers of len digits
 * in two's complement and signed digits s_i, with each negative term added as a
 * complement plus one.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the integers.
 * @param[in] s				- the factors, signed digits.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_lin(dig_t *c, const dig_t *a[4], const dis_t s[4],
		size_t len) {
	dig_t ms[4], ns[4], cs[4] = { 0, 0, 0, 0 }, k = 0, h, l, d;

	for (int i = 0; i < 4; i++) {
		ms[i] = (dig_t)(s[i] < 0 ? -s[i] : s[i]);
		ns[i] = -(dig_t)(s[i] < 0);
		k += (s[i] < 0);
	}
	for (size_t j = 0; j < len; j++) {
		d = k;
		k = 0;
		for (int i = 0; i < 4; i++) {
			RLC_MUL_DIG(h, l, ms[i], a[i][j]);
			l += cs[i];
			cs[i] = h + (l < cs[i]);
			l ^= ns[i];
			d += l;
			k += (d < l);
		}
		c[j] = d;
	}
}

/**
 * Multiplies two Eisenstein integers with signed coordinates.
 *
 * @param[out] c			- the product.
 * @param[in] a				- the first factor.
 * @param[in] b				- the second factor.
 */
static void smb3_emul(int64_t c[2], const int64_t a[2], const int64_t b[2]) {
	c[0] = a[0] * b[0] - a[1] * b[1];
	c[1] = a[0] * b[1] + a[1] * b[0] - a[1] * b[1];
}

/**
 * Computes (m * alpha + n * beta) / (1 - w)^(2h) in len digits, where the
 * division is exact, for alpha = x + y * w and beta = u + v * w.
 *
 * @param[out] c0			- the first coordinate of the result.
 * @param[out] c1			- the second coordinate of the result.
 * @param[in] m				- the factor of alpha.
 * @param[in] n				- the factor of beta.
 * @param[in] h				- half the power of 1 - w to divide by.
 * @param[in] x				- the first coordinate of alpha.
 * @param[in] y				- the second coordinate of alpha.
 * @param[in] u				- the first coordinate of beta.
 * @param[in] v				- the second coordinate of beta.
 * @param[in] len			- the number of digits.
 */
static inline void smb3_row(dig_t *c0, dig_t *c1, const int64_t m[2],
		const int64_t n[2], int h, const dig_t *x, const dig_t *y,
		const dig_t *u, const dig_t *v, size_t len) {
	/* (1 - w)^(2h) = (-3w)^h, so first multiply m and n by the unit
	 * (-w)^-h, a power of 1 + w with (a + b * w)(1 + w) = (a - b) + a * w. */
	const dig_t *f[4] = { x, y, u, v };
	int64_t m0 = m[0], m1 = m[1], n0 = n[0], n1 = n[1], t;
	dis_t f0[4], f1[4];
	dig_t p = 1, pi = 1;

	for (int j = 0; j < h % 6; j++) {
		t = m0 - m1;
		m1 = m0;
		m0 = t;
		t = n0 - n1;
		n1 = n0;
		n0 = t;
	}
	/* (m0 + m1 * w)(x + y * w) = (m0 * x - m1 * y) +
	 * (m1 * x + (m0 - m1) * y) * w, and the same for n and beta. */
	f0[0] = (dis_t)m0;
	f0[1] = (dis_t)-m1;
	f0[2] = (dis_t)n0;
	f0[3] = (dis_t)-n1;
	f1[0] = (dis_t)m1;
	f1[1] = (dis_t)(m0 - m1);
	f1[2] = (dis_t)n1;
	f1[3] = (dis_t)(n0 - n1);

	smb3_lin(c0, f, f0, len);
	smb3_lin(c1, f, f1, len);
	/* Divide by 3^h, with 3^h and its inverse by squaring and multiplying. */
	for (int j = 5; j >= 0; j--) {
		p *= p;
		pi = RLC_MLO_DIG(pi, pi);
		if ((h >> j) & 1) {
			p *= 3;
			pi = RLC_MLO_DIG(pi, (dig_t)FP_CUB_I3);
		}
	}
	smb3_divd(c0, c0, p, pi, len);
	smb3_divd(c1, c1, p, pi, len);
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
	int64_t mk[2], s[4][2], t[4][2], r[4][2], u[2], v[2];

	f[0] = smb3_modj(w[0], len);
	f[1] = smb3_modj(w[1], len);
	g[0] = smb3_modj(w[2], len);
	g[1] = smb3_modj(w[3], len);
	/* For f = (3m - 1) + 3k * w, m and k modulo 3. */
	mk[0] = smb3_c3((f[0] + 1) * FP_CUB_I3);
	mk[1] = smb3_c3(f[1] * FP_CUB_I3);
	smb3_jhalf(s, f, g, mk, d, e, n / 2);
	smb3_jhalf(t, f, g, mk, d, e, n - n / 2);
	/* The second matrix times the first. */
	for (int i = 0; i < 2; i++) {
		smb3_emul(u, t[2 * i], s[0]);
		smb3_emul(v, t[2 * i + 1], s[2]);
		r[2 * i][0] = u[0] + v[0];
		r[2 * i][1] = u[1] + v[1];
		smb3_emul(u, t[2 * i], s[1]);
		smb3_emul(v, t[2 * i + 1], s[3]);
		r[2 * i + 1][0] = u[0] + v[0];
		r[2 * i + 1][1] = u[1] + v[1];
	}
	smb3_row(c[0], c[1], r[0], r[1], n, w[0], w[1], w[2], w[3], len);
	smb3_row(c[2], c[3], r[2], r[3], n, w[0], w[1], w[2], w[3], len);
}

/**
 * Starts the symbol of a nonzero element for p = 1 mod 3 with f = pi and g = a
 * - q * pi, of norm below p, for q the rounded a / pi from the scaled inverse
 * of pi, in constant time.
 *
 * @param[out] w			- the coordinates of f and g.
 * @param[in] a				- the prime field element.
 */
static void smb3_init(dig_t w[4][FP_CUB_DIGS], const fp_t a) {
	ctx_t *ctx = core_get();
	dig_t g[RLC_FP_DIGS + 1], *x = w[2], *y = w[3];
	dig_t q[2][FP_CUB_DIGS], h[2 * (RLC_FP_DIGS + 1)], z[FP_CUB_DIGS];
	dig_t t[FP_CUB_DIGS], c;
	const dig_t *u = ctx->cub_pi[0], *v = ctx->cub_pi[1];

	/* The stored digits of a, the integer a * R mod p in Montgomery form,
	 * whose symbol is that of a times that of R. */
	dv_copy(g, a, RLC_FP_DIGS);
	g[RLC_FP_DIGS] = 0;
	dv_zero(z, FP_CUB_DIGS);
	for (int j = 0; j < 2; j++) {
		bn_muln_low(h, g, ctx->cub_inv[j], RLC_FP_DIGS + 1);
		dv_copy(q[j], h + RLC_FP_DIGS + 1, FP_CUB_DIGS);
		/* Round with the top bit of the fraction, propagating the carry
		 * through all digits so that the time does not depend on it. */
		c = h[RLC_FP_DIGS] >> (RLC_DIG - 1);
		for (size_t i = 0; i < FP_CUB_DIGS; i++) {
			q[j][i] += c;
			c = (q[j][i] < c);
		}
		/* The signs of the inverse are public. */
		if (ctx->cub_sgn[j] == RLC_NEG) {
			bn_subn_low(q[j], z, q[j], FP_CUB_DIGS);
		}
	}
	/* q * pi = (q0 * u - q1 * v) + (q0 * v + q1 * (u - v)) * w. */
	dv_copy(x, g, FP_CUB_DIGS);
	dv_zero(y, FP_CUB_DIGS);
	bn_muln_low(h, q[0], u, FP_CUB_DIGS);
	bn_subn_low(x, x, h, FP_CUB_DIGS);
	bn_muln_low(h, q[1], v, FP_CUB_DIGS);
	bn_addn_low(x, x, h, FP_CUB_DIGS);
	bn_muln_low(h, q[0], v, FP_CUB_DIGS);
	bn_subn_low(y, y, h, FP_CUB_DIGS);
	bn_subn_low(t, u, v, FP_CUB_DIGS);
	bn_muln_low(h, q[1], t, FP_CUB_DIGS);
	bn_subn_low(y, y, h, FP_CUB_DIGS);
	/* The coordinates of pi also fit in FP_CUB_DIGS digits. */
	dv_copy(w[0], u, FP_CUB_DIGS);
	dv_copy(w[1], v, FP_CUB_DIGS);
}

/**
 * Returns the number of digits that f and g need, in variable time. They do not
 * grow, but a coordinate may double, so the largest stays below 2^(RLC_DIG *
 * len - 3); digits that come back are sign-extended.
 *
 * @param[in,out] w			- the coordinates of f and g.
 * @param[in] len			- the current number of digits.
 * @return the new number of digits.
 */
static size_t smb3_shrink(dig_t w[4][FP_CUB_DIGS], size_t len) {
	dig_t s;
	size_t t = 1;

	for (int j = 0; j < 4; j++) {
		s = -(w[j][len - 1] >> (RLC_DIG - 1));
		for (size_t l = len; l > 0; l--) {
			if ((w[j][l - 1] ^ s) != 0) {
				t = RLC_MAX(t, l + (((w[j][l - 1] ^ s) >> (RLC_DIG - 3)) != 0));
				break;
			}
		}
	}
	t = RLC_MIN(t, (size_t)FP_CUB_DIGS);
	for (int j = 0; j < 4; j++) {
		s = -(w[j][len - 1] >> (RLC_DIG - 1));
		for (size_t l = len; l < t; l++) {
			w[j][l] = s;
		}
	}
	return t;
}

/**
 * Computes the cubic residue symbol by jumps of up to k combined divsteps, a
 * fixed number of them in constant time or until g is 0, with -1 for zero and 0
 * for p = 2 mod 3.
 *
 * @param[in] a				- the prime field element.
 * @param[in] ct			- the flag to run in constant time.
 * @param[in] k				- the largest number of iterations per jump.
 * @return k in {0, 1, 2}, or -1 if the element is zero.
 */
static int smb3_symbol(const fp_t a, int ct, int k) {
	dig_t w[4][FP_CUB_DIGS], c[4][FP_CUB_DIGS], z = 0;
	int64_t d = 1, e = 0;
	size_t len = FP_CUB_DIGS;
	int zero;

	for (size_t j = 0; j < RLC_FP_DIGS; j++) {
		z |= a[j];
	}
	zero = (z == 0);
	if (!ct && zero) {
		return -1;
	}
	if (fp_prime_get_mod18() % 3 == 2) {
		return -zero;
	}

	smb3_init(w, a);
	for (int i = 0, n; i < FP_CUB_ITER; i += n) {
		n = RLC_MIN(k, FP_CUB_ITER - i);
		/* Without constant time, stop once g is 0. */
		if (!ct) {
			z = 0;
			for (size_t j = 0; j < len; j++) {
				z |= w[2][j] | w[3][j];
			}
			if (z == 0) {
				break;
			}
		}
		/* A fixed number of digits in constant time, so that the compiler can
		 * specialize the loops for it. */
		if (ct) {
			smb3_jump(c, w, &d, &e, n, FP_CUB_DIGS);
		} else {
			smb3_jump(c, w, &d, &e, n, len);
		}
		for (int j = 0; j < 4; j++) {
			dv_copy(w[j], c[j], len);
		}
		/* Without constant time, keep only the digits that f and g need. */
		if (!ct) {
			len = smb3_shrink(w, len);
		}
	}
	/* g is now 0 and f the unit -1, so the symbol is w^e, divided by that
	 * of R in Montgomery form; zero has no symbol. */
	return (int)smb3_c3((uint64_t)(e + 3 - core_get()->cub_r)) | -zero;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb3_basic(const fp_t a) {
	fp_t t, u;
	int r = -1;

	fp_null(t);
	fp_null(u);

	if (fp_prime_get_mod18() % 3 == 2) {
		return smb3_symbol(a, 1, 0);
	}

	RLC_TRY {
		fp_new(t);
		fp_new(u);

		/* By Euler's criterion, a^((p - 1)/3) = z^k, and 0 for zero. */
		fp_exp(t, a, &(core_get()->over3));
		/* k from which of 1, z and z^2 is the power, with dv_equ_sec() 0 if
		 * equal and RLC_NE = 2 otherwise, without branches. */
		fp_set_dig(u, 1);
		r += 1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1);
		r += 2 * (1 - (dv_equ_sec(t, fp_prime_get_cub(), RLC_FP_DIGS) >> 1));
		dv_copy(u, fp_prime_get_cub(), RLC_FP_DIGS);
		fp_sqr(u, u);
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
	dig_t w[4][FP_CUB_DIGS], c[2][FP_CUB_DIGS], z, d;
	uint64_t v;
	int64_t x[4], nf, ng, e = 0, tab, dv, j, ua, ub, mf, kf;
	const int64_t one[2] = { 1, -1 }, nul[2] = { 0, 0 }, neg[2] = { -1, 0 };
	int64_t u[2];
	size_t len = FP_CUB_DIGS, b, l, q, r;

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
		if (dv) {
			/* g / (1 - w) = g * (1 - w) / (1 - w)^2, and (1 - w) gives
			 * w^(2m). */
			smb3_row(c[0], c[1], one, nul, 1, w[2], w[3], w[0], w[1], len);
			e += 2 * mf;
		} else {
			/* u = +/- w^-j gives w^(j(m + k)). */
			e += j * (mf + kf);
			/* Compare N(u * g) = N(g) with N(f), from the bits of the
			 * coordinates below their top one. */
			z = 0;
			for (l = len; l > 0 && z == 0; l--) {
				for (int i = 0; i < 4; i++) {
					z |= w[i][l - 1] ^ -(w[i][len - 1] >> (RLC_DIG - 1));
				}
			}
			b = RLC_DIG * l + util_bits_dig(z);
			b = (b > 29 ? b - 29 : 0);
			/* The 64 bits from position b, with the sign above the top digit. */
			q = b / RLC_DIG;
			r = b % RLC_DIG;
			for (int i = 0; i < 4; i++) {
				v = 0;
				for (size_t k = 0; k * RLC_DIG < 64 + r; k++) {
					d = (q + k < len ? w[i][q + k] :
							-(w[i][len - 1] >> (RLC_DIG - 1)));
					if (k == 0) {
						v |= (uint64_t)(d >> r);
					} else {
						v |= (uint64_t)d << (k * RLC_DIG - r);
					}
				}
				x[i] = (int64_t)v;
			}
			nf = x[0] * x[0] - x[0] * x[1] + x[1] * x[1];
			ng = x[2] * x[2] - x[2] * x[3] + x[3] * x[3];
			u[0] = ua;
			u[1] = ub;
			/* (u * g - f) / (1 - w)^2 replaces the one with the larger norm,
			 * and f becomes u * g if that is f, by reciprocity. */
			smb3_row(c[0], c[1], u, neg, 1, w[2], w[3], w[0], w[1], len);
			if (ng < nf) {
				smb3_row(w[0], w[1], u, nul, 0, w[2], w[3], w[2], w[3], len);
				mf = (smb3_mod9(w[0], len) + 1) % 9 / 3;
				kf = smb3_mod9(w[1], len) / 3;
			}
			/* (1 - w)^2 gives w^(4m) = w^m, with the m of the new f. */
			e += mf;
		}
		dv_copy(w[2], c[0], len);
		dv_copy(w[3], c[1], len);
		len = smb3_shrink(w, len);
	}
	/* g is now 0 and f the unit -1, so the symbol is w^e, divided by that
	 * of R in Montgomery form. */
	return (int)((e + 3 - core_get()->cub_r) % 3);
}

int fp_smb3_divst(const fp_t a) {
	return smb3_symbol(a, 1, 1);
}

int fp_smb3_jmpds(const fp_t a) {
	return smb3_symbol(a, 1, FP_CUB_JK);
}

int fp_smb3_jmpvt(const fp_t a) {
	return smb3_symbol(a, 0, FP_CUB_JK);
}

#if FP_SMB == FP_LOWER

int fp_smb3_lower(const fp_t a) {
	return fp_smb3_low(a);
}

#endif
