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
 * Implementation of the quartic residue symbol for prime fields.
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
 * Number of digits of the coordinates of the Gaussian integers, in two's
 * complement: a few bits more than the square root of p.
 */
#define FP_QRT_DIGS		RLC_CEIL(RLC_FP_BITS / 2 + 6, RLC_DIG)

/**
 * Iterations per jump: each loses at most two bits of the residues modulo 2^64,
 * which must keep four, and the entries of the matrices of n iterations stay
 * below 2^(1.5n + 1), so that four of their products by a digit fit in a signed
 * double digit.
 */
#if RLC_DIG == 8
#define FP_QRT_JK		2
#elif RLC_DIG == 16
#define FP_QRT_JK		7
#elif RLC_DIG == 32
#define FP_QRT_JK		18
#else
#define FP_QRT_JK		30
#endif

/**
 * Number of iterations of the constant-time symbol, B >= 1.68 log2(p) + 28.17
 * from a convex-hull bound as in safegcd-bounds for |f|, |g| <= sqrt(p), within
 * six iterations of the hull for primes of 128 to 582 bits and with a slope
 * above its own of about 5/3 beyond, as tools/relic-smb-hull.py computes and
 * checks.
 */
#define FP_QRT_ITER		RLC_CEIL(FP_PRIME * 168 + 2817, 100)

/**
 * Update rule of the doubled delta: a division adds FP_QRT_DV, a subtraction
 * adds FP_QRT_SB, and a swap, when delta > 0, sets it to FP_QRT_SW - delta.
 */
#define FP_QRT_DV		2
#define FP_QRT_SB		6
#define FP_QRT_SW		12

/**
 * Table of what an iteration does for g = x + y * i, 4 bits per pair 4 * (x mod
 * 4) + (y mod 4): bit 0 if 1 + i divides g, and otherwise the j in bits 1-2 of
 * the unit i^j that makes g primary.
 */
#define FP_QRT_TAB		((uint64_t)0x1014612114102161)

/**
 * Computes c = (s0 * f0 + s1 * f1 + s2 * g0 + s3 * g1) / 2^sh for the
 * coordinates f0, f1, g0, g1 of len digits in two's complement and signed
 * digits s_i, with 2^sh dividing the combination, in one pass from the lowest
 * digit: the combination accumulates in a signed double digit, whose digits are
 * shifted as they come.
 *
 * @param[out] c			- the result.
 * @param[in] w				- the coordinates.
 * @param[in] s				- the factors.
 * @param[in] sh			- the shift amount, below RLC_DIG.
 * @param[in] len			- the number of digits.
 */
static inline void smb4_comb(dig_t *c, dig_t w[4][FP_QRT_DIGS],
		const dis_t s[4], int sh, size_t len) {
	dig_t lo = 0, hi = 0, r = 0;

	for (size_t j = 0; j < len; j++) {
		/* The top digits are signed, as the shift brings in what is above. */
		for (int i = 0; i < 4; i++) {
			RLC_MAC_DIG(hi, lo, s[i], w[i][j],
					(j == len - 1 ? -RLC_SIGN(w[i][j]) : 0));
		}
		/* Two shifts, as sh may be 0. */
		if (j > 0) {
			c[j - 1] = r | ((lo << 1) << (RLC_DIG - 1 - sh));
		}
		r = lo >> sh;
		lo = hi;
		hi = -RLC_SIGN(hi);
	}
	c[len - 1] = r | ((lo << 1) << (RLC_DIG - 1 - sh));
}

/**
 * Applies the rows (A, B) and (C, D) over Z[i] of n combined iterations to
 * f = w[0] + w[1] * i and g = w[2] + w[3] * i, computing
 * f' = (A f + B g) / (1 + i)^(3n) and g' = (C f + D g) / (1 + i)^(3n) into c:
 * with the entries times 1 + i for odd n and times i^-sh, the denominator
 * becomes 2^sh.
 *
 * @param[out] c			- the coordinates of f' and g'.
 * @param[in] w				- the coordinates of f and g.
 * @param[in] r				- the rows A, B, C and D, as coordinate pairs.
 * @param[in] n				- the number of iterations.
 * @param[in] len			- the number of digits.
 */
static inline void smb4_apply(dig_t c[4][FP_QRT_DIGS],
		dig_t w[4][FP_QRT_DIGS], const int64_t r[4][2], int n, size_t len) {
	int64_t e[4][2], t;
	dis_t s[4][4];
	int sh = (3 * n + (n & 1)) / 2;

	for (int k = 0; k < 4; k++) {
		e[k][0] = r[k][0];
		e[k][1] = r[k][1];
		/* (a + b * i)(1 + i) = (a - b) + (a + b) * i. */
		if (n & 1) {
			t = e[k][0] - e[k][1];
			e[k][1] += e[k][0];
			e[k][0] = t;
		}
		/* (a + b * i)(-i) = b - a * i. */
		for (int j = 0; j < sh % 4; j++) {
			t = e[k][1];
			e[k][1] = -e[k][0];
			e[k][0] = t;
		}
	}
	/* (m0 + m1 * i)(x + y * i) = (m0 * x - m1 * y) + (m1 * x + m0 * y) * i,
	 * for (m, n) = (A, B) and (C, D). */
	for (int k = 0; k < 4; k += 2) {
		s[k][0] = (dis_t)e[k][0];
		s[k][1] = (dis_t)-e[k][1];
		s[k][2] = (dis_t)e[k + 1][0];
		s[k][3] = (dis_t)-e[k + 1][1];
		s[k + 1][0] = (dis_t)e[k][1];
		s[k + 1][1] = (dis_t)e[k][0];
		s[k + 1][2] = (dis_t)e[k + 1][1];
		s[k + 1][3] = (dis_t)e[k + 1][0];
	}
	for (int k = 0; k < 4; k++) {
		smb4_comb(c[k], w, s[k], sh, len);
	}
}

/**
 * Returns the lowest 64 bits of an integer of len digits in two's complement.
 *
 * @param[in] a				- the integer.
 * @param[in] len			- the number of digits.
 * @return the lowest 64 bits.
 */
static inline uint64_t smb4_low64(const dig_t *a, size_t len) {
#if RLC_DIG >= 64
	(void)len;
	return (uint64_t)a[0];
#else
	uint64_t r = 0;
	dig_t s = -RLC_SIGN(a[len - 1]);

	for (size_t j = 0; j < 64 / RLC_DIG; j++) {
		r |= (uint64_t)(j < len ? a[j] : s) << (j * RLC_DIG);
	}
	return r;
#endif
}

/**
 * Returns the exponent (N - 1) / 4 modulo 4 of the symbol of i for a primary
 * Gaussian integer x + y * i of norm N: as x^2 = 1 or 9 modulo 16, for x = +/-1
 * or +/-3 modulo 8, and y^2 = 0 or 4, for y = 0 or 2 modulo 4, it is
 * 2 * ((x >> 1) ^ (x >> 2)) + (y >> 1) in the lowest bits.
 *
 * @param[in] x				- the real part.
 * @param[in] y				- the imaginary part.
 * @return the exponent.
 */
static inline uint64_t smb4_en(uint64_t x, uint64_t y) {
	return ((x ^ (x >> 1)) & 2) + ((y >> 1) & 1);
}

/**
 * Returns the exponent (x - y - y^2 - 1) / 4 of the symbol of 1 + i for a
 * primary Gaussian integer x + y * i, correct modulo 4: as y^2 = 4 * (y >> 1)
 * modulo 16, it is (x - y - 1) / 4 - (y >> 1) in the lowest bits.
 *
 * @param[in] x				- the real part.
 * @param[in] y				- the imaginary part.
 * @return the exponent.
 */
static inline uint64_t smb4_el(uint64_t x, uint64_t y) {
	return ((x - y - 1) >> 2) - ((y >> 1) & 1);
}

/**
 * Runs len <= FP_QRT_JK / 2 combined iterations on the residues modulo 2^64 of
 * f and g in constant time, with the rows (A, B) and (C, D) over Z[i] such that
 * (1 + i)^(3 * len) * (f', g') = (A f + B g, C f + D g). An iteration divides g
 * by 1 + i if it can, and otherwise makes g primary with a unit u and replaces
 * it by (u * g - f) / (1 + i)^3, after swapping f and u * g if delta > 0. The
 * entries grow by at most 2^1.5 per iteration, so their coordinates are packed
 * in pairs of 32 bits.
 *
 * @param[out] r			- the rows A, B, C and D, as coordinate pairs.
 * @param[in,out] f			- the residues of f.
 * @param[in,out] g			- the residues of g.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] len			- the number of iterations.
 */
static void smb4_jhalf(int64_t r[4][2], uint64_t f[2], uint64_t g[2],
		int64_t *d, int64_t *e, int len) {
	/* Values in two's complement modulo 2^64, whose top bits are lost by the
	 * divisions and never used; the masks are signed, and so is delta. The
	 * exponent is only needed modulo 4, so it may wrap. */
	uint64_t f0 = f[0], f1 = f[1], g0 = g[0], g1 = g[1], h0, h1, x, y, t;
	int64_t tab, dv, nd, sw, j, ua, ub;
	/* The rows as packed coordinates, starting from the identity:
	 * p = ((A.x, B.x), (A.y, B.y), (C.x, D.x), (C.y, D.y)). */
	uint64_t p0 = 1, p1 = 0, p2 = (uint64_t)1 << 32, p3 = 0, tx, ty, ux, uy;
	uint64_t p[4];
	/* Local copies, which stay in registers. */
	uint64_t el = (uint64_t)*e;
	int64_t dl = *d;

	for (; len > 0; len--) {
		/* What to do from g mod 4, with u = i^j = ua + ub * i, and u = 1 for
		 * a division. A shift by a secret amount takes constant time. */
		tab = (int64_t)((FP_QRT_TAB >> (4 * (4 * (g0 & 3) + (g1 & 3)))) & 15);
		dv = -(tab & 1);
		nd = ~dv;
		j = tab >> 1;
		ua = (1 - j) & ((j & 1) - 1);
		ub = (2 - j) & -(j & 1);
		/* The swap mask from the sign of -delta, without a comparison. */
		sw = nd & ((-dl) >> 63);
		/* u * g = (a x - b y) + (a y + b x) i for g = x + y i and
		 * u = a + b i, and u * (C, D) on the packed row. */
		h0 = ua * g0 - ub * g1;
		h1 = ua * g1 + ub * g0;
		tx = ua * p2 - ub * p3;
		ty = ua * p3 + ub * p2;
		/* The negated exponent, modulo 4: j times that of i for f, as u^-1 =
		 * i^-j, and the reciprocity sign after a swap, 2 = -2 if u * g has an
		 * imaginary part of 2 modulo 4 and f does not. */
		t = (uint64_t)j * smb4_en(f0, f1) + ((h1 & ~f1 & 2) & sw);
		/* u * g - f, or g for a division, and f becomes u * g after a swap. */
		x = h0 - (f0 & nd);
		y = h1 - (f1 & nd);
		f0 += x & sw;
		f1 += y & sw;
		/* Then that of (1 + i)^3, three times that of 1 + i for the new f,
		 * which is minus it modulo 4, so the sum is negated; a division has
		 * t = 0 and adds that of 1 + i instead. */
		t += smb4_el(f0, f1);
		el += (t ^ nd) - nd;
		/* The new delta. */
		dl += FP_QRT_SB + ((FP_QRT_DV - FP_QRT_SB) & dv) +
				((FP_QRT_SW - FP_QRT_SB - 2 * dl) & sw);
		/* The new g: g / (1 + i) = ((x + y) + (y - x) i) / 2 for a division,
		 * or (u * g - f) / (1 + i)^3 = -(u * g - f)(1 + i) / 4 =
		 * ((y - x) - (x + y) i) / 4 otherwise. */
		h0 = x + y;
		h1 = y - x;
		g0 = (h1 ^ ((h1 ^ h0) & dv)) >> (2 + dv);
		g1 = ((0 - h0) ^ (((0 - h0) ^ h1) & dv)) >> (2 + dv);
		/* The rows, over a denominator times (1 + i)^3 = -2 + 2i per
		 * iteration: that of f is (A, B), or u * (C, D) after a swap, times
		 * (1 + i)^3, and that of g is u * (C, D) - (A, B), or (C, D) times
		 * (1 + i)^2 = 2i for a division. */
		ux = tx - (p0 & nd);
		uy = ty - (p1 & nd);
		p0 += ux & sw;
		p1 += uy & sw;
		tx = -2 * (p0 + p1);
		p1 = 2 * (p0 - p1);
		p0 = tx;
		p2 = ux ^ ((ux ^ (-2 * uy)) & dv);
		p3 = uy ^ ((uy ^ (2 * ux)) & dv);
	}
	f[0] = f0;
	f[1] = f1;
	g[0] = g0;
	g[1] = g1;
	*d = dl;
	*e = (int64_t)(el & 3);
	/* Unpack the signed entries, the high one with the borrow of the low one,
	 * into the rows (A, B) and (C, D), from an array only now, so that the
	 * rows stay in registers in the loop. */
	p[0] = p0;
	p[1] = p1;
	p[2] = p2;
	p[3] = p3;
	for (int i = 0; i < 4; i++) {
		r[i & 2][i & 1] = (int64_t)(p[i] << 32) >> 32;
		r[(i & 2) + 1][i & 1] = (int64_t)(p[i] - (uint64_t)r[i & 2][i & 1]) >> 32;
	}
}

/**
 * Computes one jump of n <= FP_QRT_JK iterations on f = w[0] + w[1] * i and
 * g = w[2] + w[3] * i: two halves on their residues give the rows (A, B) and
 * (C, D) with (1 + i)^(3n) * (f', g') = (A f + B g, C f + D g), which are
 * applied to f and g in len digits.
 *
 * @param[out] c			- the coordinates of f' and g'.
 * @param[in] w				- the coordinates of f and g.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] n				- the number of iterations.
 * @param[in] len			- the number of digits.
 */
static inline void smb4_jump(dig_t c[4][FP_QRT_DIGS],
		dig_t w[4][FP_QRT_DIGS], int64_t *d, int64_t *e, int n, size_t len) {
	uint64_t f[2], g[2];
	int64_t s[4][2], t[4][2], r[4][2];

	f[0] = smb4_low64(w[0], len);
	f[1] = smb4_low64(w[1], len);
	g[0] = smb4_low64(w[2], len);
	g[1] = smb4_low64(w[3], len);
	smb4_jhalf(s, f, g, d, e, n / 2);
	smb4_jhalf(t, f, g, d, e, n - n / 2);
	/* The second matrix times the first, entry by entry, with
	 * (a0 + a1 * i)(x0 + x1 * i) = (a0 x0 - a1 x1) + (a0 x1 + a1 x0) i. */
	for (int i = 0; i < 4; i++) {
		const int64_t *a = t[i & 2], *b = t[(i & 2) + 1];
		const int64_t *x = s[i & 1], *y = s[(i & 1) + 2];
		r[i][0] = a[0] * x[0] - a[1] * x[1] + b[0] * y[0] - b[1] * y[1];
		r[i][1] = a[0] * x[1] + a[1] * x[0] + b[0] * y[1] + b[1] * y[0];
	}
	smb4_apply(c, w, r, n, len);
}

/**
 * Starts the symbol of a nonzero element for p = 1 mod 4 with f = pi and g = a
 * - q * pi, of norm below p, for q the rounded a / pi from the scaled inverse
 * of pi, in constant time.
 *
 * @param[out] w			- the coordinates of f and g.
 * @param[in] a				- the prime field element.
 */
static void smb4_init(dig_t w[4][FP_QRT_DIGS], const fp_t a) {
	ctx_t *ctx = core_get();
	dig_t g[RLC_FP_DIGS + 1], *x = w[2], *y = w[3];
	dig_t q[2][FP_QRT_DIGS], h[2 * (RLC_FP_DIGS + 1)], z[FP_QRT_DIGS], c;
	const dig_t *u = ctx->qrt_pi[0], *v = ctx->qrt_pi[1];

	/* The stored digits of a, the integer a * R mod p in Montgomery form,
	 * whose symbol is that of a times that of R. */
	dv_copy(g, a, RLC_FP_DIGS);
	g[RLC_FP_DIGS] = 0;
	dv_zero(z, FP_QRT_DIGS);
	for (int j = 0; j < 2; j++) {
		bn_muln_low(h, g, ctx->qrt_inv[j], RLC_FP_DIGS + 1);
		dv_copy(q[j], h + RLC_FP_DIGS + 1, FP_QRT_DIGS);
		/* Round with the top bit of the fraction, propagating the carry
		 * through all digits so that the time does not depend on it. */
		c = h[RLC_FP_DIGS] >> (RLC_DIG - 1);
		for (size_t i = 0; i < FP_QRT_DIGS; i++) {
			q[j][i] += c;
			c = (q[j][i] < c);
		}
		/* The signs of the inverse are public. */
		if (ctx->qrt_sgn[j] == RLC_NEG) {
			bn_subn_low(q[j], z, q[j], FP_QRT_DIGS);
		}
	}
	/* q * pi = (q0 * u - q1 * v) + (q0 * v + q1 * u) * i. */
	dv_copy(x, g, FP_QRT_DIGS);
	dv_zero(y, FP_QRT_DIGS);
	bn_muln_low(h, q[0], u, FP_QRT_DIGS);
	bn_subn_low(x, x, h, FP_QRT_DIGS);
	bn_muln_low(h, q[1], v, FP_QRT_DIGS);
	bn_addn_low(x, x, h, FP_QRT_DIGS);
	bn_muln_low(h, q[0], v, FP_QRT_DIGS);
	bn_subn_low(y, y, h, FP_QRT_DIGS);
	bn_muln_low(h, q[1], u, FP_QRT_DIGS);
	bn_subn_low(y, y, h, FP_QRT_DIGS);
	/* The coordinates of pi also fit in FP_QRT_DIGS digits. */
	dv_copy(w[0], u, FP_QRT_DIGS);
	dv_copy(w[1], v, FP_QRT_DIGS);
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
static size_t smb4_shrink(dig_t w[4][FP_QRT_DIGS], size_t len) {
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
	t = RLC_MIN(t, (size_t)FP_QRT_DIGS);
	for (int j = 0; j < 4; j++) {
		s = -(w[j][len - 1] >> (RLC_DIG - 1));
		for (size_t l = len; l < t; l++) {
			w[j][l] = s;
		}
	}
	return t;
}

/**
 * Converts a Legendre symbol s in {1, -1, 0} into the exponent of the quartic
 * symbol for p = 3 mod 4, where the character of order gcd(4, p - 1) = 2 is
 * i^0 for squares and i^2 otherwise, and -1 for zero: 2s^2 - s - 1.
 *
 * @param[in] s				- the Legendre symbol.
 * @return k in {0, 2}, or -1 if the element is zero.
 */
static inline int smb4_from2(int s) {
	return 2 * s * s - s - 1;
}

/**
 * Computes the quartic residue symbol for p = 1 mod 4 by jumps of up to k
 * combined divsteps, a fixed number of them in constant time or until g is 0,
 * with -1 for zero.
 *
 * @param[in] a				- the prime field element.
 * @param[in] ct			- the flag to run in constant time.
 * @param[in] k				- the largest number of iterations per jump.
 * @return k in {0, 1, 2, 3}, or -1 if the element is zero.
 */
static int smb4_symbol(const fp_t a, int ct, int k) {
	dig_t w[4][FP_QRT_DIGS], c[4][FP_QRT_DIGS], z = 0;
	int64_t d = 1, e = 0;
	size_t len = FP_QRT_DIGS;
	int zero;

	for (size_t j = 0; j < RLC_FP_DIGS; j++) {
		z |= a[j];
	}
	zero = (z == 0);
	if (!ct && zero) {
		return -1;
	}

	smb4_init(w, a);
	for (int i = 0, n; i < FP_QRT_ITER; i += n) {
		n = RLC_MIN(k, FP_QRT_ITER - i);
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
			smb4_jump(c, w, &d, &e, n, FP_QRT_DIGS);
		} else {
			smb4_jump(c, w, &d, &e, n, len);
		}
		for (int j = 0; j < 4; j++) {
			dv_copy(w[j], c[j], len);
		}
		/* Without constant time, keep only the digits that f and g need. */
		if (!ct) {
			len = smb4_shrink(w, len);
		}
	}
	/* g is now 0 and f the unit 1, so the symbol is i^e, divided by that of R
	 * in Montgomery form; zero has no symbol. */
	return (int)((e - core_get()->qrt_r) & 3) | -zero;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb4_basic(const fp_t a) {
	bn_t t;
	fp_t u, v;
	int r = -1, q = (fp_prime_get_mod8() % 4 == 3);

	bn_null(t);
	fp_null(u);
	fp_null(v);

	RLC_TRY {
		bn_new(t);
		fp_new(u);
		fp_new(v);

		/* By Euler's criterion, a^((p - 1)/4) = z^k, and 0 for zero, or
		 * a^((p - 1)/2) = (-1)^(k/2) for p = 3 mod 4. */
		t->sign = RLC_POS;
		t->used = RLC_FP_DIGS;
		dv_copy(t->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_rsh(t, t, 2 - q);
		fp_exp(v, a, t);
		/* k from which of 1, z, -1 and -z is the power, with dv_equ_sec() 0
		 * if equal and RLC_NE = 2 otherwise, without branches, on the reduced
		 * values, as some backends keep elements below a multiple of p. */
		fp_norm(v, v);
		fp_set_dig(u, 1);
		fp_norm(u, u);
		r += 1 - (dv_equ_sec(v, u, RLC_FP_DIGS) >> 1);
		fp_neg(u, u);
		fp_norm(u, u);
		r += 3 * (1 - (dv_equ_sec(v, u, RLC_FP_DIGS) >> 1));
		if (!q) {
			dv_copy(u, fp_prime_get_qrt(), RLC_FP_DIGS);
			fp_norm(u, u);
			r += 2 * (1 - (dv_equ_sec(v, u, RLC_FP_DIGS) >> 1));
			fp_neg(u, u);
			fp_norm(u, u);
			r += 4 * (1 - (dv_equ_sec(v, u, RLC_FP_DIGS) >> 1));
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		fp_free(u);
		fp_free(v);
	}
	return r;
}

int fp_smb4_binar(const fp_t a) {
	dig_t w[4][FP_QRT_DIGS], c[4][FP_QRT_DIGS], z, d;
	uint64_t v;
	int64_t x[4], vf, vg, e = 0, tab, j, ua, ub, nf, lf, eh, lh;
	size_t len = FP_QRT_DIGS, b, l, q, r;
	int sw;

	if (fp_is_zero(a)) {
		return -1;
	}
	if (fp_prime_get_mod8() % 4 == 3) {
		return smb4_from2(fp_smb2_binar(a));
	}

	smb4_init(w, a);
	/* The exponents of the symbols of i and 1 + i for the primary f, from
	 * its lowest digits. */
	nf = (int64_t)smb4_en(w[0][0], w[1][0]);
	lf = (int64_t)(smb4_el(w[0][0], w[1][0]) & 3);
	while (1) {
		z = 0;
		for (l = 0; l < len; l++) {
			z |= w[2][l] | w[3][l];
		}
		if (z == 0) {
			break;
		}
		tab = (int64_t)((FP_QRT_TAB >> (4 * (4 * (w[2][0] & 3) +
				(w[3][0] & 3)))) & 15);
		j = tab >> 1;
		sw = 0;
		if (tab & 1) {
			/* g / (1 + i) = ((x + y) + (y - x) * i) / 2 for g = x + y * i,
			 * and 1 + i gives i^lf. */
			const dis_t s0[4] = { 0, 0, 1, 1 }, s1[4] = { 0, 0, -1, 1 };

			smb4_comb(c[2], w, s0, 1, len);
			smb4_comb(c[3], w, s1, 1, len);
			e += lf;
		} else {
			ua = (1 - j) & ((j & 1) - 1);
			ub = (2 - j) & -(j & 1);
			/* The factors of (u * g - f) / (1 + i)^3 = -(u * g - f)(1 + i) / 4,
			 * and of u * g. */
			const dis_t s0[4] = { 1, -1, (dis_t)(ub - ua), (dis_t)(ua + ub) };
			const dis_t s1[4] = { 1, 1, (dis_t)(-ua - ub), (dis_t)(ub - ua) };
			const dis_t s2[4] = { 0, 0, (dis_t)ua, (dis_t)-ub };
			const dis_t s3[4] = { 0, 0, (dis_t)ub, (dis_t)ua };

			/* u = i^j gives i^(-j * nf). */
			e -= j * nf;
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
			vf = x[0] * x[0] + x[1] * x[1];
			vg = x[2] * x[2] + x[3] * x[3];
			/* (u * g - f) / (1 + i)^3 replaces the one with the larger norm,
			 * and f becomes u * g if that is f, by reciprocity. */
			smb4_comb(c[2], w, s0, 2, len);
			smb4_comb(c[3], w, s1, 2, len);
			sw = (vg < vf);
			if (sw) {
				smb4_comb(c[0], w, s2, 0, len);
				smb4_comb(c[1], w, s3, 0, len);
			}
		}
		/* f only changes after a swap. */
		for (int i = (sw ? 0 : 2); i < 4; i++) {
			dv_copy(w[i], c[i], len);
		}
		if (!(tab & 1)) {
			if (sw) {
				/* (u * g / f) = (f / u * g) (-1)^(nf * nh), and then
				 * (f / u * g) = (-1 / u * g)((u * g - f) / u * g). */
				eh = (int64_t)smb4_en(w[0][0], w[1][0]);
				lh = (int64_t)(smb4_el(w[0][0], w[1][0]) & 3);
				e += (eh & ~nf & 1) << 1;
				nf = eh;
				lf = lh;
			}
			/* (1 + i)^3 gives i^(3 * lf) = i^-lf, with the lf of the new f. */
			e -= lf;
		}
		len = smb4_shrink(w, len);
	}
	/* g is now 0 and f the unit 1, so the symbol is i^e, divided by that of R
	 * in Montgomery form. */
	return (int)((e - core_get()->qrt_r) & 3);
}

int fp_smb4_divst(const fp_t a) {
	if (fp_prime_get_mod8() % 4 == 3) {
		return smb4_from2(fp_smb2_divst(a));
	}
	return smb4_symbol(a, 1, 1);
}

int fp_smb4_jmpds(const fp_t a) {
	if (fp_prime_get_mod8() % 4 == 3) {
		return smb4_from2(fp_smb2_jmpds(a));
	}
	return smb4_symbol(a, 1, FP_QRT_JK);
}

int fp_smb4_jmpvt(const fp_t a) {
	if (fp_prime_get_mod8() % 4 == 3) {
		return smb4_from2(fp_smb2_jmpvt(a));
	}
	return smb4_symbol(a, 0, FP_QRT_JK);
}

#if FP_SMB == FP_LOWER

int fp_smb4_lower(const fp_t a) {
	return fp_smb4_low(a);
}

#endif
