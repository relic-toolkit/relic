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
 * Implementation of Legendre and Jacobi symbols for prime fields.
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
 * Approach heavily inpired in the blst implementation of the algorithm.
 */
static dig_t porninstep(dis_t m[4],const dig_t f[2], const dig_t g[2], 
		dig_t k, size_t s) {
	dig_t limbx, ai = 1, bi = 0, ci = 0, di = 1;
	dig_t g_lo = g[0], g_hi = g[1], f_lo = f[0], f_hi = f[1];
	dig_t t_lo, t_hi, odd, borrow, xorm;

	/* Unrolling twice gives some small speedup. */
	for (size_t i = 0; i < s; i+=2) {
		odd = 0 - (g_lo & 1);

		/* g_ -= f_ if g_ is odd */
		t_lo = g_lo, t_hi = g_hi;

		borrow = 0;
		limbx = g_lo - (f_lo & odd);
		borrow = (g_lo < limbx);
		g_lo = limbx;

		limbx = g_hi - (f_hi & odd);
		xorm = limbx - borrow;
		borrow = -((g_hi < limbx) || (borrow && !limbx));
		g_hi = xorm;

		k += ((t_lo & f_lo) >> 1) & borrow;

		/* negate g_-f_ if it borrowed */
		g_lo ^= borrow;
		g_hi ^= borrow;
		limbx = g_lo + (borrow & 1);
		g_hi += (g_lo < limbx);
		g_lo = limbx;

		/* f_=g_ if g_-f_ borrowed */
		f_lo = ((t_lo ^ f_lo) & borrow) ^ f_lo;
		f_hi = ((t_hi ^ f_hi) & borrow) ^ f_hi;

		/* exchange ai and ci if g_-f_ borrowed */
		xorm = (ai ^ ci) & borrow;
		ai ^= xorm;
		ci ^= xorm;

		/* exchange bi and di if g_-f_ borrowed */
		xorm = (bi ^ di) & borrow;
		bi ^= xorm;
		di ^= xorm;

		/* subtract if g_ was odd */
		ai -= ci & odd;
		bi -= di & odd;

		ci <<= 1;
		di <<= 1;
		g_lo >>= 1;
		g_lo |= g_hi << (RLC_DIG - 1);
		g_hi >>= 1;

		k += (f_lo + 2) >> 2;

		odd = 0 - (g_lo & 1);

		/* g_ -= f_ if g_ is odd */
		t_lo = g_lo, t_hi = g_hi;

		borrow = 0;
		limbx = g_lo - (f_lo & odd);
		borrow = (g_lo < limbx);
		g_lo = limbx;

		limbx = g_hi - (f_hi & odd);
		xorm = limbx - borrow;
		borrow = -((g_hi < limbx) || (borrow && !limbx));
		g_hi = xorm;

		k += ((t_lo & f_lo) >> 1) & borrow;

		/* negate g_-f_ if it borrowed */
		g_lo ^= borrow;
		g_hi ^= borrow;
		limbx = g_lo + (borrow & 1);
		g_hi += (g_lo < limbx);
		g_lo = limbx;

		/* f_=g_ if g_-f_ borrowed */
		f_lo = ((t_lo ^ f_lo) & borrow) ^ f_lo;
		f_hi = ((t_hi ^ f_hi) & borrow) ^ f_hi;

		/* exchange ai and ci if g_-f_ borrowed */
		xorm = (ai ^ ci) & borrow;
		ai ^= xorm;
		ci ^= xorm;

		/* exchange bi and di if g_-f_ borrowed */
		xorm = (bi ^ di) & borrow;
		bi ^= xorm;
		di ^= xorm;

		/* subtract if g_ was odd */
		ai -= ci & odd;
		bi -= di & odd;

		ci <<= 1;
		di <<= 1;
		g_lo >>= 1;
		g_lo |= g_hi << (RLC_DIG - 1);
		g_hi >>= 1;

		k += (f_lo + 2) >> 2;
	}

	m[0] = ai;
	m[1] = bi;
	m[2] = ci;
	m[3] = di;

	return k;
}

/**
 * Number of division steps for any modulus p < 2^FP_PRIME, from the bound for
 * half-delta divsteps in https://github.com/sipa/safegcd-bounds.
 */
#define JMPDS_ITERS	((3787 * FP_PRIME + 2166) / 1644)

/**
 * Number of division steps in each jump, done in two halves so that each row
 * of the transition matrix of a half fits in a digit.
 */
#define JMPDS_STEPS			(RLC_DIG - 4)

/**
 * Performs s <= JMPDS_STEPS half-delta division steps on the lowest digits of
 * f and g, and returns the transition matrix m = (u, v; q, r) scaled by 2^s,
 * with the rows packed in single digits within each half. The count k tracks
 * the Jacobi symbol: modulo 4, the sign changes of v plus two for each flip.
 *
 * @param[out] m			- the transition matrix.
 * @param[out] k			- the count of sign changes and flips.
 * @param[in] zeta			- the current value of zeta.
 * @param[in] f				- the lowest digit of f, which must be odd.
 * @param[in] g				- the lowest digit of g.
 * @param[in] s				- the number of steps.
 * @return the updated value of zeta.
 */
#if RLC_WSIZE == 8
static int smb_steps(dis_t m[4], dig_t *k, int zeta, dig_t f, dig_t g,
		int s) {
#else
static dis_t smb_steps(dis_t m[4], dig_t *k, dis_t zeta, dig_t f, dig_t g,
		int s) {
#endif
	const int h = RLC_DIG / 2;
	dig_t uv, qr, c0, c1, fi, w, c, n = 0;
	dis_t u, v, q, r, t0, t1;

	m[0] = m[3] = 1;
	m[1] = m[2] = 0;
	for (int l, half = 0; half < 2; half++) {
		l = (half == 0 ? s / 2 : s - s / 2);
		uv = 1;
		qr = (dig_t)1 << h;
		c = 0;
		for (int j = 0; j < l; j++) {
			fi = f;
			/* c0 is all ones if zeta < 0, c1 if g is odd. */
			c0 = zeta >> (8 * sizeof(zeta) - 1);
			c1 = -(g & 1);
			/* Add (f, u, v) to (g, q, r) if g is odd, negated if zeta < 0. */
			g += ((f ^ c0) - c0) & c1;
			qr += ((uv ^ c0) - c0) & c1;
			/* Swap if zeta < 0 and g is odd, then update zeta. */
			c0 &= c1;
			zeta = (zeta ^ (dis_t)c0) - 1;
			/* When swapping, (f, u, v) becomes the old (g, q, r). */
			f += g & c0;
			uv += qr & c0;
			/* Halve g by doubling (u, v) instead, keeping integer entries. */
			g >>= 1;
			uv += uv;
			/* Flip for the rotation and the halving, from f mod 8. */
			c += ((fi & f) ^ (f >> 1)) & 2;
			/* Count the sign changes of v, the high half of uv. */
			w = uv - (dig_t)((dis_t)(uv << h) >> h);
			c += (c & 1) ^ (w >> (RLC_DIG - 1));
		}
		/* Unpack the signed entries and accumulate the matrix product. */
		u = (dis_t)(uv << h) >> h;
		v = (dis_t)(uv - u) >> h;
		q = (dis_t)(qr << h) >> h;
		r = (dis_t)(qr - q) >> h;
		t0 = u * m[0] + v * m[2];
		t1 = u * m[1] + v * m[3];
		m[2] = q * m[0] + r * m[2];
		m[3] = q * m[1] + r * m[3];
		m[0] = t0;
		m[1] = t1;
		/* Correct the count with the sign of v in the product. */
		n += c;
		n += (n & 1) ^ RLC_SIGN(m[1]);
	}
	*k = n & 3;
	return zeta;
}

/**
 * Adds a * b to the signed double digit (c1, c0); sb is the sign mask of b.
 */
static inline void smb_mac(dig_t *c1, dig_t *c0, dis_t a, dig_t b,
		dig_t sb) {
	dig_t h, l;
#ifdef RLC_CONF_NODBL
	RLC_MUL_DIG(h, l, (dig_t)a, b);
#else
	/* Multiply once to get both halves. */
	dbl_t t = (dbl_t)(dig_t)a * b;
	h = (dig_t)(t >> RLC_DIG);
	l = (dig_t)t;
#endif
	/* Correct the unsigned high half for the signs of a and b. */
	h -= (b & -RLC_SIGN(a)) + ((dig_t)a & sb);
	*c0 += l;
	*c1 += h + (*c0 < l);
}

/**
 * Applies the transition matrix m = (u, v; q, r) of s division steps to
 * (f, g), computing (u * f + v * g, q * f + r * g) / 2^s in a single pass,
 * where the division is exact. Both values have RLC_FP_DIGS + 1 signed digits.
 *
 * @param[in,out] f			- the first entry of the column vector.
 * @param[in,out] g			- the second entry of the column vector.
 * @param[in] m				- the transition matrix.
 * @param[in] s				- the number of division steps.
 */
static void smb_apply(dig_t *f, dig_t *g, const dis_t m[4], int s) {
	const dis_t u = m[0], v = m[1], q = m[2], r = m[3];
	dig_t f1 = 0, f0 = 0, g1 = 0, g0 = 0, fs = 0, gs = 0, fi, gi;
	size_t i;

	for (i = 0; i < RLC_FP_DIGS; i++) {
		fi = f[i];
		gi = g[i];
		smb_mac(&f1, &f0, u, fi, 0);
		smb_mac(&f1, &f0, v, gi, 0);
		smb_mac(&g1, &g0, q, fi, 0);
		smb_mac(&g1, &g0, r, gi, 0);
		/* Store the previous digits shifted right by s bits. */
		if (i > 0) {
			f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
			g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
		}
		/* Keep the current digits and shift the accumulators by a digit. */
		fs = f0;
		gs = g0;
		f0 = f1;
		g0 = g1;
		f1 = -RLC_SIGN(f1);
		g1 = -RLC_SIGN(g1);
	}
	/* Only the top digits are signed. */
	fi = f[i];
	gi = g[i];
	smb_mac(&f1, &f0, u, fi, -RLC_SIGN(fi));
	smb_mac(&f1, &f0, v, gi, -RLC_SIGN(gi));
	smb_mac(&g1, &g0, q, fi, -RLC_SIGN(fi));
	smb_mac(&g1, &g0, r, gi, -RLC_SIGN(gi));
	f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
	g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
	f[i] = (dis_t)f0 >> s;
	g[i] = (dis_t)g0 >> s;
}

/**
 * Number of digits of the coordinates of the first remainder of the cubic
 * residue symbol, which stay a few bits longer than the square root of p.
 */
#define FP_CUB_DIGS		RLC_CEIL(RLC_FP_BITS / 2 + 6, RLC_DIG)

/**
 * Largest number of combined iterations in each jump of the symbol, whose
 * matrices have entries of about 3^FP_CUB_JK, and which needs residues modulo
 * 3^(FP_CUB_JK + 2). It is the largest for which these residues stay below
 * 2^61 with intermediate results below 2^63.
 */
#define FP_CUB_JK		36

/**
 * Modulus 3^(FP_CUB_JK + 2) of the residues from which jumps are computed, as
 * each iteration divides by at most (1 - w)^2 and the symbol needs residues
 * modulo 9 at the end.
 */
#define FP_CUB_JM		((uint64_t)1350851717672992089)

/**
 * Number of combined iterations of the constant-time symbol. A convex-hull
 * bound of the iterations, computed as in the safegcd-bounds analysis of the
 * divsteps up to 800 iterations, gives the smallest B that reaches g = 0
 * from |f|, |g| <= M. As f = pi and g = a - q pi both have absolute values
 * at most sqrt(p), M = sqrt(p) and B >= 1.112 log2(p) + 15.12 is at most two
 * iterations above the smallest such B for primes of 128 to 690 bits. Its
 * slope is that of the bound from 200 to 600 iterations, so that it can be
 * extrapolated to larger primes.
 */
#define FP_CUB_ITER		RLC_CEIL(FP_PRIME * 139 + 1890, 125)

/**
 * Table of what an iteration does for g = x + y * w, 7 bits for each residue
 * pair 3 * (x mod 3) + (y mod 3): bit 0 when 1 - w divides g, and otherwise
 * the unit u = a + b * w that makes it primary, with bits 1 and 2 for the j
 * of u = (+/-) w^-j, bits 3 and 4 for a + 1 and bits 5 and 6 for b + 1.
 */
#define FP_CUB_TAB		((uint64_t)0xc62c18cc400a931)

/**
 * Inverse of 3 modulo 2^64.
 */
#define FP_CUB_I3		((uint64_t)0xAAAAAAAAAAAAAAAB)

/**
 * Number of 64-bit limbs of the coordinates of the Eisenstein integers that
 * compute the cubic residue symbol, in two's complement, whatever the size of
 * digits: after the first division, they stay a few bits longer than the
 * square root of p.
 */
#define FP_CUB_L		RLC_CEIL(RLC_FP_BITS / 2 + 6, 64)

/**
 * Multiplies two 64-bit integers into 128 bits, with the digit multiplication
 * for 64-bit digits and otherwise with four products of 32 bits.
 *
 * @param[out] h			- the high 64 bits.
 * @param[out] l			- the low 64 bits.
 * @param[in] a				- the first factor.
 * @param[in] b				- the second factor.
 */
static void fp_cub_mul64(uint64_t *h, uint64_t *l, uint64_t a, uint64_t b) {
#if RLC_DIG == 64
	dig_t hd, ld;

	RLC_MUL_DIG(hd, ld, (dig_t)a, (dig_t)b);
	*h = hd;
	*l = ld;
#else
	uint64_t a0 = (uint32_t)a, a1 = a >> 32, b0 = (uint32_t)b, b1 = b >> 32;
	uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
	uint64_t t = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;

	*l = (t << 32) | (uint32_t)p00;
	*h = p11 + (p01 >> 32) + (p10 >> 32) + (t >> 32);
#endif
}

/**
 * Converts an integer in two's complement from n digits to FP_CUB_L limbs.
 *
 * @param[out] c			- the limbs.
 * @param[in] a				- the digits.
 * @param[in] n				- the number of digits.
 */
static void fp_cub_pack(uint64_t *c, const dig_t *a, size_t n) {
	const dig_t m = -(a[n - 1] >> (RLC_DIG - 1));

	for (size_t j = 0; j < FP_CUB_L; j++) {
		c[j] = 0;
	}
	for (size_t i = 0; i < FP_CUB_L * 64 / RLC_DIG; i++) {
		c[i * RLC_DIG / 64] |= (uint64_t)(i < n ? a[i] : m) << (i * RLC_DIG % 64);
	}
}

/**
 * Divides an integer of FP_CUB_L limbs in two's complement by an odd 64-bit
 * integer, when the division is exact, by multiplying the limbs by its inverse
 * modulo 2^64, which is also the quotient modulo 2^(64 * FP_CUB_L).
 *
 * @param[out] c			- the quotient.
 * @param[in] a				- the integer, a multiple of d.
 * @param[in] d				- the odd divisor.
 * @param[in] inv			- the inverse of d modulo 2^64.
 */
static void fp_cub_divd(uint64_t *c, const uint64_t *a, uint64_t d,
		uint64_t inv) {
	uint64_t b = 0, h, l, q;

	for (size_t j = 0; j < FP_CUB_L; j++) {
		l = a[j] - b;
		b = (a[j] < b);
		q = l * inv;
		c[j] = q;
		/* The borrow is the high limb of d * q, the low one being l. */
		fp_cub_mul64(&h, &l, q, d);
		b += h;
	}
}

/**
 * Computes a combination of four integers of FP_CUB_L limbs in two's
 * complement with signed factors, in one pass:
 * c = s0 * a0 + s1 * a1 + s2 * a2 + s3 * a3, with each negative term added as
 * the complement of its absolute value plus one.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the integers.
 * @param[in] s				- the factors, below 2^63 in absolute value.
 */
static void fp_cub_lin(uint64_t *c, const uint64_t *a[4], const int64_t s[4]) {
	uint64_t ms[4], ns[4], cs[4] = { 0, 0, 0, 0 }, k = 0, h, l, d;

	for (int i = 0; i < 4; i++) {
		ms[i] = (uint64_t)(s[i] < 0 ? -s[i] : s[i]);
		ns[i] = -(uint64_t)(s[i] < 0);
		k += (s[i] < 0);
	}
	for (size_t j = 0; j < FP_CUB_L; j++) {
		d = k;
		k = 0;
		for (int i = 0; i < 4; i++) {
			fp_cub_mul64(&h, &l, ms[i], a[i][j]);
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
 * Computes (m * alpha + n * beta) / (1 - w)^(2h) in limbs, where the division
 * is exact, for alpha = x + y * w and beta = u + v * w.
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
 */
static void fp_cub_row(uint64_t *c0, uint64_t *c1, const int64_t m[2],
		const int64_t n[2], int h, const uint64_t *x, const uint64_t *y,
		const uint64_t *u, const uint64_t *v) {
	/* (1 - w)^(2h) = (-3w)^h, so first multiply m and n by the unit
	 * (-w)^-h, a power of 1 + w with (a + b * w)(1 + w) = (a - b) + a * w. */
	const uint64_t *f[4] = { x, y, u, v };
	int64_t m0 = m[0], m1 = m[1], n0 = n[0], n1 = n[1], t, f0[4], f1[4];
	uint64_t p = 1, pi = 1;

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
	f0[0] = m0;
	f0[1] = -m1;
	f0[2] = n0;
	f0[3] = -n1;
	f1[0] = m1;
	f1[1] = m0 - m1;
	f1[2] = n1;
	f1[3] = n0 - n1;

	fp_cub_lin(c0, f, f0);
	fp_cub_lin(c1, f, f1);
	/* Divide by 3^h, with 3^h and its inverse by squaring and multiplying. */
	for (int j = 5; j >= 0; j--) {
		p *= p;
		pi *= pi;
		if ((h >> j) & 1) {
			p *= 3;
			pi *= FP_CUB_I3;
		}
	}
	fp_cub_divd(c0, c0, p, pi);
	fp_cub_divd(c1, c1, p, pi);
}

/**
 * Precomputes the constants of fp_cub_modj(): -m^-1 mod 2^64, the powers
 * 2^(64 * (j + 1)) mod m and 2^(64 * FP_CUB_L) mod m, for m = FP_CUB_JM.
 *
 * @param[out] k			- the constants, FP_CUB_L + 2 of them.
 */
static void fp_cub_modj_pre(uint64_t *k) {
	const uint64_t m = FP_CUB_JM;
	uint64_t mi = m, c = (UINT64_MAX % m + 1) % m;

	for (int j = 0; j < 6; j++) {
		mi *= 2 - m * mi;
	}
	k[0] = -mi;
	for (size_t j = 0; j < FP_CUB_L; j++) {
		k[j + 1] = c;
		/* The next power, by doubling modulo m < 2^61. */
		for (int i = 0; i < 64; i++) {
			c <<= 1;
			c -= m & -(uint64_t)(c >= m);
		}
	}
	/* The power for j = FP_CUB_L - 1 is 2^(64 * FP_CUB_L) mod m. */
	k[FP_CUB_L + 1] = k[FP_CUB_L];
}

/**
 * Reduces an integer of FP_CUB_L limbs in two's complement modulo FP_CUB_JM,
 * with Montgomery reduction so that no division depends on the integer.
 *
 * @param[in] a				- the integer.
 * @param[in] k				- the constants from fp_cub_modj_pre().
 * @return the residue.
 */
static int64_t fp_cub_modj(const uint64_t *a, const uint64_t *k) {
	const uint64_t m = FP_CUB_JM;
	uint64_t r = 0, h, l, u, t, s;

	for (size_t j = 0; j < FP_CUB_L; j++) {
		/* The reduction of a_j * 2^(64 * (j + 1)) is a_j * 2^(64 * j). */
		fp_cub_mul64(&h, &l, a[j], k[j + 1]);
		u = l * k[0];
		fp_cub_mul64(&t, &s, u, m);
		(void)s;
		/* Both t and r stay at most m, with the sign of each difference as
		 * the mask of its correction, which compilers do not turn into
		 * branches as they may do with comparisons. */
		t += h + (l != 0) - m;
		t += m & (uint64_t)((int64_t)t >> 63);
		r += t - m;
		r += m & (uint64_t)((int64_t)r >> 63);
	}
	/* A negative integer is its limbs minus 2^(64 * FP_CUB_L). */
	r += (m - k[FP_CUB_L + 1]) & -(a[FP_CUB_L - 1] >> 63);
	return (int64_t)(r % m);
}

/**
 * Computes alpha = a - q * pi for the primary prime pi of norm p and q the
 * rounded a / pi, which has norm below p, with the scaled inverse of pi and
 * operations that do not depend on a.
 *
 * @param[out] x			- the first coordinate of alpha.
 * @param[out] y			- the second coordinate of alpha.
 * @param[in] g				- the integer a, in RLC_FP_DIGS + 1 digits.
 */
static void fp_cub_first(dig_t *x, dig_t *y, const dig_t *g) {
	ctx_t *ctx = core_get();
	dig_t q[2][FP_CUB_DIGS], h[2 * (RLC_FP_DIGS + 1)], z[FP_CUB_DIGS];
	dig_t t[FP_CUB_DIGS], c;
	const dig_t *u = ctx->cub_pi[0], *v = ctx->cub_pi[1];

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
}

/**
 * Selects between two signed integers without branches.
 *
 * @param[in] a				- the integer for a zero mask.
 * @param[in] b				- the integer for a full mask.
 * @param[in] m				- the mask, 0 or -1.
 * @return the selected integer.
 */
static int64_t fp_cub_sel(int64_t a, int64_t b, int64_t m) {
	return a ^ ((a ^ b) & m);
}

/**
 * Multiplies the Eisenstein integer x + y * w by a + b * w, for a and b in
 * {-1, 0, 1}, which applies a unit without selections.
 *
 * @param[in,out] x			- the first coordinate.
 * @param[in,out] y			- the second coordinate.
 * @param[in] a				- the first coordinate of the unit.
 * @param[in] b				- the second coordinate of the unit.
 */
static void fp_cub_unit(int64_t *x, int64_t *y, int64_t a, int64_t b) {
	int64_t x0 = *x, y0 = *y;

	*x = a * x0 - b * y0;
	*y = a * y0 + b * (x0 - y0);
}

/**
 * Reduces a signed integer below 2^61 in absolute value modulo 3, without
 * branches: adding 3^39 makes it nonnegative, and unsigned remainders are
 * cheaper. Larger integers give some residue, without overflows.
 *
 * @param[in] a				- the integer.
 * @return the residue in {0, 1, 2}.
 */
static int64_t fp_cub_c3(int64_t a) {
	return (int64_t)(((uint64_t)a + (uint64_t)4052555153018976267) % 3);
}

/**
 * Unpacks two signed 32-bit entries from a digit, as smb_steps() does.
 *
 * @param[out] lo			- the low entry.
 * @param[out] hi			- the high entry.
 * @param[in] w				- the packed entries.
 */
static void fp_cub_unpack(int64_t *lo, int64_t *hi, uint64_t w) {
	*lo = (int64_t)(w << 32) >> 32;
	*hi = (int64_t)(w - (uint64_t)*lo) >> 32;
}

/**
 * Runs len <= FP_CUB_JK / 2 combined iterations on residues of f and g, in
 * constant time, and returns their matrix: the rows (A, B) and (C, D) over
 * Z[w] with (-3w)^len * (f', g') = (A f + B g, C f + D g). An iteration
 * divides g by 1 - w if it can, or else makes g primary with a unit u and
 * replaces it by (u * g - f) / (1 - w)^2, after swapping f and u * g when
 * delta > 0, as in the half-delta divsteps. As every operation on a row is
 * the same for both of its entries, their coordinates are packed in pairs of
 * 32 bits, as smb_steps() packs its rows. An iteration multiplies the absolute
 * values of the entries by at most 3, so their coordinates stay below
 * 2 * 3^len / sqrt(3) < 2^31. As it does not increase the largest absolute
 * value of f and g, their coordinates stay below 2 * FP_CUB_JM / sqrt(3).
 *
 * @param[out] r			- the rows A, B, C and D, as coordinate pairs.
 * @param[in,out] f			- the residues of f.
 * @param[in,out] g			- the residues of g.
 * @param[in,out] mk		- m and k modulo 3, for f = (3m - 1) + 3k * w.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] len			- the number of iterations.
 */
static void fp_cub_jhalf(int64_t r[4][2], int64_t f[2], int64_t g[2],
		int64_t mk[2], int64_t *d, int64_t *e, int len) {
	/* Exact divisions by 3 are multiplications by its inverse modulo 2^64,
	 * and the results of inexact ones are never selected. */
	const uint64_t i3 = FP_CUB_I3;
	int64_t f0 = f[0], f1 = f[1], g0 = g[0], g1 = g[1], m = mk[0], k = mk[1];
	int64_t tab, dv, sw, ua, ub, j, mu, ku, h0, h1, q0, q1;
	/* The rows as packed coordinates: px = (A.x, B.x), py = (A.y, B.y), and
	 * qx, qy the same for (C, D), starting from the identity. */
	int64_t px = 1, py = 0, qx = (int64_t)1 << 32, qy = 0, tx, ty, ux, uy;
	/* Local copies, which stay in registers. */
	int64_t dl = *d, el = *e;

	for (; len > 0; len--) {
		/* From g mod 3, a table of 7 bits in a digit gives whether 1 - w
		 * divides g, and otherwise the unit u = a + b * w = (+/-) w^-j that
		 * makes g primary, 2 mod 3, which is 1 for a division. A shift by a
		 * secret amount takes constant time. */
		tab = (int64_t)((FP_CUB_TAB >> (7 * (3 * fp_cub_c3(g0) +
				fp_cub_c3(g1)))) & 127);
		dv = -(tab & 1);
		j = (tab >> 1) & 3;
		ua = ((tab >> 3) & 3) - 1;
		ub = (tab >> 5) - 1;
		sw = ~dv & -(int64_t)(dl > 0);
		/* u * g, and u * (C, D) on the packed row. */
		fp_cub_unit(&g0, &g1, ua, ub);
		tx = qx;
		ty = qy;
		fp_cub_unit(&tx, &ty, ua, ub);
		mu = fp_cub_c3((int64_t)((uint64_t)(g0 + 1) * i3));
		ku = fp_cub_c3((int64_t)((uint64_t)g1 * i3));
		/* The exponent, modulo 3: 2m for a division, or j(m + k) for the
		 * unit and 4m = m for (1 - w)^2, with the m of u * g after a swap. */
		el += (2 * m & dv) | ((j * (m + k) + m + ((mu - m) & sw)) & ~dv);
		/* The new delta: d + 2, d + 4, or 4 - d after a swap. */
		dl += 4 - (2 * dl & sw) - (2 & dv);
		/* The new f and g: g / (1 - w), or (u * g - f) / (1 - w)^2. */
		h0 = g0 - (f0 & ~dv);
		h1 = g1 - (f1 & ~dv);
		q0 = (int64_t)((uint64_t)(2 * h0 - h1) * i3);
		q1 = (int64_t)((uint64_t)(h0 + h1) * i3);
		h0 = (int64_t)((uint64_t)(2 * q0 - q1) * i3);
		h1 = (int64_t)((uint64_t)(q0 + q1) * i3);
		f0 += (g0 - f0) & sw;
		f1 += (g1 - f1) & sw;
		m += (mu - m) & sw;
		k += (ku - k) & sw;
		g0 = fp_cub_sel(h0, q0, dv);
		g1 = fp_cub_sel(h1, q1, dv);
		/* The rows, over a denominator that grows by (1 - w)^2 = -3w each
		 * iteration: u * (C, D) - (A, B) is the new row of g, and (A, B)
		 * plus it that of f after a swap, times (1 - w)^2 = (3y, 3y - 3x);
		 * a division multiplies the row of g by 1 - w = (x + y, 2y - x). */
		ux = tx - px;
		uy = ty - py;
		px += ux & sw;
		py += uy & sw;
		tx = 3 * py;
		py = 3 * (py - px);
		px = tx;
		tx = fp_cub_sel(ux, qx + qy, dv);
		qy = fp_cub_sel(uy, 2 * qy - qx, dv);
		qx = tx;
	}
	f[0] = f0;
	f[1] = f1;
	g[0] = g0;
	g[1] = g1;
	mk[0] = m;
	mk[1] = k;
	*d = dl;
	*e = el;
	fp_cub_unpack(&r[0][0], &r[1][0], (uint64_t)px);
	fp_cub_unpack(&r[0][1], &r[1][1], (uint64_t)py);
	fp_cub_unpack(&r[2][0], &r[3][0], (uint64_t)qx);
	fp_cub_unpack(&r[2][1], &r[3][1], (uint64_t)qy);
}

/**
 * Multiplies two Eisenstein integers with signed coordinates.
 *
 * @param[out] c			- the product.
 * @param[in] a				- the first factor.
 * @param[in] b				- the second factor.
 */
static void fp_cub_emul(int64_t c[2], const int64_t a[2], const int64_t b[2]) {
	c[0] = a[0] * b[0] - a[1] * b[1];
	c[1] = a[0] * b[1] + a[1] * b[0] - a[1] * b[1];
}

/**
 * Runs len <= FP_CUB_JK combined iterations on residues of f and g modulo
 * FP_CUB_JM, in constant time, and returns their matrix: the rows (A, B) and
 * (C, D) over Z[w] with (-3w)^len * (f', g') = (A f + B g, C f + D g), as the
 * product of those of two halves.
 *
 * @param[out] r			- the rows A, B, C and D, as coordinate pairs.
 * @param[in] f				- the residues of f.
 * @param[in] g				- the residues of g.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] len			- the number of iterations.
 */
static void fp_cub_jmat(int64_t r[4][2], const int64_t f[2], const int64_t g[2],
		int64_t *d, int64_t *e, int len) {
	const uint64_t i3 = FP_CUB_I3;
	int64_t ff[2] = { f[0], f[1] }, gg[2] = { g[0], g[1] }, s[4][2], t[4][2];
	int64_t u[2], v[2], mk[2];

	/* For f = (3m - 1) + 3k * w, m and k modulo 3. */
	mk[0] = fp_cub_c3((int64_t)((uint64_t)(ff[0] + 1) * i3));
	mk[1] = fp_cub_c3((int64_t)((uint64_t)ff[1] * i3));
	fp_cub_jhalf(s, ff, gg, mk, d, e, len / 2);
	fp_cub_jhalf(t, ff, gg, mk, d, e, len - len / 2);
	/* The second matrix times the first. */
	for (int i = 0; i < 2; i++) {
		fp_cub_emul(u, t[2 * i], s[0]);
		fp_cub_emul(v, t[2 * i + 1], s[2]);
		r[2 * i][0] = u[0] + v[0];
		r[2 * i][1] = u[1] + v[1];
		fp_cub_emul(u, t[2 * i], s[1]);
		fp_cub_emul(v, t[2 * i + 1], s[3]);
		r[2 * i + 1][0] = u[0] + v[0];
		r[2 * i + 1][1] = u[1] + v[1];
	}
}

/**
 * Computes the cubic residue symbol of a nonzero element for p = 1 mod 3 by
 * jumps of combined divsteps, either a number of them that only depends on
 * the size of p, or until g is 0.
 *
 * @param[in] a				- the prime field element.
 * @param[in] ct			- the flag to run in constant time.
 * @return k in {0, 1, 2}.
 */
static int fp_cub_jumps(const fp_t a, int ct) {
	ctx_t *ctx = core_get();
	dig_t g[RLC_FP_DIGS + 1], x[FP_CUB_DIGS], y[FP_CUB_DIGS];
	uint64_t w[4][FP_CUB_L], c[4][FP_CUB_L], mk[FP_CUB_L + 2], z;
	int64_t rf[2], rg[2], m[4][2], d = 1, e = 0;

	/* The stored digits of a, the integer a * R mod p in Montgomery form,
	 * whose symbol is that of a times that of R. */
	dv_copy(g, a, RLC_FP_DIGS);
	g[RLC_FP_DIGS] = 0;
	/* f = pi and g = a - q * pi, both of norm about p, in 64-bit limbs. */
	fp_cub_first(x, y, g);
	fp_cub_pack(w[0], ctx->cub_pi[0], RLC_FP_DIGS + 1);
	fp_cub_pack(w[1], ctx->cub_pi[1], RLC_FP_DIGS + 1);
	fp_cub_pack(w[2], x, FP_CUB_DIGS);
	fp_cub_pack(w[3], y, FP_CUB_DIGS);
	fp_cub_modj_pre(mk);

	for (int i = 0, n; i < FP_CUB_ITER; i += n) {
		n = RLC_MIN(FP_CUB_JK, FP_CUB_ITER - i);
		/* Without constant time, stop once g is 0. */
		if (!ct) {
			z = 0;
			for (size_t j = 0; j < FP_CUB_L; j++) {
				z |= w[2][j] | w[3][j];
			}
			if (z == 0) {
				break;
			}
		}
		rf[0] = fp_cub_modj(w[0], mk);
		rf[1] = fp_cub_modj(w[1], mk);
		rg[0] = fp_cub_modj(w[2], mk);
		rg[1] = fp_cub_modj(w[3], mk);
		fp_cub_jmat(m, rf, rg, &d, &e, n);
		/* f' = (A f + B g) / (1 - w)^(2n) and g' = (C f + D g) / (1 - w)^(2n),
		 * as (1 - w)^2 = -3w. */
		fp_cub_row(c[0], c[1], m[0], m[1], n, w[0], w[1], w[2], w[3]);
		fp_cub_row(c[2], c[3], m[2], m[3], n, w[0], w[1], w[2], w[3]);
		for (int k = 0; k < 4; k++) {
			for (size_t j = 0; j < FP_CUB_L; j++) {
				w[k][j] = c[k][j];
			}
		}
	}
	/* g is now 0 and f the unit -1, so the symbol is w^e, divided by that
	 * of R in Montgomery form. */
	return (int)((e + 3 - ctx->cub_r) % 3);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb_basic(const fp_t a) {
	bn_t t;
	int r = 0;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* t = (b - 1)/2. */
		t->sign = RLC_POS;
		t->used = RLC_FP_DIGS;
		dv_copy(t->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(t, t, 1);
		bn_hlv(t, t);

		fp_exp(t->dp, a, t);
		r = (fp_cmp_dig(t->dp, 1) == RLC_EQ);
		fp_neg(t->dp, t->dp);
		r = RLC_SEL(r, -(fp_cmp_dig(t->dp, 1) == RLC_EQ), !r);
	}
	RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return r;
}

/* Shifts the double digit H:L left by I bits, for 0 <= I <= RLC_DIG, keeping
 * the high digit. Shifting by RLC_DIG is undefined in C, but H is zero then. */
#define RLC_LSH(H, L, I)													\
		(H << (I & (RLC_DIG - 1))) |										\
		(L & -(I != 0)) >> ((RLC_DIG - I) & (RLC_DIG - 1))

int fp_smb_binar(const fp_t a) {
	const size_t s = RLC_DIG - 2;
	dv_t f, g, t;
	dig_t g_[2], f_[2], neg, l, g_hi, g_lo, f_hi, f_lo, mask, k = 0;
	dis_t m[4];
	int iterations = 2 * RLC_FP_DIGS * RLC_DIG;

	if (fp_is_zero(a)) {
		return 0;
	}

	dv_null_all(f, g, t);

	RLC_TRY {
		dv_new_all(f, g, t);

		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		/* Both stay nonnegative, with a zero sign digit for smb_apply(). */
		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;

		for (size_t len, i = 0; i < iterations / s; i++) {
			f_hi = f[RLC_FP_DIGS - 1], f_lo = f[RLC_FP_DIGS - 2];
			g_hi = g[RLC_FP_DIGS - 1], g_lo = g[RLC_FP_DIGS - 2];
			for (int j = RLC_FP_DIGS - 2; j >= 0; j--) {
				l = (f_hi | g_hi);
				l = ~l & (l - 1);
				mask = -(l >> (RLC_DIG - 1));
				f_hi = ((f_lo ^ f_hi) & mask) ^ f_hi;
				g_hi = ((g_lo ^ g_hi) & mask) ^ g_hi;
				f_lo = ((f[j] ^ f_lo) & mask) ^ f_lo;
				g_lo = ((g[j] ^ g_lo) & mask) ^ g_lo;
			}
			len = RLC_DIG - util_bits_dig(f_hi | g_hi);
			f_[0] = f[0], f_[1] = RLC_LSH(f_hi, f_lo, len);
			g_[0] = g[0], g_[1] = RLC_LSH(g_hi, g_lo, len);

			k = porninstep(m, f_, g_, k, s);

			/* (g, f) <- (m0 g + m1 f, m2 g + m3 f)/2^s, then their absolute
			 * values. */
			smb_apply(g, f, m, s);
			neg = RLC_SIGN(g[RLC_FP_DIGS]);
			bn_sneg_low(g, g, neg, RLC_FP_DIGS);
			bn_sneg_low(f, f, RLC_SIGN(f[RLC_FP_DIGS]), RLC_FP_DIGS);
			f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
			k += (f[0] >> 1) & neg;
		}

		k = porninstep(m, g, f, k, iterations % s);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv_free_all(f, g, t);
	}

	return (k & 1 ? -1 : 1);
}

int fp_smb_divst(const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	const int d = (49 * FP_PRIME + 80) / 17;
#else
	const int d = (49 * FP_PRIME + 57) / 17;
#endif
	dig_t delta = 1, g0, d0, fs, gs, k, mask, s;
	bn_t _t;
	dv_t f, g, t;
	int r = 0;

	bn_null(_t);
	dv_null_all(f, g, t);

	RLC_TRY {
		bn_new(_t);
		dv_new_all(f, g, t);

#if RLC_WSIZE == 8
		bn_set_dig(_t, d >> 8);
		bn_lsh(_t, _t, 8);
		bn_add_dig(_t, _t, d & 0xFF);
#else
		bn_set_dig(_t, d);
#endif

		k = 0;
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		dv_zero(t, 2 * RLC_FP_DIGS);
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		r = dv_cmp_sec(g, f, RLC_FP_DIGS);
		fp_subn_low(t, g, f);
		fp_copy_sec(g, t, r != RLC_LT);

		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			d0 = g[0] & ((int)delta > 0);
			/* Conditionally negate delta if d0 is set. */
			delta = (delta ^ -d0) + d0;
			/* Conditionally swap and negate based on d0. */
			mask = -d0;
			s = (fs ^ gs) & mask;
			fs ^= s;
			gs ^= s ^ d0;
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
				s = (f[j] ^ g[j]) & mask;
				f[j] ^= s;
				g[j] ^= s ^ (-d0);
			}
			fp_add1_low(g, g, d0);

			k ^= (((g[0] & f[0]) >> (dig_t)1) ^ (fs & gs)) & d0;
			k ^= (f[0] >> 1) ^ (f[0] >> 2);
			k &= 1;

			delta++;
			g0 = g[0] & 1;
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
				t[j] = f[j] & (-g0);
			}

			/* Compute g = (g + g0*f) div 2 by conditionally copying f to u and
			 * updating the sign of g. */
			gs ^= g0 & (fs ^ bn_addn_low(g, g, t, RLC_FP_DIGS));
			/* Shift and restore the sign. */
			fp_rsh1_low(g, g);
			g[RLC_FP_DIGS - 1] |= (dig_t)gs << (RLC_DIG - 1);
		}

		k = (2*k) % 4;
		fp_zero(t);
		t[0] = 1;
		bn_sneg_low(f, f, fs, RLC_FP_DIGS);
		
		r = RLC_SEL(r, 1 - k, dv_equ_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_sneg_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - k, dv_equ_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - k, fp_is_zero(f));
		r = RLC_SEL(r, 0, fp_is_zero(a));
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(_t);
		dv_free_all(f, g, t);
	}
	return r;
}

int fp_smb_jmpds(const fp_t a) {
	dis_t m[4];
	dv_t f, g, t;
	dig_t j = 0, k;
	int r = 0, s;
#if RLC_WSIZE == 8
	int zeta = -1;
#else
	dis_t zeta = -1;
#endif

	dv_null_all(f, g, t);

	RLC_TRY {
		dv_new_all(f, g, t);

		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		f[RLC_FP_DIGS] = 0;
		dv_zero(g, RLC_FP_DIGS + 1);
		dv_zero(t + RLC_FP_DIGS, RLC_FP_DIGS);

#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif

		/* The number of steps only depends on the prime size. */
		for (int i = 0; i < JMPDS_ITERS; i += s) {
			s = RLC_MIN(JMPDS_STEPS, JMPDS_ITERS - i);
			zeta = smb_steps(m, &k, zeta, f[0], g[0], s);
			smb_apply(f, g, m, s);
			/* Count the sign changes of f, whose parity is its sign. */
			j = (j + k) % 4;
			j = (j + ((j & 1) ^ RLC_SIGN(f[RLC_FP_DIGS]))) % 4;
		}
		/* Each flip of the symbol added two to the count. */
		j = (j + (j & 1)) % 4;

		fp_zero(t);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		t[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_sneg_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(f, g, t);
	}

	return r;
}

#if FP_SMB == FP_LOWER

int fp_smb_lower(const fp_t a) {
	return fp_smbm_low(a);
}

#endif

int fp_smb_cub(const fp_t a) {
	if (fp_is_zero(a)) {
		return -1;
	}
	if (fp_prime_get_mod18() % 3 == 2) {
		return 0;
	}
	return fp_cub_jumps(a, 0);
}

int fp_smb_cub_jmpds(const fp_t a) {
	dig_t z = 0;

	for (size_t j = 0; j < RLC_FP_DIGS; j++) {
		z |= a[j];
	}
	if (fp_prime_get_mod18() % 3 == 2) {
		return -(int)(z == 0);
	}
	/* Zero has no symbol. */
	return fp_cub_jumps(a, 1) | -(int)(z == 0);
}
