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
 * Constants of the reduction modulo FP_CUB_JM: -FP_CUB_JM^-1 modulo 2^64, and
 * the powers 2^(64 * i) modulo FP_CUB_JM for 0 <= i <= 33, which are enough for
 * the limbs of primes of up to 4096 bits.
 */
#define FP_CUB_JMI		((uint64_t)0xf5942fe5e5698517)
#if FP_PRIME > 4096
#error "The powers modulo FP_CUB_JM only cover primes of up to 4096 bits."
#endif
static const uint64_t smb3_pow[34] = {
	(uint64_t)1,
	(uint64_t)885671743960654459,
	(uint64_t)792073204337213275,
	(uint64_t)586490958008935255,
	(uint64_t)1295230848450375760,
	(uint64_t)710001608724358780,
	(uint64_t)635941805576807998,
	(uint64_t)533011610587339816,
	(uint64_t)762588996820054978,
	(uint64_t)131445467812113139,
	(uint64_t)1240965494095201864,
	(uint64_t)792337006269962041,
	(uint64_t)454462252115244490,
	(uint64_t)1185228923154704143,
	(uint64_t)205684517671594132,
	(uint64_t)1340767436457147481,
	(uint64_t)326157572186370961,
	(uint64_t)1029922088796227299,
	(uint64_t)631889733757841308,
	(uint64_t)1075631505205135714,
	(uint64_t)684124450186419301,
	(uint64_t)749433300652420678,
	(uint64_t)212207963177166991,
	(uint64_t)747655825117739368,
	(uint64_t)427747832907210748,
	(uint64_t)1082644498137464449,
	(uint64_t)930089920312740370,
	(uint64_t)467668154078311051,
	(uint64_t)409686187828695001,
	(uint64_t)1010659045755081532,
	(uint64_t)1032617185993781434,
	(uint64_t)1229910867075030469,
	(uint64_t)1189294920532567840,
	(uint64_t)589500091577369611
};

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
static void smb3_mul64(uint64_t *h, uint64_t *l, uint64_t a, uint64_t b) {
#if RLC_DIG == 64
	RLC_MUL_DIG(*h, *l, a, b);
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
static void smb3_pack(uint64_t *c, const dig_t *a, size_t n) {
	const dig_t m = -(a[n - 1] >> (RLC_DIG - 1));

	for (size_t j = 0; j < FP_CUB_L; j++) {
		c[j] = 0;
	}
	for (size_t i = 0; i < FP_CUB_L * 64 / RLC_DIG; i++) {
		c[i * RLC_DIG / 64] |= (uint64_t)(i < n ? a[i] : m) << (i * RLC_DIG % 64);
	}
}

/**
 * Divides an integer of len limbs in two's complement by an odd 64-bit
 * integer, when the division is exact, limb by limb from the lowest one: each
 * limb of the quotient is the current limb times the inverse modulo 2^64, and
 * the high limb of its product with the divisor is the borrow into the next.
 * This gives the quotient modulo 2^(64 * len) with two products per limb and
 * no division.
 *
 * @param[out] c			- the quotient.
 * @param[in] a				- the integer, a multiple of d.
 * @param[in] d				- the odd divisor.
 * @param[in] inv			- the inverse of d modulo 2^64.
 * @param[in] len			- the number of limbs.
 */
static inline void smb3_divd(uint64_t *c, const uint64_t *a, uint64_t d,
		uint64_t inv, size_t len) {
	uint64_t b = 0, h, l, q;

	for (size_t j = 0; j < len; j++) {
		l = a[j] - b;
		b = (a[j] < b);
		q = l * inv;
		c[j] = q;
		/* The borrow is the high limb of d * q, the low one being l. */
		smb3_mul64(&h, &l, q, d);
		b += h;
	}
}

/**
 * Computes a combination of four integers of len limbs in two's complement
 * with signed factors, in one pass:
 * c = s0 * a0 + s1 * a1 + s2 * a2 + s3 * a3, with each negative term added as
 * the complement of its absolute value plus one.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the integers.
 * @param[in] s				- the factors, below 2^63 in absolute value.
 * @param[in] len			- the number of limbs.
 */
static inline void smb3_lin(uint64_t *c, const uint64_t *a[4],
		const int64_t s[4], size_t len) {
	uint64_t ms[4], ns[4], cs[4] = { 0, 0, 0, 0 }, k = 0, h, l, d;

	for (int i = 0; i < 4; i++) {
		ms[i] = (uint64_t)(s[i] < 0 ? -s[i] : s[i]);
		ns[i] = -(uint64_t)(s[i] < 0);
		k += (s[i] < 0);
	}
	for (size_t j = 0; j < len; j++) {
		d = k;
		k = 0;
		for (int i = 0; i < 4; i++) {
			smb3_mul64(&h, &l, ms[i], a[i][j]);
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
 * Computes (m * alpha + n * beta) / (1 - w)^(2h) in len limbs, where the
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
 * @param[in] len			- the number of limbs.
 */
static inline void smb3_row(uint64_t *c0, uint64_t *c1, const int64_t m[2],
		const int64_t n[2], int h, const uint64_t *x, const uint64_t *y,
		const uint64_t *u, const uint64_t *v, size_t len) {
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

	smb3_lin(c0, f, f0, len);
	smb3_lin(c1, f, f1, len);
	/* Divide by 3^h, with 3^h and its inverse by squaring and multiplying. */
	for (int j = 5; j >= 0; j--) {
		p *= p;
		pi *= pi;
		if ((h >> j) & 1) {
			p *= 3;
			pi *= FP_CUB_I3;
		}
	}
	smb3_divd(c0, c0, p, pi, len);
	smb3_divd(c1, c1, p, pi, len);
}

/**
 * Reduces an integer of len limbs in two's complement modulo FP_CUB_JM, with
 * Montgomery reduction so that no division depends on the integer.
 *
 * @param[in] a				- the integer.
 * @param[in] len			- the number of limbs.
 * @return the residue.
 */
static inline int64_t smb3_modj(const uint64_t *a, size_t len) {
	const uint64_t m = FP_CUB_JM;
	uint64_t r = 0, h, l, u, t, s;

	for (size_t j = 0; j < len; j++) {
		/* The reduction of a_j * 2^(64 * (j + 1)) is a_j * 2^(64 * j). */
		smb3_mul64(&h, &l, a[j], smb3_pow[j + 1]);
		u = l * FP_CUB_JMI;
		smb3_mul64(&t, &s, u, m);
		(void)s;
		/* Both t and r stay at most m, with the sign of each difference as
		 * the mask of its correction, which compilers do not turn into
		 * branches as they may do with comparisons. */
		t += h + (l != 0) - m;
		t += m & (uint64_t)((int64_t)t >> 63);
		r += t - m;
		r += m & (uint64_t)((int64_t)r >> 63);
	}
	/* A negative integer is its limbs minus 2^(64 * len), which leaves r
	 * below 2m, reduced without a division, which 32-bit processors may
	 * compute in a time that depends on its operands. */
	r += (m - smb3_pow[len]) & -(a[len - 1] >> 63);
	r -= m;
	r += m & (uint64_t)((int64_t)r >> 63);
	return (int64_t)r;
}

/**
 * Reduces an integer of len limbs in two's complement modulo 9, in variable
 * time, with 2^64 = 7 mod 9.
 *
 * @param[in] a				- the integer.
 * @param[in] len			- the number of limbs.
 * @return the residue.
 */
static int smb3_mod9(const uint64_t *a, size_t len) {
	unsigned r = 0, w = 1;

	for (size_t j = 0; j < len; j++) {
		r += (unsigned)(a[j] % 9) * w;
		w = w * 7 % 9;
	}
	/* A negative integer is its limbs minus 2^(64 * len) = 7^len mod 9. */
	r += (9 - w) * (unsigned)(a[len - 1] >> 63);
	return (int)(r % 9);
}

/**
 * Reduces a signed integer below 2^61 in absolute value modulo 3, without
 * branches: adding 3^39 makes it nonnegative, and unsigned remainders are
 * cheaper. Larger integers give some residue, without overflows.
 *
 * @param[in] a				- the integer.
 * @return the residue in {0, 1, 2}.
 */
static int64_t smb3_c3(int64_t a) {
	return (int64_t)(((uint64_t)a + (uint64_t)4052555153018976267) % 3);
}

/**
 * Unpacks two signed 32-bit entries from a digit, the high one with the
 * borrow of the low one.
 *
 * @param[out] lo			- the low entry.
 * @param[out] hi			- the high entry.
 * @param[in] w				- the packed entries.
 */
static void smb3_unpack(int64_t *lo, int64_t *hi, uint64_t w) {
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
 * 32 bits. An iteration multiplies the absolute values of the entries by at
 * most 3, so their coordinates stay below 2 * 3^len / sqrt(3) < 2^31. As it
 * does not increase the largest absolute value of f and g, their coordinates
 * stay below 2 * FP_CUB_JM / sqrt(3).
 *
 * @param[out] r			- the rows A, B, C and D, as coordinate pairs.
 * @param[in,out] f			- the residues of f.
 * @param[in,out] g			- the residues of g.
 * @param[in,out] mk		- m and k modulo 3, for f = (3m - 1) + 3k * w.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] len			- the number of iterations.
 */
static void smb3_jhalf(int64_t r[4][2], int64_t f[2], int64_t g[2],
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
		tx = ua * qx - ub * qy;
		ty = ua * qy + ub * (qx - qy);
		mu = smb3_c3((int64_t)((uint64_t)(g0 + 1) * i3));
		ku = smb3_c3((int64_t)((uint64_t)g1 * i3));
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
		g0 = h0 ^ ((h0 ^ q0) & dv);
		g1 = h1 ^ ((h1 ^ q1) & dv);
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
		tx = ux ^ ((ux ^ (qx + qy)) & dv);
		qy = uy ^ ((uy ^ (2 * qy - qx)) & dv);
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
	smb3_unpack(&r[0][0], &r[1][0], (uint64_t)px);
	smb3_unpack(&r[0][1], &r[1][1], (uint64_t)py);
	smb3_unpack(&r[2][0], &r[3][0], (uint64_t)qx);
	smb3_unpack(&r[2][1], &r[3][1], (uint64_t)qy);
}

/**
 * Computes one jump of n <= FP_CUB_JK combined iterations on
 * f = w[0] + w[1] * w and g = w[2] + w[3] * w. The iterations run on the
 * residues of f and g modulo FP_CUB_JM in two halves, in constant time, and
 * give the rows (A, B) and (C, D) over Z[w] with
 * (-3w)^n * (f', g') = (A f + B g, C f + D g), as the product of those of the
 * halves, which are then applied to f and g in len limbs.
 *
 * @param[out] c			- the coordinates of f' and g'.
 * @param[in] w				- the coordinates of f and g.
 * @param[in,out] d			- the doubled delta.
 * @param[in,out] e			- the exponent of the symbol.
 * @param[in] n				- the number of iterations.
 * @param[in] len			- the number of limbs.
 */
static inline void smb3_jump(uint64_t c[4][FP_CUB_L],
		uint64_t w[4][FP_CUB_L], int64_t *d, int64_t *e, int n, size_t len) {
	int64_t f[2], g[2], mk[2], s[4][2], t[4][2], r[4][2], u[2], v[2];

	f[0] = smb3_modj(w[0], len);
	f[1] = smb3_modj(w[1], len);
	g[0] = smb3_modj(w[2], len);
	g[1] = smb3_modj(w[3], len);
	/* For f = (3m - 1) + 3k * w, m and k modulo 3. */
	mk[0] = smb3_c3((int64_t)((uint64_t)(f[0] + 1) * FP_CUB_I3));
	mk[1] = smb3_c3((int64_t)((uint64_t)f[1] * FP_CUB_I3));
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
 * Starts the cubic residue symbol of a nonzero element for p = 1 mod 3 with
 * f = pi and g = a - q * pi, for the primary prime pi of norm p and q the
 * rounded a / pi, so that g has norm below p. The quotient comes from the
 * scaled inverse of pi, with operations that do not depend on a.
 *
 * @param[out] w			- the coordinates of f and g, in 64-bit limbs.
 * @param[in] a				- the prime field element.
 */
static void smb3_init(uint64_t w[4][FP_CUB_L], const fp_t a) {
	ctx_t *ctx = core_get();
	dig_t g[RLC_FP_DIGS + 1], x[FP_CUB_DIGS], y[FP_CUB_DIGS];
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
	smb3_pack(w[0], u, RLC_FP_DIGS + 1);
	smb3_pack(w[1], v, RLC_FP_DIGS + 1);
	smb3_pack(w[2], x, FP_CUB_DIGS);
	smb3_pack(w[3], y, FP_CUB_DIGS);
}

/**
 * Returns the number of limbs that the coordinates of f and g need, in
 * variable time. Their absolute values do not grow, but a coordinate may
 * double, so the largest stays below 2^(64 * len - 3). A limb that comes back
 * is set to the sign extension, and not to what was left there before.
 *
 * @param[in,out] w			- the coordinates of f and g.
 * @param[in] len			- the current number of limbs.
 * @return the new number of limbs.
 */
static size_t smb3_shrink(uint64_t w[4][FP_CUB_L], size_t len) {
	uint64_t s;
	size_t t = 1;

	for (int j = 0; j < 4; j++) {
		s = -(w[j][len - 1] >> 63);
		for (size_t l = len; l > 0; l--) {
			if ((w[j][l - 1] ^ s) != 0) {
				t = RLC_MAX(t, l + (((w[j][l - 1] ^ s) >> 61) != 0));
				break;
			}
		}
	}
	t = RLC_MIN(t, (size_t)FP_CUB_L);
	for (int j = 0; j < 4; j++) {
		s = -(w[j][len - 1] >> 63);
		for (size_t l = len; l < t; l++) {
			w[j][l] = s;
		}
	}
	return t;
}

/**
 * Computes the cubic residue symbol by jumps of combined divsteps, either a
 * number of them that only depends on the size of p, or until g is 0, with
 * -1 for zero and 0 for p = 2 mod 3, where every element is a cube. Jumps of
 * one iteration are the divsteps themselves.
 *
 * @param[in] a				- the prime field element.
 * @param[in] ct			- the flag to run in constant time.
 * @param[in] k				- the largest number of iterations per jump.
 * @return k in {0, 1, 2}, or -1 if the element is zero.
 */
static int smb3_symbol(const fp_t a, int ct, int k) {
	uint64_t w[4][FP_CUB_L], c[4][FP_CUB_L], z = 0;
	int64_t d = 1, e = 0;
	size_t len = FP_CUB_L;
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
		/* A fixed number of limbs in constant time, so that the compiler can
		 * specialize the loops for it. */
		if (ct) {
			smb3_jump(c, w, &d, &e, n, FP_CUB_L);
		} else {
			smb3_jump(c, w, &d, &e, n, len);
		}
		for (int j = 0; j < 4; j++) {
			for (size_t l = 0; l < len; l++) {
				w[j][l] = c[j][l];
			}
		}
		/* Without constant time, keep only the limbs that f and g need. */
		if (!ct) {
			len = smb3_shrink(w, len);
		}
	}
	/* g is now 0 and f the unit -1, so the symbol is w^e, divided by that
	 * of R in Montgomery form; zero has no symbol. */
	return (int)((e + 3 - core_get()->cub_r) % 3) | -zero;
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
		/* The k of the only one of 1, z and z^2 that is equal to the power,
		 * from dv_equ_sec(), which is 0 if equal and RLC_NE = 2 otherwise,
		 * without comparisons that compilers may turn into branches. */
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
	uint64_t w[4][FP_CUB_L], c[2][FP_CUB_L], z;
	int64_t x[4], nf, ng, e = 0, tab, dv, j, ua, ub, mf, kf;
	const int64_t one[2] = { 1, -1 }, nul[2] = { 0, 0 }, neg[2] = { -1, 0 };
	int64_t u[2];
	size_t len = FP_CUB_L, b, l;

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
					z |= w[i][l - 1] ^ -(w[i][len - 1] >> 63);
				}
			}
			b = 64 * l;
			for (; z != 0; z >>= 1) {
				b++;
			}
			b = (b > 29 ? b - 29 : 0);
			/* The bits from position b, with the sign above the top limb, and
			 * a shift in two steps so that it is not by 64 bits. */
			for (int i = 0; i < 4; i++) {
				z = (b / 64 + 1 < len ? w[i][b / 64 + 1] : -(w[i][len - 1] >> 63));
				x[i] = (int64_t)((w[i][b / 64] >> (b % 64)) |
						((z << 1) << (63 - b % 64)));
			}
			nf = x[0] * x[0] - x[0] * x[1] + x[1] * x[1];
			ng = x[2] * x[2] - x[2] * x[3] + x[3] * x[3];
			u[0] = ua;
			u[1] = ub;
			if (ng < nf) {
				/* Replace f by u * g, by reciprocity, and g by
				 * (u * g - f) / (1 - w)^2. */
				smb3_row(c[0], c[1], u, neg, 1, w[2], w[3], w[0], w[1], len);
				smb3_row(w[0], w[1], u, nul, 0, w[2], w[3], w[2], w[3], len);
				mf = (smb3_mod9(w[0], len) + 1) % 9 / 3;
				kf = smb3_mod9(w[1], len) / 3;
			} else {
				/* Replace u * g by (u * g - f) / (1 - w)^2. */
				smb3_row(c[0], c[1], u, neg, 1, w[2], w[3], w[0], w[1], len);
			}
			/* (1 - w)^2 gives w^(4m) = w^m, with the m of the new f. */
			e += mf;
		}
		for (l = 0; l < len; l++) {
			w[2][l] = c[0][l];
			w[3][l] = c[1][l];
		}
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
