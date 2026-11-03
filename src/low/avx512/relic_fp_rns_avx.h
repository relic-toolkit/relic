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
 * Vector arithmetic for the lower level of a Residue Number System with
 * AVX-512 IFMA: eight residues per vector, multiplied with the 52-bit
 * multiply-add instructions. The moduli are below 2^50, so that residues and
 * sums of a few of them, below 4m, still fit the multipliers: stored elements
 * keep residues at most m, and products without reduction below 4m.
 *
 * @ingroup fp
 */

#ifndef RLC_FP_RNS_AVX_H
#define RLC_FP_RNS_AVX_H

#include <immintrin.h>

#include "relic_core.h"
#include "relic_fpx.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/*
 * Each base is padded to RLC_FP_RNSO residues, a multiple of 8, so that it
 * fills whole vectors. The moduli and constants are zero in the padding, where
 * operations give zero or harmless values that never reach the residues.
 */

/** Number of vectors that hold the residues of each base. */
#define RNS_NB		(RLC_FP_RNSO / 8)

/** Number of vectors that hold the residues of both bases. */
#define RNS_NE		(RLC_FP_LEN / 8)

/**
 * Largest number of values reduced at once: enough independent dependency
 * chains to keep the multipliers busy, within the 32 vector registers.
 */
#define RNS_K		(RNS_NB == 1 ? 8 : 4)

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a vector of residues of an element of Fp2: the vectors of each
 * component.
 */
typedef __m512i rp2_t[2];

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Applies a residue-wise operation to the vectors of both bases, with the
 * moduli in _vm and their inverses modulo 2^52 in _vi.
 */
#define RNS_VMAP(C, OP)														\
	ctx_t *_ctx = core_get();												\
	const dig_t *_m = _ctx->rns.m, *_i = _ctx->rns.iv;						\
	for (size_t _k = 0; _k < RNS_NE; _k++) {								\
		__m512i _vm = rns_load(_m, _k);										\
		__m512i _vi = rns_load(_i, _k);										\
		(void)_vi;															\
		rns_store(C, _k, OP);												\
	}

/** Loads the current vector of an operand inside RNS_VMAP(). */
#define RNS_V(A)	rns_load(A, _k)

/**
 * Gives the coefficient of w^e over Fp2 of an element of Fp4, Fp8, Fp16 or
 * Fp24, where w is the generator adjoined last and w^2, w^4, w^8 or w^12 is
 * the non-residue of Fp2: the towers multiply the exponents of their
 * generators.
 */
/** @{ */
#define RNS_CO4(A, E)		(A)[(E)]
#define RNS_CO8(A, E)		(A)[(E) % 2][(E) / 2]
#define RNS_CO16(A, E)		(A)[(E) % 2][((E) / 2) % 2][(E) / 4]
#define RNS_CO24(A, E)		(A)[(E) % 3][((E) / 3) % 2][(E) / 6]
/** @} */

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Loads the k-th vector of residues.
 */
static inline __m512i rns_load(const dig_t *a, size_t k) {
	return _mm512_loadu_si512(a + 8 * k);
}

/**
 * Stores the k-th vector of residues.
 */
static inline void rns_store(dig_t *c, size_t k, __m512i a) {
	_mm512_storeu_si512(c + 8 * k, a);
}

/**
 * Returns the bound 4m on the residues of products without reduction, below
 * 2^52 as the moduli are below 2^50: they still fit the multipliers, and their
 * sums and differences are brought back below it.
 */
static inline __m512i rns_vdv(__m512i m) {
	return _mm512_slli_epi64(m, 2);
}

/**
 * Returns the number of halvings for rns_vpeel() that bring residues below
 * b / 4 times m down to at most m: the smallest s with b <= 4 * 2^s.
 */
static inline int rns_halvings(int b) {
	int s = 0;

	while ((4 << s) < b) {
		s++;
	}
	return s;
}

/**
 * Bound on the outputs of a base extension without correction, as a multiple
 * of m / 4: RLC_FP_RNS products of residues at most m give at most
 * RLC_FP_RNS * m / 4, the Montgomery reduction adds m, and the correction by
 * alpha, below RLC_FP_RNS * m / 2^52, a little more.
 */
#define RNS_EXT_BOUND	(RLC_FP_RNS + 4 + 1)

/**
 * Subtracts m from values below 2m, lane-wise.
 */
static inline __m512i rns_vcrt(__m512i a, __m512i m) {
	/* Below m, a - m wraps around and the minimum is a. */
	return _mm512_min_epu64(a, _mm512_sub_epi64(a, m));
}

/**
 * Adds residues modulo m, lane-wise.
 */
static inline __m512i rns_vadd(__m512i a, __m512i b, __m512i m) {
	return rns_vcrt(_mm512_add_epi64(a, b), m);
}

/**
 * Subtracts residues modulo m, lane-wise.
 */
static inline __m512i rns_vsub(__m512i a, __m512i b, __m512i m) {
	__m512i d = _mm512_sub_epi64(a, b);

	/* For a >= b, d + m >= m > d; otherwise d wraps around and d + m < m. */
	return _mm512_min_epu64(d, _mm512_add_epi64(d, m));
}

/**
 * Negates residues at most m modulo m, lane-wise, as m - a in [0, m]: a factor
 * of a product only needs to fit in 52 bits, so the correction is skipped.
 */
static inline __m512i rns_vneg(__m512i a, __m512i m) {
	return _mm512_sub_epi64(m, a);
}

/**
 * Computes h + l / 2^52 + m - (q * m) / 2^52, for q = l * m^{-1} mod 2^52, as
 * one Montgomery reduction of h * 2^52 + l modulo m, lane-wise: the low halves
 * of the sum and of q * m cancel exactly, so the result is (h * 2^52 + l) /
 * 2^52 mod m, in (h', h' + m] for h' the top bits of the sum. With moduli below
 * 2^50, the top bits of a product of residues at most m are below m / 4, so k
 * products summed give a result at most (k / 4 + 1) * m.
 *
 * @param[in] l				- the low halves, below 2^63 in total.
 * @param[in] h				- the high halves, below 2^63 in total.
 * @param[in] m				- the moduli.
 * @param[in] v				- the inverses of the moduli modulo 2^52.
 */
static inline __m512i rns_vmon(__m512i l, __m512i h, __m512i m, __m512i v) {
	const __m512i z = _mm512_setzero_si512();
	__m512i q;

	h = _mm512_add_epi64(h, _mm512_srli_epi64(l, 52));
	q = _mm512_madd52lo_epu64(z, l, v);
	/* The accumulator -m gives h - (q * m) / 2^52 + m. */
	return _mm512_sub_epi64(h,
			_mm512_madd52hi_epu64(_mm512_sub_epi64(z, m), q, m));
}

/**
 * Brings residues at most 2^s * m down to at most m, lane-wise, subtracting
 * 2^(s - 1) * m, ..., 2 * m and m where that does not wrap around.
 *
 * @param[in] a				- the residues.
 * @param[in] m				- the moduli.
 * @param[in] s				- the number of halvings of the bound.
 */
static inline __m512i rns_vpeel(__m512i a, __m512i m, int s) {
	for (int i = s - 1; i >= 0; i--) {
		a = rns_vcrt(a, _mm512_slli_epi64(m, i));
	}
	return a;
}

/**
 * Multiplies residues by Montgomery multiplication, computing a * b / 2^52
 * mod m lane-wise, at most 2^(2t - 2) * m + m for inputs at most 2^t * m: for
 * products without reduction, which stay below 2^52, and below 4m.
 */
static inline __m512i rns_vmul(__m512i a, __m512i b, __m512i m, __m512i v) {
	const __m512i z = _mm512_setzero_si512();

	return rns_vmon(_mm512_madd52lo_epu64(z, a, b),
			_mm512_madd52hi_epu64(z, a, b), m, v);
}

/**
 * Multiplies residues by a constant as rns_vmul() does, given also bv = b * v
 * mod 2^52: the quotient q = (a * b mod 2^52) * v mod 2^52 is then a * bv mod
 * 2^52, computed alongside the product instead of after it, and the low half
 * of the product is not needed, as it cancels exactly.
 */
static inline __m512i rns_vmulc(__m512i a, __m512i b, __m512i bv, __m512i m) {
	const __m512i z = _mm512_setzero_si512();
	__m512i q = _mm512_madd52lo_epu64(z, a, bv);

	return _mm512_sub_epi64(_mm512_madd52hi_epu64(z, a, b),
			_mm512_madd52hi_epu64(_mm512_sub_epi64(z, m), q, m));
}

/**
 * Adds two products of residues at most m before a single Montgomery
 * reduction, computing (a * b + c * d) / 2^52 mod m lane-wise, at most
 * 3m / 2: for products without reduction.
 */
static inline __m512i rns_vmul2(__m512i a, __m512i b, __m512i c, __m512i d,
		__m512i m, __m512i v) {
	const __m512i z = _mm512_setzero_si512();
	__m512i l, h;

	l = _mm512_madd52lo_epu64(z, a, b);
	h = _mm512_madd52hi_epu64(z, a, b);
	l = _mm512_madd52lo_epu64(l, c, d);
	h = _mm512_madd52hi_epu64(h, c, d);
	return rns_vmon(l, h, m, v);
}

/**
 * Adds three products of residues at most m before a single Montgomery
 * reduction, computing (a * b + c * d + e * f) / 2^52 mod m lane-wise, at most
 * 7m / 4: for products without reduction.
 */
static inline __m512i rns_vmul3(__m512i a, __m512i b, __m512i c, __m512i d,
		__m512i e, __m512i f, __m512i m, __m512i v) {
	const __m512i z = _mm512_setzero_si512();
	__m512i l, h;

	l = _mm512_madd52lo_epu64(z, a, b);
	h = _mm512_madd52hi_epu64(z, a, b);
	l = _mm512_madd52lo_epu64(l, c, d);
	h = _mm512_madd52hi_epu64(h, c, d);
	l = _mm512_madd52lo_epu64(l, e, f);
	h = _mm512_madd52hi_epu64(h, e, f);
	return rns_vmon(l, h, m, v);
}

/**
 * Reduces h * 2^52 + l by one Montgomery reduction modulo m and brings the
 * result down to at most m, lane-wise, given that it is at most 2^s * m: for
 * k products of residues at most m, the smallest s with k / 4 + 1 <= 2^s.
 */
static inline __m512i rns_vred(__m512i l, __m512i h, __m512i m, __m512i v,
		int s) {
	return rns_vpeel(rns_vmon(l, h, m, v), m, s);
}

/**
 * Multiplies residues by a small nonnegative integer modulo m, lane-wise.
 */
static inline __m512i rns_vsml(__m512i a, int s, __m512i m) {
	__m512i r = a;
	int k = 0;

	if (s <= 1) {
		return (s == 0 ? _mm512_setzero_si512() : a);
	}
	while ((s >> (k + 1)) != 0) {
		k++;
	}
	/* Left-to-right double-and-add, from the bit below the top one. */
	for (k--; k >= 0; k--) {
		r = rns_vadd(r, r, m);
		if ((s >> k) & 1) {
			r = rns_vadd(r, a, m);
		}
	}
	return r;
}

/**
 * Gets the non-residue s + i of the extension towers over Fp2, with i^2 = q.
 *
 * @param[out] s			- the integer part of the non-residue.
 * @param[out] q			- the square of i.
 */
static inline void rns_nor(int *s, int *q) {
#ifdef FP_QNRES
	/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
	*s = 1;
	*q = -1;
#else
	*q = fp_prime_get_qnr();
	switch (fp_prime_get_mod8()) {
		case 1:
		case 5:
			/* If p = 1,5 mod 8, (i) is a QNR/CNR. */
			*s = 0;
			break;
		default:
			/* Otherwise, (2^k + i) with k >= 0, as computed by Fp2. */
			*s = fp2_field_get_qnr();
			break;
	}
#endif
}

/**
 * Multiplies vectors of elements of Fp2 by the non-residue s + i, with
 * i^2 = q.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the vector to multiply.
 * @param[in] s				- the integer part of the non-residue.
 * @param[in] q				- the square of i.
 * @param[in] m				- the moduli.
 */
rlc_inline void rp2_nor(rp2_t c, const rp2_t a, int s, int q, __m512i m) {
	/* (a_0 + a_1 * i) * (s + i) = (s * a_0 + q * a_1) + (a_0 + s * a_1) * i. */
	__m512i t = rns_vadd(a[0], rns_vsml(a[1], s, m), m);

	c[0] = rns_vsub(rns_vsml(a[0], s, m), rns_vsml(a[1], -q, m), m);
	c[1] = t;
}

/**
 * Accumulates the product of vectors of elements of Fp2, with i^2 = q, into
 * the halves of unreduced sums of products of residues, lane-wise.
 *
 * @param[in,out] l			- the low halves of the sums.
 * @param[in,out] h			- the high halves of the sums.
 * @param[in] a				- the first vector to multiply.
 * @param[in] b				- the second vector to multiply.
 * @param[in] t				- the product q * b_1.
 */
rlc_inline void rp2_mac(rp2_t l, rp2_t h, const rp2_t a, const rp2_t b,
		__m512i t) {
	/* l_0 + h_0 += a_0 * b_0 + a_1 * q * b_1. */
	l[0] = _mm512_madd52lo_epu64(l[0], a[0], b[0]);
	h[0] = _mm512_madd52hi_epu64(h[0], a[0], b[0]);
	l[0] = _mm512_madd52lo_epu64(l[0], a[1], t);
	h[0] = _mm512_madd52hi_epu64(h[0], a[1], t);
	/* l_1 + h_1 += a_0 * b_1 + a_1 * b_0. */
	l[1] = _mm512_madd52lo_epu64(l[1], a[0], b[1]);
	h[1] = _mm512_madd52hi_epu64(h[1], a[0], b[1]);
	l[1] = _mm512_madd52lo_epu64(l[1], a[1], b[0]);
	h[1] = _mm512_madd52hi_epu64(h[1], a[1], b[0]);
}

/**
 * Tests if all residues of an element of Fp2 are zero, as they are for the
 * coefficients that sparse elements leave out. Other representations of zero
 * are not detected.
 *
 * @param[in] a				- the element to test.
 * @return 1 if all residues are zero, 0 otherwise.
 */
rlc_inline int rp2_is_zero(const fp2_t a) {
	__m512i t = _mm512_setzero_si512();

	for (size_t k = 0; k < RNS_NE; k++) {
		t = _mm512_or_si512(t, rns_load(a[0], k));
		t = _mm512_or_si512(t, rns_load(a[1], k));
	}
	return _mm512_test_epi64_mask(t, t) == 0;
}

/**
 * Computes the folded terms of a cyclotomic squaring for a pair x + y * w in
 * Fp4 = Fp2[w]/(w^2 - (s + i)), with i^2 = q: c_0 = 3 * (x^2 + (s + i) y^2)
 * + k_0 * a_0 and c_1 = 6 * x * y + k_1 * a_1, where 6 * x * y is also
 * multiplied by s + i if the flag is set. All products of a result are summed
 * before a single reduction. Products take factors below 4m, so the factors
 * 3x, 3y, 2y and, for s + i = 1 + i, (s + i) * y need no corrections; the
 * results are below 4m, as products without reduction.
 *
 * @param[out] c0			- the first result.
 * @param[out] c1			- the second result.
 * @param[in] x				- the first component of the pair.
 * @param[in] y				- the second component of the pair.
 * @param[in] a0			- the element folded into the first result.
 * @param[in] a1			- the element folded into the second result.
 * @param[in] k0			- the constant multiplying a0.
 * @param[in] k1			- the constant multiplying a1.
 * @param[in] nor			- the flag to multiply 6 * x * y by s + i.
 * @param[in] s				- the integer part of the non-residue.
 * @param[in] q				- the square of i.
 * @param[in] m				- the moduli.
 * @param[in] v				- the inverses of the moduli modulo 2^52.
 */
rlc_inline void rp4_sqrf(rp2_t c0, rp2_t c1, const rp2_t x, const rp2_t y,
		const rp2_t a0, const rp2_t a1, __m512i k0, __m512i k1, int nor,
		int s, int q, __m512i m, __m512i v) {
	const __m512i z = _mm512_setzero_si512();
	const __m512i m2 = _mm512_slli_epi64(m, 1), m4 = rns_vdv(m);
	rp2_t x3, y3, t, l, h;
	__m512i n;

	for (int j = 0; j < 2; j++) {
		x3[j] = _mm512_add_epi64(x[j], _mm512_add_epi64(x[j], x[j]));
		y3[j] = _mm512_add_epi64(y[j], _mm512_add_epi64(y[j], y[j]));
	}
	/* t = (s + i) * y, below 2m, and n = q * t_1. */
	if (s == 1 && q == -1) {
		t[0] = _mm512_add_epi64(_mm512_sub_epi64(y[0], y[1]), m);
		t[1] = _mm512_add_epi64(y[0], y[1]);
		n = _mm512_sub_epi64(m2, t[1]);
	} else {
		rp2_nor(t, y, s, q, m);
		n = rns_vneg(rns_vsml(t[1], -q, m), m);
	}
	/* c0 = 3x * x + 3y * t + k0 * a0: products of 3m * m, 3m * 2m and m * m
	 * add up to 19m^2, below 4.75m * 2^52, so the result is at most 5.75m
	 * before the correction. */
	l[0] = h[0] = l[1] = h[1] = z;
	rp2_mac(l, h, x3, x, rns_vneg(rns_vsml(x[1], -q, m), m));
	rp2_mac(l, h, y3, t, n);
	for (int j = 0; j < 2; j++) {
		l[j] = _mm512_madd52lo_epu64(l[j], a0[j], k0);
		h[j] = _mm512_madd52hi_epu64(h[j], a0[j], k0);
		c0[j] = rns_vcrt(rns_vmon(l[j], h[j], m, v), m4);
	}
	/* c1 = 3x * 2t' + k1 * a1, for t' = (s + i) * y if asked and y otherwise,
	 * with 2t' below 4m: products of 3m * 4m and m * m add up to 25m^2, below
	 * 6.25m * 2^52, so the result is at most 7.25m before the correction. */
	if (!nor) {
		t[0] = y[0];
		t[1] = y[1];
	}
	t[0] = _mm512_add_epi64(t[0], t[0]);
	t[1] = _mm512_add_epi64(t[1], t[1]);
	if (q == -1) {
		n = _mm512_sub_epi64(m4, t[1]);
	} else {
		n = rns_vneg(rns_vsml(rns_vcrt(rns_vcrt(t[1], m2), m), -q, m), m);
	}
	l[0] = h[0] = l[1] = h[1] = z;
	rp2_mac(l, h, x3, t, n);
	for (int j = 0; j < 2; j++) {
		l[j] = _mm512_madd52lo_epu64(l[j], a1[j], k1);
		h[j] = _mm512_madd52hi_epu64(h[j], a1[j], k1);
		c1[j] = rns_vcrt(rns_vmon(l[j], h[j], m, v), m4);
	}
}

/**
 * Extends K values to a base into vectors, as fp_rnsx_low() does, with their
 * products interleaved so that their dependency chains overlap. The values
 * xi_i stay in vectors, with zeros in the lanes that pad the source base.
 *
 * @param[out] r			- the residues of each value in the target base.
 * @param[in] xi			- the values xi_i of each value in the source base.
 * @param[in] K				- the number of values, up to RNS_K.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- 1 to round, 0 to truncate, -1 to skip.
 * @param[in] full			- 1 to bring the residues down to at most m, 0 to
 * 							leave them below RNS_EXT_BOUND / 4 times m.
 */
rlc_inline void rns_vext(__m512i r[][RNS_NB], const __m512i xi[][RNS_NB],
		const int K, const int b, int exact, int full) {
	ctx_t *ctx = core_get();
	const dig_t *t = (b ? ctx->rns.t1[0] : ctx->rns.t2[0]);
	const dig_t *w = (b ? ctx->rns.u1 : ctx->rns.u2);
	const dig_t *m = ctx->rns.m + (b ? RLC_FP_RNSO : 0);
	const dig_t *iv = ctx->rns.iv + (b ? RLC_FP_RNSO : 0);
	/* Rows are spread over S sets of sums, to shorten dependency chains, fewer
	 * as more values provide independent ones. */
	const int S = (K == 1 ? 4 : (K * RNS_NB >= 4 ? 1 : 2));
	const __m512i z = _mm512_setzero_si512();
	__m512i l[RNS_K][4][RNS_NB], h[RNS_K][4][RNS_NB], y[RNS_NB], a, x;
	__m512i alphas = _mm512_setzero_si512();
	size_t i;

	for (int j = 0; j < K; j++) {
		for (int e = 0; e < S; e++) {
			for (size_t k = 0; k < RNS_NB; k++) {
				l[j][e][k] = h[j][e][k] = z;
			}
		}
	}
	/* Each xi_i multiplies row i of the table, for all outputs at once. The
	 * RLC_FP_RNS + 1 low and high halves of products add up below 2^56. */
	for (i = 0; i < RLC_FP_RNS; i += S) {
		for (int e = 0; e < S; e++) {
			if (i + e >= RLC_FP_RNS) {
				break;
			}
			for (size_t k = 0; k < RNS_NB; k++) {
				y[k] = rns_load(t + (i + e) * 8 * RNS_NB, k);
			}
			a = _mm512_set1_epi64((i + e) % 8);
			for (int j = 0; j < K; j++) {
				x = _mm512_permutexvar_epi64(a, xi[j][(i + e) / 8]);
				for (size_t k = 0; k < RNS_NB; k++) {
					l[j][e][k] = _mm512_madd52lo_epu64(l[j][e][k], x, y[k]);
					h[j][e][k] = _mm512_madd52hi_epu64(h[j][e][k], x, y[k]);
				}
			}
		}
	}
	/* alpha = (sum xi_i + exact * 2^49) / 2^50 comes last, so that computing
	 * it overlaps the products; the sum is below RLC_FP_RNS * 2^50. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y[k] = rns_load(w, k);
	}
	if (exact >= 0 && K >= 3) {
		/* The sums of all values at once, by a tree of transposing additions
		 * that leaves the sum of value j in lane j. */
		__m512i v[8], t[4];

		for (int j = 0; j < 8; j++) {
			v[j] = z;
			if (j < K) {
				v[j] = xi[j][0];
				for (size_t k = 1; k < RNS_NB; k++) {
					v[j] = _mm512_add_epi64(v[j], xi[j][k]);
				}
			}
		}
		for (int j = 0; j < 4; j++) {
			t[j] = _mm512_add_epi64(
					_mm512_unpacklo_epi64(v[2 * j], v[2 * j + 1]),
					_mm512_unpackhi_epi64(v[2 * j], v[2 * j + 1]));
		}
		for (int j = 0; j < 2; j++) {
			t[j] = _mm512_add_epi64(
					_mm512_shuffle_i64x2(t[2 * j], t[2 * j + 1], 0x88),
					_mm512_shuffle_i64x2(t[2 * j], t[2 * j + 1], 0xDD));
		}
		x = _mm512_add_epi64(_mm512_shuffle_i64x2(t[0], t[1], 0x88),
				_mm512_shuffle_i64x2(t[0], t[1], 0xDD));
		x = _mm512_add_epi64(x,
				_mm512_set1_epi64((dig_t)exact << (RLC_RNS_BITS - 1)));
		alphas = _mm512_srli_epi64(x, RLC_RNS_BITS);
	}
	for (int j = 0; j < K; j++) {
		if (exact >= 0) {
			if (K >= 3) {
				a = _mm512_permutexvar_epi64(_mm512_set1_epi64(j), alphas);
			} else {
				/* The sum in every lane, by swapping halves, quarters and
				 * pairs of lanes, without leaving the vectors. */
				x = xi[j][0];
				for (size_t k = 1; k < RNS_NB; k++) {
					x = _mm512_add_epi64(x, xi[j][k]);
				}
				x = _mm512_add_epi64(x, _mm512_shuffle_i64x2(x, x, 0x4E));
				x = _mm512_add_epi64(x, _mm512_shuffle_i64x2(x, x, 0xB1));
				x = _mm512_add_epi64(x, _mm512_shuffle_epi32(x, 0x4E));
				x = _mm512_add_epi64(x,
						_mm512_set1_epi64((dig_t)exact << (RLC_RNS_BITS - 1)));
				a = _mm512_srli_epi64(x, RLC_RNS_BITS);
			}
			for (size_t k = 0; k < RNS_NB; k++) {
				l[j][S - 1][k] =
						_mm512_madd52lo_epu64(l[j][S - 1][k], a, y[k]);
				h[j][S - 1][k] =
						_mm512_madd52hi_epu64(h[j][S - 1][k], a, y[k]);
			}
		}
		for (size_t k = 0; k < RNS_NB; k++) {
			for (int e = 1; e < S; e++) {
				l[j][0][k] = _mm512_add_epi64(l[j][0][k], l[j][e][k]);
				h[j][0][k] = _mm512_add_epi64(h[j][0][k], h[j][e][k]);
			}
		}
	}
	for (size_t k = 0; k < RNS_NB; k++) {
		x = rns_load(m, k);
		a = rns_load(iv, k);
		for (int j = 0; j < K; j++) {
			/* The outputs are below RNS_EXT_BOUND / 4 times m. */
			r[j][k] = rns_vred(l[j][0][k], h[j][0][k], x, a,
					full ? rns_halvings(RNS_EXT_BOUND) : 0);
		}
	}
}

/**
 * Reduces K unreduced products at once by Montgomery reduction in RNS, as
 * fp_rdcn_low() does.
 *
 * @param[out] c			- the results.
 * @param[in] a				- the products.
 * @param[in] K				- the number of products, up to RNS_K.
 */
rlc_inline void rns_vrdc(dig_t *const c[], const dig_t *const a[],
		const int K) {
	ctx_t *ctx = core_get();
	const size_t o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m;
	__m512i q[RNS_K][RNS_NB], r[RNS_K][RNS_NB], x, y, z;

	/* xi_i of q = a * (-p^{-1}) mod M, in B, as plain residues; the padding
	 * lanes are zero, as are their constants. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y = rns_load(m, k);
		z = rns_load(ctx->rns.nqv, k);
		for (int j = 0; j < K; j++) {
			/* For a below 4m, the product is at most 2m. */
			q[j][k] = rns_vpeel(rns_vmulc(rns_load(a[j], k),
					rns_load(ctx->rns.nq, k), z, y), y, 1);
		}
	}
	/* q * p for q + kM, as a product in B', with 0 <= k < RLC_FP_RNS: the
	 * extra kp only makes the result larger, so the extension skips alpha. */
	rns_vext(r, q, K, 1, -1, 0);
	/* c = (a + q * p) / M in B', and its xi_j for the exact extension. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y = rns_load(m + o, k);
		z = rns_load(ctx->rns.ibv, k);
		for (int j = 0; j < K; j++) {
			/* Below 4m plus the bound of the extension. */
			x = _mm512_add_epi64(rns_load(a[j] + o, k), r[j][k]);
			/* The product only needs a factor below 4m, so it starts
			 * once x is there, and the rest of the peel is off the
			 * critical path. */
			for (int i = rns_halvings(16 + RNS_EXT_BOUND) - 1; i >= 2; i--) {
				x = rns_vcrt(x, _mm512_slli_epi64(y, i));
			}
			rns_store(c[j] + o, k, rns_vpeel(x, y, 2));
			q[j][k] = rns_vpeel(rns_vmulc(x, rns_load(ctx->rns.ib + o, k),
					z, y), y, 1);
		}
	}
	/* c in B, exactly, since |c| < (RLC_FP_RNS + 1)p is far below M'/2. */
	rns_vext(r, q, K, 0, 1, 1);
	for (int j = 0; j < K; j++) {
		for (size_t k = 0; k < RNS_NB; k++) {
			rns_store(c[j], k, r[j][k]);
		}
	}
}

/**
 * Reduces N values as fp_rdcv_low() does, for N known at compile time, so that
 * the reduction is inlined with the pointers as constants: in one batch up to
 * RNS_K values, in two of about half otherwise. The sizes are bounded by RNS_K
 * in both branches, so that the compiler sees no batch larger than the
 * reduction takes.
 *
 * @param[out] C			- the pointers to the results.
 * @param[in] A				- the pointers to the values to reduce.
 * @param[in] N				- the number of values, up to 2 * RNS_K.
 */
#define RNS_RDCV(C, A, N)													\
	if ((N) <= RNS_K) {														\
		rns_vrdc(C, (const dig_t *const *)(A), RLC_MIN(N, RNS_K));			\
	} else {																\
		rns_vrdc(C, (const dig_t *const *)(A), RLC_MIN((N) / 2, RNS_K));	\
		rns_vrdc((C) + (N) / 2, (const dig_t *const *)(A) + (N) / 2,		\
				RLC_MIN((N) - (N) / 2, RNS_K));								\
	}

#endif /* !RLC_FP_RNS_AVX_H */
