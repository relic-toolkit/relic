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
 * multiply-add instructions. With moduli below 2^50, residues and sums of a
 * few of them, below 4m, still fit the multipliers; with moduli below 2^52,
 * the residues that enter them must be at most m.
 *
 * @ingroup rns
 */

#ifndef RLC_RNS_AVX_H
#define RLC_RNS_AVX_H

#include <immintrin.h>

#include "relic_core.h"
#include "relic_rns_low.h"

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

#endif /* !RLC_RNS_AVX_H */
