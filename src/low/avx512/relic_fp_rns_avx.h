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
 * AVX-512 IFMA: eight 52-bit residues per vector, multiplied with the 52-bit
 * multiply-add instructions.
 *
 * @ingroup fp
 */

#ifndef RLC_FP_RNS_AVX_H
#define RLC_FP_RNS_AVX_H

#include <immintrin.h>

#include "relic_core.h"
#include "relic_fp_low.h"

/*
 * Each base is padded to RLC_FP_RNSO residues, a multiple of 8, so that it
 * fills whole vectors. The moduli and constants are zero in the padding, where
 * operations give zero or harmless values that never reach the residues.
 */

/** Number of vectors that hold the residues of the first base, the larger. */
#define RNS_NB		(RLC_FP_RNSO / 8)

/** Number of vectors that hold the residues of the second base. */
#define RNS_NB		(RLC_FP_RNSO / 8)

/** Number of vectors that hold the residues of both bases. */
#define RNS_NE		(RLC_FP_LEN / 8)

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
 * Multiplies residues below m < 2^52 by Montgomery multiplication, computing
 * a * b / 2^52 mod m lane-wise.
 */
static inline __m512i rns_vmul(__m512i a, __m512i b, __m512i m, __m512i u) {
	const __m512i z = _mm512_setzero_si512();
	__m512i l, h, q;

	l = _mm512_madd52lo_epu64(z, a, b);
	h = _mm512_madd52hi_epu64(z, a, b);
	q = _mm512_madd52lo_epu64(z, l, u);
	/* l + (q * m mod 2^52) is 0 or 2^52, and its carry goes into h. */
	l = _mm512_madd52lo_epu64(l, q, m);
	h = _mm512_madd52hi_epu64(h, q, m);
	h = _mm512_add_epi64(h, _mm512_srli_epi64(l, 52));
	return rns_vcrt(h, m);
}

/**
 * Adds two products of residues below m < 2^52 before a single Montgomery
 * reduction, computing (a * b + c * d) / 2^52 mod m lane-wise.
 */
static inline __m512i rns_vmul2(__m512i a, __m512i b, __m512i c, __m512i d,
		__m512i m, __m512i u) {
	const __m512i z = _mm512_setzero_si512();
	const __m512i mask = _mm512_set1_epi64(RLC_RNS_MASK);
	__m512i l, h, q;

	l = _mm512_madd52lo_epu64(z, a, b);
	h = _mm512_madd52hi_epu64(z, a, b);
	l = _mm512_madd52lo_epu64(l, c, d);
	h = _mm512_madd52hi_epu64(h, c, d);
	h = _mm512_add_epi64(h, _mm512_srli_epi64(l, 52));
	l = _mm512_and_si512(l, mask);
	q = _mm512_madd52lo_epu64(z, l, u);
	l = _mm512_madd52lo_epu64(l, q, m);
	h = _mm512_madd52hi_epu64(h, q, m);
	h = _mm512_add_epi64(h, _mm512_srli_epi64(l, 52));
	/* The sum is below 2m^2, so the result is below 2m^2 / 2^52 + m < 3m. */
	return rns_vcrt(rns_vcrt(h, m), m);
}

/**
 * Reduces h * 2^52 + l by two Montgomery reductions modulo m < 2^52, for l
 * and h below 2^57: computes it divided by 2^104, modulo m, lane-wise.
 */
static inline __m512i rns_vred(__m512i l, __m512i h, __m512i m, __m512i u) {
	const __m512i z = _mm512_setzero_si512();
	const __m512i mask = _mm512_set1_epi64(RLC_RNS_MASK);
	__m512i q, t;

	h = _mm512_add_epi64(h, _mm512_srli_epi64(l, 52));
	l = _mm512_and_si512(l, mask);
	/* The first reduction leaves t below 2^58. */
	q = _mm512_madd52lo_epu64(z, l, u);
	l = _mm512_madd52lo_epu64(l, q, m);
	t = _mm512_madd52hi_epu64(h, q, m);
	t = _mm512_add_epi64(t, _mm512_srli_epi64(l, 52));
	/* The second one leaves a value below m + 2^6 < 2m. */
	l = _mm512_and_si512(t, mask);
	h = _mm512_srli_epi64(t, 52);
	q = _mm512_madd52lo_epu64(z, l, u);
	l = _mm512_madd52lo_epu64(l, q, m);
	t = _mm512_madd52hi_epu64(h, q, m);
	t = _mm512_add_epi64(t, _mm512_srli_epi64(l, 52));
	return rns_vcrt(t, m);
}

/** Largest number of values reduced at once. */
#define RNS_K		2

/**
 * Extends K values to a base into vectors, as fp_rnsx_low() does, with their
 * products interleaved so that their dependency chains overlap. The values
 * xi_i stay in vectors, with zeros in the lanes that pad the source base.
 *
 * @param[out] r			- the residues of each value in the target base.
 * @param[in] xi			- the values xi_i of each value in the source base.
 * @param[in] K				- the number of values, up to RNS_K.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- the flag to round instead of truncating.
 */
static inline __attribute__((always_inline)) void rns_vext(
		__m512i r[][RNS_NB], const __m512i xi[][RNS_NB], const int K,
		const int b, int exact) {
	ctx_t *ctx = core_get();
	const dig_t *t = (b ? ctx->rns.t1[0] : ctx->rns.t2[0]);
	const dig_t *w = (b ? ctx->rns.u1 : ctx->rns.u2);
	const dig_t *m = ctx->rns.m + (b ? RLC_FP_RNSO : 0);
	const dig_t *u = ctx->rns.u + (b ? RLC_FP_RNSO : 0);
	/* Rows are spread over S sets of sums, to shorten dependency chains. */
	const int S = (K == 1 ? 4 : 2);
	const __m512i z = _mm512_setzero_si512();
	__m512i l[RNS_K][4][RNS_NB], h[RNS_K][4][RNS_NB], y[RNS_NB], a, x;
	dig_t s;
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
	/* alpha = (sum xi_i + exact * 2^51) / 2^52 comes last, so that computing
	 * it overlaps the products; the sum is below RLC_FP_RNS * 2^52. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y[k] = rns_load(w, k);
	}
	for (int j = 0; j < K; j++) {
		x = xi[j][0];
		for (size_t k = 1; k < RNS_NB; k++) {
			x = _mm512_add_epi64(x, xi[j][k]);
		}
		s = (dig_t)_mm512_reduce_add_epi64(x);
		a = _mm512_set1_epi64((s + ((dig_t)exact << 51)) >> 52);
		for (size_t k = 0; k < RNS_NB; k++) {
			l[j][1][k] = _mm512_madd52lo_epu64(l[j][1][k], a, y[k]);
			h[j][1][k] = _mm512_madd52hi_epu64(h[j][1][k], a, y[k]);
			for (int e = 1; e < S; e++) {
				l[j][0][k] = _mm512_add_epi64(l[j][0][k], l[j][e][k]);
				h[j][0][k] = _mm512_add_epi64(h[j][0][k], h[j][e][k]);
			}
		}
	}
	for (size_t k = 0; k < RNS_NB; k++) {
		x = rns_load(m, k);
		a = rns_load(u, k);
		for (int j = 0; j < K; j++) {
			r[j][k] = rns_vred(l[j][0][k], h[j][0][k], x, a);
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
static inline __attribute__((always_inline)) void rns_vrdc(dig_t *const c[],
		const dig_t *const a[], const int K) {
	ctx_t *ctx = core_get();
	const size_t o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u;
	__m512i q[RNS_K][RNS_NB], r[RNS_K][RNS_NB], x, y, z;

	/* xi_i of q = a * (-p^{-1}) mod M, in B, as plain residues; the padding
	 * lanes are zero, as are their constants. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y = rns_load(m, k);
		z = rns_load(u, k);
		for (int j = 0; j < K; j++) {
			q[j][k] = rns_vmul(rns_load(a[j], k), rns_load(ctx->rns.nq, k),
					y, z);
		}
	}
	/* q * p for q, or q + M, as a product in B'. */
	rns_vext(r, q, K, 1, 0);
	/* c = (a + q * p) / M in B', and its xi_j for the exact extension. */
	for (size_t k = 0; k < RNS_NB; k++) {
		y = rns_load(m + o, k);
		z = rns_load(u + o, k);
		for (int j = 0; j < K; j++) {
			x = rns_vadd(rns_load(a[j] + o, k), r[j][k], y);
			rns_store(c[j] + o, k, x);
			q[j][k] = rns_vmul(x, rns_load(ctx->rns.ib + o, k), y, z);
		}
	}
	/* c in B, exactly, since c < 3p is far below M'/2. */
	rns_vext(r, q, K, 0, 1);
	for (int j = 0; j < K; j++) {
		for (size_t k = 0; k < RNS_NB; k++) {
			rns_store(c[j], k, r[j][k]);
		}
	}
}

/**
 * Applies a residue-wise operation to the vectors of both bases, with the
 * moduli in m and their constants in u.
 */
#define RNS_VMAP(C, OP)														\
	const dig_t *_m = core_get()->rns.m, *_u = core_get()->rns.u;			\
	for (size_t _k = 0; _k < RNS_NE; _k++) {								\
		__m512i m = rns_load(_m, _k);										\
		__m512i u = rns_load(_u, _k);										\
		(void)u;															\
		rns_store(C, _k, OP);												\
	}

/** Loads the current vector of an operand inside RNS_VMAP(). */
#define V(A)		rns_load(A, _k)

#endif /* !RLC_FP_RNS_AVX_H */
