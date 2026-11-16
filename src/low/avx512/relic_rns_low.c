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
 * Implementation of the low-level arithmetic in a Residue Number System with
 * AVX-512 IFMA, for the sizes of a context.
 *
 * @ingroup rns
 */

#include "relic_core.h"
#include "relic_rns_low.h"
#include "relic_rns_avx.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Largest number of vectors that hold the residues of a base, at least the
 * sizes that RNS_SIZES() compiles for.
 */
#define RNS_VB		RLC_MAX(RLC_RNS_MAX / 8, 12)

/**
 * Calls F with the number of vectors per base N as its last argument, as a
 * constant for up to twelve vectors, which covers moduli of about 4600 bits,
 * so that the kernels inlined into it are compiled for each size, with their
 * sums in registers.
 *
 * @param[in] N				- the number of vectors per base.
 * @param[in] F				- the kernel.
 */
#define RNS_SIZES(N, F, ...)												\
	switch (N) {															\
		case 1: F(__VA_ARGS__, 1); break;									\
		case 2: F(__VA_ARGS__, 2); break;									\
		case 3: F(__VA_ARGS__, 3); break;									\
		case 4: F(__VA_ARGS__, 4); break;									\
		case 5: F(__VA_ARGS__, 5); break;									\
		case 6: F(__VA_ARGS__, 6); break;									\
		case 7: F(__VA_ARGS__, 7); break;									\
		case 8: F(__VA_ARGS__, 8); break;									\
		case 9: F(__VA_ARGS__, 9); break;									\
		case 10: F(__VA_ARGS__, 10); break;									\
		case 11: F(__VA_ARGS__, 11); break;									\
		case 12: F(__VA_ARGS__, 12); break;									\
		default: F(__VA_ARGS__, N); break;									\
	}

/**
 * Bound on the outputs of a base extension without correction, as a multiple
 * of m / 4: each of the n products of residues at most m, and the correction
 * by alpha, has its top bits below m / 4 for moduli of 50 bits and below m for
 * moduli of 52 bits, and the Montgomery reduction adds m.
 *
 * @param[in] N				- the number of moduli in each base.
 * @param[in] B				- the size in bits of the moduli.
 */
#define RNS_BOUND(N, B)		(((int)(N) + 1) * (1 << ((B) - 50)) + 4)

/**
 * Extends a value to a base from the other, as rns_extm_imp() does, with one
 * Montgomery reduction modulo 2^52 per residue.
 *
 * @param[out] r			- the vectors of residues in the target base.
 * @param[in] xi			- the values xi_i in the source base.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- 1 to round, 0 to truncate, -1 to skip.
 * @param[in] full			- 1 to bring the residues down to at most m, 0 to
 * 							leave them below RNS_BOUND() / 4 times m.
 * @param[in] c				- the context.
 * @param[in] nb			- the number of vectors per base.
 */
rlc_inline void rns_vext(__m512i *r, const dig_t *xi, int b, int exact,
		int full, const rns_st *c, size_t nb) {
	const size_t n = c->n, o = c->o;
	const dig_t *t = (b ? c->t1 : c->t2), *w = (b ? c->u1 : c->u2);
	const dig_t *m = c->m + (b ? o : 0), *iv = c->iv + (b ? o : 0);
	/* Rows are spread over S sets of sums, to shorten dependency chains, fewer
	 * as more vectors provide independent ones. */
	const size_t S = (nb >= 4 ? 1 : (nb >= 2 ? 2 : 4));
	const __m512i z = _mm512_setzero_si512();
	__m512i l[4][RNS_VB], h[4][RNS_VB], x, y;
	dig_t a;

	for (size_t e = 0; e < S; e++) {
		for (size_t k = 0; k < nb; k++) {
			l[e][k] = h[e][k] = z;
		}
	}
	/* Each xi_i multiplies row i of the table, for all outputs at once. The
	 * n + 1 low and high halves of products add up below 2^63. */
	for (size_t i = 0; i < n; i += S) {
		for (size_t e = 0; e < S && i + e < n; e++) {
			x = _mm512_set1_epi64(xi[i + e]);
			for (size_t k = 0; k < nb; k++) {
				y = rns_load(t + (i + e) * o, k);
				l[e][k] = _mm512_madd52lo_epu64(l[e][k], x, y);
				h[e][k] = _mm512_madd52hi_epu64(h[e][k], x, y);
			}
		}
	}
	if (exact >= 0) {
		/* alpha = (sum xi_i + exact * 2^(b - 1)) / 2^b for moduli of b
		 * bits, as the sum is below n * 2^b, far from overflowing. */
		a = (dig_t)exact << (c->bits - 1);
		for (size_t i = 0; i < n; i++) {
			a += xi[i];
		}
		x = _mm512_set1_epi64(a >> c->bits);
		for (size_t k = 0; k < nb; k++) {
			y = rns_load(w, k);
			l[S - 1][k] = _mm512_madd52lo_epu64(l[S - 1][k], x, y);
			h[S - 1][k] = _mm512_madd52hi_epu64(h[S - 1][k], x, y);
		}
	}
	for (size_t k = 0; k < nb; k++) {
		for (size_t e = 1; e < S; e++) {
			l[0][k] = _mm512_add_epi64(l[0][k], l[e][k]);
			h[0][k] = _mm512_add_epi64(h[0][k], h[e][k]);
		}
		r[k] = rns_vred(l[0][k], h[0][k], rns_load(m, k), rns_load(iv, k),
				full ? rns_halvings(RNS_BOUND(n, c->bits)) : 0);
	}
}

/**
 * Reduces a product by Montgomery reduction in a Residue Number System, as
 * rns_rdcn_imp() does.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the product.
 * @param[in] c				- the context.
 * @param[in] nb			- the number of vectors per base.
 */
rlc_inline void rns_vrdc(dig_t *r, const dig_t *a, const rns_st *c,
		size_t nb) {
	const size_t o = c->o;
	const dig_t *m = c->m;
	/* The product is at most m and the extension adds its bound. */
	const int s = rns_halvings(4 + RNS_BOUND(c->n, c->bits));
	__m512i v[RNS_VB], x, y, z;
	dig_t q[RLC_RNS_MAX];

	/* xi_i of q = a * (-N^{-1}) mod M, in B, as plain residues; the padding
	 * lanes are zero, as are their constants. */
	for (size_t k = 0; k < nb; k++) {
		y = rns_load(m, k);
		/* For a at most m, the product is below 2m. */
		rns_store(q, k, rns_vpeel(rns_vmulc(rns_load(a, k),
				rns_load(c->nq, k), rns_load(c->nqv, k), y), y, 1));
	}
	/* q * N for q + kM, as a product in B', with 0 <= k < n: the extra kN only
	 * makes the result larger, so the extension skips alpha. */
	rns_vext(v, q, 1, -1, 0, c, nb);
	/* r = (a + q * N) / M in B', and its xi_j for the exact extension. */
	for (size_t k = 0; k < nb; k++) {
		y = rns_load(m + o, k);
		z = rns_load(c->ibv, k);
		x = rns_vpeel(_mm512_add_epi64(rns_load(a + o, k), v[k]), y, s);
		rns_store(r + o, k, x);
		rns_store(q, k, rns_vpeel(rns_vmulc(x, rns_load(c->ib + o, k), z, y),
				y, 1));
	}
	/* r in B, exactly, since |r| < (n + 1)N is far below M'/2. */
	rns_vext(v, q, 0, 1, 1, c, nb);
	for (size_t k = 0; k < nb; k++) {
		rns_store(r, k, v[k]);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_extm_low(dig_t *r, const dig_t *xi, int b, int exact, const rns_t c) {
	const size_t n = c->n;
	__m512i v[RNS_VB];

	RNS_SIZES(c->o / 8, rns_vext, v, xi, b, exact, 1, c);
	/* Only as many residues as each base has are written. */
	for (size_t k = 0; 8 * k < n; k++) {
		size_t l = n - 8 * k;
		_mm512_mask_storeu_epi64(r + 8 * k, l >= 8 ? 0xFF :
				(__mmask8)((1 << l) - 1), v[k]);
	}
}

void rns_muln_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	__m512i m;

	/* For factors at most m, the products are below 2m, and are brought down
	 * to at most m, as factors of 52 bits must be. */
	for (size_t k = 0; k < 2 * c->o / 8; k++) {
		m = rns_load(c->m, k);
		rns_store(r, k, rns_vpeel(rns_vmul(rns_load(a, k), rns_load(b, k), m,
				rns_load(c->iv, k)), m, 1));
	}
}


void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c) {
	RNS_SIZES(c->o / 8, rns_vrdc, r, a, c);
}

void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	rns_muln_low(t, a, b, c);
	RNS_SIZES(c->o / 8, rns_vrdc, r, t, c);
}

void rns_digs_low(dig_t *r, const dig_t *a, const rns_t c) {
	const size_t d = c->d, w = c->w, o = c->o;
	const __m512i z = _mm512_setzero_si512();
	/* Each digit times a weight at most m has its top bits below m, so the
	 * sum of all is at most (w + 1) * m once reduced. */
	const int s = rns_halvings(4 * ((int)w + 1));
	dig_t x[RLC_RNS_WORDS(RLC_BN_DIGS)];

	/* The digits of RLC_RNS_DIG bits, which straddle the machine digits. */
	for (size_t k = 0; k < w; k++) {
		size_t j = k * RLC_RNS_DIG / RLC_DIG, b = k * RLC_RNS_DIG % RLC_DIG;

		x[k] = a[j] >> b;
		if (b + RLC_RNS_DIG > RLC_DIG && j + 1 < d) {
			x[k] |= a[j + 1] << (RLC_DIG - b);
		}
		x[k] &= RLC_RNS_MASK;
	}
	for (size_t i = 0; i < 2 * o / 8; i++) {
		__m512i l = z, h = z, m = rns_load(c->m, i), y, v;

		for (size_t k = 0; k < w; k++) {
			v = _mm512_set1_epi64(x[k]);
			y = rns_load(c->pw + k * 2 * o, i);
			l = _mm512_madd52lo_epu64(l, v, y);
			h = _mm512_madd52hi_epu64(h, v, y);
		}
		rns_store(r, i, rns_vpeel(rns_vmon(l, h, m, rns_load(c->iv, i)), m,
				s));
	}
}
