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

/** Largest number of vectors that hold the residues of a base. */
#define RNS_VB		(RLC_RNS_MAX / 8)

/**
 * Bound on the outputs of a base extension without correction, as a multiple
 * of m / 4: n products of residues at most m give at most n * m / 4, the
 * Montgomery reduction adds m, and the correction by alpha a little more.
 *
 * @param[in] N				- the number of moduli in each base.
 */
#define RNS_BOUND(N)	((int)(N) + 4 + 1)

/**
 * Extends a value to a base from the other, as rns_extm_imp() does, with one
 * Montgomery reduction modulo 2^52 per residue.
 *
 * @param[out] r			- the vectors of residues in the target base.
 * @param[in] xi			- the values xi_i in the source base.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- 1 to round, 0 to truncate, -1 to skip.
 * @param[in] full			- 1 to bring the residues down to at most m, 0 to
 * 							leave them below RNS_BOUND(n) / 4 times m.
 * @param[in] c				- the context.
 */
static void rns_vext(__m512i *r, const dig_t *xi, int b, int exact, int full,
		const rns_st *c) {
	const size_t n = c->n, o = c->o, nb = o / 8;
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
		/* alpha = (sum xi_i + exact * 2^49) / 2^50, as the sum is below
		 * n * 2^50, far from overflowing. */
		a = (dig_t)exact << (RLC_RNS_BITS - 1);
		for (size_t i = 0; i < n; i++) {
			a += xi[i];
		}
		x = _mm512_set1_epi64(a >> RLC_RNS_BITS);
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
				full ? rns_halvings(RNS_BOUND(n)) : 0);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_extm_low(dig_t *r, const dig_t *xi, int b, int exact, const rns_t c) {
	const size_t n = c->n;
	__m512i v[RNS_VB];

	rns_vext(v, xi, b, exact, 1, c);
	/* Only as many residues as each base has are written. */
	for (size_t k = 0; 8 * k < n; k++) {
		size_t l = n - 8 * k;
		_mm512_mask_storeu_epi64(r + 8 * k, l >= 8 ? 0xFF :
				(__mmask8)((1 << l) - 1), v[k]);
	}
}

void rns_muln_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	/* For factors at most m, the products are at most 5m / 4. */
	for (size_t k = 0; k < 2 * c->o / 8; k++) {
		rns_store(r, k, rns_vmul(rns_load(a, k), rns_load(b, k),
				rns_load(c->m, k), rns_load(c->iv, k)));
	}
}

void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c) {
	const size_t o = c->o, nb = o / 8;
	const dig_t *m = c->m;
	const int s = rns_halvings(16 + RNS_BOUND(c->n));
	__m512i v[RNS_VB], x, y, z;
	dig_t q[RLC_RNS_MAX];

	/* xi_i of q = a * (-N^{-1}) mod M, in B, as plain residues; the padding
	 * lanes are zero, as are their constants. */
	for (size_t k = 0; k < nb; k++) {
		y = rns_load(m, k);
		/* For a below 4m, the product is at most 2m. */
		rns_store(q, k, rns_vpeel(rns_vmulc(rns_load(a, k),
				rns_load(c->nq, k), rns_load(c->nqv, k), y), y, 1));
	}
	/* q * N for q + kM, as a product in B', with 0 <= k < n: the extra kN only
	 * makes the result larger, so the extension skips alpha. */
	rns_vext(v, q, 1, -1, 0, c);
	/* r = (a + q * N) / M in B', and its xi_j for the exact extension. */
	for (size_t k = 0; k < nb; k++) {
		y = rns_load(m + o, k);
		z = rns_load(c->ibv, k);
		/* Below 4m plus the bound of the extension. */
		x = rns_vpeel(_mm512_add_epi64(rns_load(a + o, k), v[k]), y, s);
		rns_store(r + o, k, x);
		rns_store(q, k, rns_vpeel(rns_vmulc(x, rns_load(c->ib + o, k), z, y),
				y, 1));
	}
	/* r in B, exactly, since |r| < (n + 1)N is far below M'/2. */
	rns_vext(v, q, 0, 1, 1, c);
	for (size_t k = 0; k < nb; k++) {
		rns_store(r, k, v[k]);
	}
}

void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	rns_muln_low(t, a, b, c);
	rns_rdcn_low(r, t, c);
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
