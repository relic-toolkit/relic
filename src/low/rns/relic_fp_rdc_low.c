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
 * Implementation of the low-level prime field modular reduction and base
 * extensions in a Residue Number System.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifndef FP_RNS_VEC

/**
 * Reduces s2 * R^2 + s1 * R + s0 by two Montgomery reductions modulo m < R/2,
 * with R = 2^RLC_DIG: computes it divided by R^2, modulo m, in constant time.
 *
 * @param[in] s2			- the highest digit, below R^(1/2).
 * @param[in] s1			- the middle digit.
 * @param[in] s0			- the lowest digit.
 * @param[in] m				- the modulus.
 * @param[in] u				- the value -m^{-1} mod R.
 * @return the reduced digit.
 */
static dig_t fp_rns_red(dig_t s2, dig_t s1, dig_t s0, dig_t m, dig_t u) {
	dig_t h, l, q;

	/* (s2 * R^2 + s1 * R + s0 + q * m) / R, with q = s0 * u. */
	q = s0 * u;
	RLC_MUL_DIG(h, l, q, m);
	l += s0;
	h += (l < s0);
	s1 += h;
	s2 += (s1 < h);
	/* Once more on s2 * R + s1: the result is below m + s2 + 1 < 2m. */
	q = s1 * u;
	RLC_MUL_DIG(h, l, q, m);
	l += s1;
	h += (l < s1) + s2;
	return RLC_RNS_CRT(h, m);
}

#endif /* !FP_RNS_VEC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m) {
	(void)c;
	(void)a;
	(void)m;
	/* There is no special-form reduction for elements in RNS. */
	RLC_THROW(ERR_NO_VALID);
}

/* Defining FP_RNS_VEC leaves out the residue-wise functions, so that a backend
 * can replace them with vectorized ones. */
#ifndef FP_RNS_VEC

void fp_rnsx_low(dig_t *r, const dig_t *xi, int b, int exact) {
	ctx_t *ctx = core_get();
	/* From B to B' with the first table, from B' to B with the second. */
	const size_t n = RLC_FP_RNS, o = RLC_FP_RNSO;
	const dig_t *t = (b ? ctx->rns.t1[0] : ctx->rns.t2[0]);
	const dig_t *w = (b ? ctx->rns.u1 : ctx->rns.u2);
	const dig_t *m = ctx->rns.m + (b ? RLC_FP_RNSO : 0);
	const dig_t *u = ctx->rns.u + (b ? RLC_FP_RNSO : 0);
	dig_t a = fp_rns_alpha(xi, n, exact);

#ifdef RLC_CONF_NODBL
	dig_t h, l, s0, s1, s2;

	for (size_t j = 0; j < n; j++) {
		/* The n + 1 products, below R^2 / 4 each, as three digits. */
		RLC_MUL_DIG(s1, s0, a, w[j]);
		s2 = 0;
		for (size_t i = 0; i < n; i++) {
			RLC_MUL_DIG(h, l, xi[i], t[i * o + j]);
			s0 += l;
			h += (s0 < l);
			s1 += h;
			s2 += (s1 < h);
		}
		r[j] = fp_rns_red(s2, s1, s0, m[j], u[j]);
	}
#else
	/* The products are below R^2 / 4, so four of them add up in a double digit
	 * without overflow, and only these sums need their carries counted. Four
	 * outputs are computed per pass, to share the loads of xi_i. */
	size_t j = 0;
	for (; j + 3 < n; j += 4) {
		dbl_t acc[4], g;
		dig_t c[4] = { 0, 0, 0, 0 };
		const dig_t *ti;
		for (int k = 0; k < 4; k++) {
			acc[k] = (dbl_t)a * w[j + k];
		}
		size_t i = 0;
		for (; i + 4 <= n; i += 4) {
			ti = t + i * o + j;
			for (int k = 0; k < 4; k++) {
				g = (dbl_t)xi[i] * ti[k] + (dbl_t)xi[i + 1] * ti[o + k] +
						(dbl_t)xi[i + 2] * ti[2 * o + k] +
						(dbl_t)xi[i + 3] * ti[3 * o + k];
				acc[k] += g;
				c[k] += (acc[k] < g);
			}
		}
		for (; i < n; i++) {
			ti = t + i * o + j;
			for (int k = 0; k < 4; k++) {
				g = (dbl_t)xi[i] * ti[k];
				acc[k] += g;
				c[k] += (acc[k] < g);
			}
		}
		for (int k = 0; k < 4; k++) {
			r[j + k] = fp_rns_red(c[k], (dig_t)(acc[k] >> RLC_DIG),
					(dig_t)acc[k], m[j + k], u[j + k]);
		}
	}
	for (; j < n; j++) {
		dbl_t acc = (dbl_t)a * w[j], g;
		dig_t c = 0;
		for (size_t i = 0; i < n; i++) {
			g = (dbl_t)xi[i] * t[i * o + j];
			acc += g;
			c += (acc < g);
		}
		r[j] = fp_rns_red(c, (dig_t)(acc >> RLC_DIG), (dig_t)acc, m[j], u[j]);
	}
#endif
}

void fp_rdcn_low(dig_t *c, dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u;
	dig_t q[RLC_FP_RNS], r[RLC_FP_RNS];

	/* xi_i of q = a * (-p^{-1}) mod M, in B, as plain residues. */
	for (size_t i = 0; i < n; i++) {
		q[i] = fp_rns_mul(a[i], ctx->rns.nq[i], m[i], u[i]);
	}
	/* q * p for q, or q + M, as a product in B'. */
	fp_rnsx_low(r, q, 1, 0);
	/* c = (a + q * p) / M in B', as a product carries 1 / M^2 there and an
	 * element 1 / M; and its xi_j for the exact extension. */
	for (size_t j = 0; j < n; j++) {
		c[o + j] = RLC_RNS_ADD(a[o + j], r[j], m[o + j]);
		q[j] = fp_rns_mul(c[o + j], ctx->rns.ib[o + j], m[o + j], u[o + j]);
	}
	/* c in B, exactly, since c < 3p is far below M'/2. */
	fp_rnsx_low(c, q, 0, 1);
}

#endif /* !FP_RNS_VEC */

#endif /* FP_RDC == FP_RENUS */
