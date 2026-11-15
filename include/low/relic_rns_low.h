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
 * Interface of the low-level arithmetic of residues in a Residue Number System.
 *
 * @ingroup rns
 */

#ifndef RLC_RNS_LOW_H
#define RLC_RNS_LOW_H

#include "relic_conf.h"
#include "relic_types.h"
#include "relic_util.h"
#include "relic_rns.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/** Mask of the low RLC_RNS_DIG bits of a digit. */
#define RLC_RNS_MASK	RLC_MASK(RLC_RNS_DIG)

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Subtracts M from a value A below 2M in constant time.
 *
 * @param[in] A				- the value.
 * @param[in] M				- the modulus.
 */
#define RLC_RNS_CRT(A, M)	((A) - (M) * (dig_t)((A) >= (M)))

/**
 * Adds two residues A and B modulo M in constant time.
 *
 * @param[in] A				- the first residue.
 * @param[in] B				- the second residue.
 * @param[in] M				- the modulus.
 */
#define RLC_RNS_ADD(A, B, M)	RLC_RNS_CRT((A) + (B), M)

/**
 * Subtracts two residues A and B modulo M in constant time.
 *
 * @param[in] A				- the first residue.
 * @param[in] B				- the second residue.
 * @param[in] M				- the modulus.
 */
#define RLC_RNS_SUB(A, B, M)	((A) - (B) + (M) * (dig_t)((A) < (B)))

/**
 * Reduces a digit D modulo M in constant time.
 *
 * @param[in] D				- the digit.
 * @param[in] M				- the modulus.
 */
#if RLC_ARITH != RLC_AVX512
/* A digit is below R < 3M, so two subtractions reduce it. */
#define RLC_RNS_MOD(D, M)													\
	RLC_RNS_CRT((dig_t)(D) - (M) * (dig_t)((dig_t)(D) >= (M)), M)
#else
/* As 2^52 = K mod M for K = 2^52 - 4M, fold the high bits: the moduli are
 * 2^50 - c with c below 2^26, so K = 4c is below 2^28, and the result is below
 * 2^52 + 2^12 * K < 4M + 2^28 + 2^40 < 5M, which three subtractions bring
 * below M. */
#define RLC_RNS_MOD(D, M)													\
	rns_fix(((dig_t)(D) & RLC_RNS_MASK) +									\
		((dig_t)(D) >> RLC_RNS_DIG) * RLC_RNS_K(M), M)
/** The residue of 2^52 modulo a 50-bit modulus M, as 2^52 - 4M. */
#define RLC_RNS_K(M)	(((dig_t)1 << RLC_RNS_DIG) - ((dig_t)(M) << 2))
#endif

/*============================================================================*/
/* Function definitions                                                       */
/*============================================================================*/

#if RLC_ARITH == RLC_AVX512
/* The folds above assume a modulus search with c below 2^26 = 2^(52 / 2). */
RLC_STATIC_ASSERT(RLC_RNS_DIG / 2 + 2 + (RLC_DIG - RLC_RNS_DIG) + 1 <
		RLC_RNS_BITS, rns_fold);

/**
 * Brings a value below 5m down below m with three subtractions, in constant
 * time: the folds of 50-bit moduli leave values below 5m.
 *
 * @param[in] a				- the value.
 * @param[in] m				- the modulus.
 * @return the value modulo m.
 */
static inline dig_t rns_fix(dig_t a, dig_t m) {
	a = RLC_RNS_CRT(a, 2 * m);
	a = RLC_RNS_CRT(a, m);
	return RLC_RNS_CRT(a, m);
}
#endif

/**
 * Multiplies two residues by Montgomery multiplication: computes a * b / R
 * mod m in constant time. The first residue may be any digit, and the second
 * below m.
 *
 * @param[in] a				- the first residue.
 * @param[in] b				- the second residue.
 * @param[in] m				- the modulus.
 * @param[in] u				- the value -m^{-1} mod R.
 * @return the product.
 */
static inline dig_t rns_mul(dig_t a, dig_t b, dig_t m, dig_t u) {
#if RLC_ARITH != RLC_AVX512
	dig_t h, l, qh, ql, q;

	/* With a < R and b < m < R/2, a * b + q * m < R^2, and the result is
	 * below a * b / R + m < R/2 + m < 2m. */
	RLC_MUL_DIG(h, l, a, b);
	q = l * u;
	RLC_MUL_DIG(qh, ql, q, m);
	ql += l;
	h += qh + (ql < l);
	return RLC_RNS_CRT(h, m);
#else
	dbl_t t = (dbl_t)a * b;
	dig_t q = ((dig_t)t * u) & RLC_RNS_MASK, h, l;

	/* (a * b + q * m) / 2^52 < 2^64 + m, so fold its bits above 2^52. */
	t = (t + (dbl_t)q * m) >> RLC_RNS_DIG;
	l = (dig_t)t & RLC_RNS_MASK;
	h = (dig_t)(t >> RLC_RNS_DIG);
	return rns_fix(l + h * RLC_RNS_K(m), m);
#endif
}

/**
 * Computes the number of times the product M of a base is subtracted in the
 * Chinese Remainder Theorem for the values xi_i = x_i (M/m_i)^{-1} mod m_i:
 * sum xi_i / m_i, approximated by sum xi_i / 2^RLC_RNS_BITS, and truncated or
 * rounded.
 *
 * @param[in] xi			- the values xi_i.
 * @param[in] n				- the number of moduli in the base.
 * @param[in] exact			- the flag to round instead of truncating.
 * @return the result.
 */
static inline dig_t rns_alpha(const dig_t *xi, size_t n, int exact) {
	dig_t a0 = (dig_t)exact << (RLC_RNS_BITS - 1), a1 = 0;

	for (size_t i = 0; i < n; i++) {
		a0 += xi[i];
		a1 += (a0 < xi[i]);
	}
	return (a1 << (RLC_DIG - RLC_RNS_BITS)) | (a0 >> RLC_RNS_BITS);
}

#if RLC_ARITH != RLC_AVX512

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
static inline dig_t rns_rdc3(dig_t s2, dig_t s1, dig_t s0, dig_t m, dig_t u) {
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

/**
 * Extends a value to a base of the Residue Number System from the other, given
 * the plain values xi_i = x_i (M/m_i)^{-1} mod m_i in the source base. When the
 * number of times M is subtracted is truncated, the result is x or x + M, where
 * M is the product of the source base; when it is rounded, the result is x for
 * |x| < M/2; when it is not subtracted at all, the result is x + kM for some
 * 0 <= k < n. The residues come out in Montgomery form, and the tables of the
 * extensions carry the constants of the reduction.
 *
 * @param[out] r			- the n residues in the target base.
 * @param[in] xi			- the values xi_i in the source base.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- 1 to round, 0 to truncate, -1 to skip.
 * @param[in] c				- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] o				- the space taken by each base.
 */
static inline void rns_extm_imp(dig_t *r, const dig_t *xi, int b, int exact,
		const rns_st *c, size_t n, size_t o) {
	/* From B to B' with the first table, from B' to B with the second. */
	const dig_t *t = (b ? c->t1 : c->t2);
	const dig_t *w = (b ? c->u1 : c->u2);
	const dig_t *m = c->m + (b ? o : 0);
	const dig_t *u = c->u + (b ? o : 0);
	dig_t a = (exact < 0 ? 0 : rns_alpha(xi, n, exact));

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
		r[j] = rns_rdc3(s2, s1, s0, m[j], u[j]);
	}
#else
	/* The products are below R^2 / 4, so four of them add up in a double digit
	 * without overflow, and only these sums need their carries counted. Four
	 * outputs are computed per pass, to share the loads of xi_i. */
	size_t j = 0;
	for (; j + 3 < n; j += 4) {
		dbl_t acc[4], g;
		dig_t s[4] = { 0, 0, 0, 0 };
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
				s[k] += (acc[k] < g);
			}
		}
		for (; i < n; i++) {
			ti = t + i * o + j;
			for (int k = 0; k < 4; k++) {
				g = (dbl_t)xi[i] * ti[k];
				acc[k] += g;
				s[k] += (acc[k] < g);
			}
		}
		for (int k = 0; k < 4; k++) {
			r[j + k] = rns_rdc3(s[k], (dig_t)(acc[k] >> RLC_DIG),
					(dig_t)acc[k], m[j + k], u[j + k]);
		}
	}
	for (; j < n; j++) {
		dbl_t acc = (dbl_t)a * w[j], g;
		dig_t s = 0;
		for (size_t i = 0; i < n; i++) {
			g = (dbl_t)xi[i] * t[i * o + j];
			acc += g;
			s += (acc < g);
		}
		r[j] = rns_rdc3(s, (dig_t)(acc >> RLC_DIG), (dig_t)acc, m[j], u[j]);
	}
#endif
}

/**
 * Converts the digits of an integer to its residues in storage form, not
 * reduced modulo N.
 *
 * @param[out] r			- the residues.
 * @param[in] a				- the w digits of RLC_RNS_DIG bits.
 * @param[in] c				- the context.
 * @param[in] l				- the number of residues, 2o.
 * @param[in] w				- the number of digits.
 */
static inline void rns_digs_imp(dig_t *r, const dig_t *a, const rns_st *c,
		size_t l, size_t w) {
	const dig_t *m = c->m, *u = c->u;

	/* The digits are whole, as RLC_RNS_DIG is RLC_DIG. */
	for (size_t i = 0; i < l; i++) {
		r[i] = 0;
		for (size_t k = 0; k < w; k++) {
			r[i] = RLC_RNS_ADD(r[i], rns_mul(a[k], c->pw[k * l + i], m[i],
					u[i]), m[i]);
		}
	}
}

#endif

/**
 * Divides the residues of a value by M in B', so that the value can be
 * reduced as if it were a product.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the value.
 * @param[in] c				- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] o				- the space taken by each base.
 */
static inline void rns_wide_imp(dig_t *r, const dig_t *a, const rns_st *c,
		size_t n, size_t o) {
	const dig_t *m = c->m + o, *u = c->u + o;

	for (size_t i = 0; i < n; i++) {
		r[i] = a[i];
	}
	for (size_t i = 0; i < n; i++) {
		r[o + i] = rns_mul(a[o + i], c->mi[i], m[i], u[i]);
	}
}

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Extends a value to a base of the Residue Number System from the other, as
 * rns_extm_imp() does, for the sizes of the context.
 *
 * @param[out] r			- the n residues in the target base.
 * @param[in] xi			- the values xi_i in the source base.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- 1 to round, 0 to truncate, -1 to skip.
 * @param[in] c				- the context.
 * @throw ERR_NO_VALID		- with a backend without generic kernels.
 */
void rns_extm_low(dig_t *r, const dig_t *xi, int b, int exact, const rns_t c);

/**
 * Multiplies two values residue by residue, without reduction.
 *
 * @param[out] r			- the product.
 * @param[in] a				- the first value.
 * @param[in] b				- the second value.
 * @param[in] c				- the context.
 */
void rns_muln_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c);

/**
 * Reduces a product of values by Montgomery reduction modulo N.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the product.
 * @param[in] c				- the context.
 * @throw ERR_NO_VALID		- with a backend without generic kernels.
 */
void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c);

/**
 * Multiplies two values with Montgomery reduction modulo N.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the first value.
 * @param[in] b				- the second value.
 * @param[in] c				- the context.
 * @throw ERR_NO_VALID		- with a backend without generic kernels.
 */
void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c);

/**
 * Converts the digits of an integer to its residues in storage form, not
 * reduced modulo N.
 *
 * @param[out] r			- the 2o residues.
 * @param[in] a				- the w digits of RLC_RNS_DIG bits.
 * @param[in] c				- the context.
 * @throw ERR_NO_VALID		- with a backend without generic kernels.
 */
void rns_digs_low(dig_t *r, const dig_t *a, const rns_t c);

#endif /* !RLC_RNS_LOW_H */
