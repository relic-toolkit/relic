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
 * Tests if the I-th residue of a value pads its base in a context C.
 *
 * @param[in] C				- the context.
 * @param[in] I				- the index of the residue.
 */
#define RLC_RNS_PAD(C, I)	((I) % (C)->o >= (C)->n)

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
/* As 2^52 = K mod M, fold the high bits: the moduli are 2^50 - c or 2^52 - c
 * with c below 2^26, so K = 4c or c is below 2^28, and the result is below
 * 2^52 + 2^12 * K < 4M + 2^28 + 2^40 < 5M, which three subtractions bring
 * below M. */
#define RLC_RNS_MOD(D, M)													\
	rns_fix(((dig_t)(D) & RLC_RNS_MASK) +									\
		((dig_t)(D) >> RLC_RNS_DIG) * RLC_RNS_K(M), M)
/** The residue of 2^52 modulo a modulus M of 50 to 52 bits, as 2^52 - 2^k M
 * for the shift k that brings M to 52 bits. */
#define RLC_RNS_K(M)														\
	(((dig_t)1 << RLC_RNS_DIG) - ((dig_t)(M) << (((dig_t)(M) >> 51 == 0) +	\
		((dig_t)(M) >> 50 == 0))))
#endif

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a base extension in a context, as rns_extm_low() computes it.
 */
typedef void (*rns_ext_t)(dig_t *r, const dig_t *xi, int b, int exact,
		const rns_st *c);

/**
 * Represents a Montgomery reduction of a product in a context, as
 * rns_rdcn_low() computes it.
 */
typedef void (*rns_rdc_t)(dig_t *r, const dig_t *a, const rns_st *c);

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
 * sum xi_i / m_i, approximated by sum xi_i / 2^b for moduli of b bits, and
 * truncated or rounded.
 *
 * @param[in] xi			- the values xi_i.
 * @param[in] n				- the number of moduli in the base.
 * @param[in] exact			- the flag to round instead of truncating.
 * @param[in] b				- the size in bits of the moduli.
 * @return the result.
 */
static inline dig_t rns_alpha(const dig_t *xi, size_t n, int exact, size_t b) {
	dig_t a0 = (dig_t)exact << (b - 1), a1 = 0;

	for (size_t i = 0; i < n; i++) {
		a0 += xi[i];
		a1 += (a0 < xi[i]);
	}
	return (a1 << (RLC_DIG - b)) | (a0 >> b);
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
	dig_t a = (exact < 0 ? 0 : rns_alpha(xi, n, exact, c->bits));

#ifdef RLC_CONF_NODBL
	dig_t h, l, s0, s1, s2;

	for (size_t j = 0; j < n; j++) {
		/* The n + 1 products, below R^2 / 4 each, as three digits; the
		 * extension that skips alpha has n of them. */
		s0 = s1 = s2 = 0;
		if (exact >= 0) {
			RLC_MUL_DIG(s1, s0, a, w[j]);
		}
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
		/* The extension that skips alpha has no product by it. */
		for (int k = 0; k < 4; k++) {
			acc[k] = (exact < 0 ? 0 : (dbl_t)a * w[j + k]);
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
		dbl_t acc = (exact < 0 ? 0 : (dbl_t)a * w[j]), g;
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

/**
 * Reduces a product of values by Montgomery reduction in the Residue Number
 * System: computes r = a / M mod N, as an integer with -N < r < (n + 1)N. The
 * base extensions are given, so that each owner of a context uses its own.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the product.
 * @param[in] c				- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] o				- the space taken by each base.
 * @param[out] q			- scratch space for n residues.
 * @param[out] e			- scratch space for n residues.
 * @param[in] ext			- the base extension.
 */
static inline void rns_rdcn_imp(dig_t *r, const dig_t *a, const rns_st *c,
		size_t n, size_t o, dig_t *q, dig_t *e, rns_ext_t ext) {
	const dig_t *m = c->m, *u = c->u;

	/* xi_i of q = a * (-N^{-1}) mod M, in B, as plain residues. */
	for (size_t i = 0; i < n; i++) {
		q[i] = rns_mul(a[i], c->nq[i], m[i], u[i]);
	}
	/* q * N for q + kM, as a product in B', with 0 <= k < n: the extra kN
	 * only makes the result larger, so the extension skips alpha. */
	ext(e, q, 1, -1, c);
	/* r = (a + q * N) / M in B', as a product carries 1 / M^2 there and a
	 * value 1 / M; and its xi_j for the exact extension. */
	for (size_t j = 0; j < n; j++) {
		r[o + j] = RLC_RNS_ADD(a[o + j], e[j], m[o + j]);
		q[j] = rns_mul(r[o + j], c->ib[o + j], m[o + j], u[o + j]);
	}
	/* r in B, exactly, since |r| < (n + 1)N is far below M'/2. */
	ext(r, q, 0, 1, c);
}

/**
 * Tests if a value in the Residue Number System is zero modulo N, in constant
 * time. The base extension is given, so that each owner of a context uses its
 * own.
 *
 * @param[in] a				- the value to test.
 * @param[in] c				- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] o				- the space taken by each base.
 * @param[out] q			- scratch space for n residues.
 * @param[out] r			- scratch space for n residues.
 * @param[in] ext			- the base extension.
 * @return 1 if the value is zero modulo N, 0 otherwise.
 */
static inline int rns_is_zero_imp(const dig_t *a, const rns_st *c, size_t n,
		size_t o, dig_t *q, dig_t *r, rns_ext_t ext) {
	const dig_t *m = c->m, *u = c->u;
	dig_t d, z = 0;

	/* The first half of the reduction gives r = a / M in B', with |r| < 3N,
	 * so a is zero modulo N if and only if r is one of -2N, -N, 0, N or 2N,
	 * which B' tells apart without extending r back to B. */
	for (size_t i = 0; i < n; i++) {
		q[i] = rns_mul(a[i], c->nq[i], m[i], u[i]);
	}
	ext(r, q, 1, 0, c);
	for (size_t i = 0; i < n; i++) {
		r[i] = RLC_RNS_ADD(rns_mul(a[o + i], c->mi[i], m[o + i], u[o + i]),
				r[i], m[o + i]);
	}
	for (size_t k = 0; k < 5; k++) {
		d = 0;
		for (size_t i = 0; i < n; i++) {
			d |= r[i] ^ c->kp[k * 2 * o + o + i];
		}
		z |= (d == 0);
	}
	return (int)z;
}

/**
 * Adds a double digit to an accumulator of three digits.
 *
 * @param[in,out] r			- the accumulator.
 * @param[in] h				- the high digit, below the largest one.
 * @param[in] l				- the low digit.
 */
static inline void rns_acc3(dig_t *r, dig_t h, dig_t l) {
	r[0] += l;
	h += (r[0] < l);
	r[1] += h;
	r[2] += (r[1] < h);
}

/**
 * Converts a value in the Residue Number System to the digits of its residue
 * modulo N in [0, N), in constant time. The reduction is given, so that each
 * owner of a context uses its own.
 *
 * @param[out] r			- the d digits.
 * @param[in] a				- the value.
 * @param[in] c				- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] o				- the space taken by each base.
 * @param[in] d				- the number of digits of N.
 * @param[out] w			- scratch space for 2o residues.
 * @param[out] xi			- scratch space for n residues.
 * @param[out] s			- scratch space for d + 1 digits.
 * @param[out] t			- scratch space for d + 1 digits.
 * @param[in] rdc			- the reduction.
 */
static inline void rns_get_imp(dig_t *r, const dig_t *a, const rns_st *c,
		size_t n, size_t o, size_t d, dig_t *w, dig_t *xi, dig_t *s,
		dig_t *t, rns_rdc_t rdc) {
	const size_t l = d + 1;
	const dig_t *m = c->m, *u = c->u, *p = c->p;
	dig_t a1, b, q, h, x, acc[3] = { 0, 0, 0 };
	int k;

	/* w = a / M is the value of a, with -N < w < (n + 1)N. */
	rns_wide_imp(w, a, c, n, o);
	rdc(w, w, c);
	/* w = sum xi_i (M/m_i) - alpha M, where alpha rounds sum xi_i / m_i, as
	 * w / M is tiny. */
	for (size_t i = 0; i < n; i++) {
		xi[i] = rns_mul(w[i], c->ib[i], m[i], u[i]);
	}
	a1 = rns_alpha(xi, n, 1, c->bits);
	/* The low digits of w + 3N are enough to recover it, as it is positive.
	 * The multipliers are single digits, so sum them column by column in three
	 * digits, with the top two carried to the next column. */
	for (size_t j = 0; j < l; j++) {
		rns_acc3(acc, 0, c->p3[j]);
		RLC_MUL_DIG(h, x, a1, c->mm[j]);
		rns_acc3(acc, h, x);
		for (size_t i = 0; i < n; i++) {
			RLC_MUL_DIG(h, x, xi[i], c->mp[i * l + j]);
			rns_acc3(acc, h, x);
		}
		s[j] = acc[0];
		acc[0] = acc[1];
		acc[1] = acc[2];
		acc[2] = 0;
	}
	/* Now 0 < s < (n + 4)N, so subtract 2^k N where it fits, for 2^k at most
	 * n + 3 from the largest down. */
	for (k = 0; ((size_t)2 << k) <= n + 3; k++);
	for (; k >= 0; k--) {
		b = 0;
		for (size_t j = 0; j < l; j++) {
			q = (j < l - 1 ? p[j] << k : 0);
			if (j > 0 && k > 0) {
				q |= p[j - 1] >> (RLC_DIG - k);
			}
			x = s[j] - q;
			h = (s[j] < q);
			t[j] = x - b;
			b = h | (x < b);
		}
		/* Keep the difference unless it wrapped around. */
		q = b - 1;
		for (size_t j = 0; j < l; j++) {
			s[j] = (t[j] & q) | (s[j] & ~q);
		}
	}
	for (size_t j = 0; j < d; j++) {
		r[j] = s[j];
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
 */
void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c);

/**
 * Multiplies two values with Montgomery reduction modulo N.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the first value.
 * @param[in] b				- the second value.
 * @param[in] c				- the context.
 */
void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c);

/**
 * Converts the digits of an integer to its residues in storage form, not
 * reduced modulo N.
 *
 * @param[out] r			- the 2o residues.
 * @param[in] a				- the w digits of RLC_RNS_DIG bits.
 * @param[in] c				- the context.
 */
void rns_digs_low(dig_t *r, const dig_t *a, const rns_t c);

#endif /* !RLC_RNS_LOW_H */
