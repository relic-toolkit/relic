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

#endif /* !RLC_RNS_LOW_H */
