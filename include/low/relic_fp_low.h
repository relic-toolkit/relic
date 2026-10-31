/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Interface of the low-level prime field arithmetic module.
 *
 * @ingroup fp
 */

#ifndef RLC_FP_LOW_H
#define RLC_FP_LOW_H

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#include "relic_conf.h"

/*
 * Size in bytes of a temporary double-precision vector, written with integer
 * arithmetic only so that assembly can use it as an offset.
 */
#if defined(WITH_FB) && FB_POLYN > FP_PRIME
#define RLC_DV_STRIDE_D	((2 * FB_POLYN - 1) / RLC_WSIZE + 2)
#else
#define RLC_DV_STRIDE_D	((2 * FP_PRIME - 1) / RLC_WSIZE + 2)
#endif
#define RLC_DV_STRIDE_B	(2 * ((BN_PRECI - 1) / RLC_WSIZE + 1) + 2)
#if RLC_DV_STRIDE_D > RLC_DV_STRIDE_B
#define RLC_DV_STRIDE_N	(RLC_DV_STRIDE_D * (RLC_WSIZE / 8))
#else
#define RLC_DV_STRIDE_N	(RLC_DV_STRIDE_B * (RLC_WSIZE / 8))
#endif
#define RLC_DV_STRIDE	((RLC_DV_STRIDE_N + RLC_ALIGN - 1) / RLC_ALIGN * RLC_ALIGN)

#if FP_RDC == FP_RENUS
/**
 * Size in bits of a digit of the Residue Number System, so that the radix of
 * the Montgomery form of residues is R = 2^RLC_RNS_DIG: 52 bits with the
 * AVX-512 IFMA backend, and a whole digit otherwise.
 */
#if RLC_ARITH == RLC_AVX512
#define RLC_RNS_DIG		52
#else
#define RLC_RNS_DIG		RLC_DIG
#endif

/** Mask of the low RLC_RNS_DIG bits of a digit. */
#define RLC_RNS_MASK	((dig_t)-1 >> (RLC_DIG - RLC_RNS_DIG))
#endif

#ifdef ASM

#include "relic_conf.h"
#include "relic_label.h"

#if (FP_PRIME % RLC_WSIZE) > 0
#define RLC_FP_DIGS		(FP_PRIME/RLC_WSIZE + 1)
#else
#define RLC_FP_DIGS		(FP_PRIME/RLC_WSIZE)
#endif
#else

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

#if FP_RDC == FP_RENUS
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
/* As 2^52 = 2^52 - M mod M, with 2^52 - M < 2^26, fold the high bits. */
#define RLC_RNS_MOD(D, M)													\
	RLC_RNS_CRT(((dig_t)(D) & RLC_RNS_MASK) +								\
		((dig_t)(D) >> RLC_RNS_DIG) * (((dig_t)1 << RLC_RNS_DIG) - (M)), M)
#endif

/**
 * Reduces a digit D modulo the I-th modulus and converts it to Montgomery form,
 * as a multiplier of residues.
 *
 * @param[in] D				- the digit.
 * @param[in] I				- the index of the modulus.
 */
#define RLC_RNS_SCL(D, I)													\
	rns_mul(RLC_RNS_MOD(D, core_get()->rns.m[I]), core_get()->rns.r2[I],	\
		core_get()->rns.m[I], core_get()->rns.u[I])

/**
 * Converts a digit D to the representation of elements at the I-th modulus:
 * Montgomery form, and also divided by M in B'. The Montgomery product takes
 * any digit as its first operand.
 *
 * @param[in] D				- the digit.
 * @param[in] I				- the index of the modulus.
 */
#define RLC_RNS_CONV(D, I)													\
	rns_mul(D, core_get()->rns.e[I], core_get()->rns.m[I], core_get()->rns.u[I])

/**
 * Applies a residue-wise operation to all residues of both bases, with the
 * moduli in _m and their Montgomery constants in _u.
 */
#define RLC_RNS_MAP(C, OP)													\
	const dig_t *_m = core_get()->rns.m, *_u = core_get()->rns.u;			\
	(void)_u;																\
	for (size_t _i = 0; _i < RLC_FP_LEN; _i++) {							\
		C[_i] = OP;															\
	}
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Adds a digit vector and a digit. Computes c = a + digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to add.
 * @param[in] digit			- the digit to add.
 * @return the carry of the last digit addition.
 */
dig_t fp_add1_low(dig_t *c, const dig_t *a, dig_t digit);

/**
 * Adds two digit vectors of the same size. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 * @return the carry of the last digit addition.
 */
dig_t fp_addn_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Adds two digit vectors of the same size with integrated modular reduction.
 * Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 */
void fp_addm_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Adds two double-length digit vectors. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 * @return the carry of the last digit addition.
 */
dig_t fp_addd_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Adds two double-length digit vectors and reduces modulo p * R. Computes
 * c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 */
void fp_addc_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Subtracts a digit from a digit vector. Computes c = a - digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector.
 * @param[in] digit			- the digit to subtract.
 * @return the carry of the last digit subtraction.
 */
dig_t fp_sub1_low(dig_t *c, const dig_t *a, dig_t digit);

/**
 * Subtracts a digit vector from another digit vector. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector.
 * @param[in] b				- the digit vector to subtract.
 * @return the carry of the last digit subtraction.
 */
dig_t fp_subn_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Subtracts two digit vectors of the same size with integrated modular
 * reduction.
 * Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 */
void fp_subm_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Subtracts a double-length digit vector from another digit vector.
 * Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 * @return the carry of the last digit subtraction.
 */
dig_t fp_subd_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Subtracts a double-length digit vector from another digit vector.
 * Computes c = a - b. This version of the function should handle possible
 * carries by adding p * R.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 */
void fp_subc_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Negates a digit vector. Computes c = -a.
 *
 * @param[out] c			- the result.
 * @param[out] a			- the prime field element to negate.
 */
void fp_negm_low(dig_t *c, const dig_t *a);

/**
 * Doubles a digit vector. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector.
 * @return the carry of the last digit doubling.
 */
dig_t fp_dbln_low(dig_t *c, const dig_t *a);

/**
 * Doubles a digit vector with integrated modular reduction.
 * Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 */
void fp_dblm_low(dig_t *c, const dig_t *a);

/**
 * Halves a digit vector with integrated modular reduction.
 * Computes c = a/2.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to halve.
 */
void fp_hlvm_low(dig_t *c, const dig_t *a);

/**
 * Halves a double-precision digit vector. Computes c = a/2.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to halve.
 */
void fp_hlvd_low(dig_t *c, const dig_t *a);

/**
 * Shifts a digit vector to the left by 1 bits. Computes c = a << 1.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to shift.
 * @return the carry of the last digit shift.
 */
dig_t fp_lsh1_low(dig_t *c, const dig_t *a);

/**
 * Shifts a digit vector to the left by an amount smaller than a digit. Computes
 * c = a << bits.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to shift.
 * @param[in] bits			- the shift amount.
 * @return the carry of the last digit shift.
 */
dig_t fp_lshb_low(dig_t *c, const dig_t *a, uint_t bits);

/**
 * Shifts a digit vector to the right by 1 bit. Computes c = a >> 1.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to shift.
 * @return the carry of the last digit shift.
 */
dig_t fp_rsh1_low(dig_t *c, const dig_t *a);

/**
 * Shifts a digit vector to the right by an amount smaller than a digit.
 * Computes c = a >> bits.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to shift.
 * @param[in] bits			- the shift amount.
 * @return the carry of the last digit shift.
 */
dig_t fp_rshb_low(dig_t *c, const dig_t *a, uint_t bits);

/**
 * Multiplies a digit vector by a digit and adds this result to another digit
 * vector. Computes c = c + a * digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to multiply.
 * @param[in] digit			- the digit to multiply.
 * @return the carry of the addition.
 */
dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit);

/**
 * Multiplies a digit vector by a digit with modular reduction, in constant
 * time. Computes c = (a * digit) mod p for digit < 2^(RLC_DIG - 1).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to multiply.
 * @param[in] digit			- the digit to multiply.
 */
void fp_mul1_low(dig_t *c, const dig_t *a, dig_t digit);

/**
 * Multiplies two digit vectors of the same size. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] b				- the second digit vector to multiply.
 */
void fp_muln_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Multiplies two digit vectors of the same size with embedded modular
 * reduction. Computes c = (a * b) mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] b				- the second digit vector to multiply.
 */
void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b);

/**
 * Squares a digit vector. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to square.
 */
void fp_sqrn_low(dig_t *c, const dig_t *a);

/**
 * Squares a digit vector with embedded modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to square.
 */
void fp_sqrm_low(dig_t *c, const dig_t *a);

/**
 * Reduces a digit vector modulo m represented in special form.
 * Computes c = a mod m. Only arithmetic backends that support FP_RDC = FP_LOWER
 * provide it.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to reduce.
 * @param[in] m				- the modulus.
 */
void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m);

/**
 * Reduces a digit vector modulo the configured prime p. Computes c = a mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to reduce.
 */
void fp_rdcn_low(dig_t *c, dig_t *a);

/**
 * Inverts a digit vector modulo the configured prime.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to invert.
 */
void fp_invm_low(dig_t *c, const dig_t *a);

/**
 * Computes the Legendre symbol of a digit vector and the configured prime.
 *
 * @param[in] a				- the digit vector to invert.
 * @return the result.
 */
int fp_smbm_low(const dig_t *a);

#if FP_RDC == FP_RENUS

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
	return RLC_RNS_CRT(l + h * (((dig_t)1 << RLC_RNS_DIG) - m), m);
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

/**
 * Divides the residues of an element by M in B', so that the element can be
 * reduced as if it were a product.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element.
 */
static inline void rns_wide(dig_t *c, const dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m + o, *u = ctx->rns.u + o;

	for (size_t i = 0; i < n; i++) {
		c[i] = a[i];
	}
	for (size_t i = 0; i < n; i++) {
		c[o + i] = rns_mul(a[o + i], ctx->rns.mi[i], m[i], u[i]);
	}
}

/**
 * Extends a value to a base of the Residue Number System from the other, given
 * the plain values xi_i = x_i (M/m_i)^{-1} mod m_i in the source base. When the
 * number of times M is subtracted is truncated, the result is x or x + M, where
 * M is the product of the source base; when it is rounded, the result is x for
 * |x| < M/2. The residues come out in Montgomery form, and the tables of the
 * extensions carry the constants of the reduction.
 *
 * @param[out] r			- the residues in the target base.
 * @param[in] xi			- the values xi_i in the source base.
 * @param[in] b				- the target base: 0 for B, 1 for B'.
 * @param[in] exact			- the flag to round instead of truncating.
 */
void fp_rnsx_low(dig_t *r, const dig_t *xi, int b, int exact);

#endif /* FP_RDC == FP_RENUS */

#endif /* ASM */

#endif /* !RLC_FP_LOW_H */
