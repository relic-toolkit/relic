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
 * Interface of the low-level multiple precision integer arithmetic module.
 *
 * All functions assume that the destination has enough capacity to store
 * the result of the computation.
 *
 * @ingroup bn
 */

#ifndef RLC_BN_LOW_H
#define RLC_BN_LOW_H

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#ifdef ASM

#include "relic_conf.h"
#include "relic_label.h"

#if (BN_PRECI % WSIZE) > 0
#define RLC_BN_DIGS		(BN_PRECI/WSIZE + 1)
#else
#define RLC_BN_DIGS		(BN_PRECI/WSIZE)
#endif

#if BN_MAGNI == DOUBLE
#define RLC_BN_SIZE		(2 * RLC_BN_DIGS + 2)
#elif BN_MAGNI == CARRY
#define RLC_BN_SIZE		((RLC_BN_DIGS + 1)
#elif BN_MAGNI == SINGLE
#define RLC_BN_SIZE		(RLC_BN_DIGS)
#endif

#else

#include "relic_types.h"

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Adds a digit to a digit vector. Computes c = a + digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] digit			- the digit to add.
 * @param[in] size			- the number of digits in the first operand.
 * @return the carry of the last digit addition.
 */
dig_t bn_add1_low(dig_t *c, const dig_t *a, const dig_t digit, size_t size);

/**
 * Adds two digit vectors of the same size. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to add.
 * @param[in] b				- the second digit vector to add.
 * @param[in] size			- the number of digits to add.
 * @return the carry of the last digit addition.
 */
dig_t bn_addn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size);

/**
 * Subtracts a digit from a digit vector. Computes c = a - digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector.
 * @param[in] digit			- the digit to subtract.
 * @param[in] size			- the number of digits in a.
 * @return the carry of the last digit subtraction.
 */
dig_t bn_sub1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size);

/**
 * Subtracts a digit vector from another digit vector. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector.
 * @param[in] b				- the digit vector to subtract.
 * @param[in] size			- the number of digits to subtract.
 * @return the carry of the last digit subtraction.
 */
dig_t bn_subn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size);

/**
 * Conditionally negate a digit vector using two's complement representation.
 *
 * @param[out] c 		- the result.
 * @param[in] a 		- the digit vector to conditionally negate.
 * @param[in] sa 		- the sign of the digit vector.
 * @param[in] n			- the number of digits to conditionally negate.
 * @return the carry of the last digit negation.
 */
dig_t bn_negs_low(dig_t *c, const dig_t *a, dig_t sa, size_t size);

/**
 * Compares two digit vectors of the same size.
 *
 * @param[in] a				- the first digit vector to compare.
 * @param[in] sa			- the number of digits in the first argument.
 * @param[in] b				- the second digit vector to compare.
 * @param[in] sb			- the number of digits in the second argument.
 * @return RLC_LT if a < b, RLC_EQ if a == b and RLC_GT if a > b.
 */
int bn_cmpn_low(const dig_t *a, size_t sa, const dig_t *b, size_t sb);

/**
 * Shifts a digit vector to the left by 1 bit. Computes c = a << 1.
 *
 * @param[out] c			- the result
 * @param[in] a				- the digit vector to shift.
 * @param[in] size			- the number of digits to shift.
 * @return the carry of the last digit shift.
 */
dig_t bn_lsh1_low(dig_t *c, const dig_t *a, size_t size);

/**
 * Shifts a digit vector to the left by an amount smaller than a digit. Computes
 * c = a << bits.
 *
 * @param[out] c			- the result
 * @param[in] a				- the digit vector to shift.
 * @param[in] size			- the number of digits to shift.
 * @param[in] bits			- the shift amount.
 * @return the carry of the last digit shift.
 */
dig_t bn_lshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits);

/**
 * Shifts a digit vector to the right by 1 bit. Computes c = a >> 1.
 *
 * @param[out] c			- the result
 * @param[in] a				- the digit vector to shift.
 * @param[in] size			- the number of digits to shift.
 * @return the carry of the last digit shift.
 */
dig_t bn_rsh1_low(dig_t *c, const dig_t *a, size_t size);

/**
 * Shifts a digit vector to the right by an amount smaller than a digit.
 * Computes c = a >> bits.
 *
 * @param[out] c			- the result
 * @param[in] a				- the digit vector to shift.
 * @param[in] size			- the number of digits to shift.
 * @param[in] bits			- the shift amount.
 * @return the carry of the last digit shift.
 */
dig_t bn_rshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits);

/**
 * Shifts a signed digit vector to the right by an amount smaller than a digit.
 * Computes c = a >> bits.
 *
 * @param[out] c			- the result
 * @param[in] a				- the signed digit vector to shift.
 * @param[in] size			- the number of digits to shift.
 * @param[in] bits			- the shift amount.
 * @return the carry of the last digit shift.
 */
dig_t bn_rshs_low(dig_t *c, const dig_t *a, size_t size, uint_t bits);

/**
 * Multiplies a digit vector by a digit and adds this result to another digit
 * vector. Computes c = c + a * digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to multiply.
 * @param[in] digit			- the digit to multiply.
 * @param[in] size			- the number of digits to multiply.
 * @return the carry of the last addition.
 */
dig_t bn_mula_low(dig_t *c, const dig_t *a, dig_t digit, size_t size);

/**
 * Multiplies a digit vector by a digit and stores this result in another digit
 * vector. Computes c = a * digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] digit			- the digit to multiply.
 * @param[in] size			- the number of digits to multiply.
 * @return the most significant digit.
 */
dig_t bn_mul1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size);

/**
 * Multiplies a signed digit vector by a signed digit and stores this result in
 * another digit vector. Computes c = (-1)^sa * a * digit.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] sa 			- the sign of the first digit vector.
 * @param[in] digit			- the digit to multiply.
 * @param[in] size			- the number of digits to multiply.
 * @return the most significant digit.
 */
dig_t bn_muls_low(dig_t *c, const dig_t *a, dig_t sa, dis_t digit, size_t size);

/**
 * Multiplies two digit vectors of the same size. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] b				- the second digit vector to multiply.
 * @param[in] size			- the number of digits to multiply.
 */
void bn_muln_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size);

/**
 * Multiplies two digit vectors of different sizes, with sa > sb. Computes
 * c = a * b. This function outputs as result only the digits between low and
 * high, inclusive, with high > sa and low < sb.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first digit vector to multiply.
 * @param[in] b				- the second digit vector to multiply.
 * @param[in] sa			- the number of digits in the first operand.
 * @param[in] sb			- the number of digits in the second operand.
 * @param[in] low			- the first digit to compute.
 * @param[in] high			- the last digit to compute.
 */
void bn_muld_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb,
		uint_t low, uint_t high);

/**
 * Squares a digit vector and adds this result to another digit vector.
 * Computes c = c + a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to square.
 * @param[in] size			- the number of digits to square.
 * @return the carry of the last addition.
 */
dig_t bn_sqra_low(dig_t *c, const dig_t *a, size_t size);

/**
 * Squares a digit vector. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to square.
 * @param[in] size			- the number of digits to square.
 */
void bn_sqrn_low(dig_t *c, const dig_t *a, size_t size);

/**
 * Divides a digit vector by another digit vector. Computes c = floor(a / b) and
 * d = a mod b. The dividend and divisor may be destroyed inside the function.
 *
 * @param[out] c			- the quotient.
 * @param[out] d			- the remainder.
 * @param[in,out] a			- the dividend.
 * @param[in] sa			- the size of the dividend.
 * @param[in,out] b			- the divisor.
 * @param[in] sb			- the size of the divisor.
 */
void bn_divn_low(dig_t *c, dig_t *d, dig_t *a, size_t sa, dig_t *b, size_t sb);

/**
 * Divides a digit vector by a digit. Computes c = floor(a / digit) and
 * d = a mod digit.
 *
 * @param[out] c			- the quotient.
 * @param[out] d			- the remainder.
 * @param[in] a				- the dividend.
 * @param[in] size			- the size of the dividend.
 * @param[in] digit			- the divisor.
 */
void bn_div1_low(dig_t *c, dig_t *d, const dig_t *a, dig_t digit, size_t size);

/**
 * Reduces a digit vector modulo m by Montgomery's algorithm.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to reduce.
 * @param[in] sa			- the number of digits to reduce
 * @param[in] m				- the modulus.
 * @param[in] sm			- the size of the modulus.
 * @param[in] u				- the reciprocal of the modulus.
 */
void bn_modn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *m, size_t sm,
	dig_t u);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using the standard Euclidean algorithm. One of the operands must be odd.
 *
 * @param[out] c			- the result;
 * @param[in] a				- the first multiple precision integer.
 * @param[in] sa			- the number of digits in the first argument.
 * @param[in] b				- the second multiple precision integer.
 * @param[in] sa			- the number of digits in the second argument.
 */
size_t bn_gcdn_low(dig_t *c, dig_t *a, size_t sa, dig_t *b, size_t sb);

/**
 * Computes the greatest common divisor of two multiple precision integers
 * using the standard Euclidean algorithm. One of the operands must be odd.
 *
 * @param[out] c			- the result;
 * @param[out] d			- the first cofactor.
 * @param[out] sd			- the number of digits in the cofactor.
 * @param[in] a				- the first multiple precision integer.
 * @param[in] sa			- the number of digits in the first argument.
 * @param[in] b				- the second multiple precision integer.
 * @param[in] sa			- the number of digits in the second argument.
 */
size_t bn_gcde_low(dig_t *c, dig_t *d, int *sd, dig_t *a, size_t sa,
		dig_t *b, size_t sb);

#endif /* !ASM */

#endif /* !RLC_BN_LOW_H */
