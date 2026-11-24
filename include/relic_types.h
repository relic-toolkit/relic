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
 * Elementary types.
 *
 * @ingroup relic
 */

#ifndef RLC_TYPES_H
#define RLC_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "relic_conf.h"

#if RLC_ARITH == RLC_GMP || RLC_ARITH == RLC_GMP_SEC
#include <gmp.h>
#endif

#if defined(_MSC_VER) && RLC_WSIZE == 64
#include <intrin.h>
#endif

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Size in bits of a digit.
 */
#define RLC_DIG			(RLC_WSIZE)

/**
 * Logarithm of the digit size in bits in base two.
 */
#if RLC_DIG == 8
#define RLC_DIG_LOG		3
#elif RLC_DIG == 16
#define RLC_DIG_LOG		4
#elif RLC_DIG == 32
#define RLC_DIG_LOG		5
#elif RLC_DIG == 64
#define RLC_DIG_LOG		6
#endif

/**
 * Coordinate systems of elliptic curve points. Jacobian, extended and halving
 * coordinates belong to different families of curves, so they share a value.
 */
/** @{ */
#define EC_AFFIN		1
#define EC_PROJC		2
#define EC_JACOB		3
#define EC_EXTND		3
#define EC_HALVE		3
/** @} */

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a digit from a multiple precision integer.
 *
 * Each digit is represented as an unsigned long to use the biggest native
 * type that potentially supports native instructions.
 */
#if RLC_ARITH == RLC_GMP
typedef mp_limb_t dig_t;
#elif RLC_WSIZE == 8
typedef uint8_t dig_t;
#elif RLC_WSIZE == 16
typedef uint16_t dig_t;
#elif RLC_WSIZE == 32
typedef uint32_t dig_t;
#elif RLC_WSIZE == 64
typedef uint64_t dig_t;
#endif

/**
 * Represents a signed digit.
 */
#if RLC_WSIZE == 8
typedef int8_t dis_t;
#elif RLC_WSIZE == 16
typedef int16_t dis_t;
#elif RLC_WSIZE == 32
typedef int32_t dis_t;
#elif RLC_WSIZE == 64
typedef int64_t dis_t;
#endif

/**
 * Represents a double-precision integer from a multiple precision integer.
 *
 * This is useful to store a result from a multiplication of two digits.
 */
#if RLC_WSIZE == 8
typedef uint16_t dbl_t;
#elif RLC_WSIZE == 16
typedef uint32_t dbl_t;
#elif RLC_WSIZE == 32
typedef uint64_t dbl_t;
#elif RLC_WSIZE == 64
#ifdef _MSC_VER
/** MSVS does not support 128-bit type. */
#define RLC_CONF_NODBL
#else
typedef __uint128_t dbl_t;
#endif
#endif

/**
 * Multiplies two digits to give a double precision result.
 *
 * @param[out] H		- the higher half of the result.
 * @param[out] L		- the lower half of the result.
 * @param[in] A			- the first digit to multiply.
 * @param[in] B			- the second digit to multiply.
 */
#ifdef RLC_CONF_NODBL
#define RLC_MUL_DIG(H, L, A, B)		L = _umul128(A, B, &(H))
#else
/* One product for both halves, which some compilers do not merge from two. */
#define RLC_MUL_DIG(H, L, A, B)												\
	do {																	\
		dbl_t _p = (dbl_t)(A) * (dbl_t)(B);									\
		H = (dig_t)(_p >> RLC_DIG);											\
		L = (dig_t)_p;														\
	} while (0)

#endif

/**
 * Accumulates the product of a signed digit and a digit into a signed double
 * digit, correcting the unsigned high half of the product for both signs.
 *
 * @param[in,out] C1		- most significant word of the accumulator.
 * @param[in,out] C0		- least significant word of the accumulator.
 * @param[in] A				- the signed digit.
 * @param[in] B				- the digit.
 * @param[in] SB			- the sign mask of B, zero if it is unsigned.
 */
#define RLC_MAC_DIG(C1, C0, A, B, SB)										\
	do {																	\
		dig_t _h, _l;														\
		RLC_MUL_DIG(_h, _l, (dig_t)(A), (B));								\
		_h -= ((B) & -RLC_SIGN(A)) + ((dig_t)(A) & (SB));					\
		(C0) += _l;															\
		(C1) += _h + ((C0) < _l);											\
	} while (0)

/**
 * Divides a double-digit by a digit, setting quotient and remainder.
 *
 * @param[out] Q		- the quotient.
 * @param[out] R		- the remainder.
 * @param[in] H			- the higher half of the dividend.
 * @param[in] L			- the lower half of the dividend.
 * @param[in] D			- the divisor.
 */
#ifdef RLC_CONF_NODBL
#define RLC_DIV_DIG(Q, R, H, L, D)	Q = _udiv128(H, L, D, &(R))
#else

#define RLC_DIV_DIG(Q, R, H, L, D)											\
	Q = (((dbl_t)(H) << RLC_DIG) | (L)) / (D);								\
	R = (((dbl_t)(H) << RLC_DIG) | (L)) - (dbl_t)(Q) * (dbl_t)(D);			\

#endif

/**
 * Multiplies two digits modulo 2^RLC_DIG. The product is taken in at least
 * unsigned int, since narrow digits are promoted to int and could overflow.
 *
 * @param[in] A			- the first digit to multiply.
 * @param[in] B			- the second digit to multiply.
 */
#define RLC_MLO_DIG(A, B)	((dig_t)((A) * 1U * (B)))

/*
 * Represents the unsigned integer with maximum precision.
 */
typedef unsigned long long ull_t;

/*
 * Represents the unsigned integer with maximum precision.
 */
typedef unsigned long uint_t;

/**
 * Type that represents an error.
 */
typedef int err_t;

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Specification for aligned variables.
 */
#if RLC_ALIGN > 1
#define rlc_align 		__attribute__ ((aligned (RLC_ALIGN)))
#else
#define rlc_align 		/* empty */
#endif

/**
 * Size of padding to be added so that digit vectors are aligned.
 */
#if RLC_ALIGN > 1
#define RLC_PAD(A)		((A) % RLC_ALIGN == 0 ? 0 : RLC_ALIGN - ((A) % RLC_ALIGN))
#else
#define RLC_PAD(A)		(0)
#endif

#endif /* !RLC_TYPES_H */
