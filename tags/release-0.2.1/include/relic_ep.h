/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007, 2008, 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @defgroup ep Prime elliptic curves.
 */

/**
 * @file
 *
 * Interface of the prime elliptic curves functions.
 *
 * @version $Id$
 * @ingroup ep
 */

#ifndef RELIC_EP_H
#define RELIC_EP_H

#include "relic_fp.h"
#include "relic_bn.h"
#include "relic_types.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Binary elliptic curve identifiers.
 */
enum {
	/** SECG P-160 prime curve. */
	SECG_P160 = 1,
	/** NIST P-192 prime curve. */
	NIST_P192 = 2,
	/** NIST P-224 prime curve. */
	NIST_P224 = 3,
	/** NIST P-256 prime curve. */
	NIST_P256 = 4,
	/** NIST P-384 prime curve. */
	NIST_P384 = 5,
	/** NIST P-521 prime curve. */
	NIST_P521 = 6,
	/** Barreto-Naehrig curve with negative x (found by Nogami et al.). */
	BNN_P256 = 7,
	/** Barreto-Naehrig curve with positive x. */
	BNP_P256 = 8,
};

/**
 * Size of a precomputation table using the binary method.
 */
#define EP_TABLE_BASIC		(FP_BITS + 1)

/**
 * Size of a precomputation table using Yao's windowing method.
 */
#define EP_TABLE_YAOWI      (FP_BITS / EP_DEPTH + 1)

/**
 * Size of a precomputation table using the NAF windowing method.
 */
#define EP_TABLE_NAFWI      (FP_BITS / EP_DEPTH + 1)

/**
 * Size of a precomputation table using the single-table comb method.
 */
#define EP_TABLE_COMBS      (1 << EP_DEPTH)

/**
 * Size of a precomputation table using the double-table comb method.
 */
#define EP_TABLE_COMBD		(1 << (EP_DEPTH + 1))

/**
 * Size of a precomputation table using the w-(T)NAF method.
 */
#define EP_TABLE_WTNAF		(1 << (EP_DEPTH - 2))

/**
 * Size of a precomputation table using the chosen algorithm.
 */
#if EP_FIX == BASIC
#define EP_TABLE			EP_TABLE_BASIC
#elif EP_FIX == YAOWI
#define EP_TABLE			EP_TABLE_YAOWI
#elif EP_FIX == NAFWI
#define EP_TABLE			EP_TABLE_NAFWI
#elif EP_FIX == COMBS
#define EP_TABLE			EP_TABLE_COMBS
#elif EP_FIX == COMBD
#define EP_TABLE			EP_TABLE_COMBD
#elif EP_FIX == WTNAF
#define EP_TABLE			EP_TABLE_WTNAF
#endif

/**
 * Maximum size of a precomputation table.
 */
#ifdef STRIP
#define EP_TABLE_MAX EP_TABLE
#else
#define EP_TABLE_MAX EP_TABLE_BASIC
#endif

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents an ellyptic curve point over a prime field.
 */
typedef struct {
#if ALLOC == STATIC
	/** The first coordinate. */
	fp_t x;
	/** The second coordinate. */
	fp_t y;
	/** The third coordinate (projective representation). */
	fp_t z;
#elif ALLOC == DYNAMIC || ALLOC == STACK || ALLOC == AUTO
	/** The first coordinate. */
	fp_st x;
	/** The second coordinate. */
	fp_st y;
	/** The third coordinate (projective representation). */
	fp_st z;
#endif
	/** Flag to indicate that this point is normalized. */
	int norm;
} ep_st;

/**
 * Pointer to an elliptic curve point.
 */
#if ALLOC == AUTO
typedef ep_st ep_t[1];
#else
typedef ep_st *ep_t;
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a point on a prime elliptic curve with a null value.
 *
 * @param[out] A			- the point to initialize.
 */
#if ALLOC == AUTO
#define ep_null(A)		/* empty */
#else
#define ep_null(A)		A = NULL;
#endif

/**
 * Calls a function to allocate a point on a prime elliptic curve.
 *
 * @param[out] A			- the new point.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 */
#if ALLOC == DYNAMIC
#define ep_new(A)															\
	A = (ep_t)calloc(1, sizeof(ep_st));										\
	if (A == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\

#elif ALLOC == STATIC
#define ep_new(A)															\
	A = (ep_t)alloca(sizeof(ep_st));										\
	if (A == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\
	fp_new((A)->x);															\
	fp_new((A)->y);															\
	fp_new((A)->z);															\

#elif ALLOC == AUTO
#define ep_new(A)			/* empty */

#elif ALLOC == STACK
#define ep_new(A)															\
	A = (ep_t)alloca(sizeof(ep_st));										\

#endif

/**
 * Calls a function to clean and free a point on a prime elliptic curve.
 *
 * @param[out] A			- the point to free.
 */
#if ALLOC == DYNAMIC
#define ep_free(A)															\
	if (A != NULL) {														\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == STATIC
#define ep_free(A)															\
	if (A != NULL) {														\
		fp_free((A)->x);													\
		fp_free((A)->y);													\
		fp_free((A)->z);													\
		A = NULL;															\
	}																		\

#elif ALLOC == AUTO
#define ep_free(A)			/* empty */

#elif ALLOC == STACK
#define ep_free(A)															\
	A = NULL;																\

#endif

/**
 * Negates a prime elliptic curve point.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the point to negate.
 */
#if EP_ADD == BASIC
#define ep_neg(R, P)		ep_neg_basic(R, P)
#elif EP_ADD == PROJC
#define ep_neg(R, P)		ep_neg_projc(R, P)
#endif

/**
 * Adds two prime elliptic curve points.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first point to add.
 * @param[in] Q				- the second point to add.
 */
#if EP_ADD == BASIC
#define ep_add(R, P, Q)		ep_add_basic(R, P, Q);
#elif EP_ADD == PROJC
#define ep_add(R, P, Q)		ep_add_projc(R, P, Q);
#endif

/**
 * Subtracts a prime elliptic curve point from another, that is, compute
 * R = P - Q.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first point.
 * @param[in] Q				- the second point.
 */
#if EP_ADD == BASIC
#define ep_sub(R, P, Q)		ep_sub_basic(R, P, Q)
#elif EP_ADD == PROJC
#define ep_sub(R, P, Q)		ep_sub_projc(R, P, Q)
#endif

/**
 * Doubles a prime elliptic curve point.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the point to double.
 */
#if EP_ADD == BASIC
#define ep_dbl(R, P)		ep_dbl_basic(R, P);
#elif EP_ADD == PROJC
#define ep_dbl(R, P)		ep_dbl_projc(R, P);
#endif

/**
 * Multiplies a prime elliptic curve point by an integer. Computes R = kP.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the point to multiply.
 * @param[in] K				- the integer.
 */
#if EP_MUL == BASIC
#define ep_mul(R, P, K)		ep_mul_basic(R, P, K)
#elif EP_MUL == CONST
#define ep_mul(R, P, K)		ep_mul_const(R, P, K)
#elif EP_MUL == SLIDE
#define ep_mul(R, P, K)		ep_mul_slide(R, P, K)
#elif EP_MUL == WTNAF
#define ep_mul(R, P, K)		ep_mul_wtnaf(R, P, K)
#endif

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * point.
 *
 * @param[out] T			- the precomputation table.
 * @param[in] P				- the point to multiply.
 */
#if EP_FIX == BASIC
#define ep_mul_pre(T, P)		ep_mul_pre_basic(T, P)
#elif EP_FIX == YAOWI
#define ep_mul_pre(T, P)		ep_mul_pre_yaowi(T, P)
#elif EP_FIX == NAFWI
#define ep_mul_pre(T, P)		ep_mul_pre_nafwi(T, P)
#elif EP_FIX == COMBS
#define ep_mul_pre(T, P)		ep_mul_pre_combs(T, P)
#elif EP_FIX == COMBD
#define ep_mul_pre(T, P)		ep_mul_pre_combd(T, P)
#elif EP_FIX == WTNAF
#define ep_mul_pre(T, P)		ep_mul_pre_wtnaf(T, P)
#endif

/**
 * Multiplies a fixed prime elliptic point using a precomputation table.
 * Computes R = kP.
 *
 * @param[out] R			- the result.
 * @param[in] T				- the precomputation table.
 * @param[in] K				- the integer.
 */
#if EP_FIX == BASIC
#define ep_mul_fix(R, T, K)		ep_mul_fix_basic(R, T, K)
#elif EP_FIX == YAOWI
#define ep_mul_fix(R, T, K)		ep_mul_fix_yaowi(R, T, K)
#elif EP_FIX == NAFWI
#define ep_mul_fix(R, T, K)		ep_mul_fix_nafwi(R, T, K)
#elif EP_FIX == COMBS
#define ep_mul_fix(R, T, K)		ep_mul_fix_combs(R, T, K)
#elif EP_FIX == COMBD
#define ep_mul_fix(R, T, K)		ep_mul_fix_combd(R, T, K)
#elif EP_FIX == WTNAF
#define ep_mul_fix(R, T, K)		ep_mul_fix_wtnaf(R, T, K)
#endif

/**
 * Multiplies and adds two prime elliptic curve points simultaneously. Computes
 * R = kP + lQ.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first point to multiply.
 * @param[in] K				- the first integer.
 * @param[in] Q				- the second point to multiply.
 * @param[in] L				- the second integer,
 */
#if EP_SIM == BASIC
#define ep_mul_sim(R, P, K, Q, L)	ep_mul_sim_basic(R, P, K, Q, L)
#elif EP_SIM == TRICK
#define ep_mul_sim(R, P, K, Q, L)	ep_mul_sim_trick(R, P, K, Q, L)
#elif EP_SIM == INTER
#define ep_mul_sim(R, P, K, Q, L)	ep_mul_sim_inter(R, P, K, Q, L)
#elif EP_SIM == JOINT
#define ep_mul_sim(R, P, K, Q, L)	ep_mul_sim_joint(R, P, K, Q, L)
#endif

/**
 * Renames elliptic curve arithmetic operations to build precomputation
 * tables with the right coordinate system.
 */
#if defined(EP_MIXED)
/** @{ */
#define ep_add_tab			ep_add_basic
#define ep_sub_tab			ep_sub_basic
#define ep_neg_tab			ep_neg_basic
#define ep_dbl_tab			ep_dbl_basic
/** @} */
#else
/**@{ */
#define ep_add_tab			ep_add
#define ep_sub_tab			ep_sub
#define ep_neg_tab			ep_neg
#define ep_dbl_tab			ep_dbl
#define ep_frb_tab			ep_frb
/** @} */
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the prime elliptic curve arithmetic module.
 */
void ep_curve_init(void);

/**
 * Finalizes the prime elliptic curve arithmetic module.
 */
void ep_curve_clean(void);

/**
 * Returns the a coefficient of the currently configured prime elliptic curve.
 *
 * @return the a coefficient of the elliptic curve.
 */
dig_t *ep_curve_get_a(void);

/**
 * Returns the b coefficient of the currently configured prime elliptic curve.
 *
 * @return the b coefficient of the elliptic curve.
 */
dig_t *ep_curve_get_b(void);

/**
 * Returns a optimization identifier based on the coefficient a of the curve.
 *
 * @return the optimization identifier.
 */
int ep_curve_opt_a(void);

/**
 * Tests if the configured prime elliptic curve is supersingular.
 *
 * @return 1 if the prime elliptic curve is supersingular, 0 otherwise.
 */
int ep_curve_is_super(void);

/**
 * Returns the generator of the group of points in the prime elliptic curve.
 *
 * @param[out] g			- the returned generator.
 */
void ep_curve_get_gen(ep_t g);

/**
 * Returns the precomputation table for the generator.
 *
 * @return the table.
 */
ep_t *ep_curve_get_tab(void);

/**
 * Returns the order of the group of points in the prime elliptic curve.
 *
 * @param[out] r			- the returned order.
 */
void ep_curve_get_ord(bn_t n);

/**
 * Returns the parameter identifier of the currently configured prime elliptic
 * curve.
 *
 * @return the parameter identifier.
 */
int ep_param_get(void);

/**
 * Configures a new ordinary prime elliptic curve by its coefficients.
 *
 * @param[in] a			- the coefficient a of the curve.
 * @param[in] b			- the coefficient b of the curve.
 * @param[in] g			- the generator.
 * @param[in] r			- the order of the group of points.
 */
void ep_curve_set_ordin(fp_t a, fp_t b, ep_t g, bn_t r);

/**
 * Configures a new pairing-friendly prime elliptic curve by its coefficients.
 *
 * @param[in] a			- the coefficient a of the curve.
 * @param[in] b			- the coefficient b of the curve.
 * @param[in] g			- the generator.
 * @param[in] r			- the order of the group of points.
 */
void ep_curve_set_pairf(fp_t a, fp_t b, ep_t g, bn_t r);

/**
 * Configures a new prime elliptic curve by its parameter identifier.
 *
 * @param				- the parameter identifier.
 */
void ep_param_set(int param);

/**
 * Configures some set of curve parameters for the current security level.
 */
int ep_param_set_any(void);

/**
 * Configures some set of ordinary curve parameters for the current security
 * level.
 *
 * @return STS_OK if there is a curve at this security level, STS_ERR otherwise.
 */
int ep_param_set_any_ordin(void);

/**
 * Configures some set of pairing-friendly curve parameters for the current
 * security level.
 *
 * @return STS_OK if there is a curve at this security level, STS_ERR otherwise.
 */
int ep_param_set_any_pairf(void);

/**
 * Prints the current configured prime elliptic curve.
 */
void ep_param_print(void);

/**
 * Initializes a previously allocated prime elliptic curve point.
 *
 * @param[out] a			- the point to initialize.
 * @param[in] digits		- the required precision in digits.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 * @throw ERR_PRECISION		- if the required precision cannot be represented
 * 							by the library.
 */
void ep_init(ep_t a);

/**
 * Cleans an prime elliptic curve point..
 *
 * @param[out] a			- the point to free.
 */
void ep_clean(ep_t a);

/**
 * Tests if a point on a prime elliptic curve is at the infinity.
 *
 * @param[in] p				- the point to test.
 * @return 1 if the point is at infinity, 0 otherise.
 */
int ep_is_infty(ep_t p);

/**
 * Assigns a prime elliptic curve point to a point at the infinity.
 *
 * @param[out] p			- the point to assign.
 */
void ep_set_infty(ep_t p);

/**
 * Copies the second argument to the first argument.
 *
 * @param[out] q			- the result.
 * @param[in] p				- the prime elliptic curve point to copy.
 */
void ep_copy(ep_t r, ep_t p);

/**
 * Compares two prime elliptic curve points.
 *
 * @param[in] p				- the first prime elliptic curve point.
 * @param[in] q				- the second prime elliptic curve point.
 * @return CMP_EQ if p == q and CMP_NE if p != q.
 */
int ep_cmp(ep_t p, ep_t q);

/**
 * Assigns a random value to a prime elliptic curve point.
 *
 * @param[out] p			- the prime elliptic curve point to assign.
 */
void ep_rand(ep_t p);

/**
 * Prints a prime elliptic curve point.
 *
 * @param[in] p				- the prime elliptic curve point to print.
 */
void ep_print(ep_t p);

/**
 * Negates a prime elliptic curve point represented by affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to negate.
 */
void ep_neg_basic(ep_t r, ep_t p);

/**
 * Negates a prime elliptic curve point represented by projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to negate.
 */
void ep_neg_projc(ep_t r, ep_t p);

/**
 * Adds two prime elliptic curve points represented in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
void ep_add_basic(ep_t r, ep_t p, ep_t q);

/**
 * Adds two prime elliptic curve points represented in projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
void ep_add_projc(ep_t r, ep_t p, ep_t q);

/**
 * Subtracts a prime elliptic curve point from another, both points represented
 * by affine coordinates..
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point.
 * @param[in] q				- the second point.
 */
void ep_sub_basic(ep_t r, ep_t p, ep_t q);

/**
 * Subtracts a prime elliptic curve point from another, both points represented
 * by projective coordinates..
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point.
 * @param[in] q				- the second point.
 */
void ep_sub_projc(ep_t r, ep_t p, ep_t q);

/**
 * Doubles a prime elliptic curve point represented in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double.
 */
void ep_dbl_basic(ep_t r, ep_t p);

/**
 * Doubles a prime elliptic curve point represented in projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double.
 */
void ep_dbl_projc(ep_t r, ep_t p);

/**
 * Multiplies a prime elliptic point by an integer using the binary method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ep_mul_basic(ep_t r, ep_t p, bn_t k);

/**
 * Multiplies a prime elliptic point by an integer using the constant-time
 * L�pez-Dahab point multiplication method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ep_mul_const(ep_t r, ep_t p, bn_t k);

/**
 * Multiplies a prime elliptic point by an integer using the sliding window
 * method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ep_mul_slide(ep_t r, ep_t p, bn_t k);

/**
 * Multiplies a prime elliptic point by an integer using the w-NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ep_mul_wtnaf(ep_t r, ep_t p, bn_t k);

/**
 * Multiplies the generator of a prime elliptic curve by an integer.
 *
 * @param[out] r			- the result.
 * @param[in] k				- the integer.
 */
void ep_mul_gen(ep_t r, bn_t k);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using the binary method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_basic(ep_t *t, ep_t p);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using Yao's windowing method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_yaowi(ep_t *t, ep_t p);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using the NAF windowing method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_nafwi(ep_t *t, ep_t p);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using the single-table comb method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_combs(ep_t *t, ep_t p);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using the double-table comb method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_combd(ep_t *t, ep_t p);

/**
 * Builds a precomputation table for multiplying a fixed prime elliptic curve
 * using the w-(T)NAF method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ep_mul_pre_wtnaf(ep_t *t, ep_t p);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * the binary method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_basic(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * Yao's windowing method
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_yaowi(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * the w-(T)NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_nafwi(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * the single-table comb method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_combs(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * the double-table comb method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_combd(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies a fixed prime elliptic point using a precomputation table and
 * the w-(T)NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ep_mul_fix_wtnaf(ep_t r, ep_t *t, bn_t k);

/**
 * Multiplies and adds two prime elliptic curve points simultaneously using
 * scalar multiplication and point addition.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to multiply.
 * @param[in] k				- the first integer.
 * @param[in] q				- the second point to multiply.
 * @param[in] l				- the second integer,
 */
void ep_mul_sim_basic(ep_t r, ep_t p, bn_t k, ep_t q, bn_t l);

/**
 * Multiplies and adds two prime elliptic curve points simultaneously using
 * shamir's trick.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to multiply.
 * @param[in] k				- the first integer.
 * @param[in] q				- the second point to multiply.
 * @param[in] l				- the second integer,
 */
void ep_mul_sim_trick(ep_t r, ep_t p, bn_t k, ep_t q, bn_t l);

/**
 * Multiplies and adds two prime elliptic curve points simultaneously using
 * interleaving of NAFs.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to multiply.
 * @param[in] k				- the first integer.
 * @param[in] q				- the second point to multiply.
 * @param[in] l				- the second integer,
 */
void ep_mul_sim_inter(ep_t r, ep_t p, bn_t k, ep_t q, bn_t l);

/**
 * Multiplies and adds two prime elliptic curve points simultaneously using
 * Solinas' Joint Sparse Form.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to multiply.
 * @param[in] k				- the first integer.
 * @param[in] q				- the second point to multiply.
 * @param[in] l				- the second integer,
 */
void ep_mul_sim_joint(ep_t r, ep_t p, bn_t k, ep_t q, bn_t l);

/**
 * Multiplies and adds the generator and a prime elliptic curve point
 * simultaneously. Computes R = kG + lQ.
 *
 * @param[out] r			- the result.
 * @param[in] k				- the first integer.
 * @param[in] q				- the second point to multiply.
 * @param[in] l				- the second integer,
 */
void ep_mul_sim_gen(ep_t r, bn_t k, ep_t q, bn_t l);

/**
 * Converts a point to affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to convert.
 */
void ep_norm(ep_t r, ep_t p);

/**
 * Maps a byte array to a point in a prime elliptic curve.
 *
 * @param[out] p			- the result.
 * @param[in] msg			- the byte array to map.
 * @param[in] len			- the array length in bytes.
 */
void ep_map(ep_t p, unsigned char *msg, int len);

#endif /* !RELIC_EP_H */
