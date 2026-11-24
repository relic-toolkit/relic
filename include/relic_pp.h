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
 * @defgroup pp Bilinear pairings over prime elliptic curves.
 */

/**
 * @file
 *
 * Interface of the module for computing bilinear pairings over prime elliptic
 * curves.
 *
 * @ingroup pp
 */

#ifndef RLC_PP_H
#define RLC_PP_H

#include "relic_fpx.h"
#include "relic_epx.h"
#include "relic_types.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Bounds the length in bits of the parameter of the optimal ate Miller loop
 * for each embedding degree, as the parameters of the supported families
 * have about 1/8, 1/4 (the 6x + 2 of BN curves), 1/10, 1/8, 1/10, 1/18 and
 * 1/20 of the bits of the prime for K = 8, 12, 16, 18, 24, 48 and 54.
 */
/** @{ */
#define RLC_PP_BITS_K8		(RLC_FP_BITS / 8 + 4)
#define RLC_PP_BITS_K12		(RLC_FP_BITS / 4 + 4)
#define RLC_PP_BITS_K16		(RLC_FP_BITS / 10 + 4)
#define RLC_PP_BITS_K18		(RLC_FP_BITS / 8 + 4)
#define RLC_PP_BITS_K24		(RLC_FP_BITS / 10 + 4)
#define RLC_PP_BITS_K48		(RLC_FP_BITS / 18 + 4)
#define RLC_PP_BITS_K54		(RLC_FP_BITS / 20 + 4)
/** @} */

/**
 * Number of twist field elements in the table of a fixed argument for a
 * Miller loop parameter of B bits: two per line, for a doubling per bit, an
 * addition per nonzero digit of the NAF and up to three final lines.
 *
 * @param[in] B			- the bound on the bits of the loop parameter.
 */
#define RLC_PP_TABLE(B)		(2 * ((B) + ((B) + 1) / 2 + 3))

/**
 * Number of twist field elements in the table of a fixed argument for each
 * embedding degree.
 */
/** @{ */
#define RLC_PP_TABLE_K8		RLC_PP_TABLE(RLC_PP_BITS_K8)
#define RLC_PP_TABLE_K12	RLC_PP_TABLE(RLC_PP_BITS_K12)
#define RLC_PP_TABLE_K16	RLC_PP_TABLE(RLC_PP_BITS_K16)
#define RLC_PP_TABLE_K18	RLC_PP_TABLE(RLC_PP_BITS_K18)
#define RLC_PP_TABLE_K24	RLC_PP_TABLE(RLC_PP_BITS_K24)
#define RLC_PP_TABLE_K48	RLC_PP_TABLE(RLC_PP_BITS_K48)
#define RLC_PP_TABLE_K54	RLC_PP_TABLE(RLC_PP_BITS_K54)
/** @} */

/**
 * Bounds the length in bits of the order of the curve with embedding degree 1,
 * the loop parameter of its Tate pairing, which has about 1/12 of the bits of
 * the prime.
 */
#define RLC_PP_BITS_K1		(RLC_FP_BITS / 12 + 4)

/**
 * Number of prime field elements in the table of a fixed argument for
 * embedding degree 1: the three coefficients of the numerator and the two of
 * the denominator of each line, and the point itself.
 */
#define RLC_PP_TABLE_K1														\
	(5 * (RLC_PP_BITS_K1 + (RLC_PP_BITS_K1 + 1) / 2) + 2)

/**
 * Bounds the length in bits of the order of the supersingular curve with
 * embedding degree 2, the loop parameter of its Tate pairing, which has about
 * 1/6 of the bits of the prime.
 */
#define RLC_PP_BITS_K2		(RLC_FP_BITS / 6 + 4)

/**
 * Number of prime field elements in the table of a fixed argument for
 * embedding degree 2: two per line.
 */
#define RLC_PP_TABLE_K2		RLC_PP_TABLE(RLC_PP_BITS_K2)

/**
 * Bounds the length in bits of the loop parameter of the eta_d pairing for
 * embedding degree 3 over Fp^4, which has about 1/5 of the bits of the prime.
 */
#define RLC_PP_BITS_K3		(RLC_FP_BITS / 5 + 4)

/**
 * Number of elements of Fp^4 in the table of a fixed argument for embedding
 * degree 3: three per doubling and addition, and the point itself.
 */
#define RLC_PP_TABLE_K3														\
	(3 * (RLC_PP_BITS_K3 + (RLC_PP_BITS_K3 + 1) / 2) + 2)

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1.
 *
 * @param[out] L			- the numerator of the result of the evaluation.
 * @param[out] M			- the denominator of the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] P				- the second point to add.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k1(L, M, R, P, Q)	pp_add_k1_basic(L, M, R, P, Q)
#else
#define pp_add_k1(L, M, R, P, Q)	pp_add_k1_projc(L, M, R, P, Q)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] P				- the second point to add.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k2_projc(L, R, P, Q)	pp_add_k2_projc_basic(L, R, P, Q)
#else
#define pp_add_k2_projc(L, R, P, Q)	pp_add_k2_projc_lazyr(L, R, P, Q)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] P				- the second point to add.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k2(L, R, P, Q)		pp_add_k2_basic(L, R, P, Q)
#else
#define pp_add_k2(L, R, P, Q)		pp_add_k2_projc(L, R, P, Q)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k8_projc(L, R, Q, P)	pp_add_k8_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k8_projc(L, R, Q, P)	pp_add_k8_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k8(L, R, Q, P)		pp_add_k8_basic(L, R, Q, P)
#else
#define pp_add_k8(L, R, Q, P)		pp_add_k8_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k12_projc(L, R, Q, P)	pp_add_k12_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k12_projc(L, R, Q, P)	pp_add_k12_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k12(L, R, Q, P)		pp_add_k12_basic(L, R, Q, P)
#else
#define pp_add_k12(L, R, Q, P)		pp_add_k12_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k16_projc(L, R, Q, P)	pp_add_k16_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k16_projc(L, R, Q, P)	pp_add_k16_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k16(L, R, Q, P)		pp_add_k16_basic(L, R, Q, P)
#else
#define pp_add_k16(L, R, Q, P)		pp_add_k16_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k18_projc(L, R, Q, P)	pp_add_k18_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k18_projc(L, R, Q, P)	pp_add_k18_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k18(L, R, Q, P)		pp_add_k18_basic(L, R, Q, P)
#else
#define pp_add_k18(L, R, Q, P)		pp_add_k18_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k24_projc(L, R, Q, P)	pp_add_k24_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k24_projc(L, R, Q, P)	pp_add_k24_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k24(L, R, Q, P)		pp_add_k24_basic(L, R, Q, P)
#else
#define pp_add_k24(L, R, Q, P)		pp_add_k24_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k48_projc(L, R, Q, P)	pp_add_k48_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k48_projc(L, R, Q, P)	pp_add_k48_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k48(L, R, Q, P)	        pp_add_k48_basic(L, R, Q, P)
#else
#define pp_add_k48(L, R, Q, P)	        pp_add_k48_projc(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_add_k54_projc(L, R, Q, P)	pp_add_k54_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_add_k54_projc(L, R, Q, P)	pp_add_k54_projc_lazyr(L, R, Q, P)
#endif

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point and first point to add.
 * @param[in] Q				- the second point to add.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_add_k54(L, R, Q, P)		pp_add_k54_basic(L, R, Q, P)
#else
#define pp_add_k54(L, R, Q, P)		pp_add_k54_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1.
 *
 * @param[out] L			- the numerator of the result of the evaluation.
 * @param[out] M			- the denominator of the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[out] W			- the extended coordinate of the resulting point.
 * @param[in] P				- the point to double.
 * @param[in] V				- the extended coordinate of the point to double.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k1(L, M, R, W, P, V, Q)	pp_dbl_k1_basic(L, M, R, P, Q)
#else
#define pp_dbl_k1(L, M, R, W, P, V, Q)	pp_dbl_k1_projc(L, M, R, W, P, V, Q)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k2_projc(L, R, P, Q)	pp_dbl_k2_projc_basic(L, R, P, Q)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k2_projc(L, R, P, Q)	pp_dbl_k2_projc_lazyr(L, R, P, Q)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] P				- the point to double.
 * @param[in] Q				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k2(L, R, P, Q)		pp_dbl_k2_basic(L, R, P, Q)
#else
#define pp_dbl_k2(L, R, P, Q)		pp_dbl_k2_projc(L, R, P, Q)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k8(L, R, Q, P)		pp_dbl_k8_basic(L, R, Q, P)
#else
#define pp_dbl_k8(L, R, Q, P)		pp_dbl_k8_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k12_projc(L, R, Q, P)	pp_dbl_k12_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k12_projc(L, R, Q, P)	pp_dbl_k12_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k12(L, R, Q, P)		pp_dbl_k12_basic(L, R, Q, P)
#else
#define pp_dbl_k12(L, R, Q, P)		pp_dbl_k12_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k16(L, R, Q, P)		pp_dbl_k16_basic(L, R, Q, P)
#else
#define pp_dbl_k16(L, R, Q, P)		pp_dbl_k16_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k18_projc(L, R, Q, P)	pp_dbl_k18_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k18_projc(L, R, Q, P)	pp_dbl_k18_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k18(L, R, Q, P)		pp_dbl_k18_basic(L, R, Q, P)
#else
#define pp_dbl_k18(L, R, Q, P)		pp_dbl_k18_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k24_projc(L, R, Q, P)	pp_dbl_k24_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k24_projc(L, R, Q, P)	pp_dbl_k24_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k24(L, R, Q, P)		pp_dbl_k24_basic(L, R, Q, P)
#else
#define pp_dbl_k24(L, R, Q, P)		pp_dbl_k24_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k48_projc(L, R, Q, P)	pp_dbl_k48_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k48_projc(L, R, Q, P)	pp_dbl_k48_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k48(L, R, Q, P)		pp_dbl_k48_basic(L, R, Q, P)
#else
#define pp_dbl_k48(L, R, Q, P)		pp_dbl_k48_projc(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[in, out] R		- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if PP_EXT == PP_BASIC
#define pp_dbl_k54_projc(L, R, Q, P)	pp_dbl_k54_projc_basic(L, R, Q, P)
#elif PP_EXT == PP_LAZYR
#define pp_dbl_k54_projc(L, R, Q, P)	pp_dbl_k54_projc_lazyr(L, R, Q, P)
#endif

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54.
 *
 * @param[out] L			- the result of the evaluation.
 * @param[out] R			- the resulting point.
 * @param[in] Q				- the point to double.
 * @param[in] P				- the affine point to evaluate the line function.
 */
#if EP_ADD == EP_BASIC
#define pp_dbl_k54(L, R, Q, P)		pp_dbl_k54_basic(L, R, Q, P)
#else
#define pp_dbl_k54(L, R, Q, P)		pp_dbl_k54_projc(L, R, Q, P)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curves of embedding degree 1. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP || PP_MAP == PP_OATEP
#define pp_map_k1(R, P, Q)		pp_map_tatep_k1(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k1(R, P, Q)		pp_map_weilp_k1(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curves of embedding degree 2. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP || PP_MAP == PP_OATEP
#define pp_map_k2(R, P, Q)		pp_map_tatep_k2(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k2(R, P, Q)		pp_map_weilp_k2(R, P, Q)
#endif

/**
 * Computes a pairing of two points on a supersingular curve over Fp^4 of
 * embedding degree 3. Computes e(P, Q). Only the optimal eta_d pairing is
 * available, so it is used for every choice of pairing.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#define pp_map_k3(R, P, Q)		pp_map_oatep_k3(R, P, Q)

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 8. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k8(R, P, Q)		pp_map_tatep_k8(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k8(R, P, Q)		pp_map_weilp_k8(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k8(R, P, Q)		pp_map_oatep_k8(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 12. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k12(R, P, Q)		pp_map_tatep_k12(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k12(R, P, Q)		pp_map_weilp_k12(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k12(R, P, Q)		pp_map_oatep_k12(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 16. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k16(R, P, Q)		pp_map_tatep_k16(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k16(R, P, Q)		pp_map_weilp_k16(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k16(R, P, Q)		pp_map_oatep_k16(R, P, Q)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 18. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k18(R, P, Q)		pp_map_tatep_k18(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k18(R, P, Q)		pp_map_weilp_k18(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k18(R, P, Q)		pp_map_oatep_k18(R, P, Q)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 1. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_WEILP
#define pp_map_sim_k1(R, P, Q, M)	pp_map_sim_weilp_k1(R, P, Q, M)
#elif PP_MAP == PP_TATEP || PP_MAP == PP_OATEP
#define pp_map_sim_k1(R, P, Q, M)	pp_map_sim_tatep_k1(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 2. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_WEILP
#define pp_map_sim_k2(R, P, Q, M)	pp_map_sim_weilp_k2(R, P, Q, M)
#elif PP_MAP == PP_TATEP || PP_MAP == PP_OATEP
#define pp_map_sim_k2(R, P, Q, M)	pp_map_sim_tatep_k2(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of points on a supersingular curve over Fp^4 of
 * embedding degree 3. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#define pp_map_sim_k3(R, P, Q, M)	pp_map_sim_oatep_k3(R, P, Q, M)

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 8. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k8(R, P, Q, M)	pp_map_sim_tatep_k8(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k8(R, P, Q, M)	pp_map_sim_weilp_k8(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k8(R, P, Q, M)	pp_map_sim_oatep_k8(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 12. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k12(R, P, Q, M)	pp_map_sim_tatep_k12(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k12(R, P, Q, M)	pp_map_sim_weilp_k12(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k12(R, P, Q, M)	pp_map_sim_oatep_k12(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 16. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k16(R, P, Q, M)	pp_map_sim_tatep_k16(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k16(R, P, Q, M)	pp_map_sim_weilp_k16(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k16(R, P, Q, M)	pp_map_sim_oatep_k16(R, P, Q, M)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 18. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k18(R, P, Q, M)	pp_map_sim_tatep_k18(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k18(R, P, Q, M)	pp_map_sim_weilp_k18(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k18(R, P, Q, M)	pp_map_sim_oatep_k18(R, P, Q, M)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 24. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k24(R, P, Q)		pp_map_tatep_k24(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k24(R, P, Q)		pp_map_weilp_k24(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k24(R, P, Q)		pp_map_oatep_k24(R, P, Q)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 24. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k24(R, P, Q, M)	pp_map_sim_tatep_k24(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k24(R, P, Q, M)	pp_map_sim_weilp_k24(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k24(R, P, Q, M)	pp_map_sim_oatep_k24(R, P, Q, M)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 48. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k48(R, P, Q)		pp_map_tatep_k48(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k48(R, P, Q)		pp_map_weilp_k48(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k48(R, P, Q)		pp_map_oatep_k48(R, P, Q)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 48. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k48(R, P, Q, M)	pp_map_sim_tatep_k48(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k48(R, P, Q, M)	pp_map_sim_weilp_k48(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k48(R, P, Q, M)	pp_map_sim_oatep_k48(R, P, Q, M)
#endif

/**
 * Computes a pairing of two prime elliptic curve points defined on an elliptic
 * curve of embedding degree 54. Computes e(P, Q).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first elliptic curve point.
 * @param[in] Q				- the second elliptic curve point.
 */
#if PP_MAP == PP_TATEP
#define pp_map_k54(R, P, Q)		pp_map_tatep_k54(R, P, Q)
#elif PP_MAP == PP_WEILP
#define pp_map_k54(R, P, Q)		pp_map_weilp_k54(R, P, Q)
#elif PP_MAP == PP_OATEP
#define pp_map_k54(R, P, Q)		pp_map_oatep_k54(R, P, Q)
#endif

/**
 * Computes a multi-pairing of elliptic curve points defined on an elliptic
 * curve of embedding degree 54. Computes \prod e(P_i, Q_i).
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first pairing arguments.
 * @param[in] Q				- the second pairing arguments.
 * @param[in] M 			- the number of pairings to evaluate.
 */
#if PP_MAP == PP_TATEP
#define pp_map_sim_k54(R, P, Q, M)	pp_map_sim_tatep_k54(R, P, Q, M)
#elif PP_MAP == PP_WEILP
#define pp_map_sim_k54(R, P, Q, M)	pp_map_sim_weilp_k54(R, P, Q, M)
#elif PP_MAP == PP_OATEP
#define pp_map_sim_k54(R, P, Q, M)	pp_map_sim_oatep_k54(R, P, Q, M)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the pairing over prime fields.
 */
void pp_map_init(void);

/**
 * Finalizes the pairing over prime fields.
 */
void pp_map_clean(void);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1 using affine coordinates.
 *
 * @param[out] l			- the numerator of the result of the evaluation.
 * @param[out] m			- the denominator of the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1 using projective
 * coordinates.
 *
 * @param[out] l			- the numerator of the result of the evaluation.
 * @param[out] m			- the denominator of the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k1_projc(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_projc_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k8_projc_lazyr(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 8, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k8(fp8_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_projc_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k12_projc_lazyr(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k12(fp12_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k16_projc_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k16_projc_lazyr(fp16_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 16 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_projc_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k18(fp18_t l, ep_t r, const ep_t p, const ep3_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k24_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k24_projc_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k24_projc_lazyr(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Adds two points of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 24, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k24(fp24_t l, ep_t r, const ep_t p, const ep4_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k48_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k48_projc_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k48_projc_lazyr(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Adds two points of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 48, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k48(fp48_t l, ep_t r, const ep_t p, const ep8_t q);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using affine coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k54_basic(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k54_projc_basic(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Adds two points and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] q				- the second point to add.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_add_k54_projc_lazyr(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Adds two points of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 54, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point and first point to add.
 * @param[in] p				- the second point to add.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_add_lit_k54(fp54_t l, ep_t r, const ep_t p, const ep9_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1 using affine
 * coordinates.
 *
 * @param[out] l			- the numerator of the result of the evaluation.
 * @param[out] m			- the denominator of the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 1 using projective
 * coordinates.
 *
 * @param[out] l			- the numerator of the result of the evaluation.
 * @param[out] m			- the denominator of the result of the evaluation.
 * @param[out] r			- the resulting point.
 * @param[out] w			- the extended coordinate of the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] v				- the extended coordinate of the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k1_projc(fp_t l, fp_t m, ep_t r, fp_t w, const ep_t p, const fp_t v,
	const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 2 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k8_basic(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 8 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k8_projc(fp8_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 8, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k8(fp8_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_projc_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 12 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k12_projc_lazyr(fp12_t l, ep2_t r, const ep2_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 16 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k16_projc(fp16_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_projc_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 18 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k24_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k24_projc_basic(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 24 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k24_projc_lazyr(fp24_t l, ep4_t r, const ep4_t q, const ep_t p);

/**
 * Doubles a point of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 24, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k24(fp24_t l, ep_t r, const ep_t p, const ep4_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k48_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k48_projc_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 48 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k48_projc_lazyr(fp48_t l, ep8_t r, const ep8_t q, const ep_t p);

/**
 * Doubles a point of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 48, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k48(fp48_t l, ep_t r, const ep_t p, const ep8_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using affine
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k54_basic(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k54_projc_basic(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve with embedding degree 54 using projective
 * coordinates and lazy reduction.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] q				- the point to double.
 * @param[in] p				- the affine point to evaluate the line function.
 */
void pp_dbl_k54_projc_lazyr(fp54_t l, ep9_t r, const ep9_t q, const ep_t p);

/**
 * Doubles a point of G_1 and evaluates the corresponding line function at a
 * point of the twist of a curve with embedding degree 54, using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k54(fp54_t l, ep_t r, const ep_t p, const ep9_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 12 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k12(fp12_t l, ep_t r, const ep_t p, const ep2_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 16 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q);

/**
 * Doubles a point and evaluates the corresponding line function at another
 * point on an elliptic curve twist with embedding degree 18 using projective
 * coordinates.
 *
 * @param[out] l			- the result of the evaluation.
 * @param[in, out] r		- the resulting point.
 * @param[in] p				- the point to double.
 * @param[in] q				- the affine point to evaluate the line function.
 */
void pp_dbl_lit_k18(fp18_t l, ep_t r, const ep_t p, const ep3_t q);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 1. Computes c = a^(p - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k1(fp_t c, fp_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 2. Computes c = a^(p^2 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k2(fp2_t c, fp2_t a);

/**
 * Computes the final exponentiation for a pairing defined over a
 * supersingular curve over Fp^4 of embedding degree 3. Computes
 * c = a^((p^12 - 1)/r).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k3(fp12_t c, fp12_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 8. Computes c = a^(p^8 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k8(fp8_t c, fp8_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 12. Computes c = a^(p^12 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k12(fp12_t c, fp12_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 16. Computes c = a^(p^16 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k16(fp16_t c, fp16_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 18. Computes c = a^(p^18 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k18(fp18_t c, fp18_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 24. Computes c = a^(p^24 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k24(fp24_t c, fp24_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 48. Computes c = a^(p^48 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k48(fp48_t c, fp48_t a);

/**
 * Computes the final exponentiation for a pairing defined over curves of
 * embedding degree 54. Computes c = a^(p^54 - 1)/r.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
void pp_exp_k54(fp54_t c, fp54_t a);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 1.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k1(ep_t r, const ep_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 2.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k2(ep_t r, const ep_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 8.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k8(ep2_t r, const ep2_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 12.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k12(ep2_t r, const ep2_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 16.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k16(ep4_t r, const ep4_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 18.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k18(ep3_t r, const ep3_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 24.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k24(ep4_t r, const ep4_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 48.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k48(ep8_t r, const ep8_t p);

/**
 * Normalizes the accumulator point used inside pairing computation defined
 * over curves of embedding degree 54.
 *
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to normalize.
 */
void pp_norm_k54(ep9_t r, const ep9_t p);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 1.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k1(fp_t r, const ep_t p, const ep_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 1.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k1(fp_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k2(fp2_t r, const ep_t p, const ep_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k2(fp2_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Computes the optimal eta_d pairing of two points on a supersingular curve
 * over Fp^4 of embedding degree 3. Computes e(P, Q).
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_oatep_k3(fp12_t r, const ep4_t p, const ep4_t q);

/**
 * Computes the optimal eta_d multi-pairing of points on a supersingular curve
 * over Fp^4 of embedding degree 3. Computes \prod e(P_i, Q_i).
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k3(fp12_t r, const ep4_t *p, const ep4_t *q, int m);

/**
 * Precomputes the Miller loop of the eta_d pairing for a fixed point in a
 * supersingular curve with embedding degree 3 over Fp^4. As the pairing is
 * symmetric, the loop runs over the fixed point, keeping three values per
 * step that the lines need.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K3 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k3(fp4_t *t, const ep4_t q);

/**
 * Computes the eta_d pairing in a supersingular curve with embedding degree 3
 * over Fp^4, with the second argument fixed by pp_map_pre_k3().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first argument.
 * @param[in] t				- the table of the fixed argument.
 */
void pp_map_fix_k3(fp12_t r, const ep4_t p, const fp4_t *t);

/**
 * Computes a product of eta_d pairings in a supersingular curve with
 * embedding degree 3 over Fp^4, where the last n pairs have their second
 * argument fixed by pp_map_pre_k3(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed argument Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first arguments of the other pairs.
 * @param[in] q				- the second arguments of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the first arguments of the fixed pairs.
 * @param[in] t				- the tables of the fixed second arguments.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k3(fp12_t r, const ep4_t *p, const ep4_t *q, int m,
		const ep4_t *s, const fp4_t **t, int n);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 1.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k1(fp_t r, const ep_t p, const ep_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 1.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k1(fp_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Precomputes the Miller loop of the Tate pairing for a fixed point in a
 * curve with embedding degree 1. As the pairing is symmetric, the loop runs
 * over the fixed point, keeping the exact numerator and denominator of each
 * line, since the final exponentiation does not remove factors in Fp.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K1 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k1(fp_t *t, const ep_t q);

/**
 * Computes the Tate pairing in a curve with embedding degree 1, with the
 * second argument fixed by pp_map_pre_k1().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first argument.
 * @param[in] t				- the table of the fixed argument.
 */
void pp_map_fix_k1(fp_t r, const ep_t p, const fp_t *t);

/**
 * Computes a product of Tate pairings in a curve with embedding degree 1, where
 * the last n pairs have their second argument fixed by pp_map_pre_k1(),
 * sharing one Miller loop and the final exponentiation. Computes
 * r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ..., where t[i] is the table of the
 * fixed argument Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first arguments of the other pairs.
 * @param[in] q				- the second arguments of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the first arguments of the fixed pairs.
 * @param[in] t				- the tables of the fixed second arguments.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k1(fp_t r, const ep_t *p, const ep_t *q, int m,
		const ep_t *s, const fp_t **t, int n);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k2(fp2_t r, const ep_t p, const ep_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 2.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k2(fp2_t r, const ep_t *p, const ep_t *q, int m);

/**
 * Precomputes the Miller loop of the Tate pairing for a fixed point in a
 * supersingular curve with embedding degree 2. As the pairing is symmetric,
 * the loop runs over the fixed point, keeping two values per line.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K2 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k2(fp_t *t, const ep_t q);

/**
 * Computes the Tate pairing in a supersingular curve with embedding degree 2,
 * with the second argument fixed by pp_map_pre_k2().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first argument.
 * @param[in] t				- the table of the fixed argument.
 */
void pp_map_fix_k2(fp2_t r, const ep_t p, const fp_t *t);

/**
 * Computes a product of Tate pairings in a curve with embedding degree 2, where
 * the last n pairs have their second argument fixed by pp_map_pre_k2(),
 * sharing one Miller loop and the final exponentiation. Computes
 * r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ..., where t[i] is the table of the
 * fixed argument Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first arguments of the other pairs.
 * @param[in] q				- the second arguments of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the first arguments of the fixed pairs.
 * @param[in] t				- the tables of the fixed second arguments.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k2(fp2_t r, const ep_t *p, const ep_t *q, int m,
		const ep_t *s, const fp_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_tatep_k8(fp8_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k8(fp8_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_weilp_k8(fp8_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k8(fp8_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k8(fp8_t r, const ep_t p, const ep2_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic
 * curve with embedding degree 8.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k8(fp8_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 8, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K8 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k8(fp2_t *t, const ep2_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 8, with the first argument fixed by pp_map_pre_k8().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k8(fp8_t r, const ep_t p, const fp2_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 8, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k8(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k8(fp8_t r, const ep_t *p, const ep2_t *q, int m,
		const ep_t *s, const fp2_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k12(fp12_t r, const ep_t p, const ep2_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic
 * curve with embedding degree 12.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 12, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K12 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k12(fp2_t *t, const ep2_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 12, with the first argument fixed by pp_map_pre_k12().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k12(fp12_t r, const ep_t p, const fp2_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 12, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k12(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m,
		const ep_t *s, const fp2_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k16(fp16_t r, const ep_t p, const ep4_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k16(fp16_t r, const ep_t p, const ep4_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k16(fp16_t r, const ep_t p, const ep4_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic
 * curve with embedding degree 16.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 16, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K16 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k16(fp4_t *t, const ep4_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 16, with the first argument fixed by pp_map_pre_k16().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k16(fp16_t r, const ep_t p, const fp4_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 16, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k16(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m,
		const ep_t *s, const fp4_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_tatep_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_weilp_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first elliptic curve point.
 * @param[in] p				- the second elliptic curve point.
 */
void pp_map_oatep_k18(fp18_t r, const ep_t p, const ep3_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic
 * curve with embedding degree 18.
 *
 * @param[out] r			- the result.
 * @param[in] q				- the first pairing arguments.
 * @param[in] p				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 18, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K18 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k18(fp3_t *t, const ep3_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 18, with the first argument fixed by pp_map_pre_k18().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k18(fp18_t r, const ep_t p, const fp3_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 18, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k18(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m,
		const ep_t *s, const fp3_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_tatep_k24(fp24_t r, const ep_t p, const ep4_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k24(fp24_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_weilp_k24(fp24_t r, const ep_t p, const ep4_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k24(fp24_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_oatep_k24(fp24_t r, const ep_t p, const ep4_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic curve with
 * embedding degree 24.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k24(fp24_t r, const ep_t *p, const ep4_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 24, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K24 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k24(fp4_t *t, const ep4_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 24, with the first argument fixed by pp_map_pre_k24().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k24(fp24_t r, const ep_t p, const fp4_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 24, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k24(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k24(fp24_t r, const ep_t *p, const ep4_t *q, int m,
		const ep_t *s, const fp4_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_tatep_k48(fp48_t r, const ep_t p, const ep8_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k48(fp48_t r, const ep_t *p, const ep8_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_weilp_k48(fp48_t r, const ep_t p, const ep8_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k48(fp48_t r, const ep_t *p, const ep8_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_oatep_k48(fp48_t r, const ep_t p, const ep8_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic curve with
 * embedding degree 48.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k48(fp48_t r, const ep_t *p, const ep8_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 48, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K48 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k48(fp8_t *t, const ep8_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 48, with the first argument fixed by pp_map_pre_k48().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k48(fp48_t r, const ep_t p, const fp8_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 48, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k48(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k48(fp48_t r, const ep_t *p, const ep8_t *q, int m,
		const ep_t *s, const fp8_t **t, int n);

/**
 * Computes the Tate pairing of two points in a parameterized elliptic curve
 * with embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_tatep_k54(fp54_t r, const ep_t p, const ep9_t q);

/**
 * Computes the Tate multi-pairing in a parameterized elliptic curve with
 * embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_tatep_k54(fp54_t r, const ep_t *p, const ep9_t *q, int m);

/**
 * Computes the Weil pairing of two points in a parameterized elliptic curve
 * with embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_weilp_k54(fp54_t r, const ep_t p, const ep9_t q);

/**
 * Computes the Weil multi-pairing in a parameterized elliptic curve with
 * embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_weilp_k54(fp54_t r, const ep_t *p, const ep9_t *q, int m);

/**
 * Computes the optimal ate pairing of two points in a parameterized elliptic
 * curve with embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first elliptic curve point.
 * @param[in] q				- the second elliptic curve point.
 */
void pp_map_oatep_k54(fp54_t r, const ep_t p, const ep9_t q);

/**
 * Computes the optimal ate multi-pairing in a parameterized elliptic curve with
 * embedding degree 54.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments.
 * @param[in] q				- the second pairing arguments.
 * @param[in] m 			- the number of pairings to evaluate.
 */
void pp_map_sim_oatep_k54(fp54_t r, const ep_t *p, const ep9_t *q, int m);

/**
 * Precomputes the lines of the optimal ate pairing for a fixed point of G_2 in
 * a parameterized elliptic curve with embedding degree 54, normalized so that
 * evaluating each at a point of G_1 takes a single multiplication in the twist
 * field.
 *
 * @param[out] t			- the table of RLC_PP_TABLE_K54 elements.
 * @param[in] q				- the fixed point.
 */
void pp_map_pre_k54(fp9_t *t, const ep9_t q);

/**
 * Computes the optimal ate pairing in a parameterized elliptic curve with
 * embedding degree 54, with the first argument fixed by pp_map_pre_k54().
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point of G_1.
 * @param[in] t				- the table of the fixed point of G_2.
 */
void pp_map_fix_k54(fp54_t r, const ep_t p, const fp9_t *t);

/**
 * Computes a product of optimal ate pairings in a parameterized elliptic curve
 * with embedding degree 54, where the last n pairs have their point of G_2
 * fixed by pp_map_pre_k54(), sharing one Miller loop and the final
 * exponentiation. Computes r = e(p[0], q[0]) * ... * e(s[0], Q_0) * ...,
 * where t[i] is the table of the fixed point Q_i.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the points of G_1 of the other pairs.
 * @param[in] q				- the points of G_2 of the other pairs.
 * @param[in] m				- the number of other pairs.
 * @param[in] s				- the points of G_1 of the fixed pairs.
 * @param[in] t				- the tables of the fixed points of G_2.
 * @param[in] n				- the number of fixed pairs.
 */
void pp_map_sim_fix_k54(fp54_t r, const ep_t *p, const ep9_t *q, int m,
		const ep_t *s, const fp9_t **t, int n);

#endif /* !RLC_PP_H */
