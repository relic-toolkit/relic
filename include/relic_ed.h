/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * @defgroup ed Edwards curves over Edwards fields
 */

/**
 * @file
 *
 * Interface of the module for arithmetic on elliptic twisted Edwards curves.
 *
 * @ingroup ed
 */

 #ifndef RLC_ED_H
 #define RLC_ED_H

#include "relic_fp.h"
#include "relic_bn.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Prime elliptic twisted Edwards curve identifiers.
 */
enum {
    /** ED25519 Edwards curve. */
    CURVE_ED25519 = 1
};

/*============================================================================*/
/* Precomputaion table                                                        */
/*============================================================================*/
/**
 * Size of a precomputation table using the binary method.
 */
#define RLC_ED_TABLE_BASIC    (RLC_FP_BITS + 1)

/**
 * Size of a precomputation table using the single-table comb method.
 */
#define RLC_ED_TABLE_COMBS    (1 << ED_DEPTH)

/**
 * Size of a precomputation table using the double-table comb method.
 */
#define RLC_ED_TABLE_COMBD	(1 << (ED_DEPTH + 1))

/**
 * Size of a precomputation table using the w-(T)NAF method.
 */
#define RLC_ED_TABLE_LWNAF	(1 << (ED_DEPTH - 2))

/**
 * Size of a precomputation table using the chosen algorithm.
 */
#if ED_FIX == BASIC
#define RLC_ED__TABLE			RLC_ED_TABLE_BASIC
#elif ED_FIX == COMBS
#define RLC_ED_TABLE			RLC_ED_TABLE_COMBS
#elif ED_FIX == COMBD
#define RLC_ED_TABLE			RLC_ED_TABLE_COMBD
#elif ED_FIX == LWNAF
#define RLC_ED_TABLE			RLC_ED_TABLE_LWNAF
#endif

/**
 * Maximum size of a precomputation table.
 */
#ifdef STRIP
#define RLC_ED_TABLE_MAX    RLC_ED_TABLE
#else
#define RLC_ED_TABLE_MAX    RLC_MAX(RLC_ED_TABLE_BASIC, RLC_ED_TABLE_COMBD)
#endif

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents an elliptic curve point over a Edwards field.
 */
typedef struct {
    /** The first coordinate. */
    fp_st x;
    /** The second coordinate. */
    fp_st y;
    /** The third coordinate (projective representation). */
    fp_st z;
#if ED_ADD == EXTND || !defined(STRIP)
    /** The forth coordinate (extended twisted Edwards coordinates) */
    fp_st t;
#endif
    /** Flag to indicate that this point is normalized. */
    int norm;
} ed_st;

/**
 * Pointer to an elliptic curve point.
 */
#if ALLOC == AUTO
typedef ed_st ed_t[1];
#else
typedef ed_st *ed_t;
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a point on a twisted Edwards Edwards curve with a null value.
 *
 * @param[out] A      - the point to initialize.
 */
#if ALLOC == AUTO
#define ed_null(A)        /* empty */
#else
#define ed_null(A)    A = NULL;
#endif

/**
 * Calls a function to allocate a point on a twisted Edwards Edwards curve.
 *
 * @param[out] A      - the new point.
 * @throw ERR_NO_MEMORY   - if there is no available memory.
 */
#if ALLOC == DYNAMIC
#define ed_new(A)															\
    A = (ed_t)calloc(1, sizeof(ed_st));										\
    if (A == NULL) {														\
        THROW(ERR_NO_MEMORY);												\
    }

#elif ALLOC == AUTO
#define ed_new(A)       /* empty */

#elif ALLOC == STACK
#define ed_new(A)															\
    A = (ed_t)alloca(sizeof(ed_st));										\

#endif

/**
 * Calls a function to clean and free a point on a twisted Edwards Edwards curve.
 *
 * @param[out] A      - the point to free.
 */
#if ALLOC == DYNAMIC
#define ed_free(A)															\
	if (A != NULL) {														\
    	free(A);															\
    	A = NULL;															\
	}

#elif ALLOC == AUTO
#define ed_free(A)        /* empty */

#elif ALLOC == STACK
#define ed_free(A)															\
	A = NULL;																\

#endif

/**
 * Negates an Edwards elliptic curve point. Computes R = -P.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the point to negate.
 */
#if ED_ADD == BASIC
#define ed_neg(R, P)		ed_neg_basic(R, P)
#elif ED_ADD == PROJC || ED_ADD == EXTND
#define ed_neg(R, P)		ed_neg_projc(R, P)
#endif

/**
 * Adds two Edwards elliptic curve points. Computes R = P + Q.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first point to add.
 * @param[in] Q				- the second point to add.
 */
#if ED_ADD == BASIC
#define ed_add(R, P, Q)		ed_add_basic(R, P, Q)
#elif ED_ADD == PROJC
#define ed_add(R, P, Q)		ed_add_projc(R, P, Q)
#elif ED_ADD == EXTND
#define ed_add(R, P, Q)		ed_add_extnd(R, P, Q)
#endif

/**
 * Subtracts a Edwards elliptic curve point from another. Computes R = P - Q.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the first point.
 * @param[in] Q				- the second point.
 */
#if ED_ADD == BASIC
#define ed_sub(R, P, Q)		ed_sub_basic(R, P, Q)
#elif ED_ADD == PROJC
#define ed_sub(R, P, Q)		ed_sub_projc(R, P, Q)
#elif ED_ADD == EXTND
#define ed_sub(R, P, Q)		ed_sub_extnd(R, P, Q)
#endif

/**
 * Doubles an Edwards elliptic curve point. Computes R = 2P.
 *
 * @param[out] R			- the result.
 * @param[in] P				- the point to double.
 */
#if ED_ADD == BASIC
#define ed_dbl(R, P)		ed_dbl_basic(R, P)
#elif ED_ADD == PROJC
#define ed_dbl(R, P)		ed_dbl_projc(R, P)
#elif ED_ADD == EXTND
#define ed_dbl(R, P)		ed_dbl_extnd(R, P)
#endif


/**
 * Configures a twisted Edwards Edwards curve by its parameter identifier.
 *
 * @param				- the parameter identifier.
 */
void ed_param_set(int param);

/**
 * Configures some set of curve parameters for the current security level.
 */
int ed_param_set_any(void);

/**
 * Returns the parameter identifier of the currently configured Edwards elliptic
 * curve.
 *
 * @return the parameter identifier.
 */
int ed_param_get(void);

/**
 * Returns the order of the group of points in the twisted Edwards Edwards curve.
 *
 * @param[out] r      - the returned order.
 */
void ed_curve_get_ord(bn_t r);

/**
 * Returns the generator of the group of points in the twisted Edwards curve.
 *
 * @param[out] g      - the returned generator.
 */
void ed_curve_get_gen(ed_t g);

/**
 * Returns the precomputation table for the generator.
 *
 * @return the table.
 */
const ed_t *ed_curve_get_tab(void);

/**
 * Returns the cofactor of the twisted Edwards Edwards elliptic curve.
 *
 * @param[out] n      - the returned cofactor.
 */
void ed_curve_get_cof(bn_t h);

/**
 * Prints the current configured twisted Edwards Edwards elliptic curve.
 */
void ed_param_print(void);

/**
 * Returns the current security level.
 */
int ed_param_level(void);

#if ED_ADD == EXTND
/**
 * Converts projective twisted Edwards point into extended twisted Edwards point.
 */
void ed_projc_to_extnd(ed_t r, const fp_t x, const fp_t y, const fp_t z);
#endif

/**
 * Assigns a random value to a Edwards elliptic twisted Edwards curve point.
 *
 * @param[out] p	- the Edwards elliptic twisted Edwards curve point to assign.
 */
void ed_rand(ed_t p);

/**
 * Computes the right-hand side of the elliptic curve equation at a certain
 * Edwards elliptic curve point.
 *
 * @param[out] rhs			- the result.
 * @param[in] p				- the point.
 */
void ed_rhs(fp_t rhs, const ed_t p);

/**
 * Copies the second argument to the first argument.
 *
 * @param[out] q	- the result.
 * @param[in] p		- the Edwards elliptic curve point to copy.
 */
void ed_copy(ed_t r, const ed_t p);

/**
 * Compares two Edwards elliptic twisted Edwards curve points.
 *
 * @param[in] p		- the first Edwards elliptic curve point.
 * @param[in] q		- the second Edwards elliptic curve point.
 * @return RLC_EQ if p == q and RLC_NE if p != q.
 */
int ed_cmp(const ed_t p, const ed_t q);

/**
 * Assigns a Edwards elliptic curve point to a point at the infinity.
 *
 * @param[out] p	- the point to assign.
 */
void ed_set_infty(ed_t p);

/**
 * Tests if a point on a Edwards elliptic curve is at the infinity.
 *
 * @param[in] p		- the point to test.
 * @return 1 if the point is at infinity, 0 otherise.
 */
int ed_is_infty(const ed_t p);

/**
 * Negates a Edwards elliptic curve point represented by affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to negate.
 */
void ed_neg_basic(ed_t r, const ed_t p);

/**
 * Negates a Edwards elliptic curve point represented by projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to negate.
 */
void ed_neg_projc(ed_t r, const ed_t p);

/**
 * Adds two Edwards elliptic curve points represented in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
void ed_add_basic(ed_t r, const ed_t p, const ed_t q);

/**
 * Adds two Edwards elliptic curve points represented in projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
void ed_add_projc(ed_t r, const ed_t p, const ed_t q);

/**
 * Adds two Edwards elliptic curve points represented in exteded coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
void ed_add_extnd(ed_t r, const ed_t p, const ed_t q);

/**
 * Subtracts a Edwards elliptic curve point from another, both points represented
 * by affine coordinates..
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point.
 * @param[in] q				- the second point.
 */
void ed_sub_basic(ed_t r, const ed_t p, const ed_t q);

/**
 * Subtracts a Edwards elliptic curve point from another, both represented
 * by projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point.
 * @param[in] q				- the second point.
 */
void ed_sub_projc(ed_t r, const ed_t p, const ed_t q);

/**
 * Subtracts a Edwards elliptic curve point from another, both represented
 * by extended coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point.
 * @param[in] q				- the second point.
 */
void ed_sub_extnd(ed_t r, const ed_t p, const ed_t q);

/**
 * Doubles a Edwards elliptic curve point represented in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double.
 */
void ed_dbl_basic(ed_t r, const ed_t p);

/**
 * Doubles a Edwards elliptic curve point represented in projective coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double.
 */
void ed_dbl_projc(ed_t r, const ed_t p);

/**
 * Doubles a Edwards elliptic curve point represented in extended coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double.
 */
void ed_dbl_extnd(ed_t r, const ed_t p);

/**
 * Converts a point to affine coordinates.
 *
 * @param[out] r		- the result.
 * @param[in] p			- the point to convert.
 */
void ed_norm(ed_t r, const ed_t p);

/**
 * Converts multiple points to affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the points to convert.
 * @param[in] n				- the number of points.
 */
void ed_norm_sim(ed_t *r, const ed_t *t, int n);

/**
 * Maps a byte array to a point in a Edwards elliptic twisted Edwards curve.
 *
 * @param[out] p			- the result.
 * @param[in] msg			- the byte array to map.
 * @param[in] len			- the array length in bytes.
 */
void ed_map(ed_t p, const uint8_t *msg, int len);

/**
 * Multiplies a Edwards elliptic curve point by an integer. Computes R = kP.
 *
 * @param[out] R		- the result.
 * @param[in] P			- the point to multiply.
 * @param[in] K			- the integer.
 */
#if ED_MUL == BASIC
#define ed_mul(R, P, K)   ed_mul_basic(R, P, K)
#elif ED_MUL == SLIDE
#define ed_mul(R, P, K)   ed_mul_slide(R, P, K)
#elif ED_MUL == MONTY
#define ed_mul(R, P, K)   ed_mul_monty(R, P, K)
#elif ED_MUL == FIXWI
#define ed_mul(R, P, K)   ed_mul_fixed(R, P, K)
#elif ED_MUL == LWNAF
#define ed_mul(R, P, K)   ed_mul_lwnaf(R, P, K)
#endif

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point.
 *
 * @param[out] T		- the precomputation table.
 * @param[in] P			- the point to multiply.
 */
#if ED_FIX == BASIC
#define ed_mul_pre(T, P)    ed_mul_pre_basic(T, P)
#elif ED_FIX == COMBS
#define ed_mul_pre(T, P)    ed_mul_pre_combs(T, P)
#elif ED_FIX == COMBD
#define ed_mul_pre(T, P)    ed_mul_pre_combd(T, P)
#elif ED_FIX == LWNAF
#define ed_mul_pre(T, P)    ed_mul_pre_lwnaf(T, P)
#endif

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table.
 * Computes R = kP.
 *
 * @param[out] R		- the result.
 * @param[in] T			- the precomputation table.
 * @param[in] K			- the integer.
 */
#if ED_FIX == BASIC
#define ed_mul_fix(R, T, K)   ed_mul_fix_basic(R, T, K)
#elif ED_FIX == COMBS
#define ed_mul_fix(R, T, K)   ed_mul_fix_combs(R, T, K)
#elif ED_FIX == COMBD
#define ed_mul_fix(R, T, K)   ed_mul_fix_combd(R, T, K)
#elif ED_FIX == LWNAF
#define ed_mul_fix(R, T, K)   ed_mul_fix_lwnaf(R, T, K)
#endif

 /**
 * Multiplies and adds two Edwards elliptic curve points simultaneously. Computes
 * R = kP + mQ.
 *
 * @param[out] R		- the result.
 * @param[in] P			- the first point to multiply.
 * @param[in] K			- the first integer.
 * @param[in] Q			- the second point to multiply.
 * @param[in] M			- the second integer,
 */
#if ED_SIM == BASIC
#define ed_mul_sim(R, P, K, Q, M) ed_mul_sim_basic(R, P, K, Q, M)
#elif ED_SIM == TRICK
#define ed_mul_sim(R, P, K, Q, M) ed_mul_sim_trick(R, P, K, Q, M)
#elif ED_SIM == INTER
#define ed_mul_sim(R, P, K, Q, M) ed_mul_sim_inter(R, P, K, Q, M)
#elif ED_SIM == JOINT
#define ed_mul_sim(R, P, K, Q, M) ed_mul_sim_joint(R, P, K, Q, M)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the Edwards elliptic curve arithmetic module.
 */
void ed_curve_init(void);

/**
 * Finalizes the Edwards elliptic curve arithmetic module.
 */
void ed_curve_clean(void);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using the binary method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_basic(ed_t *t, const ed_t p);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using Yao's windowing method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_yaowi(ed_t *t, const ed_t p);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using the NAF windowing method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_nafwi(ed_t *t, const ed_t p);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using the single-table comb method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_combs(ed_t *t, const ed_t p);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using the double-table comb method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_combd(ed_t *t, const ed_t p);

/**
 * Builds a precomputation table for multiplying a fixed Edwards elliptic point
 * using the w-(T)NAF method.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 */
void ed_mul_pre_lwnaf(ed_t *t, const ed_t p);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the binary method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_basic(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * Yao's windowing method
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_yaowi(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the w-(T)NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_nafwi(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the single-table comb method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_combs(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the double-table comb method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_combd(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the w-(T)NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] t				- the precomputation table.
 * @param[in] k				- the integer.
 */
void ed_mul_fix_lwnaf(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies a fixed Edwards elliptic point using a precomputation table and
 * the w-(T)NAF mixed coordinate method.
 *
 * @param[out] r      - the result.
 * @param[in] t       - the precomputation table.
 * @param[in] k       - the integer.
 */
void ed_mul_fix_lwnaf_mixed(ed_t r, const ed_t *t, const bn_t k);

/**
 * Multiplies the generator of a Edwards elliptic twisted Edwards curve by an integer.
 *
 * @param[out] r      - the result.
 * @param[in] k       - the integer.
 */
void ed_mul_gen(ed_t r, const bn_t k);

/**
 * Multiplies a Edwards elliptic twisted Edwards curve point by a small integer.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the point to multiply.
 * @param[in] k       - the integer.
 */
void ed_mul_dig(ed_t r, const ed_t p, dig_t k);

/**
 * Multiplies and adds two Edwards elliptic curve points simultaneously using
 * scalar multiplication and point addition.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the first point to multiply.
 * @param[in] k       - the first integer.
 * @param[in] q       - the second point to multiply.
 * @param[in] m       - the second integer,
 */
void ed_mul_sim_basic(ed_t r, const ed_t p, const bn_t k, const ed_t q,
    const bn_t m);

/**
 * Multiplies and adds two Edwards elliptic curve points simultaneously using
 * shamir's trick.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the first point to multiply.
 * @param[in] k       - the first integer.
 * @param[in] q       - the second point to multiply.
 * @param[in] m       - the second integer,
 */
void ed_mul_sim_trick(ed_t r, const ed_t p, const bn_t k, const ed_t q,
    const bn_t m);

/**
 * Multiplies and adds two Edwards elliptic curve points simultaneously using
 * interleaving of NAFs.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the first point to multiply.
 * @param[in] k       - the first integer.
 * @param[in] q       - the second point to multiply.
 * @param[in] m       - the second integer,
 */
void ed_mul_sim_inter(ed_t r, const ed_t p, const bn_t k, const ed_t q,
    const bn_t m);

/**
 * Multiplies and adds two Edwards elliptic curve points simultaneously using
 * Solinas' Joint Sparse Form.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the first point to multiply.
 * @param[in] k       - the first integer.
 * @param[in] q       - the second point to multiply.
 * @param[in] m       - the second integer,
 */
void ed_mul_sim_joint(ed_t r, const ed_t p, const bn_t k, const ed_t q,
    const bn_t m);

/**
 * Multiplies and adds the generator and a Edwards elliptic curve point
 * simultaneously. Computes R = kG + mQ.
 *
 * @param[out] r      - the result.
 * @param[in] k       - the first integer.
 * @param[in] q       - the second point to multiply.
 * @param[in] m       - the second integer.
 */
void ed_mul_sim_gen(ed_t r, const bn_t k, const ed_t q, const bn_t m);

/**
 * Builds a precomputation table for multiplying a random Edwards elliptic twisted Edwards point.
 *
 * @param[out] t			- the precomputation table.
 * @param[in] p				- the point to multiply.
 * @param[in] w				- the window width.
 */
void ed_tab(ed_t *t, const ed_t p, int w);

/**
 * Prints a Edwards elliptic twisted Edwards curve point.
 *
 * @param[in] p       - the Edwards elliptic curve point to print.
 */
void ed_print(const ed_t p);

/**
 * Tests if a point is in the curve.
 *
 * @param[in] p       - the point to test.
 */
int ed_is_valid(const ed_t p);

/**
 * Returns the number of bytes necessary to store a Edwards elliptic twisted Edwards curve point
 * with optional point compression.
 *
 * @param[in] a       - the Edwards field element.
 * @param[in] pack      - the flag to indicate compression.
 * @return the number of bytes.
 */
int ed_size_bin(const ed_t a, int pack);

/**
 * Reads a Edwards elliptic twisted Edwards curve point from a byte vector in big-endian format.
 *
 * @param[out] a      - the result.
 * @param[in] bin     - the byte vector.
 * @param[in] len     - the buffer capacity.
 * @throw ERR_NO_VALID    - if the encoded point is invalid.
 * @throw ERR_NO_BUFFER   - if the buffer capacity is invalid.
 */
void ed_read_bin(ed_t a, const uint8_t *bin, int len);

/**
 * Writes a Edwards elliptic twisted Edwards curve point to a byte vector in big-endian format
 * with optional point compression.
 *
 * @param[out] bin      - the byte vector.
 * @param[in] len     - the buffer capacity.
 * @param[in] a       - the Edwards elliptic curve point to write.
 * @param[in] pack      - the flag to indicate point compression.
 * @throw ERR_NO_BUFFER   - if the buffer capacity is invalid.
 */
void ed_write_bin(uint8_t *bin, int len, const ed_t a, int pack);

/**
 * Multiplies a Edwards elliptic point by an integer using the binary method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ed_mul_basic(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using the sliding window
 * method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ed_mul_slide(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using the constant-time
 * Montgomery laddering point multiplication method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ed_mul_monty(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using the constant-time
 * fixed window method.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the point to multiply.
 * @param[in] k       - the integer.
 */
void ed_mul_fixed(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using the w-NAF method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ed_mul_lwnaf(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using the w-NAF mixed coordinate method.
 *
 * @param[out] r      - the result.
 * @param[in] p       - the point to multiply.
 * @param[in] k       - the integer.
 */
void ed_mul_lwnaf_mixed(ed_t r, const ed_t p, const bn_t k);

/**
 * Multiplies a Edwards elliptic point by an integer using a regular method.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 */
void ed_mul_lwreg(ed_t r, const ed_t p, const bn_t k);

/**
 * Compresses a point.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to compress.
 */
void ed_pck(ed_t r, const ed_t p);

/**
 * Decompresses a point.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to decompress.
 * @return if the decompression was successful
 */
int ed_upk(ed_t r, const ed_t p);

#endif
