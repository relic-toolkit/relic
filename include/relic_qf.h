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
 * @defgroup bn Quadratic form arithmetic
 */

/**
 * @file
 *
 * Interface of the module for quadratic form arithmetic.
 *
 * The implementation is partially inspired in the BYCICL library:
 * "BICYCL Implements CryptographY in CLass groups" by Cyril Bouvier,
 * Guilhem Castagnos, Laurent Imbert1, and Fabien Laguillaumie1.
 * https://eprint.iacr.org/2022/1466
 *
 * @ingroup qr
 */

#ifndef RLC_QF_H
#define RLC_QF_H

#include "relic_conf.h"
#include "relic_bn.h"
#include "relic_util.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/


/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * A positive definite binary quadratic form (a, b, c) of discriminant
 * b^2 - 4ac.  All public operations return reduced forms, which are unique
 * representatives of their class, so qf_cmp doubles as equality of classes.
 */
typedef struct {
	/** The first integer in the quadratic form. */
	bn_t a;
	/** The second integer in the quadratic form. */
	bn_t b;
	/** The third integer in the quadratic form. */
	bn_t c;
} qf_st;

/**
 * Pointer to a multiple precision integer structure.
 */
#if ALLOC == AUTO
typedef qf_st qf_t[1];
#elif ALLOC == DYNAMIC
#ifdef CHECK
typedef qf_st *volatile qf_t;
#else
typedef qf_st *qf_t;
#endif
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a CRT moduli set with a null value.
 *
 * @param[out] A			- the moduli to initialize.
 */
#define qf_null(A)			RLC_NULL(A)

/**
 * Calls a function to allocate and initialize a quadratic form.
 *
 * @param[out] A			- the new quadratic form.
 */
#if ALLOC == DYNAMIC
#define qf_new(A)															\
	A = (qf_t)calloc(1, sizeof(qf_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#elif ALLOC == AUTO
#define qf_new(A)															\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#endif

/**
 * Calls a function to clean and free a quadratic form.
 *
 * @param[out] A			- the quadratic form to clean and free.
 */
#if ALLOC == DYNAMIC
#define qf_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->a);													\
		bn_free((A)->b);													\
		bn_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == AUTO
#define qf_free(A)				/* empty */

#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Copies the second argument to the first argument.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to copy.
 */
void qf_copy(qf_t c, const qf_t a);

void qf_neg(qf_t f, const qf_t g);

void qf_set_dig(qf_t f, dig_t a, dig_t b, dig_t c);

void qf_set_int(qf_t f, int a, int b, int c);

void qf_set_one(qf_t r, const bn_t d);

void qf_print(const qf_t f);

/**
 * Composes two binary quadratic forms into a third one, possibly negating one.
 *
 * @param[out] r			- the result.
 * @param[in] f				- the first quadratic form to compose.
 * @param[in] g				- the second quadratic form to compose.
 * @param[in] neg			- the flag to negate the second operand.
 * @param[in] d				- the discriminant bound.
 */
void qf_com(qf_t r, const qf_t f, const qf_t g, int neg, const bn_t d);

/**
 * Duplicates a binary quadratic form.
 *
 * @param[out] r			- the result.
 * @param[in] f				- the quadratic form to duplicate.
 * @param[in] d				- the discriminant bound.
 */
void qf_dup(qf_t r, const qf_t f, const bn_t d);

/**
 * Reduces a binary quadratic form.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the quadratic form to reduce.
 */
void qf_rdc(qf_t c, const qf_t a);

void qf_exp(qf_t r, const qf_t f, const bn_t n, const bn_t bound);

void qf_exp_sim(qf_t r, const qf_t f0, const bn_t n0, const qf_t f1,
		const bn_t n1, const bn_t bound);

void qf_exp_fix(qf_t r, const qf_t f, const bn_t n, size_t d, size_t e,
		const qf_t fe, const qf_t fd, const qf_t fde, const bn_t bound);

#endif /* !RLC_QF_H */