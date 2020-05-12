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
 * @defgroup mpc Multi-party computation
 */

/**
 * @file
 *
 * Interface of the module for multi-party computation.
 *
 * @ingroup bn
 */

#ifndef RLC_MPC_H
#define RLC_MPC_H

#include "relic_conf.h"
#include "relic_util.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a multiplication triple.
 */
typedef struct {
	/* The share of the first operand. */
	bn_t a;
	/* The share of the second operand. */
	bn_t b;
	/* The share of the multiplication. */
	bn_t c;
} mt_st;

/**
 * Pointer to a multiplication triple structure.
 */
#if ALLOC == AUTO
typedef mt_st mt_t[1];
#else
typedef mt_st *mt_t;
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a multiplication triple.
 *
 * @param[out] A			- the multiple precision integer to initialize.
 */
#if ALLOC == AUTO
#define mt_null(A)				/* empty */
#else
#define mt_null(A)			A = NULL;
#endif

/**
 * Calls a function to allocate and initialize a multiple precision integer.
 *
 * @param[in,out] A			- the multiple precision integer to initialize.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 */
#if ALLOC == DYNAMIC
#define mt_new(A)															\
	A = (mt_t)calloc(1, sizeof(mt_st));										\
	if ((A) == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\
	bn_null((A)->a);														\
	bn_null((A)->b);														\
	bn_null((A)->c);														\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#elif ALLOC == AUTO
#define mt_new(A)															\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#elif ALLOC == STACK
#define mt_new(A)															\
	A = (bn_t)alloca(sizeof(mt_st));										\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);															\

#endif

/**
 * Calls a function to clean and free a multiple precision integer.
 *
 * @param[in,out] A			- the multiple precision integer to free.
 */
#if ALLOC == DYNAMIC
#define mt_free(A)															\
	if (A != NULL) {														\
		bn_free(A)->a);														\
		bn_free((A)->b);													\
		bn_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == AUTO
#define mt_free(A)			/* empty */										\

#elif ALLOC == STACK
#define mt_free(A)															\
	A = NULL;																\
	bn_free(A)->a);															\
	bn_free((A)->b);														\
	bn_free((A)->c);														\

#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Generates a pair of multiplication triples for use in MPC protocols such that
 * [a] * [b] = [c] modulo a certain order.
 *
 * @param[out] triple				- the multiplication triples to generate.
 * @param[in] order					- the underlying order.
 */
void mt_gen(mt_t triple[2], bn_t order);

#endif /* !RLC_MPC_H */
