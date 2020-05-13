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
#include "relic_pc.h"

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

/**
 * Represents a pairing triple.
 */
typedef struct _pt_st {
	/** The shares of the G1 element a. */
	g1_t a;
	/** The shares of the G2 element b. */
	g2_t b;
	/** The shares of the GT element c = e(a,b). */
	gt_t c;
} pt_st;

/**
 * Pointer to a pairing triple.
 */
#if ALLOC == AUTO
typedef pt_st pt_t[1];
#else
typedef pt_st *pt_t;
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

/**
 * Initializes a pairing triple with a null value.
 *
 * @param[out] A			- the key pair to initialize.
 */
#if ALLOC == AUTO
#define pt_null(A)				/* empty */
#else
#define pt_null(A)			A = NULL;
#endif

/**
 * Calls a function to allocate and initialize a pairing triple.
 *
 * @param[out] A			- the new pairing triple.
 */
#if ALLOC == DYNAMIC
#define pt_new(A)															\
	A = (pt_t)calloc(1, sizeof(pt_st));										\
	if (A == NULL) {														\
		THROW(ERR_NO_MEMORY);												\
	}																		\
	g1_new((A)->a);															\
	g2_new((A)->b);															\
	gt_new((A)->c);															\

#elif ALLOC == AUTO
#define pt_new(A)				/* empty */

#elif ALLOC == STACK
#define pt_new(A)															\
	A = (pt_t)alloca(sizeof(pt_st));										\
	g1_new((A)->a);															\
	g2_new((A)->b);															\
	g2_new((A)->c);															\

#endif

/**
 * Calls a function to clean and free a pairing triple.
 *
 * @param[out] A			- the pairing triple to clean and free.
 */
#if ALLOC == DYNAMIC
#define pt_free(A)															\
	if (A != NULL) {														\
		g1_free((A)->a);													\
		g2_free((A)->b);													\
		gt_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == AUTO
#define pt_free(A)				/* empty */

#elif ALLOC == STACK
#define pt_free(A)															\
	g1_free((A)->a);														\
	g2_free((A)->b);														\
	gt_free((A)->c);														\
	A = NULL;																\

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

/**
 * Generates a pairing triple.
 *
 * @param[out] t			- the pairing triple to generate.
 */
void pc_map_tri(pt_t t[2]);

/**
 * Computes the public values from the pairing inputs and triple.
 *
 * @param[out] d			- the share of the first public value.
 * @param[out] e			- the share of the second public value.
 * @param[in] p				- the share of the first pairnig argument.
 * @param[in] q				- the share of the second pairing argument.
 * @param[in] t				- the pairing triple.
 */
void pc_map_lcl(g1_t d, g2_t e, g1_t p, g2_t q, pt_t t);

/**
 * Broadcasts the public values for pairing computation.
 *
 * @param[out] d			- the first set of public values.
 * @param[out] e			- the second set of public values.
 */
void pc_map_bct(g1_t d[2], g2_t e[2]);

/**
 * Computes a pairing using a pairing triple.
 *
 * @param[out] r 			- the pairing result.
 * @param[in] p				- the share of the first pairnig argument.
 * @param[in] q				- the share of the second pairing argument.
 * @param[in] triple		- the pairing triple.
 * @param[in] d				- the first public value.
 * @param[in] e				- the second public value.
 * @param[in] party			- the number of the party executing the computation.
 */
void pc_map_mpc(gt_t r, g1_t p, g2_t q, pt_t triple, g1_t d, g2_t e, int party);

#endif /* !RLC_MPC_H */
