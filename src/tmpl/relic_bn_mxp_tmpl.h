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
 * Templates for modular exponentiation: the representation of elements under
 * the configured modular reduction, and the operations on them.
 *
 * @ingroup tmpl
 */

#ifndef RLC_BN_MXP_TMPL_H
#define RLC_BN_MXP_TMPL_H

#include "relic_core.h"
#if BN_MOD == BN_RENUS
#include "relic_rns_low.h"
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*
 * Modular exponentiations are written once against the representation of
 * the modular reduction: the type of elements and of the precomputed value V,
 * and the conversions and operations on them. Positional reductions keep
 * elements as integers, while a Residue Number System keeps residues. In the
 * macros, X, Y, Z and T are elements, A and C integers converted to and from
 * them, M is the modulus and B the condition of a swap.
 */
#if BN_MOD == BN_RENUS

/*
 * Room of the contexts for exponentiation: products of values below (n + 1)N
 * need 2 log2(n + 1) bits of it, so 16 bits cover bases of up to 255 moduli.
 */
#define BN_MXP_ROOM		16

#define MXP_T					dv_t
#define MXP_V					const rns_st *
#define MXP_V_NULL(V)			V = NULL
#define MXP_V_NEW(V, M)			V = rns_lookup(M, BN_MXP_ROOM)
#define MXP_V_FREE(V)			(void)(V)
#define MXP_NULL(X)				dv_null(X)
#define MXP_NEW(X, V)			dv_new(X)
#define MXP_FREE(X)				dv_free(X)
#define MXP_GROW(X, M)			(void)(X)
#define MXP_CONV(X, A, M, V)	rns_set_bn(X, A, V)
#define MXP_BACK(C, X, M, V)	rns_get_bn(C, X, V)
#define MXP_ONE(X, M, V)		dv_copy(X, (V)->one, 2 * (V)->o)
#define MXP_COPY(X, Y, V)		dv_copy(X, Y, 2 * (V)->o)
#define MXP_SWAP(X, Y, B, V)	dv_swap_sec(X, Y, 2 * (V)->o, B)
#define MXP_MUL(X, Y, Z, M, V)	rns_mulm_low(X, Y, Z, V)
#define MXP_SQR(X, Y, M, V)		rns_mulm_low(X, Y, Y, V)
/* A step of the ladder: X = X * Y and Y = Y^2, with T unused. */
#define MXP_STEP(X, Y, T, M, V)												\
	(void)(T);																\
	rns_mulm_low(X, X, Y, V);												\
	rns_mulm_low(Y, Y, Y, V)

#else

#define MXP_T					bn_t
#define MXP_V					bn_t
#define MXP_V_NULL(V)			bn_null(V)
#define MXP_V_NEW(V, M)														\
	bn_new(V);																\
	bn_mod_pre(V, M)
#define MXP_V_FREE(V)			bn_free(V)
#define MXP_NULL(X)				bn_null(X)
#define MXP_NEW(X, V)			bn_new(X)
#define MXP_FREE(X)				bn_free(X)
#define MXP_GROW(X, M)			bn_grow(X, (M)->alloc)
#define MXP_COPY(X, Y, V)		bn_copy(X, Y)
#define MXP_SWAP(X, Y, B, V)	bn_swap_sec(X, Y, B)
#define MXP_MUL(X, Y, Z, M, V)												\
	bn_mul(X, Y, Z);														\
	bn_mod(X, X, M, V)
#define MXP_SQR(X, Y, M, V)													\
	bn_sqr(X, Y);															\
	bn_mod(X, X, M, V)
/* A step of the ladder: X = X * Y and Y = Y^2, with the products in T so that
 * X and Y keep their size for the swaps. */
#define MXP_STEP(X, Y, T, M, V)												\
	bn_mul(T, X, Y);														\
	bn_mod(X, T, M, V);														\
	bn_sqr(T, Y);															\
	bn_mod(Y, T, M, V)
#if BN_MOD == BN_MONTY
#define MXP_CONV(X, A, M, V)	bn_mod_monty_conv(X, A, M)
#define MXP_BACK(C, X, M, V)	bn_mod_monty_back(C, X, M)
#define MXP_ONE(X, M, V)													\
	bn_set_dig(X, 1);														\
	bn_mod_monty_conv(X, X, M)
#else
/* The reductions expect operands in [0, m). */
#define MXP_CONV(X, A, M, V)	bn_mod_basic(X, A, M)
#define MXP_BACK(C, X, M, V)	bn_copy(C, X)
#define MXP_ONE(X, M, V)		bn_set_dig(X, 1)
#endif

#endif

#endif /* !RLC_BN_MXP_TMPL_H */
