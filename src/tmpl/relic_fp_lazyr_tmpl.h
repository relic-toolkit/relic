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
 * Templates for formulas with lazy reduction over the prime field: operations
 * on unreduced elements, and the reduction of several of them at once.
 *
 * @ingroup tmpl
 */

#ifndef RLC_FP_LAZYR_TMPL_H
#define RLC_FP_LAZYR_TMPL_H

#include "relic_core.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Selects the operations on unreduced elements of a field F for formulas with
 * lazy reduction: multiplication (MULN) and squaring (SQRN) without reduction,
 * addition (ADDC) and subtraction (SUBC) of unreduced elements, and modular
 * reduction of one element (RDCN) or of N elements at once (RDCV).
 */
/** @{ */
#define TMPL_LAZYR_MULN_fp(C, A, B)	fp_muln_low(C, A, B)
#define TMPL_LAZYR_SQRN_fp(C, A)	fp_sqrn_low(C, A)
#define TMPL_LAZYR_ADDC_fp(C, A, B)	fp_addc_low(C, A, B)
#define TMPL_LAZYR_SUBC_fp(C, A, B)	fp_subc_low(C, A, B)
#define TMPL_LAZYR_RDCN_fp(C, A)	fp_rdcn_low(C, A)
#define TMPL_LAZYR_RDCV_fp(C, A, N)	fp_rdcv_low(C, A, N)
/** @} */

/**
 * Reduces N double-precision elements of a field into destinations given by
 * pointers to them. In a Residue Number System, all their prime field
 * components are reduced together, as reductions are cheaper in batches;
 * otherwise, each element is reduced by itself.
 *
 * @param[in] F			- the field prefix.
 * @param[out] C		- the pointers to the destinations.
 * @param[in] U			- the elements to reduce.
 * @param[in] N			- the number of elements.
 */
#if FP_RDC == FP_RENUS
#define TMPL_LAZYR_RDCP(F, C, U, N)											\
	{																		\
		enum { _M = sizeof(F##_t) / (sizeof(fp_t)) };						\
		dig_t *_c[(N) * _M], *_a[(N) * _M];									\
																			\
		RLC_UNROLL(8)														\
		for (int _i = 0; _i < (N); _i++) {									\
			for (int _k = 0; _k < _M; _k++) {								\
				/* An element of the prime field is its only component. */	\
				_c[_i * _M + _k] = (_M == 1 ? (dig_t *)(C)[_i] :			\
						((fp_t *)(C)[_i])[_k]);								\
				_a[_i * _M + _k] = (_M == 1 ? (dig_t *)(U)[_i] :			\
						((dv_t *)(U)[_i])[_k]);								\
			}																\
		}																	\
		fp_rdcv_low(_c, _a, (N) * _M);										\
	}
#else
#define TMPL_LAZYR_RDCP(F, C, U, N)											\
	RLC_UNROLL(8)															\
	for (int _i = 0; _i < (N); _i++) {										\
		TMPL_LAZYR_RDCN_##F((C)[_i], (U)[_i]);								\
	}
#endif

/**
 * Reduces K unreduced elements of a field and computes N - K products of pairs
 * of elements, into destinations given by pointers to them: the first K
 * destinations receive the reductions of the first K elements of U, and the
 * others the products of the factors with the same indices, squaring when both
 * factors are the same. In a Residue Number System, all N are reduced
 * together, as reductions are cheaper in batches; otherwise, each is computed
 * by itself, the products with the fused multiplications of the field, so
 * destinations must not be later factors. Factors may be pointers to constant
 * elements, which the field functions take without qualifiers when elements
 * are allocated dynamically.
 *
 * @param[in] F			- the field prefix.
 * @param[out] C		- the pointers to the destinations.
 * @param[in] A			- the pointers to the first factors.
 * @param[in] B			- the pointers to the second factors.
 * @param[in,out] U		- the unreduced elements, and scratch for the rest.
 * @param[in] K			- the number of unreduced elements.
 * @param[in] N			- the number of destinations.
 */
#if FP_RDC == FP_RENUS
#define TMPL_LAZYR_MULP(F, C, A, B, U, K, N)								\
	RLC_UNROLL(8)															\
	for (int _j = (K); _j < (N); _j++) {									\
		if ((A)[_j] == (B)[_j]) {											\
			TMPL_LAZYR_SQRN_##F((U)[_j], (A)[_j]);							\
		} else {															\
			TMPL_LAZYR_MULN_##F((U)[_j], (A)[_j], (B)[_j]);					\
		}																	\
	}																		\
	TMPL_LAZYR_RDCP(F, C, U, N)
#else
#define TMPL_LAZYR_MULP(F, C, A, B, U, K, N)								\
	TMPL_LAZYR_RDCP(F, C, U, K);											\
	RLC_UNROLL(8)															\
	for (int _j = (K); _j < (N); _j++) {									\
		if ((A)[_j] == (B)[_j]) {											\
			F##_sqr((C)[_j], (void *)(A)[_j]);								\
		} else {															\
			F##_mul((C)[_j], (void *)(A)[_j], (void *)(B)[_j]);				\
		}																	\
	}
#endif

#endif /* !RLC_FP_LAZYR_TMPL_H */
