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
 * Builds the lists taken by the batches below: pointers to destinations
 * (DSTS), pointers to factors (PTRS) and signs (SGNS).
 *
 * @param[in] ...		- the elements of the list.
 */
/** @{ */
#define TMPL_LAZYR_DSTS(...)	((void *[]){ __VA_ARGS__ })
#define TMPL_LAZYR_PTRS(...)	((const void *[]){ __VA_ARGS__ })
#define TMPL_LAZYR_SGNS(...)	((const int[]){ __VA_ARGS__ })
/** @} */

/**
 * Multiplies two elements of a field, without reduction (MULN) or with the
 * fused multiplication of the field (MULM), squaring when both factors are the
 * same. Factors may be pointers to constant elements, which the field functions
 * take without qualifiers when elements are allocated dynamically.
 *
 * @param[in] F			- the field prefix.
 * @param[out] C		- the result.
 * @param[in] A			- the pointer to the first factor.
 * @param[in] B			- the pointer to the second factor.
 */
/** @{ */
#define TMPL_LAZYR_MULN(F, C, A, B)											\
	if ((A) == (B)) {														\
		TMPL_LAZYR_SQRN_##F(C, A);											\
	} else {																\
		TMPL_LAZYR_MULN_##F(C, A, B);										\
	}
#define TMPL_LAZYR_MULM(F, C, A, B)											\
	if ((A) == (B)) {														\
		F##_sqr(C, (void *)(A));											\
	} else {																\
		F##_mul(C, (void *)(A), (void *)(B));								\
	}
/** @} */

/**
 * Computes the sum with index J of TMPL_LAZYR_ADDP without reduction.
 *
 * @param[in] F			- the field prefix.
 * @param[in] A			- the pointers to the first factors of the products.
 * @param[in] B			- the pointers to the second factors of the products.
 * @param[in] S			- the signs of the second products.
 * @param[in] D			- the pointers to the first factors of the second
 * 						products.
 * @param[in] E			- the pointers to the second factors of the second
 * 						products.
 * @param[out] U		- the unreduced sums.
 * @param[out] T		- the scratch for one unreduced element.
 * @param[in] J			- the index of the sum.
 */
#define TMPL_LAZYR_ADDN(F, A, B, S, D, E, U, T, J)							\
	TMPL_LAZYR_MULN(F, (U)[J], (A)[J], (B)[J]);								\
	if ((S)[J] != 0) {														\
		TMPL_LAZYR_MULN(F, T, (D)[J], (E)[J]);								\
		if ((S)[J] > 0) {													\
			TMPL_LAZYR_ADDC_##F((U)[J], (U)[J], T);							\
		} else {															\
			TMPL_LAZYR_SUBC_##F((U)[J], (U)[J], T);							\
		}																	\
	}

/**
 * Computes N sums of products of elements of a field into destinations given
 * by pointers to them: the destination with index i receives
 * A[i] * B[i] + S[i] * D[i] * E[i], for a sign S[i] in {-1, 0, 1}. In a Residue
 * Number System, all N are reduced together, as reductions are cheaper in
 * batches. Otherwise, the sums with nonzero signs are computed before any
 * destination is written and reduced each by itself, and then the single
 * products are computed with the fused multiplication of the field, so their
 * destinations must not be later factors.
 *
 * @param[in] F			- the field prefix.
 * @param[out] C		- the pointers to the destinations.
 * @param[in] A			- the pointers to the first factors of the products.
 * @param[in] B			- the pointers to the second factors of the products.
 * @param[in] S			- the signs of the second products.
 * @param[in] D			- the pointers to the first factors of the second
 * 						products.
 * @param[in] E			- the pointers to the second factors of the second
 * 						products.
 * @param[out] U		- the scratch for N unreduced elements.
 * @param[out] T		- the scratch for one more unreduced element.
 * @param[in] N			- the number of destinations.
 */
#if FP_RDC == FP_RENUS
#define TMPL_LAZYR_ADDP(F, C, A, B, S, D, E, U, T, N)						\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		TMPL_LAZYR_ADDN(F, A, B, S, D, E, U, T, _j);						\
	}																		\
	TMPL_LAZYR_RDCP(F, C, U, N)
#else
#define TMPL_LAZYR_ADDP(F, C, A, B, S, D, E, U, T, N)						\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		if ((S)[_j] != 0) {													\
			TMPL_LAZYR_ADDN(F, A, B, S, D, E, U, T, _j);					\
		}																	\
	}																		\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		if ((S)[_j] != 0) {													\
			TMPL_LAZYR_RDCN_##F((C)[_j], (U)[_j]);							\
		}																	\
	}																		\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		if ((S)[_j] == 0) {													\
			TMPL_LAZYR_MULM(F, (C)[_j], (A)[_j], (B)[_j]);					\
		}																	\
	}
#endif

/**
 * Computes N products of pairs of elements of a field into destinations given
 * by pointers to them, as TMPL_LAZYR_ADDP with all signs zero.
 *
 * @param[in] F			- the field prefix.
 * @param[out] C		- the pointers to the destinations.
 * @param[in] A			- the pointers to the first factors.
 * @param[in] B			- the pointers to the second factors.
 * @param[out] U		- the scratch for N unreduced elements.
 * @param[in] N			- the number of destinations.
 */
#if FP_RDC == FP_RENUS
#define TMPL_LAZYR_MULP(F, C, A, B, U, N)									\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		TMPL_LAZYR_MULN(F, (U)[_j], (A)[_j], (B)[_j]);						\
	}																		\
	TMPL_LAZYR_RDCP(F, C, U, N)
#else
#define TMPL_LAZYR_MULP(F, C, A, B, U, N)									\
	RLC_UNROLL(8)															\
	for (int _j = 0; _j < (N); _j++) {										\
		TMPL_LAZYR_MULM(F, (C)[_j], (A)[_j], (B)[_j]);						\
	}
#endif

#endif /* !RLC_FP_LAZYR_TMPL_H */
