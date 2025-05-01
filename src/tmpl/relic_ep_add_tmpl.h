/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2024 RELIC Authors
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
 * Template for point addition on prime elliptic curves.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for point addition in affine coordinates.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_ADD_BASIC_IMP(C, F)											\
	static void C##_add_basic_imp(C##_t r, F##_t s, const C##_t p,			\
			const C##_t q) {												\
		F##_t t0, t1, t2;													\
																			\
		F##_null(t0);														\
		F##_null(t1);														\
		F##_null(t2);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
			F##_new(t1);													\
			F##_new(t2);													\
																			\
			/* t0 = x2 - x1. */												\
			F##_sub(t0, q->x, p->x);										\
			/* t1 = y2 - y1. */												\
			F##_sub(t1, q->y, p->y);										\
																			\
			/* If t0 is zero. */											\
			if (F##_is_zero(t0)) {											\
				if (F##_is_zero(t1)) {										\
					/* If t1 is zero, q = p, should have doubled. */		\
					C##_dbl_basic(r, p);									\
				} else {													\
					/* If t1 != 0 and t0 == 0, q = -p and r = infinity. */	\
					C##_set_infty(r);										\
				}															\
			} else {														\
				/* t2 = 1/(x2 - x1). */										\
				F##_inv(t2, t0);											\
				/* t2 = lambda = (y2 - y1)/(x2 - x1). */					\
				F##_mul(t2, t1, t2);										\
																			\
				/* x3 = lambda^2 - x2 - x1. */								\
				F##_sqr(t1, t2);											\
				F##_sub(t0, t1, p->x);										\
				F##_sub(t0, t0, q->x);										\
																			\
				/* y3 = lambda * (x1 - x3) - y1. */							\
				F##_sub(t1, p->x, t0);										\
				F##_mul(t1, t2, t1);										\
				F##_sub(r->y, t1, p->y);									\
																			\
				F##_copy(r->x, t0);											\
				F##_copy(r->z, p->z);										\
																			\
				if (s != NULL) {											\
					F##_copy(s, t2);										\
				}															\
																			\
				r->coord = BASIC;											\
			}																\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
		}																	\
	}																		\

/**
 * Defines a template for mixed point addition in homogeneous projective
 * coordinates.
 *
 * Formulas for mixed addition from
 * "Complete addition formulas for prime order elliptic curves"
 * by Joost Renes, Craig Costello, and Lejla Batina
 * https://eprint.iacr.org/2015/1060.pdf
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_ADD_PROJC_MIX(C, F)											\
	static void C##_add_projc_mix(C##_t r, const C##_t p, const C##_t q) {	\
		F##_t t0, t1, t2, t3, t4, t5;										\
																			\
		F##_null(t0);														\
		F##_null(t1);														\
		F##_null(t2);														\
		F##_null(t3);														\
		F##_null(t4);														\
		F##_null(t5);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
			F##_new(t1);													\
			F##_new(t2);													\
			F##_new(t3);													\
			F##_new(t4);													\
			F##_new(t5);													\
																			\
			F##_mul(t0, p->x, q->x);										\
			F##_mul(t1, p->y, q->y);										\
			F##_add(t3, q->x, q->y);										\
			F##_add(t4, p->x, p->y);										\
			F##_mul(t3, t3, t4);											\
			F##_add(t4, t0, t1);											\
			F##_sub(t3, t3, t4);											\
																			\
			if (C##_curve_opt_a() == RLC_ZERO) {							\
				/* Cost of 11M + 2m_3b + 13a. */							\
				if (p->coord == BASIC) {									\
					/* Save 1M + 1m_3b if z1 = 1. */						\
					F##_add(t4, q->y, p->y);								\
					F##_add(r->y, q->x, p->x);								\
					F##_dbl(t5, C##_curve_get_b());							\
					F##_add(t5, t5, C##_curve_get_b());						\
					F##_add(r->z, t1, t5);									\
					F##_sub(t1, t1, t5);									\
				} else {													\
					F##_mul(t4, q->y, p->z);								\
					F##_add(t4, t4, p->y);									\
					F##_mul(r->y, q->x, p->z);								\
					F##_add(r->y, r->y, p->x);								\
					F##_dbl(t2, p->z);										\
					F##_add(t2, t2, p->z);									\
					C##_curve_mul_b(t2, t2);								\
					F##_add(r->z, t1, t2);									\
					F##_sub(t1, t1, t2);									\
				}															\
				F##_dbl(r->x, t0);											\
				F##_add(t0, t0, r->x);										\
				F##_dbl(t5, r->y);											\
				F##_add(r->y, r->y, t5);									\
				C##_curve_mul_b(r->y, r->y);								\
				F##_mul(r->x, t4, r->y);									\
				F##_mul(t2, t3, t1);										\
				F##_sub(r->x, t2, r->x);									\
				F##_mul(r->y, t0, r->y);									\
				F##_mul(t1, t1, r->z);										\
				F##_add(r->y, t1, r->y);									\
				F##_mul(t0, t0, t3);										\
				F##_mul(r->z, r->z, t4);									\
				F##_add(r->z, r->z, t0);									\
			} else if (C##_curve_opt_a() == RLC_MIN3) {						\
				/* Cost of 11M + 2m_b + 23a. */								\
				if (p->coord == BASIC) {									\
					/* Save 2M + 3a if z1 = 1. */							\
					F##_set_dig(t2, 3);										\
					F##_add(t4, q->y, p->y);								\
					F##_add(r->y, q->x, p->x);								\
					F##_sub(r->x, r->y, C##_curve_get_b());					\
				} else {													\
					F##_dbl(t2, p->z);										\
					F##_add(t2, t2, p->z);									\
					F##_mul(t4, q->y, p->z);								\
					F##_add(t4, t4, p->y);									\
					F##_mul(r->y, q->x, p->z);								\
					F##_add(r->y, r->y, p->x);								\
					C##_curve_mul_b(r->z, p->z);							\
					F##_sub(r->x, r->y, r->z);								\
				}															\
				F##_dbl(r->z, r->x);										\
				F##_add(r->x, r->x, r->z);									\
				F##_sub(r->z, t1, r->x);									\
				F##_add(r->x, t1, r->x);									\
				C##_curve_mul_b(r->y, r->y);								\
				F##_sub(r->y, r->y, t2);									\
				F##_sub(r->y, r->y, t0);									\
				F##_dbl(t1, r->y);											\
				F##_add(r->y, t1, r->y);									\
				F##_dbl(t1, t0);											\
				F##_add(t0, t1, t0);										\
				F##_sub(t0, t0, t2);										\
				F##_mul(t1, t4, r->y);										\
				F##_mul(t2, t0, r->y);										\
				F##_mul(r->y, r->x, r->z);									\
				F##_add(r->y, r->y, t2);									\
				F##_mul(r->x, t3, r->x);									\
				F##_sub(r->x, r->x, t1);									\
				F##_mul(r->z, t4, r->z);									\
				F##_mul(t1, t3, t0);										\
				F##_add(r->z, r->z, t1);									\
			} else {														\
				/* Cost of 11M + 3m_a + 2m_3b + 17a. */						\
				if (p->coord == BASIC) {									\
					/* Save 1M + 1m_a + 1m_3b if z1 = 1. */					\
					F##_copy(t2, C##_curve_get_a());						\
					F##_add(t4, q->x, p->x);								\
					F##_add(t5, q->y, p->y);								\
					C##_curve_mul_a(r->z, t4);								\
					F##_dbl(r->y, C##_curve_get_b());						\
					F##_add(r->y, r->y, C##_curve_get_b());					\
					F##_add(r->z, r->z, r->y);								\
				} else {													\
					C##_curve_mul_a(t2, p->z);								\
					F##_mul(t4, q->x, p->z);								\
					F##_add(t4, t4, p->x);									\
					F##_mul(t5, q->y, p->z);								\
					F##_add(t5, t5, p->y);									\
					F##_dbl(r->x, p->z);									\
					F##_add(r->x, r->x, p->z);								\
					C##_curve_mul_b(r->x, r->x);							\
					C##_curve_mul_a(r->z, t4);								\
					F##_add(r->z, r->x, r->z);								\
				}															\
				F##_sub(r->x, t1, r->z);									\
				F##_add(r->z, t1, r->z);									\
				F##_mul(r->y, r->x, r->z);									\
				F##_dbl(t1, t4);											\
				F##_add(t1, t1, t4);										\
				C##_curve_mul_b(t4, t1);									\
				F##_dbl(t1, t0);											\
				F##_add(t1, t1, t0);										\
				F##_add(t1, t1, t2);										\
				F##_sub(t2, t0, t2);										\
				C##_curve_mul_a(t2, t2);									\
				F##_add(t4, t4, t2);										\
				F##_mul(t0, t1, t4);										\
				F##_add(r->y, r->y, t0);									\
				F##_mul(t0, t5, t4);										\
				F##_mul(r->x, t3, r->x);									\
				F##_sub(r->x, r->x, t0);									\
				F##_mul(t0, t3, t1);										\
				F##_mul(r->z, t5, r->z);									\
				F##_add(r->z, r->z, t0);									\
			}																\
																			\
			r->coord = PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
			F##_free(t3);													\
			F##_free(t4);													\
			F##_free(t5);													\
		}																	\
	}																		\

/**
 * Defines a template for point addition in homogeneous projective
 * coordinates.
 *
 * Formulas for mixed addition from
 * "Complete addition formulas for prime order elliptic curves"
 * by Joost Renes, Craig Costello, and Lejla Batina
 * https://eprint.iacr.org/2015/1060.pdf
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#if defined(EP_MIXED) && defined(STRIP)

#define TMPL_ADD_PROJC_IMP(C, F)											\
	static void C##_add_projc_imp(C##_t r, const C##_t p, const C##_t q) {	\
		/* If code size is a problem, leave only the mixed version. */		\
		C##_add_projc_mix(r, p, q);											\
	}																		\

#else

#define TMPL_ADD_PROJC_IMP(C, F)											\
	static void C##_add_projc_imp(C##_t r, const C##_t p, const C##_t q) {	\
		F##_t t0, t1, t2, t3, t4, t5;										\
																			\
		if (q->coord == BASIC) {											\
			C##_add_projc_mix(r, p, q);										\
			return;															\
		}																	\
																			\
		F##_null(t0);														\
		F##_null(t1);														\
		F##_null(t2);														\
		F##_null(t3);														\
		F##_null(t4);														\
		F##_null(t5);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
			F##_new(t1);													\
			F##_new(t2);													\
			F##_new(t3);													\
			F##_new(t4);													\
			F##_new(t5);													\
																			\
			F##_mul(t0, p->x, q->x);										\
			F##_mul(t1, p->y, q->y);										\
			F##_mul(t2, p->z, q->z);										\
			F##_add(t3, p->x, p->y);										\
			F##_add(t4, q->x, q->y);										\
			F##_mul(t3, t3, t4);											\
			F##_add(t4, t0, t1);											\
			F##_sub(t3, t3, t4);											\
			if (C##_curve_opt_a() == RLC_ZERO) {							\
				/* Cost of 12M + 2m_3b + 19a. */							\
				F##_add(t4, p->y, p->z);									\
				F##_add(t5, q->y, q->z);									\
				F##_mul(t4, t4, t5);										\
				F##_add(t5, t1, t2);										\
				F##_sub(t4, t4, t5);										\
				F##_add(r->y, q->x, q->z);									\
				F##_add(r->x, p->x, p->z);									\
				F##_mul(r->x, r->x, r->y);									\
				F##_add(r->y, t0, t2);										\
				F##_sub(r->y, r->x, r->y);									\
				F##_dbl(r->x, t0);											\
				F##_add(t0, t0, r->x);										\
				F##_dbl(t5, t2);											\
				F##_add(t2, t2, t5);										\
				C##_curve_mul_b(t2, t2);									\
				F##_add(r->z, t1, t2);										\
				F##_sub(t1, t1, t2);										\
				F##_dbl(t5, r->y);											\
				F##_add(r->y, r->y, t5);									\
				C##_curve_mul_b(r->y, r->y);								\
				F##_mul(r->x, t4, r->y);									\
				F##_mul(t2, t3, t1);										\
				F##_sub(r->x, t2, r->x);									\
				F##_mul(r->y, t0, r->y);									\
				F##_mul(t1, t1, r->z);										\
				F##_add(r->y, t1, r->y);									\
				F##_mul(t0, t0, t3);										\
				F##_mul(r->z, r->z, t4);									\
				F##_add(r->z, r->z, t0);									\
			} else if (C##_curve_opt_a() == RLC_MIN3) {						\
				/* Cost of 12M + 2m_b + 29a. */								\
				F##_add(t4, p->y, p->z);									\
				F##_add(t5, q->y, q->z);									\
				F##_mul(t4, t4, t5);										\
				F##_add(t5, t1, t2);										\
				F##_sub(t4, t4, t5);										\
				F##_add(r->x, p->x, p->z);									\
				F##_add(r->y, q->x, q->z);									\
				F##_mul(r->x, r->x, r->y);									\
				F##_add(r->y, t0, t2);										\
				F##_sub(r->y, r->x, r->y);									\
				C##_curve_mul_b(r->z, t2);									\
				F##_sub(r->x, r->y, r->z);									\
				F##_dbl(r->z, r->x);										\
				F##_add(r->x, r->x, r->z);									\
				F##_sub(r->z, t1, r->x);									\
				F##_add(r->x, t1, r->x);									\
				C##_curve_mul_b(r->y, r->y);								\
				F##_dbl(t1, t2);											\
				F##_add(t2, t1, t2);										\
				F##_sub(r->y, r->y, t2);									\
				F##_sub(r->y, r->y, t0);									\
				F##_dbl(t1, r->y);											\
				F##_add(r->y, t1, r->y);									\
				F##_dbl(t1, t0);											\
				F##_add(t0, t1, t0);										\
				F##_sub(t0, t0, t2);										\
				F##_mul(t1, t4, r->y);										\
				F##_mul(t2, t0, r->y);										\
				F##_mul(r->y, r->x, r->z);									\
				F##_add(r->y, r->y, t2);									\
				F##_mul(r->x, t3, r->x);									\
				F##_sub(r->x, r->x, t1);									\
				F##_mul(r->z, t4, r->z);									\
				F##_mul(t1, t3, t0);										\
				F##_add(r->z, r->z, t1);									\
			} else {														\
				/* Cost of 12M + 3m_a + 2_m3b + 23a. */						\
				F##_add(t4, p->x, p->z);									\
				F##_add(t5, q->x, q->z);									\
				F##_mul(t4, t4, t5);										\
				F##_add(t5, t0, t2);										\
				F##_sub(t4, t4, t5);										\
				F##_add(t5, p->y, p->z);									\
				F##_add(r->x, q->y, q->z);									\
				F##_mul(t5, t5, r->x);										\
				F##_add(r->x, t1, t2);										\
				F##_sub(t5, t5, r->x);										\
				C##_curve_mul_a(r->z, t4);									\
				F##_dbl(r->x, t2);											\
				F##_add(r->x, r->x, t2);									\
				C##_curve_mul_b(r->x, r->x);								\
				F##_add(r->z, r->x, r->z);									\
				F##_sub(r->x, t1, r->z);									\
				F##_add(r->z, t1, r->z);									\
				F##_mul(r->y, r->x, r->z);									\
				F##_dbl(t1, t4);											\
				F##_add(t1, t1, t4);										\
				C##_curve_mul_b(t4, t1);									\
				F##_dbl(t1, t0);											\
				F##_add(t1, t1, t0);										\
				C##_curve_mul_a(t2, t2);									\
				F##_add(t1, t1, t2);										\
				F##_sub(t2, t0, t2);										\
				C##_curve_mul_a(t2, t2);									\
				F##_add(t4, t4, t2);										\
				F##_mul(t0, t1, t4);										\
				F##_add(r->y, r->y, t0);									\
				F##_mul(t0, t5, t4);										\
				F##_mul(r->x, t3, r->x);									\
				F##_sub(r->x, r->x, t0);									\
				F##_mul(t0, t3, t1);										\
				F##_mul(r->z, t5, r->z);									\
				F##_add(r->z, r->z, t0);									\
			}																\
			r->coord = PROJC;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
			F##_free(t3);													\
			F##_free(t4);													\
			F##_free(t5);													\
		}																	\
	}																		\

#endif

/**
 * Defines a template for mixed point addition in Jacobian coordinates.
 *
 * madd-2007-bl formulas: 7M + 4S + 9add + 1*4 + 3*2.
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_ADD_JACOB_MIX(C, F)											\
	static void C##_add_jacob_mix(C##_t r, const C##_t p, const C##_t q) {	\
		F##_t t0, t1, t2, t3, t4, t5;										\
																			\
		F##_null(t0);														\
		F##_null(t1);														\
		F##_null(t2);														\
		F##_null(t3);														\
		F##_null(t4);														\
		F##_null(t5);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
			F##_new(t1);													\
			F##_new(t2);													\
			F##_new(t3);													\
			F##_new(t4);													\
			F##_new(t5);													\
																			\
			if (p->coord != BASIC) {										\
				/* t0 = z1^2. */											\
				F##_sqr(t0, p->z);											\
																			\
				/* t3 = U2 = x2 * z1^2. */									\
				F##_mul(t3, q->x, t0);										\
																			\
				/* t1 = S2 = y2 * z1^3. */									\
				F##_mul(t1, t0, p->z);										\
				F##_mul(t1, t1, q->y);										\
																			\
				/* t3 = H = U2 - x1. */										\
				F##_sub(t3, t3, p->x);										\
																			\
				/* t1 = R = 2 * (S2 - y1). */								\
				F##_sub(t1, t1, p->y);										\
				F##_dbl(t1, t1);											\
			} else {														\
				/* H = x2 - x1. */											\
				F##_sub(t3, q->x, p->x);									\
																			\
				/* t1 = R = 2 * (y2 - y1). */								\
				F##_sub(t1, q->y, p->y);									\
				F##_dbl(t1, t1);											\
			}																\
																			\
			/* t2 = HH = H^2. */											\
			F##_sqr(t2, t3);												\
																			\
			/* If H is zero. */												\
			if (F##_is_zero(t3)) {											\
				if (F##_is_zero(t1)) {										\
					/* If I is zero, p = q, should have doubled. */			\
					C##_dbl_jacob(r, p);									\
				} else {													\
					/* If I is not zero, q = -p, r = infinity. */			\
					C##_set_infty(r);										\
				}															\
			} else {														\
				/* t4 = I = 4*HH. */										\
				F##_dbl(t4, t2);											\
				F##_dbl(t4, t4);											\
																			\
				/* t5 = J = H * I. */										\
				F##_mul(t5, t3, t4);										\
																			\
				/* t4 = V = x1 * I. */										\
				F##_mul(t4, p->x, t4);										\
																			\
				/* x3 = R^2 - J - 2 * V. */									\
				F##_sqr(r->x, t1);											\
				F##_sub(r->x, r->x, t5);									\
				F##_sub(r->x, r->x, t4);									\
				F##_sub(r->x, r->x, t4);									\
																			\
				/* y3 = R * (V - x3) - 2 * Y1 * J. */						\
				F##_sub(t4, t4, r->x);										\
				F##_mul(t4, t4, t1);										\
				F##_mul(t1, p->y, t5);										\
				F##_dbl(t1, t1);											\
				F##_sub(r->y, t4, t1);										\
																			\
				if (p->coord != BASIC) {									\
					/* z3 = (z1 + H)^2 - z1^2 - HH. */						\
					F##_add(r->z, p->z, t3);								\
					F##_sqr(r->z, r->z);									\
					F##_sub(r->z, r->z, t0);								\
					F##_sub(r->z, r->z, t2);								\
				} else {													\
					/* z3 = 2 * H. */										\
					F##_dbl(r->z, t3);										\
				}															\
			}																\
			r->coord = JACOB;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
			F##_free(t3);													\
			F##_free(t4);													\
			F##_free(t5);													\
		}																	\
	}																		\

/**
 * Defines a template for point addition in Jacobian coordinates.
 *
 * add-2007-bl formulas: 11M + 5S + 9add + 4*2
 * http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#if defined(EP_MIXED) && defined(STRIP)

#define TMPL_ADD_JACOB_IMP(C, F)											\
	static void C##_add_jacob_imp(C##_t r, const C##_t p, const C##_t q) {	\
		/* If code size is a problem, leave only the mixed version. */		\
		C##_add_jacob_mix(r, p, q);											\
	}																		\

#else

#define TMPL_ADD_JACOB_IMP(C, F)											\
	static void C##_add_jacob_imp(C##_t r, const C##_t p, const C##_t q) {	\
		F##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		if (q->coord == BASIC) {											\
			C##_add_jacob_mix(r, p, q);										\
			return;															\
		}																	\
																			\
		F##_null(t0);														\
		F##_null(t1);														\
		F##_null(t2);														\
		F##_null(t3);														\
		F##_null(t4);														\
		F##_null(t5);														\
		F##_null(t6);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
			F##_new(t1);													\
			F##_new(t2);													\
			F##_new(t3);													\
			F##_new(t4);													\
			F##_new(t5);													\
			F##_new(t6);													\
																			\
			/* t0 = z1^2. */												\
			F##_sqr(t0, p->z);												\
																			\
			/* t1 = z2^2. */												\
			F##_sqr(t1, q->z);												\
																			\
			/* t2 = U1 = x1 * z2^2. */										\
			F##_mul(t2, p->x, t1);											\
																			\
			/* t3 = U2 = x2 * z1^2. */										\
			F##_mul(t3, q->x, t0);											\
																			\
			/* t6 = z1^2 + z2^2. */											\
			F##_add(t6, t0, t1);											\
																			\
			/* t0 = S2 = y2 * z1^3. */										\
			F##_mul(t0, t0, p->z);											\
			F##_mul(t0, t0, q->y);											\
																			\
			/* t1 = S1 = y1 * z2^3. */										\
			F##_mul(t1, t1, q->z);											\
			F##_mul(t1, t1, p->y);											\
																			\
			/* t3 = H = U2 - U1. */											\
			F##_sub(t3, t3, t2);											\
																			\
			/* t0 = R = 2 * (S2 - S1). */									\
			F##_sub(t0, t0, t1);											\
			F##_dbl(t0, t0);												\
																			\
			/* If E is zero. */												\
			if (F##_is_zero(t3)) {											\
				if (F##_is_zero(t0)) {										\
					/* If I is zero, p = q, should have doubled. */			\
					C##_dbl_jacob(r, p);									\
				} else {													\
					/* If I is not zero, q = -p, r = infinity. */			\
					C##_set_infty(r);										\
				}															\
			} else {														\
				/* t4 = I = (2*H)^2. */										\
				F##_dbl(t4, t3);											\
				F##_sqr(t4, t4);											\
																			\
				/* t5 = J = H * I. */										\
				F##_mul(t5, t3, t4);										\
																			\
				/* t4 = V = U1 * I. */										\
				F##_mul(t4, t2, t4);										\
																			\
				/* x3 = R^2 - J - 2 * V. */									\
				F##_sqr(r->x, t0);											\
				F##_sub(r->x, r->x, t5);									\
				F##_dbl(t2, t4);											\
				F##_sub(r->x, r->x, t2);									\
																			\
				/* y3 = R * (V - x3) - 2 * S1 * J. */						\
				F##_sub(t4, t4, r->x);										\
				F##_mul(t4, t4, t0);										\
				F##_mul(t1, t1, t5);										\
				F##_dbl(t1, t1);											\
				F##_sub(r->y, t4, t1);										\
																			\
				/* z3 = ((z1 + z2)^2 - z1^2 - z2^2) * H. */					\
				F##_add(r->z, p->z, q->z);									\
				F##_sqr(r->z, r->z);										\
				F##_sub(r->z, r->z, t6);									\
				F##_mul(r->z, r->z, t3);									\
			}																\
			r->coord = JACOB;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
			F##_free(t3);													\
			F##_free(t4);													\
			F##_free(t5);													\
			F##_free(t6);													\
		}																	\
	}																		\

#endif