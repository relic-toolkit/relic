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
 * Template for point doubling on prime elliptic curves.
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
#define TMPL_DBL_BASIC_IMP(C, F)											\
	static void C##_dbl_basic_imp(C##_t r, F##_t s, const C##_t p) {		\
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
			/* t0 = 1/2 * y1. */											\
			F##_dbl(t0, p->y);												\
			F##_inv(t0, t0);												\
																			\
			/* t1 = 3 * x1^2 + a. */										\
			F##_sqr(t1, p->x);												\
			F##_copy(t2, t1);												\
			F##_dbl(t1, t1);												\
			F##_add(t1, t1, t2);											\
			F##_add(t1, t1, C##_curve_get_a());								\
																			\
			/* t1 = (3 * x1^2 + a)/(2 * y1). */								\
			F##_mul(t1, t1, t0);											\
																			\
			if (s != NULL) {												\
				F##_copy(s, t1);											\
			}																\
																			\
			/* t2 = t1^2. */												\
			F##_sqr(t2, t1);												\
																			\
			/* x3 = t1^2 - 2 * x1. */										\
			F##_dbl(t0, p->x);												\
			F##_sub(t0, t2, t0);											\
																			\
			/* y3 = t1 * (x1 - x3) - y1. */									\
			F##_sub(t2, p->x, t0);											\
			F##_mul(t1, t1, t2);											\
			F##_sub(r->y, t1, p->y);										\
																			\
			F##_copy(r->x, t0);												\
			F##_copy(r->z, p->z);											\
																			\
			r->coord = BASIC;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t0);													\
			F##_free(t1);													\
			F##_free(t2);													\
		}																	\
	}																		\

/**
 * Defines a template for point addition in affine coordinates.
 *
 * Formulas for point doubling from
 * "Complete addition formulas for prime order elliptic curves"
 * by Joost Renes, Craig Costello, and Lejla Batina
 * https://eprint.iacr.org/2015/1060.pdf
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_DBL_PROJC_IMP(C, F)											\
	static void C##_dbl_projc_imp(C##_t r, const C##_t p) {					\
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
			if (C##_curve_opt_a() == RLC_ZERO) {							\
				/* Cost of 6M + 2S + 1m_3b + 9a. */							\
				F##_sqr(t0, p->y);											\
				F##_mul(t3, p->x, p->y);									\
																			\
				if (p->coord == BASIC) {									\
					/* Save 1M + 1S + 1m_b3 if z1 = 1. */					\
					F##_copy(t1, p->y);										\
					F##_dbl(t2, C##_curve_get_b());							\
					F##_add(t2, t2, C##_curve_get_b());						\
				} else {													\
					F##_mul(t1, p->y, p->z);								\
					F##_sqr(t2, p->z);										\
					F##_dbl(t5, t2);										\
					F##_add(t5, t5, t2);									\
					C##_curve_mul_b(t2, t5);								\
				}															\
				F##_dbl(r->z, t0);											\
				F##_dbl(r->z, r->z);										\
				F##_dbl(r->z, r->z);										\
				F##_mul(r->x, t2, r->z);									\
				F##_add(r->y, t0, t2);										\
				F##_mul(r->z, t1, r->z);									\
				F##_dbl(t1, t2);											\
				F##_add(t2, t1, t2);										\
				F##_sub(t0, t0, t2);										\
				F##_mul(r->y, t0, r->y);									\
				F##_add(r->y, r->x, r->y);									\
				F##_mul(r->x, t0, t3);										\
				F##_dbl(r->x, r->x);										\
			} else {														\
				F##_sqr(t0, p->x);											\
				F##_sqr(t1, p->y);											\
				F##_mul(t3, p->x, p->y);									\
				F##_dbl(t3, t3);											\
				F##_mul(t4, p->y, p->z);									\
																			\
				if (C##_curve_opt_a() == RLC_MIN3) {						\
					/* Cost of 8M + 3S + 2mb + 21a. */						\
					if (p->coord == BASIC) {								\
						/* Save 1S + 1m_b + 2a if z1 = 1. */				\
						F##_set_dig(t2, 3);									\
						F##_copy(r->y, C##_curve_get_b());					\
					} else {												\
						F##_sqr(t2, p->z);									\
						C##_curve_mul_b(r->y, t2);							\
						F##_dbl(t5, t2);									\
						F##_add(t2, t2, t5);								\
					}														\
					F##_mul(r->z, p->x, p->z);								\
					F##_dbl(r->z, r->z);									\
					F##_sub(r->y, r->y, r->z);								\
					F##_dbl(r->x, r->y);									\
					F##_add(r->y, r->x, r->y);								\
					F##_sub(r->x, t1, r->y);								\
					F##_add(r->y, t1, r->y);								\
					F##_mul(r->y, r->x, r->y);								\
					F##_mul(r->x, t3, r->x);								\
					C##_curve_mul_b(r->z, r->z);							\
					F##_sub(t3, r->z, t2);									\
					F##_sub(t3, t3, t0);									\
					F##_dbl(r->z, t3);										\
					F##_add(t3, t3, r->z);									\
					F##_dbl(r->z, t0);										\
					F##_add(t0, t0, r->z);									\
					F##_sub(t0, t0, t2);									\
				} else {													\
					/* Common cost of 8M + 3S + 3m_a + 2m_3b + 15a. */		\
					if (p->coord == BASIC) {								\
						/* Save 1S + 1m_b + 1m_a if z1 = 1. */				\
						F##_dbl(r->y, C##_curve_get_b());					\
						F##_add(r->y, r->y, C##_curve_get_b());				\
						F##_copy(t2, C##_curve_get_a());					\
					} else {												\
						F##_sqr(t2, p->z);									\
						F##_dbl(t5, t2);									\
						F##_add(t5, t5, t2);								\
						C##_curve_mul_b(r->y, t5);							\
						C##_curve_mul_a(t2, t2);							\
					}														\
					F##_mul(r->z, p->x, p->z);								\
					F##_dbl(r->z, r->z);									\
					C##_curve_mul_a(r->x, r->z);							\
					F##_add(r->y, r->x, r->y);								\
					F##_sub(r->x, t1, r->y);								\
					F##_add(r->y, t1, r->y);								\
					F##_mul(r->y, r->x, r->y);								\
					F##_mul(r->x, t3, r->x);								\
					F##_dbl(t5, r->z);										\
					F##_add(t5, t5, r->z);									\
					C##_curve_mul_b(r->z, t5);								\
					F##_sub(t3, t0, t2);									\
					C##_curve_mul_a(t3, t3);								\
					F##_add(t3, t3, r->z);									\
					F##_dbl(r->z, t0);										\
					F##_add(t0, t0, r->z);									\
					F##_add(t0, t0, t2);									\
				}															\
				/* Common part with renamed variables. */					\
				F##_mul(t0, t0, t3);										\
				F##_add(r->y, r->y, t0);									\
				F##_dbl(t2, t4);											\
				F##_mul(t0, t2, t3);										\
				F##_sub(r->x, r->x, t0);									\
				F##_mul(r->z, t2, t1);										\
				F##_dbl(r->z, r->z);										\
				F##_dbl(r->z, r->z);										\
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

/**
 * Defines a template for point addition in Jacobian coordinates.
 *
 * Formulas from http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_DBL_JACOB_IMP(C, F)											\
	static void C##_dbl_jacob_imp(C##_t r, const C##_t p) {					\
		F##_t t0, t1, t2, t3, t4, t5;										\
																			\
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
			if (p->coord != BASIC && C##_curve_opt_a() == RLC_MIN3) {		\
				/* dbl-2001-b formulas: 3M + 5S + 8add + 1*4 + 2*8 + 1*3 */	\
																			\
				/* t0 = delta = z1^2. */									\
				F##_sqr(t0, p->z);											\
																			\
				/* t1 = gamma = y1^2. */									\
				F##_sqr(t1, p->y);											\
																			\
				/* t2 = beta = x1 * y1^2. */								\
				F##_mul(t2, p->x, t1);										\
																			\
				/* t3 = alpha = 3 * (x1 - z1^2) * (x1 + z1^2). */			\
				F##_sub(t3, p->x, t0);										\
				F##_add(t4, p->x, t0);										\
				F##_mul(t4, t3, t4);										\
				F##_dbl(t3, t4);											\
				F##_add(t3, t3, t4);										\
																			\
				/* x3 = alpha^2 - 8 * beta. */								\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_dbl(t5, t2);											\
				F##_sqr(r->x, t3);											\
				F##_sub(r->x, r->x, t5);									\
																			\
				/* z3 = (y1 + z1)^2 - gamma - delta. */						\
				F##_add(r->z, p->y, p->z);									\
				F##_sqr(r->z, r->z);										\
				F##_sub(r->z, r->z, t1);									\
				F##_sub(r->z, r->z, t0);									\
																			\
				/* y3 = alpha * (4 * beta - x3) - 8 * gamma^2. */			\
				F##_dbl(t1, t1);											\
				F##_sqr(t1, t1);											\
				F##_dbl(t1, t1);											\
				F##_sub(r->y, t2, r->x);									\
				F##_mul(r->y, r->y, t3);									\
				F##_sub(r->y, r->y, t1);									\
			} else if (C##_curve_opt_a() == RLC_ZERO) {						\
				/* dbl-2009-l formulas: 2M + 5S + 6add + 1*8 + 3*2 + 1*3.*/	\
																			\
				/* A = X1^2 */												\
				F##_sqr(t0, p->x);											\
																			\
				/* B = Y1^2 */												\
				F##_sqr(t1, p->y);											\
																			\
				/* C = B^2 */												\
				F##_sqr(t2, t1);											\
																			\
				/* D = 2*((X1+B)^2-A-C) */									\
				F##_add(t1, t1, p->x);										\
				F##_sqr(t1, t1);											\
				F##_sub(t1, t1, t0);										\
				F##_sub(t1, t1, t2);										\
				F##_dbl(t1, t1);											\
																			\
				/* E = 3*A */												\
				F##_dbl(t3, t0);											\
				F##_add(t0, t3, t0);										\
																			\
				/* F = E^2 */												\
				F##_sqr(t3, t0);											\
																			\
				/* Z3 = 2*Y1*Z1 */											\
				F##_mul(r->z, p->y, p->z);									\
				F##_dbl(r->z, r->z);										\
																			\
				/* X3 = F-2*D */											\
				F##_sub(r->x, t3, t1);										\
				F##_sub(r->x, r->x, t1);									\
																			\
				/* Y3 = E*(D-X3)-8*C */										\
				F##_sub(r->y, t1, r->x);									\
				F##_mul(r->y, r->y, t0);									\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_sub(r->y, r->y, t2);									\
			} else {														\
				/* dbl-2007-bl: 1M + 8S + 1*a + 10add + 1*8 + 2*2 + 1*3 */	\
																			\
				/* t0 = x1^2, t1 = y1^2, t2 = y1^4. */						\
				F##_sqr(t0, p->x);											\
				F##_sqr(t1, p->y);											\
				F##_sqr(t2, t1);											\
																			\
				if (p->coord != BASIC) {									\
					/* t3 = z1^2. */										\
					F##_sqr(t3, p->z);										\
																			\
					if (C##_curve_opt_a() == RLC_ZERO) {					\
						/* z3 = 2 * y1 * z1. */								\
						F##_mul(r->z, p->y, p->z);							\
						F##_dbl(r->z, r->z);								\
					} else {												\
						/* z3 = (y1 + z1)^2 - y1^2 - z1^2. */				\
						F##_add(r->z, p->y, p->z);							\
						F##_sqr(r->z, r->z);								\
						F##_sub(r->z, r->z, t1);							\
						F##_sub(r->z, r->z, t3);							\
					}														\
				} else {													\
					/* z3 = 2 * y1. */										\
					F##_dbl(r->z, p->y);									\
				}															\
																			\
				/* t4 = S = 2*((x1 + y1^2)^2 - x1^2 - y1^4). */				\
				F##_add(t4, p->x, t1);										\
				F##_sqr(t4, t4);											\
				F##_sub(t4, t4, t0);										\
				F##_sub(t4, t4, t2);										\
				F##_dbl(t4, t4);											\
																			\
				/* t5 = M = 3 * x1^2 + a * z1^4. */							\
				F##_dbl(t5, t0);											\
				F##_add(t5, t5, t0);										\
				if (p->coord != BASIC) {									\
					C##_curve_mul_a(t1, t3);								\
					F##_add(t5, t5, t1);									\
				} else {													\
					F##_add(t5, t5, C##_curve_get_a());						\
				}															\
				/* x3 = T = M^2 - 2 * S. */									\
				F##_sqr(r->x, t5);											\
				F##_dbl(t1, t4);											\
				F##_sub(r->x, r->x, t1);									\
																			\
				/* y3 = M * (S - T) - 8 * y1^4. */							\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_sub(t4, t4, r->x);										\
				F##_mul(t5, t5, t4);										\
				F##_sub(r->y, t5, t2);										\
			}																\
																			\
			r->coord = JACOB;												\
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

