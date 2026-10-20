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
 * Defines a template for point tripling in affine coordinates.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_TPL_BASIC(C, F)												\
	void C##_tpl_basic(C##_t r, const C##_t p) {							\
		if (C##_is_infty(p)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		F##_t t0, t1, t2, t3, t4, t5;										\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5);								\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5);							\
																			\
			/* t0 = A = 3x^2 + a */											\
			F##_sqr(t0, p->x);												\
			F##_mul_dig(t0, t0, 3);											\
			F##_add(t0, t0, C##_curve_get_a());								\
			/* t1 = B = 2y */												\
			F##_dbl(t1, p->y);												\
			/* t2 = B^2 = 4y^2 */											\
			F##_sqr(t2, t1);												\
			/* t3 = D = A^2 - 3xB^2 */										\
			F##_sqr(t3, t0);        /* t3 = A^2 */							\
			F##_mul(t4, p->x, t2);  /* t4 = xB^2 */							\
			F##_dbl(t5, t4);												\
			F##_add(t4, t4, t5);	/* t4 = 3xB^2 */						\
			F##_sub(t3, t3, t4);    /* t3 = D (the denominator) */			\
			if (F##_is_zero(t3)) {											\
				C##_set_infty(r);											\
			} else {														\
				/* t4 = Single Inversion = 1 / (B * D) */					\
				F##_mul(t4, t1, t3);										\
				F##_inv(t4, t4);											\
				/* t3 = L1 = A * D * (1/BD) = A/B */						\
				F##_mul(t5, t0, t3);										\
				F##_mul(t3, t5, t4);										\
				/* t2 = L2 = -L1 - (B^4 * (1/BD)) = -L1 - B^3/D */			\
				F##_sqr(t5, t2);        /* t5 = B^4 */						\
				F##_mul(t5, t5, t4);    /* t5 = B^4 * (1/BD) */				\
				F##_add(t2, t3, t5);										\
				F##_neg(t2, t2);											\
				/* R->x = L2^2 - L1^2 + x1 */								\
				F##_sqr(t0, t2);        /* t0 = L2^2 */						\
				F##_sqr(t1, t3);        /* t1 = L1^2 */						\
				F##_sub(t1, t0, t1);										\
				F##_add(t1, t1, p->x);										\
				/* R->y = L2(x1 - x3) - y1 */								\
				F##_sub(t0, p->x, t1);										\
				F##_mul(t0, t0, t2);										\
				F##_sub(r->y, t0, p->y);									\
				F##_copy(r->x, t1);											\
				F##_copy(r->z, p->z);										\
				r->coord = EC_AFFIN;											\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5);							\
		}																	\
	}																		\

/**
 * Defines a template for point tripling in projective coordinates.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_TPL_PROJC(C, F)												\
	void C##_tpl_projc(C##_t r, const C##_t p) {							\
		/* The formulas are complete, including for the point at infinity	\
		 * (0 : 1 : 0). */													\
		F##_t t0, t1, t2, t3, t4;											\
		C##_t q;															\
																			\
		F##_null_all(t0, t1, t2, t3, t4);									\
		C##_null(q);														\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4);								\
			C##_new(q);														\
																			\
			if (C##_curve_opt_a() == RLC_ZERO) {							\
				/* Complete formula 3P = f'(f(P)), with the 3-isogeny		\
				 * f(X : Y : Z) = (X(Y^2 + 3bZ^2) : Y(Y^2 - 9bZ^2) :		\
				 * Z(Y^2 - bZ^2)) from y^2 = x^3 + b to y^2 = x^3 - 27b,	\
				 * the same map f' to y^2 = x^3 + 729b and then the			\
				 * isomorphism (X : Y : Z) -> (3X : Y : 27Z) back.			\
				 * Cost of 6M + 4S + 2m_b. */								\
				F##_sqr(t0, p->y);											\
				F##_sqr(t1, p->z);											\
				C##_curve_mul_b(t1, t1);									\
				F##_dbl(t2, t1);											\
				F##_add(t2, t2, t1);										\
				F##_add(t3, t0, t2);										\
				F##_mul(t3, t3, p->x);										\
				F##_dbl(t4, t2);											\
				F##_add(t2, t4, t2);										\
				F##_sub(t4, t0, t2);										\
				F##_mul(t4, t4, p->y);										\
				F##_sub(t0, t0, t1);										\
				F##_mul(t0, t0, p->z);										\
				/* With u = 27bZ^2 = 3b(3Z)^2 on f(P), f' multiplies X,		\
				 * Y and Z by Y^2 - 3u, Y^2 + 9u and Y^2 + u, and the		\
				 * results are scaled as 3X = X(3Y^2 - 9u) and				\
				 * 27Z = 9 * 3Z(Y^2 + u). */								\
				F##_dbl(t2, t0);											\
				F##_add(t0, t0, t2);										\
				F##_sqr(t1, t4);											\
				F##_sqr(t2, t0);											\
				C##_curve_mul_b(t2, t2);									\
				F##_dbl(r->x, t2);											\
				F##_add(t2, t2, r->x);										\
				F##_add(r->z, t1, t2);										\
				F##_mul(r->z, r->z, t0);									\
				for (int i = 0; i < 2; i++) {								\
					F##_dbl(r->x, t2);										\
					F##_add(t2, t2, r->x);									\
				}															\
				F##_add(r->y, t1, t2);										\
				F##_mul(r->y, r->y, t4);									\
				F##_dbl(r->x, t1);											\
				F##_add(r->x, r->x, t1);									\
				F##_sub(r->x, r->x, t2);									\
				F##_mul(r->x, r->x, t3);									\
				for (int i = 0; i < 2; i++) {								\
					F##_dbl(t0, r->z);										\
					F##_add(r->z, r->z, t0);								\
				}															\
				r->coord = EC_PROJC;									\
			} else {														\
				/* No particularly efficient formula is known, so reuse. */	\
				C##_dbl_projc(q, p);										\
				C##_add_projc(r, q, p);										\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4);								\
			C##_free(q);													\
		}																	\
	}																		\

/**
 * Defines a template for point tripling in Jacobian coordinates.
 *
 * Formulas from http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_TPL_JACOB(C, F)												\
	void C##_tpl_jacob(C##_t r, const C##_t p) {							\
		if (C##_is_infty(p)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		F##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			/* t0 = XX = X1^2 */											\
			F##_sqr(t0, p->x);												\
			/* t1 = YY = Y1^2 */											\
			F##_sqr(t1, p->y);												\
																			\
			if (C##_curve_opt_a() == RLC_ZERO) {							\
				/* Formula from https://eprint.iacr.org/2024/1906.pdf */	\
				/* t2 = Xt = 4Y1^2 - 3*X1^3.	*/							\
				F##_dbl(t2, t1);											\
				F##_dbl(t2, t2);											\
				F##_mul(t4, t0, p->x);										\
				F##_dbl(t3, t4);											\
				F##_add(t3, t3, t4);										\
				F##_sub(t2, t2, t3);										\
				/* t4 = Yt = Y1(-2Xt + 3X1^3)*/								\
				F##_dbl(t4, t2);											\
				F##_sub(t4, t3, t4);										\
				F##_mul(t4, t4, p->y);										\
				/* Z3 = 3*XtX1Z1. */										\
				if (p->coord == EC_AFFIN) {									\
					F##_mul(t1, p->x, t2);									\
				} else {													\
					F##_mul(t1, p->x, p->z);								\
					F##_mul(t1, t1, t2);									\
				}															\
				F##_dbl(r->z, t1);											\
				F##_add(r->z, r->z, t1);									\
				/* X3 = 4Yt^2 - 3*Xt^3.	*/									\
				F##_sqr(t1, t4);											\
				F##_dbl(t1, t1);											\
				F##_dbl(t1, t1);											\
				F##_sqr(t0, t2);											\
				F##_mul(t2, t0, t2);										\
				F##_dbl(t3, t2);											\
				F##_add(t3, t3, t2);										\
				F##_sub(r->x, t1, t3);										\
				/* Y3 = Yt(-2X3 + 3Xt^3)*/									\
				F##_dbl(r->y, r->x);										\
				F##_sub(r->y, t3, r->y);									\
				F##_mul(r->y, r->y, t4);									\
			} else {														\
				/* Formula from EFD */										\
				/* t2 = ZZ = Z1^2 */										\
				F##_sqr(t2, p->z);											\
				/* t3 = YYYY = YY^2 */										\
				F##_sqr(t3, t1);											\
				/* t4 = M = 3*XX + a*ZZ^2 */								\
				F##_dbl(t4, t0);											\
				F##_add(t4, t4, t0);										\
				F##_sqr(t5, t2);											\
				F##_mul(t5, t5, C##_curve_get_a());							\
				F##_add(t4, t4, t5);										\
				/* t5 = MM = M^2 */											\
				F##_sqr(t5, t4);											\
				/* t6 = E = 6*((X1+YY)^2 - XX - YYYY) - MM */				\
				F##_add(t6, p->x, t1);										\
				F##_sqr(t6, t6);											\
				F##_sub(t6, t6, t0);										\
				F##_sub(t6, t6, t3);										\
				F##_dbl(t0, t6);											\
				F##_add(t0, t0, t6);										\
				F##_dbl(t6, t0);											\
				F##_sub(t6, t6, t5);										\
				/* t0 = EE = E^2 */											\
				F##_sqr(t0, t6);											\
				/* Z3 = (Z1+E)^2 - ZZ - EE */								\
				F##_add(r->z, p->z, t6);									\
				F##_sqr(r->z, r->z);										\
				F##_sub(r->z, r->z, t2);									\
				F##_sub(r->z, r->z, t0);									\
				/* t2 = T = 16*YYYY */										\
				F##_dbl(t2, t3);											\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				F##_dbl(t2, t2);											\
				/* t3 = U = (M+E)^2 - MM - EE - T */						\
				F##_add(t3, t4, t6);										\
				F##_sqr(t3, t3);											\
				F##_sub(t3, t3, t5);										\
				F##_sub(t3, t3, t0);										\
				F##_sub(t3, t3, t2);										\
				/* X3 = 4*(X1*EE - 4*YY*U) */								\
				F##_mul(t4, p->x, t0);										\
				F##_sqr(t5, p->y);											\
				F##_dbl(t5, t5);											\
				F##_dbl(t5, t5);											\
				F##_mul(t5, t5, t3);										\
				F##_sub(r->x, t4, t5);										\
				F##_dbl(r->x, r->x);										\
				F##_dbl(r->x, r->x);										\
				/* Y3 = 8*Y1*(U*(T-U) - E*EE) */							\
				F##_sub(t4, t2, t3);										\
				F##_mul(t4, t4, t3);										\
				F##_mul(t5, t6, t0);										\
				F##_sub(t4, t4, t5);										\
				F##_mul(r->y, p->y, t4);									\
				F##_dbl(r->y, r->y);										\
				F##_dbl(r->y, r->y);										\
				F##_dbl(r->y, r->y);										\
			}																\
			r->coord = EC_JACOB;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}																		\

