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
 * Templates for pairings over curves with twists: line functions for
 * embedding degree 24, 48 and 54 (also for points of G_1 on sextic twists),
 * Miller loops for 8, 12, 16, 18, 24, 48 and 54, and pairings.
 *
 * @ingroup pp
 */

#ifndef RLC_PP_TMPL_H
#define RLC_PP_TMPL_H

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Selects where a line function stores its coefficients in the sparse element
 * of the extension field of degree K: the twist field element multiplied by
 * x_P (LX), the one multiplied by y_P (LY) and its first coordinate in the
 * prime field (LY0), and the constant term (LJ). ART applies the correction of
 * the constant term for D-type twists, and TWIST rejects the twist types that
 * have no coefficient placement.
 */
/** @{ */
#define TMPL_PP_LX_24(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[2][0] : L[1][1])
#define TMPL_PP_LY_24(L)		L[0][1]
#define TMPL_PP_LY0_24(L)		L[0][1][0][0]
#define TMPL_PP_LJ_24(L)		L[0][0]
#define TMPL_PP_ART_24(L)													\
	if (ep4_curve_is_twist() != RLC_EP_MTYPE) {								\
		fp4_mul_art(L[0][0], L[0][0]);										\
	}
#define TMPL_PP_TWIST_24		/* Both twist types are supported. */

#define TMPL_PP_LX_48(L)		L[0][1]
#define TMPL_PP_LY_48(L)		L[1][1]
#define TMPL_PP_LY0_48(L)		L[1][1][0][0][0]
#define TMPL_PP_LJ_48(L)		L[0][0]
#define TMPL_PP_ART_48(L)		/* Only M-type twists are supported. */
#define TMPL_PP_TWIST_48													\
	if (ep8_curve_is_twist() != RLC_EP_MTYPE) {								\
		RLC_THROW(ERR_NO_VALID);											\
		return;																\
	}

#define TMPL_PP_LX_54(L)		L[2][0]
#define TMPL_PP_LY_54(L)		L[0][1]
#define TMPL_PP_LY0_54(L)		L[0][1][0][0]
#define TMPL_PP_LJ_54(L)		L[0][0]
#define TMPL_PP_ART_54(L)		/* Only M-type twists are supported. */
#define TMPL_PP_TWIST_54													\
	if (ep9_curve_is_twist() != RLC_EP_MTYPE) {								\
		RLC_THROW(ERR_NO_VALID);											\
		return;																\
	}
/** @} */

/**
 * Defines a template for adding two points and evaluating the line through
 * them at a point in affine coordinates.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_ADD_BASIC(K, C, F)											\
	void pp_add_k##K##_basic(fp##K##_t l, C##_t r, const C##_t q,			\
			const ep_t p) {													\
		F##_t s;															\
		C##_t t;															\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null(s);														\
		C##_null(t);														\
																			\
		RLC_TRY {															\
			F##_new(s);														\
			C##_new(t);														\
																			\
			C##_copy(t, r);													\
			C##_add_slp_basic(r, s, r, q);									\
			fp##K##_zero(l);												\
																			\
			F##_mul_fp(TMPL_PP_LX_##K(l), s, p->x);							\
			F##_mul(TMPL_PP_LJ_##K(l), s, t->x);							\
			F##_sub(TMPL_PP_LJ_##K(l), t->y, TMPL_PP_LJ_##K(l));			\
			TMPL_PP_ART_##K(l)												\
			fp_neg(TMPL_PP_LY0_##K(l), p->y);								\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free(s);													\
			C##_free(t);													\
		}																	\
	}

/**
 * Defines a template for adding two points and evaluating the line through
 * them at a point in affine coordinates, with the first point in projective
 * coordinates.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] N			- the suffix of the function name.
 */
#define TMPL_PP_ADD_PROJC(K, C, F, N)										\
	void pp_add_k##K##_##N(fp##K##_t l, C##_t r, const C##_t q,			\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4;											\
		fp_t u;																\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4);									\
		fp_null(u);															\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4);								\
			fp_new(u);														\
																			\
			/* B = t0 = x1 - x2 * z1. */									\
			F##_mul(t0, r->z, q->x);										\
			F##_sub(t0, r->x, t0);											\
			/* A = t1 = y1 - y2 * z1. */									\
			F##_mul(t1, r->z, q->y);										\
			F##_sub(t1, r->y, t1);											\
																			\
			/* D = B^2. */													\
			F##_sqr(t2, t0);												\
			/* G = x1 * D. */												\
			F##_mul(r->x, r->x, t2);										\
			/* E = B^3. */													\
			F##_mul(t2, t2, t0);											\
			/* C = A^2. */													\
			F##_sqr(t3, t1);												\
			/* F = E + z1 * C. */											\
			F##_mul(t3, t3, r->z);											\
			F##_add(t3, t2, t3);											\
																			\
			/* l10 = - (A * xp). */											\
			fp_neg(u, p->x);												\
			F##_mul_fp(TMPL_PP_LX_##K(l), t1, u);							\
																			\
			/* t4 = A * x2. */												\
			F##_mul(t4, q->x, t1);											\
																			\
			/* H = E + F - 2 * G. */										\
			F##_sub(t3, t3, r->x);											\
			F##_sub(t3, t3, r->x);											\
			/* y3 = A * (G - H) - y1 * E. */								\
			F##_sub(r->x, r->x, t3);										\
			F##_mul(t1, t1, r->x);											\
			F##_mul(r->y, t2, r->y);										\
			F##_sub(r->y, t1, r->y);										\
			/* x3 = B * H. */												\
			F##_mul(r->x, t0, t3);											\
			/* z3 = z1 * E. */												\
			F##_mul(r->z, r->z, t2);										\
																			\
			/* l11 = J = A * x2 - B * y2. */								\
			F##_mul(t2, q->y, t0);											\
			F##_sub(TMPL_PP_LJ_##K(l), t4, t2);								\
			TMPL_PP_ART_##K(l)												\
																			\
			/* l00 = B * yp. */												\
			F##_mul_fp(TMPL_PP_LY_##K(l), t0, p->y);						\
																			\
			r->coord = PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4);								\
			fp_free(u);														\
		}																	\
	}

/**
 * Defines a template for doubling a point and evaluating the tangent line at
 * a point in affine coordinates.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_DBL_BASIC(K, C, F)											\
	void pp_dbl_k##K##_basic(fp##K##_t l, C##_t r, const C##_t q,			\
			const ep_t p) {													\
		F##_t s;															\
		C##_t t;															\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null(s);														\
		C##_null(t);														\
																			\
		RLC_TRY {															\
			F##_new(s);														\
			C##_new(t);														\
																			\
			C##_copy(t, q);													\
			C##_dbl_slp_basic(r, s, q);										\
			fp##K##_zero(l);												\
																			\
			F##_mul_fp(TMPL_PP_LX_##K(l), s, p->x);							\
			F##_mul(TMPL_PP_LJ_##K(l), s, t->x);							\
			F##_sub(TMPL_PP_LJ_##K(l), t->y, TMPL_PP_LJ_##K(l));			\
			TMPL_PP_ART_##K(l)												\
			fp_copy(TMPL_PP_LY0_##K(l), p->y);								\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free(s);													\
			C##_free(t);													\
		}																	\
	}

/**
 * Defines a template for doubling a point in projective coordinates and
 * evaluating the tangent line at a point in affine coordinates.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] N			- the suffix of the function name.
 */
#define TMPL_PP_DBL_PROJC(K, C, F, N)										\
	void pp_dbl_k##K##_##N(fp##K##_t l, C##_t r, const C##_t q,			\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			/* A = x1^2. */													\
			F##_sqr(t0, q->x);												\
			/* B = y1^2. */													\
			F##_sqr(t1, q->y);												\
			/* C = z1^2. */													\
			F##_sqr(t2, q->z);												\
			/* D = 3bC, with b from the twisted curve. */					\
			F##_dbl(t3, t2);												\
			F##_add(t3, t3, t2);											\
			F##_mul(t3, t3, C##_curve_get_b());								\
			/* E = (x1 + y1)^2 - A - B. */									\
			F##_add(t4, q->x, q->y);										\
			F##_sqr(t4, t4);												\
			F##_sub(t4, t4, t0);											\
			F##_sub(t4, t4, t1);											\
			/* F = (y1 + z1)^2 - B - C. */									\
			F##_add(t5, q->y, q->z);										\
			F##_sqr(t5, t5);												\
			F##_sub(t5, t5, t1);											\
			F##_sub(t5, t5, t2);											\
			/* G = 3D. */													\
			F##_dbl(t6, t3);												\
			F##_add(t6, t6, t3);											\
			/* x3 = E * (B - G). */											\
			F##_sub(r->x, t1, t6);											\
			F##_mul(r->x, r->x, t4);										\
			/* y3 = (B + G)^2 -12D^2. */									\
			F##_add(t6, t6, t1);											\
			F##_sqr(t6, t6);												\
			F##_sqr(t2, t3);												\
			F##_dbl(r->y, t2);												\
			F##_dbl(t2, r->y);												\
			F##_dbl(r->y, t2);												\
			F##_add(r->y, r->y, t2);										\
			F##_sub(r->y, t6, r->y);										\
			/* z3 = 4B * F. */												\
			F##_dbl(r->z, t1);												\
			F##_dbl(r->z, r->z);											\
			F##_mul(r->z, r->z, t5);										\
																			\
			/* l11 = D - B. */												\
			F##_sub(TMPL_PP_LJ_##K(l), t3, t1);								\
			TMPL_PP_ART_##K(l)												\
			/* l10 = (3 * xp) * A. */										\
			F##_mul_fp(TMPL_PP_LX_##K(l), t0, p->x);						\
			/* l00 = F * (-yp). */											\
			F##_mul_fp(TMPL_PP_LY_##K(l), t5, p->y);						\
																			\
			r->coord = PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Selects where the line functions of curves with embedding degree 8, 12, 16
 * and 18 store their coefficients, as the selectors above do for K = 24, 48
 * and 54: the term multiplied by x_P (LX), the one multiplied by y_P (LY) and
 * its first coordinate in the prime field (LY0), and the remaining term (LJ).
 * M-type twists swap the positions, and no correction of LJ is needed.
 */
/** @{ */
#define TMPL_PP_LX_8(L)														\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][1] : L[1][0])
#define TMPL_PP_LY_8(L)														\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LJ_8(L)														\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LY0_8(L)	TMPL_PP_LY_8(L)[0]
#define TMPL_PP_ART_8(L)	/* No correction of LJ. */

#define TMPL_PP_LX_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][1] : L[1][0])
#define TMPL_PP_LY_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LJ_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LY0_12(L)	TMPL_PP_LY_12(L)[0]
#define TMPL_PP_ART_12(L)	/* No correction of LJ. */

#define TMPL_PP_LX_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[0][1] : L[1][0])
#define TMPL_PP_LY_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LJ_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LY0_16(L)	TMPL_PP_LY_16(L)[0][0]
#define TMPL_PP_ART_16(L)	/* No correction of LJ. */

#define TMPL_PP_LX_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[0][1] : L[1][0])
#define TMPL_PP_LY_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LJ_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LY0_18(L)	TMPL_PP_LY_18(L)[0]
#define TMPL_PP_ART_18(L)	/* No correction of LJ. */
/** @} */

/**
 * Defines a template for adding two points of a quartic twist, the first in
 * Jacobian coordinates, and evaluating the line through them at a point.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] N			- the suffix of the function name.
 */
#define TMPL_PP_ADD_PROJC4(K, C, F, N)										\
	void pp_add_k##K##_##N(fp##K##_t l, C##_t r, const C##_t q,				\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4, t5;										\
		fp_t u;																\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5);								\
		fp_null(u);															\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5);							\
			fp_new(u);														\
																			\
			/* t0 = A = Z1^2, t1 = B = X2*Z1. */							\
			F##_sqr(t0, r->z);												\
			F##_mul(t1, r->z, q->x);										\
																			\
			/* t0 = C = y2*A, t2 = D = (x1 - B) */							\
			F##_mul(t0, t0, q->y);											\
			F##_sub(t2, r->x, t1);											\
																			\
			/* t3 = E = 2*(y1 - C), t4 = F = 2*D*z1, t2 = G = 4*D*F. */		\
			F##_sub(t3, r->y, t0);											\
			F##_dbl(t3, t3);												\
			F##_dbl(t2, t2);												\
			F##_mul(t4, t2, r->z);											\
			F##_mul(t2, t2, t4);											\
			F##_dbl(t2, t2);												\
																			\
			/* l = E*X2 - F*Y2 - E*xQ + F*yQ. */							\
			F##_mul(TMPL_PP_LJ_##K(l), t3, q->x);							\
			F##_mul(t0, t4, q->y);											\
			F##_sub(TMPL_PP_LJ_##K(l), TMPL_PP_LJ_##K(l), t0);				\
			fp_neg(u, p->x);												\
			F##_mul_fp(TMPL_PP_LX_##K(l), t3, u);							\
			F##_mul_fp(TMPL_PP_LY_##K(l), t4, p->y);						\
																			\
			/* z3 = F^2, t4 = (F + E)^2, t3 = E^2. */						\
			F##_sqr(r->z, t4);												\
			F##_add(t4, t4, t3);											\
			F##_sqr(t4, t4);												\
			F##_sqr(t3, t3);												\
																			\
			/* t5 = x3 = 2*E^2 - (x1 + B)*G. */								\
			F##_add(t1, t1, r->x);											\
			F##_mul(t1, t1, t2);											\
			F##_dbl(t5, t3);												\
			F##_sub(t5, t5, t1);											\
																			\
			/* y3 = ((F + E)^2 - E^2 - F^2)*(x1*G - x3) - y1*G^2. */		\
			F##_sub(t4, t4, r->z);											\
			F##_sub(t4, t4, t3);											\
			F##_mul(t1, r->x, t2);											\
			F##_sub(t1, t1, t5);											\
			F##_mul(t4, t4, t1);											\
			F##_sqr(t2, t2);												\
			F##_mul(r->y, r->y, t2);										\
			F##_sub(r->y, t4, r->y);										\
																			\
			/* Z3 = 2*F^2. */												\
			F##_dbl(r->z, r->z);											\
			F##_copy(r->x, t5);												\
																			\
			r->coord = PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5);							\
			fp_free(u);														\
		}																	\
	}

/**
 * Defines a template for doubling a point of a quartic twist in Jacobian
 * coordinates and evaluating the tangent line at a point.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] N			- the suffix of the function name.
 */
#define TMPL_PP_DBL_PROJC4(K, C, F, N)										\
	void pp_dbl_k##K##_##N(fp##K##_t l, C##_t r, const C##_t q,				\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			/* t0 = A = X1^2, t1 = B = Y1^2, t2 = C = Z1^2, t3 = D = a*C. */\
			F##_sqr(t0, q->x);												\
			F##_sqr(t1, q->y);												\
			F##_sqr(t2, q->z);												\
			C##_curve_mul_a(t3, t2);										\
																			\
			/* x3 = (A - D)^2, l11 = (A - D + x1)^2 - x3 - A. */			\
			F##_sub(t5, t0, t3);											\
			F##_add(TMPL_PP_LJ_##K(l), t5, q->x);							\
			F##_sqr(r->x, t5);												\
			F##_sqr(TMPL_PP_LJ_##K(l), TMPL_PP_LJ_##K(l));					\
			F##_sub(TMPL_PP_LJ_##K(l), TMPL_PP_LJ_##K(l), r->x);			\
			F##_sub(TMPL_PP_LJ_##K(l), TMPL_PP_LJ_##K(l), t0);				\
																			\
			/* l10 := -xp*z1*2*(3A + D). */									\
			F##_add(t6, t0, t3);											\
			F##_dbl(t0, t0);												\
			F##_add(t0, t0, t6);											\
			F##_dbl(t0, t0);												\
			F##_mul(TMPL_PP_LX_##K(l), t0, q->z);							\
			F##_mul_fp(TMPL_PP_LX_##K(l), TMPL_PP_LX_##K(l), p->x);			\
																			\
			/* l01 = 2*((y1 + z1)^2 - B - C)*yP. */							\
			F##_add(TMPL_PP_LY_##K(l), q->y, q->z);							\
			F##_sqr(TMPL_PP_LY_##K(l), TMPL_PP_LY_##K(l));					\
			F##_sub(TMPL_PP_LY_##K(l), TMPL_PP_LY_##K(l), t1);				\
			F##_sub(TMPL_PP_LY_##K(l), TMPL_PP_LY_##K(l), t2);				\
			F##_dbl(TMPL_PP_LY_##K(l), TMPL_PP_LY_##K(l));					\
			F##_mul_fp(TMPL_PP_LY_##K(l), TMPL_PP_LY_##K(l), p->y);			\
																			\
			/* t4 = E = 2*(A + D)^2 - x3. */								\
			F##_sqr(t4, t6);												\
			F##_dbl(t4, t4);												\
			F##_sub(t4, t4, r->x);											\
			/* y3 = E * ((A - D + y1)^2 - B - x3). */						\
			F##_add(r->y, t5, q->y);										\
			F##_sqr(r->y, r->y);											\
			F##_sub(r->y, r->y, t1);										\
			F##_sub(r->y, r->y, r->x);										\
			F##_mul(r->y, r->y, t4);										\
			/* z3 = 4*B. */													\
			F##_dbl(r->z, t1);												\
			F##_dbl(r->z, r->z);											\
																			\
			r->coord = PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for converting a point of the twist used by the Miller
 * loop to affine coordinates. Curves with quartic twists, where b = 0, keep
 * that point in Jacobian coordinates, so y is divided by z twice.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_NORM(K, C, F)												\
	void pp_norm_k##K(C##_t r, const C##_t p) {								\
		if (C##_is_infty(p)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (p->coord == BASIC) {											\
			/* If the point is in affine coordinates, just copy it. */		\
			C##_copy(r, p);													\
			return;															\
		}																	\
		F##_inv(r->z, p->z);												\
		F##_mul(r->x, p->x, r->z);											\
		F##_mul(r->y, p->y, r->z);											\
		if (ep_curve_opt_b() == RLC_ZERO) {									\
			F##_mul(r->y, r->y, r->z);										\
		}																	\
		F##_set_dig(r->z, 1);												\
		r->coord = BASIC;													\
	}

/**
 * Selects how the Miller loop of degree K prepares the point of G_1 for the
 * doubling lines: its negation for affine coordinates, and for projective
 * ones (3x_P, -y_P) with sextic twists or (-x_P, y_P) with quartic twists
 * (K = 8 and 16).
 *
 * @param[out] R		- the prepared point.
 * @param[in] P			- the point of G_1.
 */
/** @{ */
#if EP_ADD == BASIC
#define TMPL_PP_MIL_P6(R, P)	ep_neg(R, P);
#define TMPL_PP_MIL_P4(R, P)	ep_neg(R, P);
#else
#define TMPL_PP_MIL_P6(R, P)												\
	fp_add(R->x, P->x, P->x);												\
	fp_add(R->x, R->x, P->x);												\
	fp_neg(R->y, P->y);
#define TMPL_PP_MIL_P4(R, P)												\
	fp_neg(R->x, P->x);														\
	fp_copy(R->y, P->y);
#endif
#define TMPL_PP_MIL_P_8(R, P)	TMPL_PP_MIL_P4(R, P)
#define TMPL_PP_MIL_P_12(R, P)	TMPL_PP_MIL_P6(R, P)
#define TMPL_PP_MIL_P_16(R, P)	TMPL_PP_MIL_P4(R, P)
#define TMPL_PP_MIL_P_18(R, P)	TMPL_PP_MIL_P6(R, P)
#define TMPL_PP_MIL_P_24(R, P)	TMPL_PP_MIL_P6(R, P)
#define TMPL_PP_MIL_P_48(R, P)	TMPL_PP_MIL_P6(R, P)
#define TMPL_PP_MIL_P_54(R, P)	TMPL_PP_MIL_P6(R, P)
/** @} */

/**
 * Defines a template for the Miller loop of pairings of type G_2 x G_1 over
 * the bits of a given parameter represented in sparse form.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MIL(K, C)													\
	static void pp_mil_k##K(fp##K##_t r, C##_t *t, C##_t *q, ep_t *p, int m,\
			bn_t a) {														\
		fp##K##_t l;														\
		ep_t *_p = NULL;													\
		C##_t *_q = NULL;													\
		size_t len = bn_bits(a) + 1;										\
		int i, j;															\
		int8_t s[RLC_FP_BITS + 1];											\
																			\
		if (m == 0) {														\
			return;															\
		}																	\
																			\
		/* Allocate after the early return, so that it does not leak. */	\
		_p = RLC_ALLOCA(ep_t, m);											\
		_q = RLC_ALLOCA(C##_t, m);											\
		if (_p == NULL || _q == NULL) {										\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		fp##K##_null(l);													\
																			\
		RLC_TRY {															\
			fp##K##_new(l);													\
			for (j = 0; j < m; j++) {										\
				ep_null(_p[j]);												\
				C##_null(_q[j]);											\
				ep_new(_p[j]);												\
				C##_new(_q[j]);												\
				C##_copy(t[j], q[j]);										\
				C##_neg(_q[j], q[j]);										\
				TMPL_PP_MIL_P_##K(_p[j], p[j])								\
			}																\
																			\
			fp##K##_zero(l);												\
			bn_rec_naf(s, &len, a, 2);										\
			pp_dbl_k##K(r, t[0], t[0], _p[0]);								\
			for (j = 1; j < m; j++) {										\
				pp_dbl_k##K(l, t[j], t[j], _p[j]);							\
				fp##K##_mul_dxs(r, r, l);									\
			}																\
			if (s[len - 2] > 0) {											\
				for (j = 0; j < m; j++) {									\
					pp_add_k##K(l, t[j], q[j], p[j]);						\
					fp##K##_mul_dxs(r, r, l);								\
				}															\
			}																\
			if (s[len - 2] < 0) {											\
				for (j = 0; j < m; j++) {									\
					pp_add_k##K(l, t[j], _q[j], p[j]);						\
					fp##K##_mul_dxs(r, r, l);								\
				}															\
			}																\
																			\
			for (i = len - 3; i >= 0; i--) {								\
				fp##K##_sqr(r, r);											\
				for (j = 0; j < m; j++) {									\
					pp_dbl_k##K(l, t[j], t[j], _p[j]);						\
					fp##K##_mul_dxs(r, r, l);								\
					if (s[i] > 0) {											\
						pp_add_k##K(l, t[j], q[j], p[j]);					\
						fp##K##_mul_dxs(r, r, l);							\
					}														\
					if (s[i] < 0) {											\
						pp_add_k##K(l, t[j], _q[j], p[j]);					\
						fp##K##_mul_dxs(r, r, l);							\
					}														\
				}															\
			}																\
																			\
			/* For a negative parameter, f_{a,Q} = 1/f_{|a|,Q} and T = aQ. */\
			if (bn_sign(a) == RLC_NEG) {									\
				fp##K##_inv_cyc(r, r);										\
				for (j = 0; j < m; j++) {									\
					C##_neg(t[j], t[j]);									\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp##K##_free(l);												\
			for (j = 0; j < m; j++) {										\
				ep_free(_p[j]);												\
				C##_free(_q[j]);											\
			}																\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
		}																	\
	}

/**
 * Defines a template for the Miller loop of pairings of type G_1 x G_2 over
 * the bits of a given parameter, as used by the Tate and Weil pairings.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MIL_LIT(K, C)												\
	static void pp_mil_lit_k##K(fp##K##_t r, ep_t *t, ep_t *p, C##_t *q,	\
			int m, bn_t a) {												\
		fp##K##_t l;														\
		C##_t *_q = RLC_ALLOCA(C##_t, m);									\
		int i, j;															\
																			\
		fp##K##_null(l);													\
																			\
		if (_q == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		for (j = 0; j < m; j++) {											\
			C##_null(_q[j]);												\
		}																	\
																			\
		RLC_TRY {															\
			fp##K##_new(l);													\
			for (j = 0; j < m; j++) {										\
				C##_new(_q[j]);												\
				ep_copy(t[j], p[j]);										\
				C##_neg(_q[j], q[j]);										\
			}																\
																			\
			fp##K##_zero(l);												\
			for (i = bn_bits(a) - 2; i >= 0; i--) {							\
				fp##K##_sqr(r, r);											\
				for (j = 0; j < m; j++) {									\
					pp_dbl_lit_k##K(l, t[j], t[j], _q[j]);					\
					fp##K##_mul(r, r, l);									\
					if (bn_get_bit(a, i)) {									\
						pp_add_lit_k##K(l, t[j], p[j], q[j]);				\
						fp##K##_mul(r, r, l);								\
					}														\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp##K##_free(l);												\
			for (j = 0; j < m; j++) {										\
				C##_free(_q[j]);											\
			}																\
			RLC_FREE(_q);													\
		}																	\
	}

/**
 * Selects where the line functions evaluated at a point Q of the twist store
 * their coefficients in the sparse element of the extension field of degree
 * K: the term multiplied by x_Q (LIT_X), the one multiplied by y_Q (LIT_Y),
 * the constant term (LIT_J) and its first coordinate in the prime field
 * (LIT_J0). With w^6 the non-residue xi that defines a sextic twist, a D-type
 * twist maps Q to (x_Q * w^2, y_Q * w^3). An M-type twist maps Q to
 * (x_Q * w^4 / xi, y_Q * w^3 / xi), and the lines are multiplied by w^3 so
 * that the coefficients land on w, 1 and w^3 without scaling Q. Quartic
 * twists (K = 8 and 16) work the same with w^4 = xi.
 */
/** @{ */
#define TMPL_PP_LIT_X_8(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][0] : L[0][1])
#define TMPL_PP_LIT_Y_8(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LIT_J_8(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LIT_J0_8(L)		TMPL_PP_LIT_J_8(L)[0]
#define TMPL_PP_TWIST_8			/* Both twist types are supported. */

#define TMPL_PP_LIT_X_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][0] : L[0][1])
#define TMPL_PP_LIT_Y_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LIT_J_12(L)													\
	(ep2_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LIT_J0_12(L)	TMPL_PP_LIT_J_12(L)[0]
#define TMPL_PP_TWIST_12		/* Both twist types are supported. */

#define TMPL_PP_LIT_X_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[1][0] : L[0][1])
#define TMPL_PP_LIT_Y_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LIT_J_16(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LIT_J0_16(L)	TMPL_PP_LIT_J_16(L)[0][0]
#define TMPL_PP_TWIST_16		/* Both twist types are supported. */

#define TMPL_PP_LIT_X_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[1][0] : L[0][1])
#define TMPL_PP_LIT_Y_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[1][1])
#define TMPL_PP_LIT_J_18(L)													\
	(ep3_curve_is_twist() == RLC_EP_MTYPE ? L[1][1] : L[0][0])
#define TMPL_PP_LIT_J0_18(L)	TMPL_PP_LIT_J_18(L)[0]
#define TMPL_PP_TWIST_18		/* Both twist types are supported. */

#define TMPL_PP_LIT_X_24(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[1][0] : L[2][0])
#define TMPL_PP_LIT_Y_24(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[0][0] : L[0][1])
#define TMPL_PP_LIT_J_24(L)													\
	(ep4_curve_is_twist() == RLC_EP_MTYPE ? L[0][1] : L[0][0])
#define TMPL_PP_LIT_J0_24(L)	TMPL_PP_LIT_J_24(L)[0][0]

#define TMPL_PP_LIT_X_48(L)		L[1][0]
#define TMPL_PP_LIT_Y_48(L)		L[0][0]
#define TMPL_PP_LIT_J_48(L)		L[1][1]
#define TMPL_PP_LIT_J0_48(L)	L[1][1][0][0][0]

#define TMPL_PP_LIT_X_54(L)		L[1][0]
#define TMPL_PP_LIT_Y_54(L)		L[0][0]
#define TMPL_PP_LIT_J_54(L)		L[0][1]
#define TMPL_PP_LIT_J0_54(L)	L[0][1][0][0]
/** @} */

/**
 * Defines a template for doubling a point of G_1 in projective coordinates
 * and evaluating the line through it at a point of the twist, for curves
 * y^2 = x^3 + b.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_DBL_LIT(K, C, F)											\
	void pp_dbl_lit_k##K(fp##K##_t l, ep_t r, const ep_t p, const C##_t q) {\
		fp_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		fp_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			fp_new_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
			fp_sqr(t0, p->x);												\
			fp_sqr(t1, p->y);												\
			fp_sqr(t2, p->z);												\
																			\
			fp_mul(t4, ep_curve_get_b(), t2);								\
																			\
			fp_dbl(t3, t4);													\
			fp_add(t3, t3, t4);												\
																			\
			fp_add(t4, p->x, p->y);											\
			fp_sqr(t4, t4);													\
			fp_sub(t4, t4, t0);												\
			fp_sub(t4, t4, t1);												\
			fp_add(t5, p->y, p->z);											\
			fp_sqr(t5, t5);													\
			fp_sub(t5, t5, t1);												\
			fp_sub(t5, t5, t2);												\
			fp_dbl(t6, t3);													\
			fp_add(t6, t6, t3);												\
			fp_sub(r->x, t1, t6);											\
			fp_mul(r->x, r->x, t4);											\
			fp_add(r->y, t1, t6);											\
			fp_sqr(r->y, r->y);												\
			fp_sqr(t4, t3);													\
			fp_dbl(t6, t4);													\
			fp_add(t6, t6, t4);												\
			fp_dbl(t6, t6);													\
			fp_dbl(t6, t6);													\
			fp_sub(r->y, r->y, t6);											\
			fp_mul(r->z, t1, t5);											\
			fp_dbl(r->z, r->z);												\
			fp_dbl(r->z, r->z);												\
			r->coord = PROJC;												\
																			\
			F##_dbl(TMPL_PP_LIT_X_##K(l), q->x);							\
			F##_add(TMPL_PP_LIT_X_##K(l), TMPL_PP_LIT_X_##K(l), q->x);		\
			F##_mul_fp(TMPL_PP_LIT_X_##K(l), TMPL_PP_LIT_X_##K(l), t0);		\
			F##_zero(TMPL_PP_LIT_J_##K(l));									\
			fp_sub(TMPL_PP_LIT_J0_##K(l), t3, t1);							\
			F##_mul_fp(TMPL_PP_LIT_Y_##K(l), q->y, t5);						\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for doubling a point of G_1 in projective coordinates
 * and evaluating the line through it at a point of the twist, for curves
 * y^2 = x^3 + ax + b with a != 0, as the ones with quartic twists (K = 8
 * and 16).
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_DBL_LIT4(K, C, F)											\
	void pp_dbl_lit_k##K(fp##K##_t l, ep_t r, const ep_t p, const C##_t q) {\
		fp_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		fp_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			fp_new_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
			/* The tangent has slope (3X^2 + aZ^2)/(2YZ), so compute		\
			 * t0 = 3X^2 + aZ^2, t3 = 3bZ^2 + 2aXZ, t1 = Y^2 and t5 = 2YZ. */\
			fp_sqr(t0, p->x);												\
			fp_dbl(t4, t0);													\
			fp_add(t0, t0, t4);												\
			fp_sqr(t2, p->z);												\
			fp_mul(t4, ep_curve_get_a(), t2);								\
			fp_add(t0, t0, t4);												\
			fp_mul(t4, ep_curve_get_b(), t2);								\
			fp_dbl(t3, t4);													\
			fp_add(t3, t3, t4);												\
			fp_mul(t6, p->x, p->z);											\
			fp_mul(t6, t6, ep_curve_get_a());								\
			fp_dbl(t6, t6);													\
			fp_add(t3, t3, t6);												\
			fp_sqr(t1, p->y);												\
			fp_mul(t5, p->y, p->z);											\
			fp_dbl(t5, t5);													\
			/* Double the point after reading it, since r may alias p. */	\
			ep_dbl_projc(r, p);												\
																			\
			F##_mul_fp(TMPL_PP_LIT_X_##K(l), q->x, t0);						\
			F##_zero(TMPL_PP_LIT_J_##K(l));									\
			fp_sub(TMPL_PP_LIT_J0_##K(l), t3, t1);							\
			F##_mul_fp(TMPL_PP_LIT_Y_##K(l), q->y, t5);						\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for adding two points of G_1, the first in projective
 * coordinates, and evaluating the line through them at a point of the twist.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_ADD_LIT(K, C, F)											\
	void pp_add_lit_k##K(fp##K##_t l, ep_t r, const ep_t p, const C##_t q) {\
		fp_t t0, t1, t2, t3;												\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		fp_null_all(t0, t1, t2, t3);										\
																			\
		RLC_TRY {															\
			fp_new_all(t0, t1, t2, t3);										\
																			\
			fp_mul(t0, r->z, p->x);											\
			fp_sub(t0, r->x, t0);											\
			fp_mul(t1, r->z, p->y);											\
			fp_sub(t1, r->y, t1);											\
			fp_mul(t2, p->x, t1);											\
			r->coord = PROJC;												\
																			\
			F##_zero(TMPL_PP_LIT_J_##K(l));									\
			fp_mul(TMPL_PP_LIT_J0_##K(l), t0, p->y);						\
			fp_sub(TMPL_PP_LIT_J0_##K(l), t2, TMPL_PP_LIT_J0_##K(l));		\
			F##_mul_fp(TMPL_PP_LIT_X_##K(l), q->x, t1);						\
			F##_neg(TMPL_PP_LIT_X_##K(l), TMPL_PP_LIT_X_##K(l));			\
			F##_mul_fp(TMPL_PP_LIT_Y_##K(l), q->y, t0);						\
																			\
			fp_sqr(t2, t0);													\
			fp_mul(r->x, t2, r->x);											\
			fp_mul(t2, t0, t2);												\
			fp_sqr(t3, t1);													\
			fp_mul(t3, t3, r->z);											\
			fp_add(t3, t2, t3);												\
			fp_sub(t3, t3, r->x);											\
			fp_sub(t3, t3, r->x);											\
			fp_sub(r->x, r->x, t3);											\
			fp_mul(t1, t1, r->x);											\
			fp_mul(r->y, t2, r->y);											\
			fp_sub(r->y, t1, r->y);											\
			fp_mul(r->x, t0, t3);											\
			fp_mul(r->z, r->z, t2);											\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp_free_all(t0, t1, t2, t3);									\
		}																	\
	}

/**
 * Selects the final lines of the optimal ate pairing of degree K, which
 * evaluate at P the lines that the loop over the parameter leaves out. Only
 * K = 54 has them: f^3 times three more lines. Degrees 12, 16 and 18 add
 * their family-specific final lines by hand.
 */
/** @{ */
#define TMPL_PP_FIN_8(R, T, Q, P, M)	/* No final lines. */
#define TMPL_PP_FIN_24(R, T, Q, P, M)	/* No final lines. */
#define TMPL_PP_FIN_48(R, T, Q, P, M)	/* No final lines. */
#define TMPL_PP_FIN_54(R, T, Q, P, M)	pp_fin_k54(R, T, Q, P, M);
/** @} */

/**
 * Defines a template for the optimal ate pairing, including its final lines.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] T			- the family of pairing-friendly curves.
 */
#define TMPL_PP_MAP_OATEP(K, C, T)											\
	void pp_map_oatep_k##K(fp##K##_t r, const ep_t p, const C##_t q) {		\
		ep_t _p[1];															\
		C##_t t[1], _q[1];													\
		bn_t a;																\
																			\
		ep_null(_p[0]);														\
		C##_null(_q[0]);													\
		C##_null(t[0]);														\
		bn_null(a);															\
																			\
		RLC_TRY {															\
			ep_new(_p[0]);													\
			C##_new(_q[0]);													\
			C##_new(t[0]);													\
			bn_new(a);														\
																			\
			fp_prime_get_par(a);											\
			fp##K##_set_dig(r, 1);											\
																			\
			ep_norm(_p[0], p);												\
			C##_norm(_q[0], q);												\
																			\
			if (!ep_is_infty(_p[0]) && !C##_is_infty(_q[0])) {				\
				switch (ep_curve_is_pairf()) {								\
					case T:													\
						/* r = f_{a,Q}(P). */								\
						pp_mil_k##K(r, t, _q, _p, 1, a);					\
						TMPL_PP_FIN_##K(r, t, _q, _p, 1)					\
						pp_exp_k##K(r, r);									\
						break;												\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			ep_free(_p[0]);													\
			C##_free(_q[0]);												\
			C##_free(t[0]);													\
			bn_free(a);														\
		}																	\
	}

/**
 * Defines a template for the product of optimal ate pairings.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] T			- the family of pairing-friendly curves.
 */
#define TMPL_PP_MAP_SIM_OATEP(K, C, T)										\
	void pp_map_sim_oatep_k##K(fp##K##_t r, const ep_t *p, const C##_t *q,	\
			int m) {														\
		ep_t *_p = RLC_ALLOCA(ep_t, m);										\
		C##_t *t = RLC_ALLOCA(C##_t, m), *_q = RLC_ALLOCA(C##_t, m);		\
		bn_t a;																\
		int i, j;															\
																			\
		if (_p == NULL || _q == NULL || t == NULL) {						\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(t);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		bn_null(a);															\
		for (i = 0; i < m; i++) {											\
			ep_null(_p[i]);													\
			C##_null(_q[i]);												\
			C##_null(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new(a);														\
			for (i = 0; i < m; i++) {										\
				ep_new(_p[i]);												\
				C##_new(_q[i]);												\
				C##_new(t[i]);												\
			}																\
																			\
			j = 0;															\
			for (i = 0; i < m; i++) {										\
				if (!ep_is_infty(p[i]) && !C##_is_infty(q[i])) {			\
					ep_norm(_p[j], p[i]);									\
					C##_norm(_q[j++], q[i]);								\
				}															\
			}																\
																			\
			fp_prime_get_par(a);											\
			fp##K##_set_dig(r, 1);											\
																			\
			if (j > 0) {													\
				switch (ep_curve_is_pairf()) {								\
					case T:													\
						/* r = f_{a,Q}(P). */								\
						pp_mil_k##K(r, t, _q, _p, j, a);					\
						TMPL_PP_FIN_##K(r, t, _q, _p, j)					\
						pp_exp_k##K(r, r);									\
						break;												\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(a);														\
			for (i = 0; i < m; i++) {										\
				ep_free(_p[i]);												\
				C##_free(_q[i]);											\
				C##_free(t[i]);												\
			}																\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(t);													\
		}																	\
	}

/**
 * Defines a template for the Tate pairing.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MAP_TATEP(K, C)												\
	void pp_map_tatep_k##K(fp##K##_t r, const ep_t p, const C##_t q) {		\
		ep_t _p[1], t[1];													\
		C##_t _q[1];														\
		bn_t n;																\
																			\
		ep_null(_p[0]);														\
		ep_null(t[0]);														\
		C##_null(_q[0]);													\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			ep_new(_p[0]);													\
			ep_new(t[0]);													\
			C##_new(_q[0]);													\
			bn_new(n);														\
																			\
			ep_norm(_p[0], p);												\
			C##_norm(_q[0], q);												\
			ep_curve_get_ord(n);											\
			fp##K##_set_dig(r, 1);											\
																			\
			if (!ep_is_infty(_p[0]) && !C##_is_infty(_q[0])) {				\
				pp_mil_lit_k##K(r, t, _p, _q, 1, n);						\
				pp_exp_k##K(r, r);											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			ep_free(_p[0]);													\
			ep_free(t[0]);													\
			C##_free(_q[0]);												\
			bn_free(n);														\
		}																	\
	}

/**
 * Defines a template for the product of Tate pairings.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MAP_SIM_TATEP(K, C)											\
	void pp_map_sim_tatep_k##K(fp##K##_t r, const ep_t *p, const C##_t *q,	\
			int m) {														\
		ep_t *_p = RLC_ALLOCA(ep_t, m), *t = RLC_ALLOCA(ep_t, m);			\
		C##_t *_q = RLC_ALLOCA(C##_t, m);									\
		bn_t n;																\
		int i, j;															\
																			\
		if (_p == NULL || _q == NULL || t == NULL) {						\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(t);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		bn_null(n);															\
		for (i = 0; i < m; i++) {											\
			ep_null(_p[i]);													\
			ep_null(t[i]);													\
			C##_null(_q[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			for (i = 0; i < m; i++) {										\
				ep_new(_p[i]);												\
				ep_new(t[i]);												\
				C##_new(_q[i]);												\
			}																\
																			\
			j = 0;															\
			for (i = 0; i < m; i++) {										\
				if (!ep_is_infty(p[i]) && !C##_is_infty(q[i])) {			\
					ep_norm(_p[j], p[i]);									\
					C##_norm(_q[j++], q[i]);								\
				}															\
			}																\
																			\
			ep_curve_get_ord(n);											\
			fp##K##_set_dig(r, 1);											\
			if (j > 0) {													\
				pp_mil_lit_k##K(r, t, _p, _q, j, n);						\
				pp_exp_k##K(r, r);											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
			for (i = 0; i < m; i++) {										\
				ep_free(_p[i]);												\
				ep_free(t[i]);												\
				C##_free(_q[i]);											\
			}																\
			RLC_FREE(_p);													\
			RLC_FREE(t);													\
			RLC_FREE(_q);													\
		}																	\
	}

/**
 * Defines a template for the Weil pairing, computed as
 * (f_{n-1,P}(Q) / f_{n-1,Q}(P))^(2(p^(K/2) - 1)) to remove the factors in
 * proper subfields that the twist introduces.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MAP_WEILP(K, C)												\
	void pp_map_weilp_k##K(fp##K##_t r, const ep_t p, const C##_t q) {		\
		ep_t _p[1], t0[1];													\
		C##_t _q[1], t1[1];													\
		fp##K##_t r0, r1;													\
		bn_t n;																\
																			\
		ep_null(_p[0]);														\
		ep_null(t0[0]);														\
		C##_null(_q[0]);													\
		C##_null(t1[0]);													\
		fp##K##_null(r0);													\
		fp##K##_null(r1);													\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			ep_new(_p[0]);													\
			ep_new(t0[0]);													\
			C##_new(_q[0]);													\
			C##_new(t1[0]);													\
			fp##K##_new(r0);												\
			fp##K##_new(r1);												\
			bn_new(n);														\
																			\
			ep_norm(_p[0], p);												\
			C##_norm(_q[0], q);												\
																			\
			ep_curve_get_ord(n);											\
			bn_sub_dig(n, n, 1);											\
			fp##K##_set_dig(r0, 1);											\
			fp##K##_set_dig(r1, 1);											\
																			\
			if (!ep_is_infty(_p[0]) && !C##_is_infty(_q[0])) {				\
				pp_mil_k##K(r1, t1, _q, _p, 1, n);							\
				pp_mil_lit_k##K(r0, t0, _p, _q, 1, n);						\
				fp##K##_inv(r1, r1);										\
				fp##K##_mul(r0, r0, r1);									\
				fp##K##_inv(r1, r0);										\
				fp##K##_inv_cyc(r0, r0);									\
			}																\
			fp##K##_mul(r, r0, r1);											\
			fp##K##_sqr(r, r);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			ep_free(_p[0]);													\
			ep_free(t0[0]);													\
			C##_free(_q[0]);												\
			C##_free(t1[0]);												\
			fp##K##_free(r0);												\
			fp##K##_free(r1);												\
			bn_free(n);														\
		}																	\
	}

/**
 * Defines a template for the product of Weil pairings.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 */
#define TMPL_PP_MAP_SIM_WEILP(K, C)											\
	void pp_map_sim_weilp_k##K(fp##K##_t r, const ep_t *p, const C##_t *q,	\
			int m) {														\
		ep_t *_p = RLC_ALLOCA(ep_t, m), *t0 = RLC_ALLOCA(ep_t, m);			\
		C##_t *_q = RLC_ALLOCA(C##_t, m), *t1 = RLC_ALLOCA(C##_t, m);		\
		fp##K##_t r0, r1;													\
		bn_t n;																\
		int i, j;															\
																			\
		if (_p == NULL || _q == NULL || t0 == NULL || t1 == NULL) {			\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(t0);													\
			RLC_FREE(t1);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		fp##K##_null(r0);													\
		fp##K##_null(r1);													\
		bn_null(n);															\
		for (i = 0; i < m; i++) {											\
			ep_null(_p[i]);													\
			ep_null(t0[i]);													\
			C##_null(_q[i]);												\
			C##_null(t1[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			fp##K##_new(r0);												\
			fp##K##_new(r1);												\
			bn_new(n);														\
			for (i = 0; i < m; i++) {										\
				ep_new(_p[i]);												\
				ep_new(t0[i]);												\
				C##_new(_q[i]);												\
				C##_new(t1[i]);												\
			}																\
																			\
			j = 0;															\
			for (i = 0; i < m; i++) {										\
				if (!ep_is_infty(p[i]) && !C##_is_infty(q[i])) {			\
					ep_norm(_p[j], p[i]);									\
					C##_norm(_q[j++], q[i]);								\
				}															\
			}																\
																			\
			ep_curve_get_ord(n);											\
			bn_sub_dig(n, n, 1);											\
			fp##K##_set_dig(r0, 1);											\
			fp##K##_set_dig(r1, 1);											\
																			\
			if (j > 0) {													\
				pp_mil_k##K(r1, t1, _q, _p, j, n);							\
				pp_mil_lit_k##K(r0, t0, _p, _q, j, n);						\
				fp##K##_inv(r1, r1);										\
				fp##K##_mul(r0, r0, r1);									\
				fp##K##_inv(r1, r0);										\
				fp##K##_inv_cyc(r0, r0);									\
			}																\
			fp##K##_mul(r, r0, r1);											\
			fp##K##_sqr(r, r);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp##K##_free(r0);												\
			fp##K##_free(r1);												\
			bn_free(n);														\
			for (i = 0; i < m; i++) {										\
				ep_free(_p[i]);												\
				ep_free(t0[i]);												\
				C##_free(_q[i]);											\
				C##_free(t1[i]);											\
			}																\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(t0);													\
			RLC_FREE(t1);													\
		}																	\
	}

#endif /* !RLC_PP_TMPL_H */
