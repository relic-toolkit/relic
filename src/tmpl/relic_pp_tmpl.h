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
 * Templates for the line functions of pairings over curves with sextic twists
 * of embedding degree 24, 48 and 54.
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
 */
#define TMPL_PP_ADD_PROJC(K, C, F)											\
	void pp_add_k##K##_projc(fp##K##_t l, C##_t r, const C##_t q,			\
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
 */
#define TMPL_PP_DBL_PROJC(K, C, F)											\
	void pp_dbl_k##K##_projc(fp##K##_t l, C##_t r, const C##_t q,			\
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

#endif /* !RLC_PP_TMPL_H */
