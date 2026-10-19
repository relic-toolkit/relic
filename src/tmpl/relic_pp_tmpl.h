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
#include "relic_fpx_low.h"
#include "relic_fpx_dv_tmpl.h"

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
	void pp_add_k##K##_projc_basic(fp##K##_t l, C##_t r,					\
			const C##_t q, const ep_t p) {									\
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
			r->coord = EC_PROJC;												\
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
	void pp_dbl_k##K##_projc_basic(fp##K##_t l, C##_t r,					\
			const C##_t q, const ep_t p) {									\
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
			r->coord = EC_PROJC;												\
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
 * Selects the operations on unreduced elements of the twist field F used by
 * the lazy-reduced line functions: multiplication (MULN) and squaring (SQRN)
 * without reduction, addition (ADDC) and subtraction (SUBC) of unreduced
 * elements, and modular reduction (RDCN).
 */
/** @{ */
#define TMPL_PP_MULN_fp2(C, A, B)	fp2_muln_low(C, A, B)
#define TMPL_PP_SQRN_fp2(C, A)		fp2_sqrn_low(C, A)
#define TMPL_PP_ADDC_fp2(C, A, B)	fp2_addc_low(C, A, B)
#define TMPL_PP_SUBC_fp2(C, A, B)	fp2_subc_low(C, A, B)
#define TMPL_PP_RDCN_fp2(C, A)		fp2_rdcn_low(C, A)

#define TMPL_PP_MULN_fp3(C, A, B)	fp3_muln_low(C, A, B)
#define TMPL_PP_SQRN_fp3(C, A)		fp3_sqrn_low(C, A)
#define TMPL_PP_ADDC_fp3(C, A, B)	fp3_addc_low(C, A, B)
#define TMPL_PP_SUBC_fp3(C, A, B)	fp3_subc_low(C, A, B)
#define TMPL_PP_RDCN_fp3(C, A)		fp3_rdcn_low(C, A)

#define TMPL_PP_MULN_fp4(C, A, B)	fp4_mul_unr(C, A, B)
#define TMPL_PP_SQRN_fp4(C, A)		fp4_sqr_unr(C, A)
#define TMPL_PP_ADDC_fp4(C, A, B)	TMPL_DV_ADDC(fp2, dv2, 2, C, A, B)
#define TMPL_PP_SUBC_fp4(C, A, B)	TMPL_DV_SUBC(fp2, dv2, 2, C, A, B)
#define TMPL_PP_RDCN_fp4(C, A)		TMPL_DV_RDCN(fp2, dv2, 2, C, A)

#define TMPL_PP_MULN_fp8(C, A, B)	fp8_mul_unr(C, A, B)
#define TMPL_PP_SQRN_fp8(C, A)		fp8_sqr_unr(C, A)
#define TMPL_PP_ADDC_fp8(C, A, B)	TMPL_DV_ADDC(fp2, dv2, 4, C, A, B)
#define TMPL_PP_SUBC_fp8(C, A, B)	TMPL_DV_SUBC(fp2, dv2, 4, C, A, B)
#define TMPL_PP_RDCN_fp8(C, A)		TMPL_DV_RDCN(fp2, dv2, 4, C, A)

#define TMPL_PP_MULN_fp9(C, A, B)	fp9_mul_unr(C, A, B)
#define TMPL_PP_SQRN_fp9(C, A)		fp9_sqr_unr(C, A)
#define TMPL_PP_ADDC_fp9(C, A, B)	TMPL_DV_ADDC(fp3, dv3, 3, C, A, B)
#define TMPL_PP_SUBC_fp9(C, A, B)	TMPL_DV_SUBC(fp3, dv3, 3, C, A, B)
#define TMPL_PP_RDCN_fp9(C, A)		TMPL_DV_RDCN(fp3, dv3, 3, C, A)
/** @} */

/**
 * Defines a template for adding two points of a sextic twist, the first in
 * projective coordinates, and evaluating the line through them at a point,
 * with lazy reduction: each difference of two products is reduced once.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] D			- the prefix of unreduced elements of the twist field.
 */
#define TMPL_PP_ADD_LAZYR(K, C, F, D)										\
	void pp_add_k##K##_projc_lazyr(fp##K##_t l, C##_t r, const C##_t q,		\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3;												\
		D##_t u0, u1;														\
		fp_t u;																\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3);										\
		D##_null_all(u0, u1);												\
		fp_null(u);															\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3);									\
			D##_new_all(u0, u1);											\
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
			/* H = E + F - 2 * G. */										\
			F##_sub(t3, t3, r->x);											\
			F##_sub(t3, t3, r->x);											\
			/* y3 = A * (G - H) - y1 * E, reduced once. */					\
			F##_sub(r->x, r->x, t3);										\
			TMPL_PP_MULN_##F(u0, t1, r->x);									\
			TMPL_PP_MULN_##F(u1, t2, r->y);									\
			TMPL_PP_SUBC_##F(u1, u0, u1);									\
			TMPL_PP_RDCN_##F(r->y, u1);										\
			/* x3 = B * H. */												\
			F##_mul(r->x, t0, t3);											\
			/* z3 = z1 * E. */												\
			F##_mul(r->z, r->z, t2);										\
																			\
			/* l10 = - (A * xp). */											\
			fp_neg(u, p->x);												\
			F##_mul_fp(TMPL_PP_LX_##K(l), t1, u);							\
																			\
			/* l11 = J = A * x2 - B * y2, reduced once. */					\
			TMPL_PP_MULN_##F(u0, q->x, t1);									\
			TMPL_PP_MULN_##F(u1, q->y, t0);									\
			TMPL_PP_SUBC_##F(u0, u0, u1);									\
			TMPL_PP_RDCN_##F(TMPL_PP_LJ_##K(l), u0);						\
			TMPL_PP_ART_##K(l)												\
																			\
			/* l00 = B * yp. */												\
			F##_mul_fp(TMPL_PP_LY_##K(l), t0, p->y);						\
																			\
			r->coord = EC_PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3);									\
			D##_free_all(u0, u1);											\
			fp_free(u);														\
		}																	\
	}

/**
 * Defines a template for doubling a point of a sextic twist in projective
 * coordinates and evaluating the tangent line at a point, with lazy
 * reduction: y3 = (B + G)^2 - 3(2D)^2 is reduced once.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] D			- the prefix of unreduced elements of the twist field.
 */
#define TMPL_PP_DBL_LAZYR(K, C, F, D)										\
	void pp_dbl_k##K##_projc_lazyr(fp##K##_t l, C##_t r, const C##_t q,		\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4, t5, t6;									\
		D##_t u0, u1;														\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
		D##_null_all(u0, u1);												\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
			D##_new_all(u0, u1);											\
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
			/* y3 = (B + G)^2 - 3(2D)^2, reduced once. */					\
			F##_add(t6, t6, t1);											\
			F##_dbl(t2, t3);												\
			TMPL_PP_SQRN_##F(u1, t2);										\
			TMPL_PP_ADDC_##F(u0, u1, u1);									\
			TMPL_PP_ADDC_##F(u1, u0, u1);									\
			TMPL_PP_SQRN_##F(u0, t6);										\
			TMPL_PP_SUBC_##F(u0, u0, u1);									\
			TMPL_PP_RDCN_##F(r->y, u0);										\
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
			r->coord = EC_PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
			D##_free_all(u0, u1);											\
		}																	\
	}

/**
 * Defines a template for adding two points of a quartic twist, the first in
 * Jacobian coordinates, and evaluating the line through them at a point, with
 * lazy reduction: each difference of two products is reduced once.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 * @param[in] D			- the prefix of unreduced elements of the twist field.
 */
#define TMPL_PP_ADD_LAZYR4(K, C, F, D)										\
	void pp_add_k##K##_projc_lazyr(fp##K##_t l, C##_t r, const C##_t q,		\
			const ep_t p) {													\
		F##_t t0, t1, t2, t3, t4, t5;										\
		D##_t u0, u1;														\
		fp_t u;																\
																			\
		TMPL_PP_TWIST_##K													\
																			\
		F##_null_all(t0, t1, t2, t3, t4, t5);								\
		D##_null_all(u0, u1);												\
		fp_null(u);															\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4, t5);							\
			D##_new_all(u0, u1);											\
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
			/* l = E*X2 - F*Y2 - E*xQ + F*yQ, with E*X2 - F*Y2 reduced once. */\
			TMPL_PP_MULN_##F(u0, t3, q->x);									\
			TMPL_PP_MULN_##F(u1, t4, q->y);									\
			TMPL_PP_SUBC_##F(u0, u0, u1);									\
			TMPL_PP_RDCN_##F(TMPL_PP_LJ_##K(l), u0);						\
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
			/* y3 = ((F + E)^2 - E^2 - F^2)*(x1*G - x3) - y1*G^2, with lazy	\
			 * reduction. */												\
			F##_sub(t4, t4, r->z);											\
			F##_sub(t4, t4, t3);											\
			F##_mul(t1, r->x, t2);											\
			F##_sub(t1, t1, t5);											\
			TMPL_PP_MULN_##F(u0, t4, t1);									\
			F##_sqr(t2, t2);												\
			TMPL_PP_MULN_##F(u1, r->y, t2);									\
			TMPL_PP_SUBC_##F(u0, u0, u1);									\
			TMPL_PP_RDCN_##F(r->y, u0);										\
																			\
			/* Z3 = 2*F^2. */												\
			F##_dbl(r->z, r->z);											\
			F##_copy(r->x, t5);												\
																			\
			r->coord = EC_PROJC;												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4, t5);							\
			D##_free_all(u0, u1);											\
			fp_free(u);														\
		}																	\
	}

/**
 * Defines a template for adding two points of a quartic twist, the first in
 * Jacobian coordinates, and evaluating the line through them at a point.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_ADD_PROJC4(K, C, F)											\
	void pp_add_k##K##_projc_basic(fp##K##_t l, C##_t r, const C##_t q,		\
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
			r->coord = EC_PROJC;												\
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
 */
#define TMPL_PP_DBL_PROJC4(K, C, F)											\
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
			r->coord = EC_PROJC;												\
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
		if (p->coord == EC_AFFIN) {											\
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
		r->coord = EC_AFFIN;													\
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
#if EP_ADD == EP_BASIC
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
		for (j = 0; j < m; j++) {											\
			ep_null(_p[j]);													\
			C##_null(_q[j]);												\
		}																	\
																			\
		RLC_TRY {															\
			fp##K##_new(l);													\
			for (j = 0; j < m; j++) {										\
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
			r->coord = EC_PROJC;												\
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
			r->coord = EC_PROJC;												\
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
 * Defines the helpers of the pairing with a fixed point of G_2. A table keeps
 * two elements of the twist field per line, the coefficients of x_P and of
 * the constant term, both divided by the coefficient of y_P, which the final
 * exponentiation then removes. A table whose first two elements are zero
 * stands for the point at infinity, as the constant term of a real line is
 * not zero.
 *
 * The lines are linear in the coordinates of the point they are evaluated
 * at, so a line function evaluated at the point (1, 1) gives its three
 * coefficients, which pp_rec_kK() stores in the next entry of the table,
 * keeping the coefficient of y_P in Y. pp_lin_kK() evaluates the next stored
 * line at P into L, which must have been zero outside the slots of a line.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_LIN(K, F)													\
	static void pp_rec_k##K(F##_t *t, F##_t *y, int *j,						\
			const fp##K##_t l) {											\
		if (*j >= RLC_PP_TABLE_K##K / 2) {									\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		F##_copy(t[2 * *j], TMPL_PP_LX_##K(l));								\
		F##_copy(t[2 * *j + 1], TMPL_PP_LJ_##K(l));							\
		F##_copy(y[*j], TMPL_PP_LY_##K(l));									\
		(*j)++;																\
	}																		\
																			\
	static void pp_lin_k##K(fp##K##_t l, const F##_t *t, int *j,			\
			const ep_t p) {													\
		F##_mul_fp(TMPL_PP_LX_##K(l), t[2 * *j], p->x);						\
		fp_copy(TMPL_PP_LY0_##K(l), p->y);									\
		F##_copy(TMPL_PP_LJ_##K(l), t[2 * *j + 1]);							\
		(*j)++;																\
	}

/**
 * Defines a template for precomputing the lines of the optimal ate pairing
 * with a fixed point of G_2. It runs the Miller loop of TMPL_PP_MIL on Q
 * alone, recording each line at the point (1, 1), and then the final lines
 * of TMPL_PP_PRE_FIN_K, before normalizing all lines with a simultaneous
 * inversion. TMPL_PP_PAR_K adjusts the loop parameter of the family.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_MAP_PRE(K, C, F)											\
	void pp_map_pre_k##K(F##_t *t, const C##_t q) {							\
		F##_t *y = RLC_ALLOCA(F##_t, RLC_PP_TABLE_K##K / 2);				\
		C##_t r, _q, n;														\
		fp##K##_t l;														\
		ep_t e;																\
		bn_t a;																\
		size_t len = RLC_FP_BITS + 1;										\
		int8_t s[RLC_FP_BITS + 1];											\
		int i, j = 0;														\
																			\
		if (y == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		C##_null_all(r, _q, n);												\
		fp##K##_null(l);													\
		ep_null(e);															\
		bn_null(a);															\
		for (i = 0; i < RLC_PP_TABLE_K##K / 2; i++) {						\
			F##_null(y[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			C##_new_all(r, _q, n);											\
			fp##K##_new(l);													\
			ep_new(e);														\
			bn_new(a);														\
			for (i = 0; i < RLC_PP_TABLE_K##K / 2; i++) {					\
				F##_new(y[i]);												\
			}																\
																			\
			C##_norm(_q, q);												\
			F##_zero(t[0]);													\
			F##_zero(t[1]);													\
			if (!C##_is_infty(_q)) {										\
				fp_set_dig(e->x, 1);										\
				fp_set_dig(e->y, 1);										\
				fp_set_dig(e->z, 1);										\
				e->coord = EC_AFFIN;										\
				fp_prime_get_par(a);										\
				TMPL_PP_PAR_##K(a)											\
				bn_rec_naf(s, &len, a, 2);									\
				C##_copy(r, _q);											\
				C##_neg(n, _q);												\
																			\
				for (i = len - 2; i >= 0; i--) {							\
					fp##K##_zero(l);										\
					pp_dbl_k##K(l, r, r, e);								\
					pp_rec_k##K(t, y, &j, l);								\
					if (s[i] != 0) {										\
						fp##K##_zero(l);									\
						pp_add_k##K(l, r, s[i] > 0 ? _q : n, e);			\
						pp_rec_k##K(t, y, &j, l);							\
					}														\
				}															\
				/* For a negative parameter, T = aQ. */						\
				if (bn_sign(a) == RLC_NEG) {								\
					C##_neg(r, r);											\
				}															\
				TMPL_PP_PRE_FIN_##K(t, y, &j, l, r, _q, e)					\
																			\
				/* Divide each line by its coefficient of y_P. */			\
				F##_inv_sim(y, (const F##_t *)y, j);						\
				for (i = 0; i < j; i++) {									\
					F##_mul(t[2 * i], t[2 * i], y[i]);						\
					F##_mul(t[2 * i + 1], t[2 * i + 1], y[i]);				\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free_all(r, _q, n);											\
			fp##K##_free(l);												\
			ep_free(e);														\
			bn_free(a);														\
			for (i = 0; i < RLC_PP_TABLE_K##K / 2; i++) {					\
				F##_free(y[i]);												\
			}																\
			RLC_FREE(y);													\
		}																	\
	}

/**
 * Defines a template for the optimal ate pairing with a fixed point of G_2,
 * given by the table of TMPL_PP_MAP_PRE. It replays the Miller loop over the
 * same parameter, evaluating the stored lines at P, and then the final lines
 * of TMPL_PP_FIX_FIN_K, before the final exponentiation. The doubling lines
 * are evaluated at the point that TMPL_PP_MIL_P_K prepares, and the others
 * at P.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_MAP_FIX(K, F)												\
	void pp_map_fix_k##K(fp##K##_t r, const ep_t p, const F##_t *t) {		\
		fp##K##_t l;														\
		ep_t _p, d;															\
		bn_t a;																\
		size_t len = RLC_FP_BITS + 1;										\
		int8_t s[RLC_FP_BITS + 1];											\
		int i, j = 0;														\
																			\
		fp##K##_null(l);													\
		ep_null_all(_p, d);													\
		bn_null(a);															\
																			\
		RLC_TRY {															\
			fp##K##_new(l);													\
			ep_new_all(_p, d);												\
			bn_new(a);														\
																			\
			fp##K##_set_dig(r, 1);											\
			ep_norm(_p, p);													\
			if (!ep_is_infty(_p) &&											\
					!(F##_is_zero(t[0]) && F##_is_zero(t[1]))) {			\
				TMPL_PP_MIL_P_##K(d, _p)									\
				fp_prime_get_par(a);										\
				TMPL_PP_PAR_##K(a)											\
				bn_rec_naf(s, &len, a, 2);									\
				fp##K##_zero(l);											\
																			\
				for (i = len - 2; i >= 0; i--) {							\
					pp_lin_k##K(l, t, &j, d);								\
					if (j == 1) {											\
						fp##K##_copy(r, l);									\
					} else {												\
						fp##K##_sqr(r, r);									\
						fp##K##_mul_dxs(r, r, l);							\
					}														\
					if (s[i] != 0) {										\
						pp_lin_k##K(l, t, &j, _p);							\
						fp##K##_mul_dxs(r, r, l);							\
					}														\
				}															\
				/* For a negative parameter, f_{a,Q} = 1/f_{|a|,Q}. */		\
				if (bn_sign(a) == RLC_NEG) {								\
					fp##K##_inv_cyc(r, r);									\
				}															\
				TMPL_PP_FIX_FIN_##K(r, l, t, &j, _p, d, 1)					\
				pp_exp_k##K(r, r);											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp##K##_free(l);												\
			ep_free_all(_p, d);												\
			bn_free(a);														\
		}																	\
	}

/**
 * Defines a template for a product of optimal ate pairings in which some
 * points of G_2 are fixed, given by the tables of TMPL_PP_MAP_PRE. All pairs
 * share the squarings of one Miller loop and the final exponentiation: the
 * other pairs run the point arithmetic of TMPL_PP_MIL, and the fixed ones
 * evaluate their stored lines as in TMPL_PP_MAP_FIX. TMPL_PP_FIN_K applies
 * the step that the family takes on the whole product and the final lines of
 * the other pairs, and TMPL_PP_FIX_FIN_K the final lines of the fixed pairs,
 * taking that step itself only when there are no other pairs.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] F			- the prefix of the twist field.
 */
#define TMPL_PP_MAP_SIM_FIX(K, C, F)										\
	void pp_map_sim_fix_k##K(fp##K##_t r, const ep_t *p, const C##_t *q,	\
			int m, const ep_t *s, const F##_t **t, int n) {					\
		/* One more element each, so that no allocation is empty. */		\
		ep_t *_p = RLC_ALLOCA(ep_t, 2 * (m + n) + 1), *e, *_s, *d;			\
		C##_t *_q = RLC_ALLOCA(C##_t, 3 * m + 1), *u, *v;					\
		const F##_t **_t = RLC_ALLOCA(const F##_t *, n + 1);				\
		fp##K##_t l, h;														\
		bn_t a;																\
		size_t len = RLC_FP_BITS + 1;										\
		int8_t w[RLC_FP_BITS + 1];											\
		int i, j, k, c = 0, mm = 0, nn = 0, first = 1;						\
																			\
		if (_p == NULL || _q == NULL || _t == NULL) {						\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(_t);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		e = _p + m;															\
		_s = e + m;															\
		d = _s + n;															\
		u = _q + m;															\
		v = u + m;															\
																			\
		fp##K##_null_all(l, h);												\
		bn_null(a);															\
		for (i = 0; i < 2 * (m + n) + 1; i++) {								\
			ep_null(_p[i]);													\
		}																	\
		for (i = 0; i < 3 * m + 1; i++) {									\
			C##_null(_q[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			fp##K##_new_all(l, h);											\
			bn_new(a);														\
			for (i = 0; i < 2 * (m + n) + 1; i++) {							\
				ep_new(_p[i]);												\
			}																\
			for (i = 0; i < 3 * m + 1; i++) {								\
				C##_new(_q[i]);												\
			}																\
																			\
			/* Pairs with a point at infinity contribute nothing. */		\
			for (i = 0; i < m; i++) {										\
				if (!ep_is_infty(p[i]) && !C##_is_infty(q[i])) {			\
					ep_norm(_p[mm], p[i]);									\
					C##_norm(_q[mm], q[i]);									\
					C##_copy(u[mm], _q[mm]);								\
					C##_neg(v[mm], _q[mm]);									\
					TMPL_PP_MIL_P_##K(e[mm], _p[mm])						\
					mm++;													\
				}															\
			}																\
			for (i = 0; i < n; i++) {										\
				if (!ep_is_infty(s[i]) &&									\
						!(F##_is_zero(t[i][0]) && F##_is_zero(t[i][1]))) {	\
					ep_norm(_s[nn], s[i]);									\
					TMPL_PP_MIL_P_##K(d[nn], _s[nn])						\
					_t[nn++] = t[i];										\
				}															\
			}																\
																			\
			fp##K##_set_dig(r, 1);											\
			if (mm + nn > 0) {												\
				fp_prime_get_par(a);										\
				TMPL_PP_PAR_##K(a)											\
				bn_rec_naf(w, &len, a, 2);									\
				/* The fixed pairs use their own line, as pp_lin_k##K()		\
				 * keeps the slots that it does not write. */				\
				fp##K##_zero(l);											\
				fp##K##_zero(h);											\
																			\
				for (i = len - 2; i >= 0; i--) {							\
					if (!first) {											\
						fp##K##_sqr(r, r);									\
					}														\
					for (j = 0; j < mm; j++) {								\
						pp_dbl_k##K(l, u[j], u[j], e[j]);					\
						if (first) {										\
							fp##K##_copy(r, l);								\
							first = 0;										\
						} else {											\
							fp##K##_mul_dxs(r, r, l);						\
						}													\
					}														\
					for (j = 0; j < nn; j++) {								\
						k = c;												\
						pp_lin_k##K(h, _t[j], &k, d[j]);					\
						if (first) {										\
							fp##K##_copy(r, h);								\
							first = 0;										\
						} else {											\
							fp##K##_mul_dxs(r, r, h);						\
						}													\
					}														\
					c++;													\
					if (w[i] != 0) {										\
						for (j = 0; j < mm; j++) {							\
							pp_add_k##K(l, u[j], w[i] > 0 ? _q[j] : v[j],	\
									_p[j]);									\
							fp##K##_mul_dxs(r, r, l);						\
						}													\
						for (j = 0; j < nn; j++) {							\
							k = c;											\
							pp_lin_k##K(h, _t[j], &k, _s[j]);				\
							fp##K##_mul_dxs(r, r, h);						\
						}													\
						c++;												\
					}														\
				}															\
				/* For a negative parameter, f = 1/f_{|a|,Q} and T = aQ. */	\
				if (bn_sign(a) == RLC_NEG) {								\
					fp##K##_inv_cyc(r, r);									\
					for (j = 0; j < mm; j++) {								\
						C##_neg(u[j], u[j]);								\
					}														\
				}															\
				if (mm > 0) {												\
					TMPL_PP_FIN_##K(r, u, _q, _p, mm)						\
				}															\
				for (j = 0; j < nn; j++) {									\
					k = c;													\
					TMPL_PP_FIX_FIN_##K(r, h, _t[j], &k, _s[j], d[j],		\
							mm == 0 && j == 0)								\
				}															\
				pp_exp_k##K(r, r);											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			fp##K##_free_all(l, h);											\
			bn_free(a);														\
			for (i = 0; i < 2 * (m + n) + 1; i++) {							\
				ep_free(_p[i]);												\
			}																\
			for (i = 0; i < 3 * m + 1; i++) {								\
				C##_free(_q[i]);											\
			}																\
			RLC_FREE(_p);													\
			RLC_FREE(_q);													\
			RLC_FREE(_t);													\
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
