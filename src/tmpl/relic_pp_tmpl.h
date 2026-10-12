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
 * embedding degree 24, 48 and 54, and Miller loops for 12, 16, 18, 24, 48
 * and 54.
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

/**
 * Selects the final step of the Miller loop of degree K, which evaluates at
 * P the lines that the loop over the parameter leaves out. It only exists for
 * K = 54, where the optimal ate pairing needs f^3 times three more lines. For
 * K = 12 and 18 the final lines depend on the curve family, so the callers
 * add them.
 */
/** @{ */
#define TMPL_PP_FIN_12(R, T, Q, P, _P, M)	/* Added by the callers. */
#define TMPL_PP_FIN_18(R, T, Q, P, _P, M)	/* Added by the callers. */
#define TMPL_PP_FIN_24(R, T, Q, P, _P, M)	/* No final lines. */
#define TMPL_PP_FIN_48(R, T, Q, P, _P, M)	/* No final lines. */
#define TMPL_PP_FIN_54(R, T, Q, P, _P, M)	pp_fin_k54(R, T, Q, P, _P, M);
/** @} */

/**
 * Prepares the point of G_1 at which the doubling line is evaluated: its
 * negation for affine coordinates, and (3x_P, -y_P) for projective ones.
 *
 * @param[out] R		- the prepared point.
 * @param[in] P			- the point of G_1.
 */
#if EP_ADD == BASIC
#define TMPL_PP_MIL_P(R, P)		ep_neg(R, P);
#else
#define TMPL_PP_MIL_P(R, P)													\
	fp_add(R->x, P->x, P->x);												\
	fp_add(R->x, R->x, P->x);												\
	fp_neg(R->y, P->y);
#endif

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
				TMPL_PP_MIL_P(_p[j], p[j])									\
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
																			\
			TMPL_PP_FIN_##K(r, t, q, p, _p, m)								\
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
 * Defines a template for the optimal ate pairing.
 *
 * @param[in] K			- the embedding degree.
 * @param[in] C			- the prefix of the twisted curve.
 * @param[in] T			- the family of pairing-friendly curves.
 */
#define TMPL_PP_MAP(K, C, T)												\
	void pp_map_k##K(fp##K##_t r, const ep_t p, const C##_t q) {			\
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
#define TMPL_PP_MAP_SIM(K, C, T)											\
	void pp_map_sim_k##K(fp##K##_t r, const ep_t *p, const C##_t *q,		\
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

#endif /* !RLC_PP_TMPL_H */
