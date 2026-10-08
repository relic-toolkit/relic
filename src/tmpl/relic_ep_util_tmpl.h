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
 * Templates for utilities on prime elliptic curves.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Randomizes the coordinates of a point according to the chosen coordinate
 * system.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 * @param[out] R		- the result.
 * @param[in] P			- the point to randomize.
 * @param[in] T			- the random field element.
 */
#if EP_ADD == BASIC

#define TMPL_EP_BLIND_COORD(C, F, R, P, T)									\
	(void)T;																\
	C##_copy(R, P)

#elif EP_ADD == PROJC

#define TMPL_EP_BLIND_COORD(C, F, R, P, T)									\
	F##_mul(R->x, P->x, T);													\
	F##_mul(R->y, P->y, T);													\
	F##_mul(R->z, P->z, T);													\
	R->coord = PROJC

#elif EP_ADD == JACOB

#define TMPL_EP_BLIND_COORD(C, F, R, P, T)									\
	F##_mul(R->z, P->z, T);													\
	F##_mul(R->y, P->y, T);													\
	F##_sqr(T, T);															\
	F##_mul(R->x, P->x, T);													\
	F##_mul(R->y, R->y, T);													\
	R->coord = JACOB

#endif

/**
 * Normalizes a point in projective coordinates if these are enabled.
 *
 * @param[in] C			- the curve.
 * @param[out] R		- the result.
 * @param[in] P			- the point to normalize.
 * @param[in] I			- the flag to indicate if z is already inverted.
 */
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

#define TMPL_EP_NORM_CALL(C, R, P, I)		C##_norm_imp(R, P, I)

#else

#define TMPL_EP_NORM_CALL(C, R, P, I)		/* Nothing to do. */

#endif

/**
 * Defines a template for basic utilities: testing for and setting the
 * point at infinity, copying, sampling, blinding, validating and printing
 * points.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_UTIL(C, F)													\
	int C##_is_infty(const C##_t p) {										\
		return (F##_is_zero(p->z) == 1);									\
	}																		\
																			\
	void C##_set_infty(C##_t p) {											\
		F##_zero(p->x);														\
		F##_zero(p->y);														\
		F##_zero(p->z);														\
		p->coord = BASIC;													\
	}																		\
																			\
	void C##_copy(C##_t r, const C##_t p) {									\
		F##_copy(r->x, p->x);												\
		F##_copy(r->y, p->y);												\
		F##_copy(r->z, p->z);												\
		r->coord = p->coord;												\
	}																		\
																			\
	void C##_rand(C##_t p) {												\
		bn_t n, k;															\
																			\
		bn_null(k);															\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			bn_new(k);														\
			bn_new(n);														\
																			\
			C##_curve_get_ord(n);											\
			bn_rand_mod(k, n);												\
																			\
			C##_mul_gen(p, k);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(k);														\
			bn_free(n);														\
		}																	\
	}																		\
																			\
	void C##_blind(C##_t r, const C##_t p) {								\
		F##_t rand;															\
																			\
		F##_null(rand);														\
																			\
		RLC_TRY {															\
			F##_new(rand);													\
			F##_rand(rand);													\
			TMPL_EP_BLIND_COORD(C, F, r, p, rand);							\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(rand);													\
		}																	\
	}																		\
																			\
	int C##_on_curve(const C##_t p) {										\
		C##_t t;															\
		int r = 0;															\
																			\
		C##_null(t);														\
																			\
		RLC_TRY {															\
			C##_new(t);														\
																			\
			C##_norm(t, p);													\
																			\
			C##_rhs(t->x, t->x);											\
			F##_sqr(t->y, t->y);											\
																			\
			r = (F##_cmp(t->x, t->y) == RLC_EQ) || C##_is_infty(p);			\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			C##_free(t);													\
		}																	\
		return r;															\
	}																		\
																			\
	void C##_print(const C##_t p) {											\
		F##_print(p->x);													\
		F##_print(p->y);													\
		F##_print(p->z);													\
	}

/**
 * Defines a template for point negation.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_NEG(C, F)													\
	void C##_neg(C##_t r, const C##_t p) {									\
		if (C##_is_infty(p)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (r != p) {														\
			F##_copy(r->x, p->x);											\
			F##_copy(r->z, p->z);											\
		}																	\
																			\
		F##_neg(r->y, p->y);												\
																			\
		r->coord = p->coord;												\
	}

/**
 * Defines a template for normalizing a point represented in projective
 * coordinates, with a flag to indicate if z is already inverted.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_NORM_IMP(C, F)												\
	static void C##_norm_imp(C##_t r, const C##_t p, int inv) {				\
		if (p->coord != BASIC) {											\
			F##_t t;														\
																			\
			F##_null(t);													\
																			\
			RLC_TRY {														\
				F##_new(t);													\
																			\
				if (inv) {													\
					F##_copy(r->z, p->z);									\
				} else {													\
					F##_inv(r->z, p->z);									\
				}															\
																			\
				switch (p->coord) {											\
					case PROJC:												\
						F##_mul(r->x, p->x, r->z);							\
						F##_mul(r->y, p->y, r->z);							\
						break;												\
					case JACOB:												\
						F##_sqr(t, r->z);									\
						F##_mul(r->x, p->x, t);								\
						F##_mul(t, t, r->z);								\
						F##_mul(r->y, p->y, t);								\
						break;												\
					default:												\
						C##_copy(r, p);										\
						break;												\
				}															\
				F##_set_dig(r->z, 1);										\
			}																\
			RLC_CATCH_ANY {													\
				RLC_THROW(ERR_CAUGHT);										\
			}																\
			RLC_FINALLY {													\
				F##_free(t);												\
			}																\
		}																	\
																			\
		r->coord = BASIC;													\
	}

/**
 * Defines a template for normalizing one or several points.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_NORM(C, F)													\
	void C##_norm(C##_t r, const C##_t p) {									\
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
																			\
		TMPL_EP_NORM_CALL(C, r, p, 0);										\
	}																		\
																			\
	void C##_norm_sim(C##_t *r, const C##_t *t, int n) {					\
		int i;																\
		F##_t* a = RLC_ALLOCA(F##_t, n);									\
																			\
		RLC_TRY {															\
			if (a == NULL) {												\
				RLC_THROW(ERR_NO_MEMORY);									\
			}																\
			for (i = 0; i < n; i++) {										\
				F##_null(a[i]);												\
				F##_new(a[i]);												\
				if (C##_is_infty(t[i])) {									\
					F##_set_dig(a[i], 1);									\
				} else {													\
					F##_copy(a[i], t[i]->z);								\
				}															\
			}																\
																			\
			F##_inv_sim(a, (const F##_t *)a, n);							\
																			\
			for (i = 0; i < n; i++) {										\
				F##_copy(r[i]->x, t[i]->x);									\
				F##_copy(r[i]->y, t[i]->y);									\
				if (C##_is_infty(t[i])) {									\
					C##_set_infty(r[i]);									\
				} else {													\
					F##_copy(r[i]->z, a[i]);								\
				}															\
			}																\
																			\
			for (i = 0; i < n; i++) {										\
				TMPL_EP_NORM_CALL(C, r[i], r[i], 1);						\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			for (i = 0; i < n; i++) {										\
				F##_free(a[i]);												\
			}																\
			RLC_FREE(a);													\
		}																	\
	}
