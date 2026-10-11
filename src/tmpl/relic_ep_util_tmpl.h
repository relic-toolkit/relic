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

#define TMPL_EP_NORM_CALL(C, R, P, I)		C##_norm_imp(R, P, I)

/**
 * Defines a template for basic utilities: testing for and setting the
 * point at infinity, copying, sampling, blinding, validating, tabulating
 * multiples and printing points.
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
		bn_null_all(k, n);													\
																			\
		RLC_TRY {															\
			bn_new_all(k, n);												\
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
			bn_free_all(k, n);												\
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
	void C##_tab(C##_t *t, const C##_t p, int w) {							\
		if (w > 2) {														\
			C##_dbl(t[0], p);												\
			C##_norm(t[0], t[0]);											\
			C##_add(t[1], p, t[0]);											\
			for (int i = 2; i < (1 << (w - 2)); i++) {						\
				C##_add(t[i], t[i - 1], t[0]);								\
			}																\
			C##_norm_sim(t + 1, (const C##_t *)t + 1, (1 << (w - 2)) - 1);	\
		}																	\
		C##_norm(t[0], p);													\
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

/**
 * Defines a template for point comparison.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_CMP(C, F)													\
	int C##_cmp(const C##_t p, const C##_t q) {								\
		C##_t r, s;															\
		int result = RLC_NE;												\
																			\
		if (C##_is_infty(p) && C##_is_infty(q)) {							\
			return RLC_EQ;													\
		}																	\
																			\
		C##_null_all(r, s);													\
																			\
		RLC_TRY {															\
			C##_new_all(r, s);												\
																			\
			switch (q->coord) {												\
				case PROJC:													\
					/* If q is in homogeneous projective coordinates,		\
					 * compute x1 * z2 and y1 * z2. */						\
					F##_mul(r->x, p->x, q->z);								\
					F##_mul(r->y, p->y, q->z);								\
					break;													\
				case JACOB:													\
					/* If q is in Jacobian projective coordinates,			\
					 * compute x1 * z2^2 and y1 * z2^3. */					\
					F##_sqr(r->z, q->z);									\
					F##_mul(r->x, p->x, r->z);								\
					F##_mul(r->z, r->z, q->z);								\
					F##_mul(r->y, p->y, r->z);								\
					break;													\
				default:													\
					C##_copy(r, p);											\
					break;													\
			}																\
																			\
			switch (p->coord) {												\
				/* Now do the same for the other point. */					\
				case PROJC:													\
					F##_mul(s->x, q->x, p->z);								\
					F##_mul(s->y, q->y, p->z);								\
					break;													\
				case JACOB:													\
					F##_sqr(s->z, p->z);									\
					F##_mul(s->x, q->x, s->z);								\
					F##_mul(s->z, s->z, p->z);								\
					F##_mul(s->y, q->y, s->z);								\
					break;													\
				default:													\
					C##_copy(s, q);											\
					break;													\
			}																\
																			\
			if ((F##_cmp(r->x, s->x) == RLC_EQ) &&							\
					(F##_cmp(r->y, s->y) == RLC_EQ)) {						\
				result = RLC_EQ;											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free_all(r, s);												\
		}																	\
																			\
		return result;														\
	}

/**
 * Adds a curve coefficient to a field element according to the optimization
 * identifier of the coefficient. Small coefficients are only exploited without
 * Montgomery reduction, since their stored representation is not small then.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 * @param[in,out] T		- the field element.
 * @param[in] V			- the coefficient (a or b).
 */
#if FP_RDC != MONTY

#define TMPL_EP_RHS_ADD(C, F, T, V)											\
	switch (C##_curve_opt_##V()) {											\
		case RLC_ZERO:														\
			break;															\
		case RLC_MIN3:														\
			F##_sub_dig(T, T, 3);											\
			break;															\
		case RLC_ONE:														\
			F##_add_dig(T, T, 1);											\
			break;															\
		case RLC_TWO:														\
			F##_add_dig(T, T, 2);											\
			break;															\
		case RLC_TINY:														\
			F##_add_dig(T, T, ((fp_t *)C##_curve_get_##V())[0][0]);			\
			break;															\
		default:															\
			F##_add(T, T, C##_curve_get_##V());								\
			break;															\
	}

#else

#define TMPL_EP_RHS_ADD(C, F, T, V)											\
	if (C##_curve_opt_##V() != RLC_ZERO) {									\
		F##_add(T, T, C##_curve_get_##V());									\
	}

#endif

/**
 * Defines a template for computing the right-hand side of the curve equation
 * for a point in a twisted curve over an extension field.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_RHS(C, F)													\
	void C##_rhs(F##_t rhs, const F##_t x) {								\
		F##_t t0;															\
																			\
		F##_null(t0);														\
																			\
		RLC_TRY {															\
			F##_new(t0);													\
																			\
			/* Compute x^3 + a * x + b as (x^2 + a) * x + b. */				\
			F##_sqr(t0, x);													\
			TMPL_EP_RHS_ADD(C, F, t0, a);									\
			F##_mul(t0, t0, x);												\
			TMPL_EP_RHS_ADD(C, F, t0, b);									\
			F##_copy(rhs, t0);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t0);													\
		}																	\
	}

/**
 * Computes the sign of an extension field element used in point compression:
 * whether its highest nonzero coefficient is larger than (p - 1)/2.
 *
 * @param[in] F			- the field prefix.
 * @param[in] Y			- the extension field element.
 * @param[in] H			- the value (p - 1)/2.
 * @param[in] K			- a temporary multiple precision integer.
 * @param[out] S		- the sign.
 */
#define TMPL_EP_PCK_SIGN(F, Y, H, K, S)										\
	S = 0;																	\
	for (int _i = 0; _i < (int)(sizeof(F##_t) / sizeof(fp_t)); _i++) {		\
		fp_prime_back(K, ((fp_t *)Y)[_i]);									\
		if (!bn_is_zero(K)) {												\
			S = (bn_cmp(K, H) == RLC_GT);									\
		}																	\
	}

/**
 * Defines a template for point compression and decompression, keeping the
 * abscissa and the sign of the ordinate as in the IETF pairing-friendly
 * curves specification.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_PCK(C, F)													\
	void C##_pck(C##_t r, const C##_t p) {									\
		bn_t h, k;															\
		int b;																\
																			\
		bn_null_all(h, k);													\
																			\
		RLC_TRY {															\
			bn_new_all(h, k);												\
																			\
			h->used = RLC_FP_DIGS;											\
			dv_copy(h->dp, fp_prime_get(), RLC_FP_DIGS);					\
			bn_hlv(h, h);													\
			TMPL_EP_PCK_SIGN(F, p->y, h, k, b);								\
																			\
			F##_copy(r->x, p->x);											\
			F##_zero(r->y);													\
			fp_set_bit(((fp_t *)r->y)[0], 0, b);							\
			F##_set_dig(r->z, 1);											\
			r->coord = BASIC;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free_all(h, k);												\
		}																	\
	}																		\
																			\
	int C##_upk(C##_t r, const C##_t p) {									\
		F##_t t;															\
		bn_t h, k;															\
		int b, result = 0;													\
																			\
		F##_null(t);														\
		bn_null_all(h, k);													\
																			\
		RLC_TRY {															\
			F##_new(t);														\
			bn_new_all(h, k);												\
																			\
			C##_rhs(t, p->x);												\
			result = F##_srt(t, t);											\
			if (result) {													\
				h->used = RLC_FP_DIGS;										\
				dv_copy(h->dp, fp_prime_get(), RLC_FP_DIGS);				\
				bn_hlv(h, h);												\
				TMPL_EP_PCK_SIGN(F, t, h, k, b);							\
				if (b != fp_get_bit(((fp_t *)p->y)[0], 0)) {				\
					F##_neg(t, t);											\
				}															\
				F##_copy(r->x, p->x);										\
				F##_copy(r->y, t);											\
				F##_set_dig(r->z, 1);										\
				r->coord = BASIC;											\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free(t);													\
			bn_free_all(h, k);												\
		}																	\
		return result;														\
	}

/**
 * Defines a template for reading and writing points in compressed or
 * uncompressed form, including point compression itself.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_BIN(C, F)													\
	TMPL_EP_PCK(C, F)														\
																			\
	size_t C##_size_bin(const C##_t a, int pack) {							\
		const size_t l = (sizeof(F##_t) / sizeof(fp_t)) * RLC_FP_BYTES;		\
																			\
		if (C##_is_infty(a)) {												\
			return 1;														\
		}																	\
		return (pack ? 1 + l : 1 + 2 * l);									\
	}																		\
																			\
	void C##_read_bin(C##_t a, const uint8_t *bin, size_t len) {			\
		const size_t l = (sizeof(F##_t) / sizeof(fp_t)) * RLC_FP_BYTES;		\
																			\
		if (len == 1) {														\
			if (bin[0] == 0) {												\
				C##_set_infty(a);											\
				return;														\
			} else {														\
				RLC_THROW(ERR_NO_BUFFER);									\
				return;														\
			}																\
		}																	\
																			\
		if (len != l + 1 && len != 2 * l + 1) {								\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
																			\
		a->coord = BASIC;													\
		F##_set_dig(a->z, 1);												\
		F##_read_bin(a->x, bin + 1, l);										\
		if (len == l + 1) {													\
			switch (bin[0]) {												\
				case 2:														\
					F##_zero(a->y);											\
					break;													\
				case 3:														\
					F##_zero(a->y);											\
					fp_set_bit(((fp_t *)a->y)[0], 0, 1);					\
					break;													\
				default:													\
					RLC_THROW(ERR_NO_VALID);								\
					return;													\
			}																\
			C##_upk(a, a);													\
		} else {															\
			if (bin[0] != 4) {												\
				RLC_THROW(ERR_NO_VALID);									\
				return;														\
			}																\
			F##_read_bin(a->y, bin + l + 1, l);								\
		}																	\
																			\
		if (!C##_on_curve(a)) {												\
			RLC_THROW(ERR_NO_VALID);										\
		}																	\
	}																		\
																			\
	void C##_write_bin(uint8_t *bin, size_t len, const C##_t a, int pack) {	\
		const size_t l = (sizeof(F##_t) / sizeof(fp_t)) * RLC_FP_BYTES;		\
		C##_t t;															\
																			\
		C##_null(t);														\
																			\
		memset(bin, 0, len);												\
																			\
		if (C##_is_infty(a)) {												\
			if (len < 1) {													\
				RLC_THROW(ERR_NO_BUFFER);									\
			}																\
			return;															\
		}																	\
																			\
		RLC_TRY {															\
			C##_new(t);														\
																			\
			C##_norm(t, a);													\
																			\
			if (pack) {														\
				if (len < l + 1) {											\
					RLC_THROW(ERR_NO_BUFFER);								\
				} else {													\
					C##_pck(t, t);											\
					bin[0] = 2 | fp_get_bit(((fp_t *)t->y)[0], 0);			\
					F##_write_bin(bin + 1, l, t->x, 0);						\
				}															\
			} else {														\
				if (len < 2 * l + 1) {										\
					RLC_THROW(ERR_NO_BUFFER);								\
				} else {													\
					bin[0] = 4;												\
					F##_write_bin(bin + 1, l, t->x, 0);						\
					F##_write_bin(bin + l + 1, l, t->y, 0);					\
				}															\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			C##_free(t);													\
		}																	\
	}

/**
 * Defines a template for the point arithmetic shared by all prime elliptic
 * curves: addition, subtraction and doubling in every coordinate system,
 * normalization, utilities, comparison and negation.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_ARITH(C, F)													\
	TMPL_ADD_BASIC_IMP(C, F)												\
	TMPL_ADD_PROJC_MIX(C, F)												\
	TMPL_ADD_PROJC_IMP(C, F)												\
	TMPL_ADD_JACOB_MIX(C, F)												\
	TMPL_ADD_JACOB_IMP(C, F)												\
	TMPL_ADD_BASIC(C, F)													\
	TMPL_ADD(C, projc)														\
	TMPL_ADD(C, jacob)														\
	TMPL_SUB(C)																\
	TMPL_DBL_BASIC_IMP(C, F)												\
	TMPL_DBL_PROJC_IMP(C, F)												\
	TMPL_DBL_JACOB_IMP(C, F)												\
	TMPL_EP_NORM_IMP(C, F)													\
	TMPL_EP_UTIL(C, F)														\
	TMPL_EP_CMP(C, F)														\
	TMPL_EP_NEG(C, F)														\
	TMPL_DBL_BASIC(C, F)													\
	TMPL_DBL(C, projc)														\
	TMPL_DBL(C, jacob)														\
	TMPL_EP_NORM(C, F)
