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
 * Templates for point multiplication on prime elliptic curves.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Normalizes a point if mixed coordinates are enabled.
 *
 * @param[in] C			- the curve.
 * @param[in,out] P		- the point to normalize.
 */
#if defined(EP_MIXED)

#define TMPL_EP_MIXED_NORM(C, P)		C##_norm(P, P)

#else

#define TMPL_EP_MIXED_NORM(C, P)		/* Nothing to do. */

#endif

/**
 * Prepares a point to receive coordinates selected in constant time from a
 * precomputation table, and selects the z-coordinate if needed. With mixed
 * coordinates, table points are normalized and z is not selected.
 *
 * @param[in] F			- the field prefix.
 * @param[out] P		- the point receiving the coordinates.
 * @param[in] T			- the table entry.
 * @param[in] B			- the flag to indicate if the entry is selected.
 */
#if defined(EP_MIXED)

#define TMPL_EP_SEL_INIT(F, P)												\
	F##_set_dig(P->z, 1);													\
	P->coord = BASIC

#define TMPL_EP_SEL_Z(F, P, T, B)		/* The z-coordinate is one. */

#else

#define TMPL_EP_SEL_INIT(F, P)			P->coord = EP_ADD

#define TMPL_EP_SEL_Z(F, P, T, B)		F##_copy_sec(P->z, T->z, B)

#endif

/**
 * Defines a template for point multiplication using the binary method.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_BASIC(C)												\
	void C##_mul_basic(C##_t r, const C##_t p, const bn_t k) {				\
		C##_t t;															\
		int8_t u, *naf = RLC_ALLOCA(int8_t, bn_bits(k) + 1);				\
		size_t l;															\
																			\
		C##_null(t);														\
																			\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			RLC_FREE(naf);													\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (bn_bits(k) <= RLC_DIG) {										\
			C##_mul_dig(r, p, k->dp[0]);									\
			if (bn_sign(k) == RLC_NEG) {									\
				C##_neg(r, r);												\
			}																\
			RLC_FREE(naf);													\
			return;															\
		}																	\
																			\
		RLC_TRY {															\
			C##_new(t);														\
			if (naf == NULL) {												\
				RLC_THROW(ERR_NO_BUFFER);									\
			}																\
																			\
			l = bn_bits(k) + 1;												\
			bn_rec_naf(naf, &l, k, 2);										\
			C##_copy(t, p);													\
			for (int i = l - 2; i >= 0; i--) {								\
				C##_dbl(t, t);												\
																			\
				u = naf[i];													\
				if (u > 0) {												\
					C##_add(t, t, p);										\
				} else if (u < 0) {											\
					C##_sub(t, t, p);										\
				}															\
			}																\
																			\
			C##_norm(r, t);													\
			if (bn_sign(k) == RLC_NEG) {									\
				C##_neg(r, r);												\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free(t);													\
			RLC_FREE(naf);													\
		}																	\
	}

/**
 * Defines a template for regular point multiplication using the GLS
 * endomorphism. The scalar is decomposed in S subscalars, which are split in T
 * groups recoded with the sign-aligned column method, each with its own
 * precomputation table of 2^(S/T - 1) points.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 * @param[in] S			- the number of subscalars.
 * @param[in] T			- the number of precomputation tables.
 */
#define TMPL_EP_MUL_REG_GLS(C, F, S, T)										\
	static void C##_mul_reg_gls(C##_t r, const C##_t p, const bn_t k) {		\
		const int flag = (ep_curve_is_pairf() == EP_BN);					\
		size_t l;															\
		bn_t n, _k[S], u;													\
		int8_t even[T], col, sac[T][(S / T) * (RLC_FP_BITS + 1)];			\
		C##_t q[S], t[T][1 << (S / T - 1)];									\
																			\
		bn_null(n);															\
		bn_null(u);															\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			bn_new(u);														\
			for (int i = 0; i < S; i++) {									\
				bn_null(_k[i]);												\
				C##_null(q[i]);												\
				bn_new(_k[i]);												\
				C##_new(q[i]);												\
			}																\
			for (int i = 0; i < T; i++) {									\
				for (int j = 0; j < (1 << (S / T - 1)); j++) {				\
					C##_null(t[i][j]);										\
					C##_new(t[i][j]);										\
				}															\
			}																\
																			\
			C##_curve_get_ord(n);											\
			fp_prime_get_par(u);											\
			if (ep_curve_is_pairf() == EP_SG18) {							\
				/* The endomorphism acts as multiplication by -3u. */		\
				bn_mul_dig(u, u, 3);										\
				bn_neg(u, u);												\
			}																\
			bn_mod(_k[0], k, n);											\
			bn_rec_frb(_k, S, _k[0], u, n, flag);							\
																			\
			C##_norm(q[0], p);												\
			for (int i = 1; i < S; i++) {									\
				C##_psi(q[i], q[i - 1]);									\
			}																\
			for (int i = 0; i < S; i++) {									\
				C##_neg(r, q[i]);											\
				F##_copy_sec(q[i]->y, r->y, bn_sign(_k[i]) == RLC_NEG);		\
				bn_abs(_k[i], _k[i]);										\
			}																\
			for (int i = 0; i < T; i++) {									\
				even[i] = bn_is_even(_k[i * (S / T)]);						\
				bn_add_dig(_k[i * (S / T)], _k[i * (S / T)], even[i]);		\
			}																\
																			\
			for (int i = 0; i < T; i++) {									\
				C##_copy(t[i][0], q[i * (S / T)]);							\
				for (int j = 1; j < (1 << (S / T - 1)); j++) {				\
					l = util_bits_dig(j);									\
					C##_add(t[i][j], t[i][j ^ (1 << (l - 1))],				\
							q[l + i * (S / T)]);							\
				}															\
				/* The endomorphism may return projective points. */		\
				l = (t[i][0]->coord == BASIC);								\
				C##_norm_sim(t[i] + l, (const C##_t *)t[i] + l,				\
						(1 << (S / T - 1)) - l);							\
				l = RLC_FP_BITS + 1;										\
				bn_rec_sac(sac[i], &l, _k + i * (S / T), u, T, S / T,		\
						bn_bits(n), flag);									\
			}																\
																			\
			TMPL_EP_SEL_INIT(F, q[1]);										\
			C##_set_infty(r);												\
			for (int j = l - 1; j >= 0; j--) {								\
				C##_dbl(r, r);												\
				for (int i = 0; i < T; i++) {								\
					col = 0;												\
					for (int m = S / T - 1; m > 0; m--) {					\
						col <<= 1;											\
						col += sac[i][m * l + j];							\
					}														\
					for (int m = 0; m < (1 << (S / T - 1)); m++) {			\
						F##_copy_sec(q[1]->x, t[i][m]->x, m == col);		\
						F##_copy_sec(q[1]->y, t[i][m]->y, m == col);		\
						TMPL_EP_SEL_Z(F, q[1], t[i][m], m == col);			\
					}														\
					C##_neg(q[2], q[1]);									\
					F##_copy_sec(q[1]->y, q[2]->y, sac[i][j]);				\
					C##_add(r, r, q[1]);									\
				}															\
			}																\
																			\
			for (int i = 0; i < T; i++) {									\
				C##_sub(q[1], r, q[i * (S / T)]);							\
				F##_copy_sec(r->x, q[1]->x, even[i]);						\
				F##_copy_sec(r->y, q[1]->y, even[i]);						\
				F##_copy_sec(r->z, q[1]->z, even[i]);						\
			}																\
																			\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
			bn_free(u);														\
			for (int i = 0; i < S; i++) {									\
				bn_free(_k[i]);												\
				C##_free(q[i]);												\
			}																\
			for (int i = 0; i < T; i++) {									\
				for (int j = 0; j < (1 << (S / T - 1)); j++) {				\
					C##_free(t[i][j]);										\
				}															\
			}																\
		}																	\
	}

/**
 * Defines a template for regular point multiplication using a regular
 * w-NAF recoding of the scalar.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_REG_IMP(C, F)											\
	static void C##_mul_reg_imp(C##_t r, const C##_t p, const bn_t k) {		\
		bn_t m;																\
		int i, j, n;														\
		int8_t s, reg[1 + RLC_CEIL(RLC_FP_BITS + 1, RLC_WIDTH - 1)];		\
		C##_t t[1 << (RLC_WIDTH - 2)], u, v;								\
		size_t l;															\
																			\
		bn_null(m);															\
		C##_null(u);														\
		C##_null(v);														\
																			\
		RLC_TRY {															\
			bn_new(m);														\
			C##_new(u);														\
			C##_new(v);														\
			/* Prepare the precomputation table. */							\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_null(t[i]);												\
				C##_new(t[i]);												\
			}																\
			/* Compute the precomputation table. */							\
			C##_tab(t, p, RLC_WIDTH);										\
																			\
			C##_curve_get_ord(m);											\
			n = bn_bits(m);													\
																			\
			/* Make a copy of the scalar for processing. */					\
			bn_abs(m, k);													\
			m->dp[0] |= 1;													\
																			\
			/* Compute the regular w-NAF representation of k. */			\
			l = RLC_CEIL(n, RLC_WIDTH - 1) + 1;								\
			bn_rec_reg(reg, &l, m, n, RLC_WIDTH);							\
																			\
			TMPL_EP_SEL_INIT(F, u);											\
			C##_set_infty(r);												\
			for (i = l - 1; i >= 0; i--) {									\
				for (j = 0; j < RLC_WIDTH - 1; j++) {						\
					C##_dbl(r, r);											\
				}															\
																			\
				n = reg[i];													\
				s = (n >> 7);												\
				n = ((n ^ s) - s) >> 1;										\
																			\
				for (j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {				\
					F##_copy_sec(u->x, t[j]->x, j == n);					\
					F##_copy_sec(u->y, t[j]->y, j == n);					\
					TMPL_EP_SEL_Z(F, u, t[j], j == n);						\
				}															\
				C##_neg(v, u);												\
				F##_copy_sec(u->y, v->y, s != 0);							\
				C##_add(r, r, u);											\
			}																\
			/* t[0] has an unmodified copy of p. */							\
			C##_sub(u, r, t[0]);											\
			F##_copy_sec(r->x, u->x, bn_is_even(k));						\
			F##_copy_sec(r->y, u->y, bn_is_even(k));						\
			F##_copy_sec(r->z, u->z, bn_is_even(k));						\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
			C##_neg(u, r);													\
			F##_copy_sec(r->y, u->y, bn_sign(k) == RLC_NEG);				\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			/* Free the precomputation table. */							\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_free(t[i]);												\
			}																\
			bn_free(m);														\
			C##_free(u);													\
			C##_free(v);													\
		}																	\
	}

/**
 * Defines a template for multiplying a point by a small integer.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_DIG(C)													\
	void C##_mul_dig(C##_t r, const C##_t p, const dig_t k) {				\
		C##_t t;															\
		bn_t _k;															\
		int8_t u, naf[RLC_DIG + 1];											\
		size_t l;															\
																			\
		C##_null(t);														\
		bn_null(_k);														\
																			\
		if (k == 0 || C##_is_infty(p)) {									\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		RLC_TRY {															\
			C##_new(t);														\
			bn_new(_k);														\
																			\
			bn_set_dig(_k, k);												\
																			\
			l = RLC_DIG + 1;												\
			bn_rec_naf(naf, &l, _k, 2);										\
																			\
			C##_copy(t, p);													\
			for (int i = l - 2; i >= 0; i--) {								\
				C##_dbl(t, t);												\
																			\
				u = naf[i];													\
				if (u > 0) {												\
					C##_add(t, t, p);										\
				} else if (u < 0) {											\
					C##_sub(t, t, p);										\
				}															\
			}																\
																			\
			C##_norm(r, t);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free(t);													\
			bn_free(_k);													\
		}																	\
	}

/**
 * Defines a template for fixed-point multiplication using the binary method,
 * including the precomputation.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_FIX_BASIC(C)											\
	void C##_mul_pre_basic(C##_t *t, const C##_t p) {						\
		bn_t n;																\
																			\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			bn_new(n);														\
																			\
			C##_curve_get_ord(n);											\
																			\
			C##_copy(t[0], p);												\
			for (size_t i = 1; i < bn_bits(n); i++) {						\
				C##_dbl(t[i], t[i - 1]);									\
			}																\
																			\
			C##_norm_sim(t + 1, (const C##_t *)t + 1, bn_bits(n) - 1);		\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
		}																	\
	}																		\
																			\
	void C##_mul_fix_basic(C##_t r, const C##_t *t, const bn_t k) {			\
		bn_t n, _k;															\
																			\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null(n);															\
		bn_null(_k);														\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			bn_new(_k);														\
																			\
			C##_curve_get_ord(n);											\
			bn_mod(_k, k, n);												\
																			\
			C##_set_infty(r);												\
			for (size_t i = 0; i < bn_bits(_k); i++) {						\
				if (bn_get_bit(_k, i)) {									\
					C##_add(r, r, t[i]);									\
				}															\
			}																\
			C##_norm(r, r);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free(n);														\
			bn_free(_k);													\
		}																	\
	}

/**
 * Defines a template for fixed-point multiplication using the single-table
 * comb method, including the precomputation.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_COMBS(C)												\
	void C##_mul_pre_combs(C##_t *t, const C##_t p) {						\
		int i, j, l;														\
		bn_t n;																\
																			\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			bn_new(n);														\
																			\
			C##_curve_get_ord(n);											\
			l = RLC_CEIL(bn_bits(n), RLC_DEPTH);							\
																			\
			C##_set_infty(t[0]);											\
																			\
			C##_copy(t[1], p);												\
			for (j = 1; j < RLC_DEPTH; j++) {								\
				C##_dbl(t[1 << j], t[1 << (j - 1)]);						\
				for (i = 1; i < l; i++) {									\
					C##_dbl(t[1 << j], t[1 << j]);							\
				}															\
				TMPL_EP_MIXED_NORM(C, t[1 << j]);							\
				for (i = 1; i < (1 << j); i++) {							\
					C##_add(t[(1 << j) + i], t[i], t[1 << j]);				\
				}															\
			}																\
																			\
			C##_norm_sim(t + 2, (const C##_t *)t + 2,						\
					RLC_EP_TABLE_COMBS - 2);								\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
		}																	\
	}																		\
																			\
	void C##_mul_fix_combs(C##_t r, const C##_t *t, const bn_t k) {			\
		int i, j, l, w, n0, p0, p1;											\
		bn_t n, _k;															\
																			\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null(n);															\
		bn_null(_k);														\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			bn_new(_k);														\
																			\
			C##_curve_get_ord(n);											\
			l = RLC_CEIL(bn_bits(n), RLC_DEPTH);							\
																			\
			bn_mod(_k, k, n);												\
			n0 = bn_bits(_k);												\
																			\
			p0 = (RLC_DEPTH) * l - 1;										\
																			\
			w = 0;															\
			p1 = p0--;														\
			for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {					\
				w = w << 1;													\
				if (p1 < n0 && bn_get_bit(_k, p1)) {						\
					w = w | 1;												\
				}															\
			}																\
			C##_copy(r, t[w]);												\
																			\
			for (i = l - 2; i >= 0; i--) {									\
				C##_dbl(r, r);												\
																			\
				w = 0;														\
				p1 = p0--;													\
				for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {				\
					w = w << 1;												\
					if (p1 < n0 && bn_get_bit(_k, p1)) {					\
						w = w | 1;											\
					}														\
				}															\
				if (w > 0) {												\
					C##_add(r, r, t[w]);									\
				}															\
			}																\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
			bn_free(_k);													\
		}																	\
	}

/**
 * Defines a template for fixed-point multiplication using the double-table
 * comb method, including the precomputation.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_COMBD(C)												\
	void C##_mul_pre_combd(C##_t *t, const C##_t p) {						\
		int i, j, d, e;														\
		bn_t n;																\
																			\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			bn_new(n);														\
																			\
			C##_curve_get_ord(n);											\
			d = RLC_CEIL(bn_bits(n), RLC_DEPTH);							\
			e = (d % 2 == 0 ? (d / 2) : (d / 2) + 1);						\
																			\
			C##_set_infty(t[0]);											\
			C##_copy(t[1], p);												\
			for (j = 1; j < RLC_DEPTH; j++) {								\
				C##_dbl(t[1 << j], t[1 << (j - 1)]);						\
				for (i = 1; i < d; i++) {									\
					C##_dbl(t[1 << j], t[1 << j]);							\
				}															\
				TMPL_EP_MIXED_NORM(C, t[1 << j]);							\
				for (i = 1; i < (1 << j); i++) {							\
					C##_add(t[(1 << j) + i], t[i], t[1 << j]);				\
				}															\
			}																\
			C##_set_infty(t[1 << RLC_DEPTH]);								\
			for (j = 1; j < (1 << RLC_DEPTH); j++) {						\
				C##_dbl(t[(1 << RLC_DEPTH) + j], t[j]);						\
				for (i = 1; i < e; i++) {									\
					C##_dbl(t[(1 << RLC_DEPTH) + j],						\
							t[(1 << RLC_DEPTH) + j]);						\
				}															\
			}																\
																			\
			C##_norm_sim(t + 2, (const C##_t *)t + 2, (1 << RLC_DEPTH) - 2);\
			C##_norm_sim(t + (1 << RLC_DEPTH) + 1,							\
					(const C##_t *)t + (1 << RLC_DEPTH) + 1,				\
					(1 << RLC_DEPTH) - 1);									\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
		}																	\
	}																		\
																			\
	void C##_mul_fix_combd(C##_t r, const C##_t *t, const bn_t k) {			\
		int i, j, d, e, w0, w1, n0, p0, p1;									\
		bn_t n, _k;															\
																			\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null(n);															\
		bn_null(_k);														\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			bn_new(_k);														\
																			\
			C##_curve_get_ord(n);											\
			d = RLC_CEIL(bn_bits(n), RLC_DEPTH);							\
			e = (d % 2 == 0 ? (d / 2) : (d / 2) + 1);						\
																			\
			C##_set_infty(r);												\
			bn_mod(_k, k, n);												\
			n0 = bn_bits(_k);												\
																			\
			p1 = (e - 1) + (RLC_DEPTH - 1) * d;								\
			for (i = e - 1; i >= 0; i--) {									\
				C##_dbl(r, r);												\
																			\
				w0 = 0;														\
				p0 = p1;													\
				for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {				\
					w0 = w0 << 1;											\
					if (p0 < n0 && bn_get_bit(_k, p0)) {					\
						w0 = w0 | 1;										\
					}														\
				}															\
																			\
				w1 = 0;														\
				p0 = p1-- + e;												\
				for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {				\
					w1 = w1 << 1;											\
					if (i + e < d && p0 < n0 && bn_get_bit(_k, p0)) {		\
						w1 = w1 | 1;										\
					}														\
				}															\
																			\
				C##_add(r, r, t[w0]);										\
				C##_add(r, r, t[(1 << RLC_DEPTH) + w1]);					\
			}																\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(n);														\
			bn_free(_k);													\
		}																	\
	}


/**
 * Defines a template for simultaneous point multiplication using two
 * independent multiplications.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_SIM_BASIC(C)											\
	void C##_mul_sim_basic(C##_t r, const C##_t p, const bn_t k,			\
			const C##_t q, const bn_t m) {									\
		C##_t t;															\
																			\
		C##_null(t);														\
																			\
		RLC_TRY {															\
			C##_new(t);														\
			C##_mul(t, q, m);												\
			C##_mul(r, p, k);												\
			C##_add(t, t, r);												\
			C##_norm(r, t);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free(t);													\
		}																	\
	}

/**
 * Defines a template for simultaneous multiplication of several points by
 * small integers.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_SIM_DIG(C)												\
	void C##_mul_sim_dig(C##_t r, const C##_t p[], const dig_t k[],			\
			size_t len) {													\
		C##_t t;															\
		int max;															\
																			\
		C##_null(t);														\
																			\
		max = util_bits_dig(k[0]);											\
		for (size_t i = 1; i < len; i++) {									\
			max = RLC_MAX(max, util_bits_dig(k[i]));						\
		}																	\
																			\
		RLC_TRY {															\
			C##_new(t);														\
																			\
			C##_set_infty(t);												\
			for (int i = max - 1; i >= 0; i--) {							\
				C##_dbl(t, t);												\
				for (size_t j = 0; j < len; j++) {							\
					if (k[j] & ((dig_t)1 << i)) {							\
						C##_add(t, t, p[j]);								\
					}														\
				}															\
			}																\
																			\
			C##_norm(r, t);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free(t);													\
		}																	\
	}

/**
 * Defines a template for multiplying the generator by an integer.
 *
 * @param[in] C			- the curve.
 */
#ifdef EP_PRECO

#define TMPL_EP_MUL_GEN(C)													\
	void C##_mul_gen(C##_t r, const bn_t k) {								\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		C##_mul_fix(r, C##_curve_get_tab(), k);								\
	}

#else

#define TMPL_EP_MUL_GEN(C)													\
	void C##_mul_gen(C##_t r, const bn_t k) {								\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		C##_t g;															\
																			\
		C##_null(g);														\
																			\
		RLC_TRY {															\
			C##_new(g);														\
			C##_curve_get_gen(g);											\
			C##_mul(r, g, k);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			C##_free(g);													\
		}																	\
	}

#endif
