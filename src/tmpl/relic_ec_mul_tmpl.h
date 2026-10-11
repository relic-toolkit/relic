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
 * Templates for point multiplication shared by elliptic curves over prime
 * and binary fields.
 *
 * @ingroup tmpl
 */

#ifndef RLC_EC_MUL_TMPL_H
#define RLC_EC_MUL_TMPL_H

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for point multiplication using the binary method.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_BASIC(C)												\
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
 * Defines a template for multiplying a point by a small integer.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_DIG(C)													\
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
 * Defines a template for fixed-point multiplication using the single-table
 * comb method, including the precomputation. The multiplication dispatches to
 * C##_mul_fix_##E when the scalar is decomposed with an endomorphism.
 *
 * @param[in] C			- the curve.
 * @param[in] E			- the endomorphism method, glv or plain.
 */
#define TMPL_EC_MUL_FIX_BASIC(C, E)											\
	static void C##_mul_fix_plain(C##_t r, const C##_t *t, const bn_t k) {	\
		int i, j, l, w, n0, p0, p1;											\
		bn_t n, _k;															\
																			\
		bn_null_all(n, _k);													\
																			\
		RLC_TRY {															\
			bn_new_all(n, _k);												\
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
			bn_free_all(n, _k);												\
		}																	\
	}																		\
																			\
	void C##_mul_pre_basic(C##_t *t, const C##_t p) {						\
		int i, j, l;														\
		bn_t n;																\
																			\
		bn_null(n);															\
																			\
		RLC_TRY {															\
			bn_new(n);														\
																			\
			/* The teeth are spaced for the length of the subscalars. */	\
			C##_curve_get_ord(n);											\
			l = RLC_CEIL(bn_bits(n), TMPL_EP_MUL_FIX_DIM_##E(2) * RLC_DEPTH);	\
																			\
			C##_set_infty(t[0]);											\
																			\
			C##_copy(t[1], p);												\
			for (j = 1; j < RLC_DEPTH; j++) {								\
				C##_dbl(t[1 << j], t[1 << (j - 1)]);						\
				for (i = 1; i < l; i++) {									\
					C##_dbl(t[1 << j], t[1 << j]);							\
				}															\
				C##_norm(t[1 << j], t[1 << j]);								\
				for (i = 1; i < (1 << j); i++) {							\
					C##_add(t[(1 << j) + i], t[i], t[1 << j]);				\
				}															\
			}																\
																			\
			C##_norm_sim(t + 2, (const C##_t *)t + 2, (1 << RLC_DEPTH) - 2);\
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
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (TMPL_EP_MUL_FIX_DIM_##E(2) > 1) {									\
			C##_mul_fix_##E(r, t, k);										\
			return;															\
		}																	\
																			\
		C##_mul_fix_plain(r, t, k);											\
	}

/**
 * Defines a template for fixed-point multiplication using the regular signed
 * comb method, including the precomputation. Two combs of RLC_DEPTH teeth are
 * spaced s bits apart, so that each column needs one doubling and two
 * additions of points read from the table in constant time. With the GLV
 * endomorphism, the combs run over both subscalars at once, applying the
 * endomorphism to the points read for the second one, which halves the
 * number of doublings. Applying the GLS endomorphism to every point read
 * costs more than the doublings it saves, so curves over extension fields
 * use the comb without an endomorphism.
 *
 * Mike Hamburg. Fast and compact elliptic-curve cryptography.
 * https://eprint.iacr.org/2012/309
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 * @param[in] E			- the endomorphism method, glv or plain.
 * @param[in] S			- the dimension of the decomposition, 2 or 1.
 * @param[in] B			- the size in bits of the field, which bounds the order.
 */
#define TMPL_EC_MUL_FIX_LWREG(C, F, E, S, B)									\
	void C##_mul_pre_lwreg(C##_t *t, const C##_t p) {						\
		const int h = 1 << (RLC_DEPTH - 1);									\
		const int dim = TMPL_EP_MUL_FIX_DIM_##E(S);							\
		int i, j, e;														\
		size_t s;															\
		C##_t b[2 * RLC_DEPTH];												\
		bn_t n;																\
																			\
		bn_null(n);															\
		for (i = 0; i < 2 * RLC_DEPTH; i++) {								\
			C##_null(b[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new(n);														\
			for (i = 0; i < 2 * RLC_DEPTH; i++) {							\
				C##_new(b[i]);												\
			}																\
																			\
			/* The teeth are spaced for the length of the subscalars. */	\
			C##_curve_get_ord(n);											\
			s = (dim > 1 ? TMPL_EP_MUL_FIX_LEN_##E(n) : bn_bits(n));		\
			s = RLC_CEIL(s, 2 * RLC_DEPTH);									\
																			\
			/* b[i] = 2^(i * s) * P, one point per tooth. */				\
			C##_copy(b[0], p);												\
			for (i = 1; i < 2 * RLC_DEPTH; i++) {							\
				C##_copy(b[i], b[i - 1]);									\
				for (j = 0; j < s; j++) {									\
					C##_dbl(b[i], b[i]);									\
				}															\
			}																\
			/* Entry e of comb c adds the top tooth and the other teeth, each\
			 * with the sign given by its bit in e. */						\
			for (i = 0; i < 2; i++) {										\
				C##_t *u = t + i * h, *v = b + i * RLC_DEPTH;				\
																			\
				C##_copy(u[0], v[RLC_DEPTH - 1]);							\
				for (j = 0; j < RLC_DEPTH - 1; j++) {						\
					C##_sub(u[0], u[0], v[j]);								\
				}															\
				/* Turning tooth j positive adds twice its point. */		\
				for (j = 0; j < RLC_DEPTH - 1; j++) {						\
					C##_dbl(v[j], v[j]);									\
					for (e = 0; e < (1 << j); e++) {						\
						C##_add(u[(1 << j) + e], u[e], v[j]);				\
					}														\
				}															\
			}																\
			/* The last entry corrects the subscalars made odd. */			\
			C##_copy(t[2 * h], p);											\
			C##_norm_sim(t, (const C##_t *)t, 2 * h + 1);					\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free(n);														\
			for (i = 0; i < 2 * RLC_DEPTH; i++) {							\
				C##_free(b[i]);												\
			}																\
		}																	\
	}																		\
																			\
	void C##_mul_fix_lwreg(C##_t r, const C##_t *t, const bn_t k) {			\
		const int h = 1 << (RLC_DEPTH - 1);									\
		const int dim = TMPL_EP_MUL_FIX_DIM_##E(S);							\
		dig_t d[S][RLC_CEIL(B + 2 * RLC_DEPTH, RLC_DIG)];					\
		int i, j, c, e, top, neg, sgn[S], even[S];							\
		size_t l, s;														\
		bn_t m, n, u, _k[S];												\
		C##_t q, v, w;														\
																			\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null_all(m, n, u);												\
		C##_null_all(q, v, w);												\
		for (j = 0; j < S; j++) {											\
			bn_null(_k[j]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(m, n, u);											\
			C##_new_all(q, v, w);											\
			for (j = 0; j < S; j++) {										\
				bn_new(_k[j]);												\
			}																\
																			\
			C##_curve_get_ord(n);											\
			l = (dim > 1 ? TMPL_EP_MUL_FIX_LEN_##E(n) : bn_bits(n));		\
			s = RLC_CEIL(l, 2 * RLC_DEPTH);									\
			l = 2 * RLC_DEPTH * s;											\
																			\
			/* Reduce the scalar, keeping its sign to negate the result. */	\
			bn_mod(m, k, n);												\
			neg = (bn_sign(m) == RLC_NEG);									\
			bn_abs(m, m);													\
			for (j = 0; j < S; j++) {										\
				sgn[j] = even[j] = 0;										\
			}																\
			if (dim == 1) {													\
				/* Recode m as (m + 2^l - 1)/2 mod n, so that bits b_i give	\
				 * k = sum (2 * b_i - 1) * 2^i mod n. */					\
				bn_set_2b(_k[0], l);										\
				bn_sub_dig(_k[0], _k[0], 1);								\
				bn_add(_k[0], _k[0], m);									\
				bn_add_dig(u, n, 1);										\
				bn_hlv(u, u);												\
				bn_mul(_k[0], _k[0], u);									\
				bn_mod(_k[0], _k[0], n);									\
			} else {														\
				TMPL_EP_MUL_FIX_REC_##E(_k, m, n);							\
				/* Make each subscalar positive and odd, then recode it as	\
				 * (k_j + 2^l - 1)/2, which is exact for odd k_j. */		\
				bn_set_2b(u, l);											\
				bn_sub_dig(u, u, 1);										\
				for (j = 0; j < dim; j++) {									\
					sgn[j] = (bn_sign(_k[j]) == RLC_NEG);					\
					bn_abs(_k[j], _k[j]);									\
					even[j] = bn_is_even(_k[j]);							\
					bn_add_dig(_k[j], _k[j], even[j]);						\
					bn_add(_k[j], _k[j], u);								\
					bn_hlv(_k[j], _k[j]);									\
				}															\
			}																\
			/* Read the bits from buffers of fixed length. */				\
			for (j = 0; j < dim; j++) {										\
				dv_zero(d[j], RLC_CEIL(B + 2 * RLC_DEPTH, RLC_DIG));		\
				dv_copy(d[j], _k[j]->dp, _k[j]->used);						\
			}																\
																			\
			F##_set_dig(q->z, 1);											\
			q->coord = BASIC;												\
			C##_set_infty(r);												\
			for (i = s - 1; i >= 0; i--) {									\
				if (i != s - 1) {											\
					C##_dbl(r, r);											\
				}															\
				for (j = 0; j < dim; j++) {									\
					for (c = 0; c < 2; c++) {								\
						/* The top tooth is the sign, the others the index. */\
						int b = (c * RLC_DEPTH + RLC_DEPTH - 1) * s + i;	\
						top = (d[j][b / RLC_DIG] >> (b % RLC_DIG)) & 1;		\
						e = 0;												\
						for (int z = 0; z < RLC_DEPTH - 1; z++) {			\
							b = (c * RLC_DEPTH + z) * s + i;				\
							b = (d[j][b / RLC_DIG] >> (b % RLC_DIG)) & 1;	\
							e |= b << z;									\
						}													\
						/* A negative top tooth flips all the signs. */		\
						e ^= (top - 1) & (h - 1);							\
						for (int z = 0; z < h; z++) {						\
							F##_copy_sec(q->x, t[c * h + z]->x, z == e);	\
							F##_copy_sec(q->y, t[c * h + z]->y, z == e);	\
						}													\
						C##_neg(v, q);										\
						F##_copy_sec(q->y, v->y, (top == 0) ^ sgn[j]);		\
						/* The second subscalar multiplies psi(P). */		\
						if (j == 0) {										\
							C##_add(r, r, q);								\
						} else {											\
							TMPL_EP_MUL_FIX_PSI_##E(C, w, q);				\
							C##_add(r, r, w);								\
						}													\
					}														\
				}															\
			}																\
			/* Subtract P and psi(P) where k_j was made odd. */				\
			for (j = 0; j < (dim > 1 ? dim : 0); j++) {						\
				C##_copy(w, t[2 * h]);										\
				if (j > 0) {												\
					TMPL_EP_MUL_FIX_PSI_##E(C, w, w);						\
				}															\
				C##_neg(v, w);												\
				F##_copy_sec(w->y, v->y, sgn[j]);							\
				C##_sub(v, r, w);											\
				F##_copy_sec(r->x, v->x, even[j]);							\
				F##_copy_sec(r->y, v->y, even[j]);							\
				F##_copy_sec(r->z, v->z, even[j]);							\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
			C##_neg(v, r);													\
			F##_copy_sec(r->y, v->y, neg);									\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free_all(m, n, u);											\
			C##_free_all(q, v, w);											\
			for (j = 0; j < S; j++) {										\
				bn_free(_k[j]);												\
			}																\
		}																	\
	}

/**
 * Defines a template for fixed-point multiplication using the double-table
 * comb method, including the precomputation.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_COMBD(C)												\
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
				C##_norm(t[1 << j], t[1 << j]);								\
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
		bn_null_all(n, _k);													\
																			\
		RLC_TRY {															\
			bn_new_all(n, _k);												\
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
			bn_free_all(n, _k);												\
		}																	\
	}

/**
 * Defines a template for multiplying the generator by an integer, with the
 * precomputed table of the generator (preco) or without one (plain).
 *
 * @param[in] C			- the curve.
 * @param[in] P			- preco or plain.
 */
#define TMPL_EC_MUL_GEN(C, P)	TMPL_EC_MUL_GEN_##P(C)

#define TMPL_EC_MUL_GEN_preco(C)													\
	void C##_mul_gen(C##_t r, const bn_t k) {								\
		if (bn_is_zero(k)) {												\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		C##_mul_fix(r, C##_curve_get_tab(), k);								\
	}

#define TMPL_EC_MUL_GEN_plain(C)													\
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

#endif /* !RLC_EC_MUL_TMPL_H */
