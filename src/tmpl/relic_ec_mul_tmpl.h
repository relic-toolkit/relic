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
#define TMPL_EC_MUL_FIX_LWREG(C, E, S, B)									\
	void C##_mul_pre_lwreg(C##_t *t, const C##_t p) {						\
		const int h = 1 << (RLC_DEPTH - 1);									\
		const int dim = TMPL_EP_MUL_FIX_DIM_##E(S);							\
		int i, e;															\
		size_t j, s;														\
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
			C##_set_infty(r);												\
			for (i = s - 1; i >= 0; i--) {									\
				if ((size_t)i != s - 1) {									\
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
							C##_copy_sec(q, t[c * h + z], z == e);			\
						}													\
						C##_neg(v, q);										\
						C##_copy_sec(q, v, (top == 0) ^ sgn[j]);			\
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
				C##_copy_sec(w, v, sgn[j]);									\
				C##_sub(v, r, w);											\
				C##_copy_sec(r, v, even[j]);								\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
			C##_neg(v, r);													\
			C##_copy_sec(r, v, neg);										\
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

/**
 * Defines a template for point multiplication using the left-to-right w-NAF
 * method, for curves without an endomorphism.
 *
 * @param[in] C			- the curve.
 * @param[in] B			- the bound on the bit length of the scalars.
 */
#define TMPL_EC_MUL_NAF_IMP(C, B)											\
	static void C##_mul_naf_imp(C##_t r, const C##_t p, const bn_t k) {		\
		/* Some of the supported prime curves have order > field. */		\
		int8_t u, naf[B + 2];												\
		C##_t t[1 << (RLC_WIDTH - 2)];										\
		bn_t m, n;															\
		size_t l;															\
																			\
		bn_null_all(n, m);													\
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
			C##_null(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, m);												\
			/* Prepare the precomputation table. */							\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				C##_new(t[i]);												\
			}																\
																			\
			C##_curve_get_ord(n);											\
			bn_mod(m, k, n);												\
																			\
			/* Compute the precomputation table. */							\
			C##_tab(t, p, RLC_WIDTH);										\
																			\
			/* Compute the w-NAF representation of k. */					\
			l = B + 2;														\
			bn_rec_naf(naf, &l, m, RLC_WIDTH);								\
																			\
			C##_set_infty(r);												\
			for (int i = l - 1; i >= 0; i--) {								\
				C##_dbl(r, r);												\
																			\
				u = naf[i];													\
				if (u > 0) {												\
					C##_add(r, r, t[u / 2]);								\
				} else if (u < 0) {											\
					C##_sub(r, r, t[-u / 2]);								\
				}															\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free_all(n, m);												\
			/* Free the precomputation table. */							\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				C##_free(t[i]);												\
			}																\
		}																	\
	}

/**
 * Defines a template for regular point multiplication using a regular
 * w-NAF recoding of the scalar.
 *
 * @param[in] C			- the curve.
 * @param[in] B			- the bound on the bit length of the scalars.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EC_MUL_REG_IMP(C, B)											\
	static void C##_mul_reg_imp(C##_t r, const C##_t p, const bn_t k) {		\
		bn_t m, o;															\
		int i, j, n, even, neg;												\
		int8_t s, reg[1 + RLC_CEIL(B + 1, RLC_WIDTH - 1)];					\
		C##_t t[1 << (RLC_WIDTH - 2)], u, v;								\
		size_t l;															\
																			\
		bn_null_all(m, o);													\
		C##_null_all(u, v);													\
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {						\
			C##_null(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(m, o);												\
			C##_new_all(u, v);												\
			/* Prepare the precomputation table. */							\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_new(t[i]);												\
			}																\
			/* Compute the precomputation table. */							\
			C##_tab(t, p, RLC_WIDTH);										\
																			\
			C##_curve_get_ord(o);											\
			n = bn_bits(o);													\
																			\
			/* Reduce the scalar, keeping its sign and parity. */			\
			bn_mod(m, k, o);												\
			neg = (bn_sign(m) == RLC_NEG);									\
			bn_abs(m, m);													\
			even = bn_is_even(m);											\
			m->dp[0] |= 1;													\
																			\
			/* Compute the regular w-NAF representation of k. */			\
			l = RLC_CEIL(n, RLC_WIDTH - 1) + 1;								\
			bn_rec_reg(reg, &l, m, n, RLC_WIDTH);							\
																			\
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
					C##_copy_sec(u, t[j], j == n);							\
				}															\
				C##_neg(v, u);												\
				C##_copy_sec(u, v, s != 0);									\
				C##_add(r, r, u);											\
			}																\
			/* t[0] has an unmodified copy of p. */							\
			C##_sub(u, r, t[0]);											\
			C##_copy_sec(r, u, even);										\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
			C##_neg(u, r);													\
			C##_copy_sec(r, u, neg);										\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			/* Free the precomputation table. */							\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_free(t[i]);												\
			}																\
			bn_free_all(m, o);												\
			C##_free_all(u, v);												\
		}																	\
	}

/**
 * Defines a template for point multiplication using the Montgomery ladder.
 * The coordinates are swapped in constant time limb by limb, which works for
 * both automatic and dynamic memory allocation.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EC_MUL_MONTY(C)												\
	void C##_mul_monty(C##_t r, const C##_t p, const bn_t k) {				\
		C##_t t[2];															\
		bn_t n, l, _k;														\
		size_t bits;														\
																			\
		bn_null_all(n, l, _k);												\
		C##_null(t[0]);														\
		C##_null(t[1]);														\
																			\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, l, _k);											\
			C##_new(t[0]);													\
			C##_new(t[1]);													\
																			\
			C##_curve_get_ord(n);											\
			bits = bn_bits(n);												\
																			\
			bn_mod(_k, k, n);												\
			bn_abs(l, _k);													\
			bn_add(l, l, n);												\
			bn_add(n, l, n);												\
			dv_swap_sec(l->dp, n->dp, RLC_MAX(l->used, n->used),			\
				bn_get_bit(l, bits) == 0);									\
			l->used = RLC_SEL(l->used, n->used, bn_get_bit(l, bits) == 0);	\
																			\
			C##_norm(t[0], p);												\
			C##_dbl(t[1], t[0]);											\
																			\
			/* Blind both points independently. */							\
			C##_blind(t[0], t[0]);											\
			C##_blind(t[1], t[1]);											\
																			\
			for (int i = bits - 1; i >= 0; i--) {							\
				int j = bn_get_bit(l, i);									\
				C##_swap_sec(t[0], t[1], j ^ 1);							\
				C##_add(t[0], t[0], t[1]);									\
				C##_dbl(t[1], t[1]);										\
				C##_swap_sec(t[0], t[1], j ^ 1);							\
			}																\
																			\
			C##_norm(r, t[0]);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free_all(n, l, _k);											\
			C##_free(t[1]);													\
			C##_free(t[0]);													\
		}																	\
	}

/**
 * Defines a template for simultaneous point multiplication by interleaving
 * w-NAFs.
 *
 * @param[in] C			- the curve.
 * @param[in] B			- the bound on the bit length of the scalars.
 */
#define TMPL_EC_MUL_SIM_PLAIN(C, B)											\
	static void C##_mul_sim_plain(C##_t r, const C##_t p, const bn_t k,		\
			const C##_t q, const bn_t m) {									\
		int i;																\
		int8_t naf0[B + 1], naf1[B + 1], n0, n1, *u, *v;					\
		C##_t t0[1 << (RLC_WIDTH - 2)];										\
		C##_t t1[1 << (RLC_WIDTH - 2)];										\
		size_t l, l0, l1;													\
																			\
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {						\
			C##_null(t0[i]);												\
			C##_null(t1[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			/* Compute the precomputation tables. */						\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_new(t0[i]);												\
				C##_new(t1[i]);												\
			}																\
			C##_tab(t0, p, RLC_WIDTH);										\
			C##_tab(t1, q, RLC_WIDTH);										\
																			\
			/* Compute the w-NAF representations of k and m. */				\
			l0 = l1 = B + 1;												\
			bn_rec_naf(naf0, &l0, k, RLC_WIDTH);							\
			bn_rec_naf(naf1, &l1, m, RLC_WIDTH);							\
																			\
			l = RLC_MAX(l0, l1);											\
			if (bn_sign(k) == RLC_NEG) {									\
				for (size_t j = 0; j < l0; j++) {							\
					naf0[j] = -naf0[j];										\
				}															\
			}																\
			if (bn_sign(m) == RLC_NEG) {									\
				for (size_t j = 0; j < l1; j++) {							\
					naf1[j] = -naf1[j];										\
				}															\
			}																\
																			\
			u = naf0 + l - 1;												\
			v = naf1 + l - 1;												\
			C##_set_infty(r);												\
			for (i = l - 1; i >= 0; i--, u--, v--) {						\
				C##_dbl(r, r);												\
																			\
				n0 = *u;													\
				n1 = *v;													\
				if (n0 > 0) {												\
					C##_add(r, r, t0[n0 / 2]);								\
				}															\
				if (n0 < 0) {												\
					C##_sub(r, r, t0[-n0 / 2]);								\
				}															\
				if (n1 > 0) {												\
					C##_add(r, r, t1[n1 / 2]);								\
				}															\
				if (n1 < 0) {												\
					C##_sub(r, r, t1[-n1 / 2]);								\
				}															\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			/* Free the precomputation tables. */							\
			for (i = 0; i < 1 << (RLC_WIDTH - 2); i++) {					\
				C##_free(t0[i]);											\
				C##_free(t1[i]);											\
			}																\
		}																	\
	}

/**
 * Defines a template for simultaneous multiplication of the generator and
 * another point.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_SIM_GEN(C)												\
	void C##_mul_sim_gen(C##_t r, const bn_t k, const C##_t q,				\
			const bn_t m) {													\
		C##_t g;															\
		bn_t n, _k, _m;														\
																			\
		if (bn_is_zero(k)) {												\
			C##_mul(r, q, m);												\
			return;															\
		}																	\
		if (bn_is_zero(m) || C##_is_infty(q)) {								\
			C##_mul_gen(r, k);												\
			return;															\
		}																	\
																			\
		C##_null(g);														\
		bn_null_all(n, _k, _m);												\
																			\
		RLC_TRY {															\
			C##_new(g);														\
			bn_new_all(n, _k, _m);											\
																			\
			C##_curve_get_gen(g);											\
			C##_curve_get_ord(n);											\
			bn_mod(_k, k, n);												\
			bn_mod(_m, m, n);												\
																			\
			C##_mul_sim(r, g, _k, q, _m);									\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			C##_free(g);													\
			bn_free_all(n, _k, _m);											\
		}																	\
	}

/**
 * Defines a template for simultaneous multiplication of several points by
 * small integers.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_SIM_DIG(C)												\
	void C##_mul_sim_dig(C##_t r, const C##_t p[], const dig_t k[],			\
			size_t len) {													\
		C##_t t;															\
		int max;															\
																			\
		C##_null(t);														\
																			\
		max = util_bits_dig(k[0]);											\
		for (size_t i = 1; i < len; i++) {									\
			max = RLC_MAX(max, (int)util_bits_dig(k[i]));					\
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
 * Defines a template for simultaneous multiplication of several points by
 * interleaving their NAFs, without endomorphisms. The number of points must be
 * positive.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EC_MUL_SIM_LOT_PLAIN(C)										\
	static void C##_mul_sim_lot_plain(C##_t r, const C##_t p[],				\
			const bn_t k[], int n) {										\
		int i, j;															\
		int8_t *naf = NULL;													\
		C##_t *_p = RLC_ALLOCA(C##_t, n);									\
		size_t l, *_l = RLC_ALLOCA(size_t, n);								\
																			\
		l = 0;																\
		for (i = 0; i < n; i++) {											\
			l = RLC_MAX(l, bn_bits(k[i]) + 1);								\
		}																	\
		naf = RLC_ALLOCA(int8_t, n * l);									\
		if (naf == NULL || _p == NULL || _l == NULL) {						\
			RLC_FREE(naf);													\
			RLC_FREE(_p);													\
			RLC_FREE(_l);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		for (i = 0; i < n; i++) {											\
			C##_null(_p[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			for (i = 0; i < n; i++) {										\
				C##_new(_p[i]);												\
			}																\
																			\
			for (i = 0; i < n; i++) {										\
				_l[i] = l;													\
				C##_norm(_p[i], p[i]);										\
				bn_rec_naf(&naf[i*l], &_l[i], k[i], 2);						\
				if (bn_sign(k[i]) == RLC_NEG) {								\
					C##_neg(_p[i], _p[i]);									\
				}															\
			}																\
																			\
			C##_set_infty(r);												\
			for (i = l - 1; i >= 0; i--) {									\
				C##_dbl(r, r);												\
				for (j = 0; j < n; j++) {									\
					if (naf[j*l + i] > 0) {									\
						C##_add(r, r, _p[j]);								\
					}														\
					if (naf[j*l + i] < 0) {									\
						C##_sub(r, r, _p[j]);								\
					}														\
				}															\
			}																\
																			\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			for (i = 0; i < n; i++) {										\
				C##_free(_p[i]);											\
			}																\
			RLC_FREE(_l);													\
			RLC_FREE(_p);													\
			RLC_FREE(naf);													\
		}																	\
	}

#endif /* !RLC_EC_MUL_TMPL_H */
