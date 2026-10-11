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
 * Defines a template for point multiplication using the GLS endomorphism. The
 * scalar is decomposed in S subscalars, each recoded in w-NAF form and
 * processed by interleaving.
 *
 * @param[in] C			- the curve.
 * @param[in] S			- the number of subscalars.
 */
#define TMPL_EP_MUL_GLS_IMP(C, S)											\
	static void C##_mul_gls_imp(C##_t r, const C##_t p, const bn_t k) {		\
		size_t l, _l[S], w = RLC_WIDTH;										\
		bn_t n, _k[S], u;													\
		int8_t naf[S][RLC_FP_BITS + 1];										\
		C##_t q, t[S][1 << (RLC_WIDTH - 2)];								\
																			\
		bn_null_all(n, u);													\
		C##_null(q);														\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
			C##_new(q);														\
			for (size_t i = 0; i < S; i++) {								\
				bn_null(_k[i]);												\
				bn_new(_k[i]);												\
				for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {		\
					C##_null(t[i][j]);										\
					C##_new(t[i][j]);										\
				}															\
			}																\
																			\
			C##_curve_get_ord(n);											\
			ep_curve_frbase(u);												\
			bn_mod(_k[0], k, n);											\
			bn_rec_frb(_k, S, _k[0], u, n, ep_curve_is_pairf() == EP_BN);	\
																			\
			l = 0;															\
			for (size_t i = 0; i < S; i++) {								\
				l = RLC_MAX(l, bn_bits(_k[i]));								\
			}																\
			if (l < bn_bits(u) / 2) {										\
				w = 2;														\
			}																\
																			\
			l = 0;															\
			for (size_t i = 0; i < S; i++) {								\
				_l[i] = RLC_FP_BITS + 1;									\
				bn_rec_naf(naf[i], &_l[i], _k[i], w);						\
				l = RLC_MAX(l, _l[i]);										\
				if (i == 0) {												\
					C##_norm(q, p);											\
					if (bn_sign(_k[0]) == RLC_NEG) {						\
						C##_neg(q, q);										\
					}														\
					C##_tab(t[0], q, w);									\
				} else if (ep_curve_is_pairf() == EP_K16 ||					\
						ep_curve_is_pairf() == EP_AFG16) {					\
					/* Minimize use of endomorphism when it's expensive. */	\
					C##_psi(q, t[i - 1][0]);								\
					if (bn_sign(_k[i]) != bn_sign(_k[i - 1])) {				\
						C##_neg(q, q);										\
					}														\
					C##_tab(t[i], q, w);									\
				} else {													\
					for (int j = 0; j < (1 << (w - 2)); j++) {				\
						C##_psi(t[i][j], t[i - 1][j]);						\
						if (bn_sign(_k[i]) != bn_sign(_k[i - 1])) {			\
							C##_neg(t[i][j], t[i][j]);						\
						}													\
					}														\
				}															\
			}																\
																			\
			C##_set_infty(r);												\
			for (int j = l - 1; j >= 0; j--) {								\
				C##_dbl(r, r);												\
																			\
				for (size_t i = 0; i < S; i++) {							\
					if (naf[i][j] > 0) {									\
						C##_add(r, r, t[i][naf[i][j] / 2]);					\
					}														\
					if (naf[i][j] < 0) {									\
						C##_sub(r, r, t[i][-naf[i][j] / 2]);				\
					}														\
				}															\
			}																\
																			\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free_all(n, u);												\
			C##_free(q);													\
			for (size_t i = 0; i < S; i++) {								\
				bn_free(_k[i]);												\
				for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {		\
					C##_free(t[i][j]);										\
				}															\
			}																\
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
		bn_null_all(n, u);													\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
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
			ep_curve_frbase(u);												\
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
			F##_set_dig(q[1]->z, 1);										\
			q[1]->coord = BASIC;											\
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
			bn_free_all(n, u);												\
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
 * Defines a template for point multiplication using the left-to-right w-NAF
 * method, for curves without an endomorphism.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_NAF_IMP(C)												\
	static void C##_mul_naf_imp(C##_t r, const C##_t p, const bn_t k) {		\
		/* Some of the supported prime curves have order > field. */		\
		int8_t u, naf[RLC_FP_BITS + 2];										\
		C##_t t[1 << (RLC_WIDTH - 2)];										\
		bn_t m, n;															\
		size_t l;															\
																			\
		bn_null_all(n, m);													\
																			\
		RLC_TRY {															\
			bn_new_all(n, m);												\
			/* Prepare the precomputation table. */							\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				C##_null(t[i]);												\
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
			l = RLC_FP_BITS + 2;											\
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
 * Defines a template for point multiplication using the Montgomery ladder.
 * The coordinates are swapped in constant time limb by limb, which works for
 * both automatic and dynamic memory allocation.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_MONTY(C, F)												\
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
				for (size_t c = 0; c < sizeof(F##_t) / sizeof(fp_t); c++) {	\
					dv_swap_sec(((fp_t *)t[0]->x)[c], ((fp_t *)t[1]->x)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
					dv_swap_sec(((fp_t *)t[0]->y)[c], ((fp_t *)t[1]->y)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
					dv_swap_sec(((fp_t *)t[0]->z)[c], ((fp_t *)t[1]->z)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
				}															\
				C##_add(t[0], t[0], t[1]);									\
				C##_dbl(t[1], t[1]);										\
				for (size_t c = 0; c < sizeof(F##_t) / sizeof(fp_t); c++) {	\
					dv_swap_sec(((fp_t *)t[0]->x)[c], ((fp_t *)t[1]->x)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
					dv_swap_sec(((fp_t *)t[0]->y)[c], ((fp_t *)t[1]->y)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
					dv_swap_sec(((fp_t *)t[0]->z)[c], ((fp_t *)t[1]->z)[c],	\
							RLC_FP_DIGS, j ^ 1);							\
				}															\
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
 * Defines a template for regular point multiplication using a regular
 * w-NAF recoding of the scalar.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_REG_IMP(C, F)											\
	static void C##_mul_reg_imp(C##_t r, const C##_t p, const bn_t k) {		\
		bn_t m, o;															\
		int i, j, n, even, neg;												\
		int8_t s, reg[1 + RLC_CEIL(RLC_FP_BITS + 1, RLC_WIDTH - 1)];		\
		C##_t t[1 << (RLC_WIDTH - 2)], u, v;								\
		size_t l;															\
																			\
		bn_null_all(m, o);													\
		C##_null_all(u, v);													\
																			\
		RLC_TRY {															\
			bn_new_all(m, o);												\
			C##_new_all(u, v);												\
			/* Prepare the precomputation table. */							\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_null(t[i]);												\
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
			F##_set_dig(u->z, 1);											\
			u->coord = BASIC;												\
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
				}															\
				C##_neg(v, u);												\
				F##_copy_sec(u->y, v->y, s != 0);							\
				C##_add(r, r, u);											\
			}																\
			/* t[0] has an unmodified copy of p. */							\
			C##_sub(u, r, t[0]);											\
			F##_copy_sec(r->x, u->x, even);									\
			F##_copy_sec(r->y, u->y, even);									\
			F##_copy_sec(r->z, u->z, even);									\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
			C##_neg(u, r);													\
			F##_copy_sec(r->y, u->y, neg);									\
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
 * Number of subscalars of the single-table comb method: one, or two when the
 * GLV endomorphism of a prime curve is available.
 */
#define TMPL_EP_MUL_FIX_DIM_plain	1
#define TMPL_EP_MUL_FIX_DIM_glv		(ep_curve_is_endom() ? 2 : 1)

/**
 * Defines a template for fixed-point multiplication using the single-table
 * comb method, including the precomputation. The multiplication dispatches to
 * C##_mul_fix_##E when the scalar is decomposed with an endomorphism.
 *
 * @param[in] C			- the curve.
 * @param[in] E			- the endomorphism method, glv or plain.
 */
#define TMPL_EP_MUL_FIX_BASIC(C, E)											\
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
			l = RLC_CEIL(bn_bits(n), TMPL_EP_MUL_FIX_DIM_##E * RLC_DEPTH);	\
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
			C##_norm_sim(t + 2, (const C##_t *)t + 2,						\
					RLC_EP_TABLE_BASIC - 2);								\
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
		if (TMPL_EP_MUL_FIX_DIM_##E > 1) {									\
			C##_mul_fix_##E(r, t, k);										\
			return;															\
		}																	\
																			\
		C##_mul_fix_plain(r, t, k);											\
	}

/**
 * Decomposes the scalar M modulo N into the subscalars K of the regular signed
 * comb, with the GLV endomorphism or without one.
 */
#define TMPL_EC_MUL_FIX_REC_glv(K, M, N)									\
	bn_rec_glv(K[0], K[1], M, N, ep_curve_get_v1(), ep_curve_get_v2())
#define TMPL_EC_MUL_FIX_REC_plain(K, M, N)	bn_copy(K[0], M)

/**
 * Bounds the bit length of the subscalars, with a margin for making them odd.
 */
#define TMPL_EC_MUL_FIX_LEN_glv(N)			(RLC_CEIL(bn_bits(N), 2) + 2)
#define TMPL_EC_MUL_FIX_LEN_plain(N)		bn_bits(N)

/**
 * Gives the dimension of the decomposition, which is S only for curves with an
 * endomorphism, and applies the endomorphism to a point. The plain versions
 * never reach the endomorphism, so curves without one need not provide it.
 */
#define TMPL_EC_MUL_FIX_DIM_glv(S)			(ep_curve_is_endom() ? S : 1)
#define TMPL_EC_MUL_FIX_DIM_plain(S)		1
#define TMPL_EC_MUL_FIX_PSI_glv(C, R, P)	C##_psi(R, P)
#define TMPL_EC_MUL_FIX_PSI_plain(C, R, P)	C##_copy(R, P)

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
		const int dim = TMPL_EC_MUL_FIX_DIM_##E(S);							\
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
			s = (dim > 1 ? TMPL_EC_MUL_FIX_LEN_##E(n) : bn_bits(n));		\
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
		const int dim = TMPL_EC_MUL_FIX_DIM_##E(S);							\
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
			l = (dim > 1 ? TMPL_EC_MUL_FIX_LEN_##E(n) : bn_bits(n));		\
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
				TMPL_EC_MUL_FIX_REC_##E(_k, m, n);							\
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
							TMPL_EC_MUL_FIX_PSI_##E(C, w, q);				\
							C##_add(r, r, w);								\
						}													\
					}														\
				}															\
			}																\
			/* Subtract P and psi(P) where k_j was made odd. */				\
			for (j = 0; j < (dim > 1 ? dim : 0); j++) {						\
				C##_copy(w, t[2 * h]);										\
				if (j > 0) {												\
					TMPL_EC_MUL_FIX_PSI_##E(C, w, w);						\
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
 * Defines a template for simultaneous point multiplication by interleaving
 * w-NAFs.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_SIM_PLAIN(C)											\
	static void C##_mul_sim_plain(C##_t r, const C##_t p, const bn_t k,		\
			const C##_t q, const bn_t m) {									\
		int i;																\
		int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], n0, n1, *u, *v;\
		C##_t t0[1 << (RLC_WIDTH - 2)];										\
		C##_t t1[1 << (RLC_WIDTH - 2)];										\
		size_t l, l0, l1;													\
																			\
		RLC_TRY {															\
			/* Compute the precomputation tables. */						\
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
				C##_null(t0[i]);											\
				C##_null(t1[i]);											\
				C##_new(t0[i]);												\
				C##_new(t1[i]);												\
			}																\
			C##_tab(t0, p, RLC_WIDTH);										\
			C##_tab(t1, q, RLC_WIDTH);										\
																			\
			/* Compute the w-NAF representations of k and m. */				\
			l0 = l1 = RLC_FP_BITS + 1;										\
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
 * Builds the table for the i-th subscalar of a simultaneous GLS
 * multiplication, applying the endomorphism to the previous table.
 *
 * @param[in] C			- the curve prefix.
 * @param[out] T		- the tables, each with E points.
 * @param[in] K			- the subscalars.
 * @param[in] P			- the point to multiply.
 * @param[in] V			- a temporary point.
 * @param[in] I			- the index of the subscalar.
 * @param[in] E			- the number of points in each table.
 * @param[in] W			- the window width.
 */
#define TMPL_EP_MUL_SIM_ENDOM_TAB(C, T, K, P, V, I, E, W)					\
	if (I == 0) {															\
		C##_norm(V, P);														\
		if (bn_sign(K[0]) == RLC_NEG) {										\
			C##_neg(V, V);													\
		}																	\
		C##_tab(T, V, W);													\
	} else {																\
		for (int _j = 0; _j < E; _j++) {									\
			C##_psi(T[I * E + _j], T[(I - 1) * E + _j]);					\
			if (bn_sign(K[I]) != bn_sign(K[I - 1])) {						\
				C##_neg(T[I * E + _j], T[I * E + _j]);						\
			}																\
		}																	\
	}

/**
 * Defines a template for simultaneous point multiplication by interleaving
 * w-NAFs of the subscalars produced by the GLS endomorphism.
 *
 * @param[in] C			- the curve.
 * @param[in] S			- the number of subscalars.
 */
#define TMPL_EP_MUL_SIM_ENDOM_GLS(C, S)										\
	static void C##_mul_sim_endom(C##_t r, const C##_t p, const bn_t k,		\
			const C##_t q, const bn_t m) {									\
		size_t l, _l[S], w = RLC_WIDTH, e;									\
		bn_t _k[S], _m[S], n, u;											\
		int8_t naf0[S][RLC_FP_BITS + 1], naf1[S][RLC_FP_BITS + 1];			\
		C##_t _p[S << (RLC_WIDTH - 2)], _q[S << (RLC_WIDTH - 2)], v;		\
																			\
		bn_null_all(n, u);													\
		C##_null(v);														\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
			C##_new(v);														\
			for (int i = 0; i < S; i++) {									\
				bn_null(_k[i]);												\
				bn_new(_k[i]);												\
				bn_null(_m[i]);												\
				bn_new(_m[i]);												\
			}																\
			for (int i = 0; i < (S << (RLC_WIDTH - 2)); i++) {				\
				C##_null(_p[i]);											\
				C##_null(_q[i]);											\
				C##_new(_p[i]);												\
				C##_new(_q[i]);												\
			}																\
																			\
			C##_curve_get_ord(n);											\
			ep_curve_frbase(u);												\
			bn_mod(_k[0], k, n);											\
			bn_rec_frb(_k, S, _k[0], u, n, ep_curve_is_pairf() == EP_BN);	\
			bn_mod(_m[0], m, n);											\
			bn_rec_frb(_m, S, _m[0], u, n, ep_curve_is_pairf() == EP_BN);	\
																			\
			l = 0;															\
			for (int i = 0; i < S; i++) {									\
				l = RLC_MAX(l, bn_bits(_k[i]));								\
				l = RLC_MAX(l, bn_bits(_m[i]));								\
			}																\
			/* Windows do not pay off for short subscalars or when the		\
			 * endomorphism is expensive, since each table entry needs it. */\
			if (l < bn_bits(u) / 2 || ep_curve_is_pairf() == EP_K16 ||		\
					ep_curve_is_pairf() == EP_AFG16 ||						\
					ep_curve_embed() == 18) {								\
				w = 2;														\
			}																\
			e = (1 << (w - 2));												\
																			\
			l = 0;															\
			for (int i = 0; i < S; i++) {									\
				_l[i] = RLC_FP_BITS + 1;									\
				bn_rec_naf(naf0[i], &_l[i], _k[i], w);						\
				l = RLC_MAX(l, _l[i]);										\
				_l[i] = RLC_FP_BITS + 1;									\
				bn_rec_naf(naf1[i], &_l[i], _m[i], w);						\
				l = RLC_MAX(l, _l[i]);										\
				TMPL_EP_MUL_SIM_ENDOM_TAB(C, _p, _k, p, v, i, e, w);		\
				TMPL_EP_MUL_SIM_ENDOM_TAB(C, _q, _m, q, v, i, e, w);		\
			}																\
			/* Normalize if the endomorphism returns projective points. */	\
			if (_p[e]->coord != BASIC) {									\
				C##_norm_sim(_p + e, (const C##_t *)_p + e, (S - 1) * e);	\
				C##_norm_sim(_q + e, (const C##_t *)_q + e, (S - 1) * e);	\
			}																\
																			\
			C##_set_infty(r);												\
			for (int i = l - 1; i >= 0; i--) {								\
				C##_dbl(r, r);												\
				for (int j = 0; j < S; j++) {								\
					if (naf0[j][i] > 0) {									\
						C##_add(r, r, _p[j * e + naf0[j][i] / 2]);			\
					}														\
					if (naf0[j][i] < 0) {									\
						C##_sub(r, r, _p[j * e - naf0[j][i] / 2]);			\
					}														\
					if (naf1[j][i] > 0) {									\
						C##_add(r, r, _q[j * e + naf1[j][i] / 2]);			\
					}														\
					if (naf1[j][i] < 0) {									\
						C##_sub(r, r, _q[j * e - naf1[j][i] / 2]);			\
					}														\
				}															\
			}																\
																			\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free_all(n, u);												\
			C##_free(v);													\
			for (int i = 0; i < S; i++) {									\
				bn_free(_k[i]);												\
				bn_free(_m[i]);												\
			}																\
			for (int i = 0; i < (S << (RLC_WIDTH - 2)); i++) {				\
				C##_free(_p[i]);											\
				C##_free(_q[i]);											\
			}																\
		}																	\
	}

/**
 * Defines a template for simultaneous point multiplication by interleaving,
 * using the endomorphism when the curve has one.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_SIM(C)													\
	void C##_mul_sim(C##_t r, const C##_t p, const bn_t k,					\
			const C##_t q, const bn_t m) {									\
		bn_t n, _k, _m;														\
																			\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_mul(r, q, m);												\
			return;															\
		}																	\
		if (bn_is_zero(m) || C##_is_infty(q)) {								\
			C##_mul(r, p, k);												\
			return;															\
		}																	\
																			\
		bn_null_all(n, _k, _m);												\
																			\
		RLC_TRY {															\
			bn_new_all(n, _k, _m);											\
																			\
			/* Reduce the scalars here to simplify the static functions. */	\
			C##_curve_get_ord(n);											\
			bn_mod(_k, k, n);												\
			bn_mod(_m, m, n);												\
																			\
			if (ep_curve_is_endom()) {										\
				C##_mul_sim_endom(r, p, _k, q, _m);							\
			} else {														\
				C##_mul_sim_plain(r, p, _k, q, _m);							\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free_all(n, _k, _m);											\
		}																	\
	}

/**
 * Defines a template for simultaneous multiplication of the generator and
 * another point.
 *
 * @param[in] C			- the curve.
 */
#define TMPL_EP_MUL_SIM_GEN(C)												\
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
 * Defines a template for simultaneous multiplication of several points using
 * the GLS endomorphism. Each scalar is decomposed in S subscalars. Few points
 * are processed by interleaving, many points by the bucket method over all the
 * endomorphism images.
 *
 * @param[in] C			- the curve.
 * @param[in] S			- the number of subscalars.
 */
#define TMPL_EP_MUL_SIM_LOT(C, S)											\
	void C##_mul_sim_lot(C##_t r, const C##_t p[], const bn_t k[],			\
			size_t n) {														\
		const int flag = (ep_curve_is_pairf() == EP_BN);					\
		const size_t len = RLC_FP_BITS + 1;									\
		size_t i, j, m;														\
		bn_t _k[S], q, x;													\
		int8_t ptr, *naf = RLC_ALLOCA(int8_t, S * n * len);					\
		size_t l, _l[S];													\
																			\
		if (n == 0) {														\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null_all(q, x);													\
																			\
		if (n <= 10) {														\
			C##_t *_p = RLC_ALLOCA(C##_t, S * n);							\
																			\
			RLC_TRY {														\
				if (naf == NULL || _p == NULL) {							\
					RLC_THROW(ERR_NO_MEMORY);								\
				}															\
				bn_new_all(q, x);											\
				for (j = 0; j < S; j++) {									\
					bn_null(_k[j]);											\
					bn_new(_k[j]);											\
					for (i = 0; i < n; i++) {								\
						C##_null(_p[S*i + j]);								\
						C##_new(_p[S*i + j]);								\
					}														\
				}															\
																			\
				l = 0;														\
				C##_curve_get_ord(q);										\
				ep_curve_frbase(x);											\
				for (i = 0; i < n; i++) {									\
					C##_norm(_p[S*i], p[i]);								\
					for (j = 1; j < S; j++) {								\
						C##_psi(_p[S*i + j], _p[S*i + j - 1]);				\
					}														\
																			\
					bn_mod(_k[0], k[i], q);									\
					bn_rec_frb(_k, S, _k[0], x, q, flag);					\
					for (j = 0; j < S; j++) {								\
						_l[j] = len;										\
						bn_rec_naf(&naf[(S*i + j)*len], &_l[j], _k[j], 2);	\
						if (bn_sign(_k[j]) == RLC_NEG) {					\
							C##_neg(_p[S*i + j], _p[S*i + j]);				\
						}													\
						l = RLC_MAX(l, _l[j]);								\
					}														\
				}															\
																			\
				C##_set_infty(r);											\
				for (int b = l - 1; b >= 0; b--) {							\
					C##_dbl(r, r);											\
					for (j = 0; j < n; j++) {								\
						for (m = 0; m < S; m++) {							\
							if (naf[(S*j + m)*len + b] > 0) {				\
								C##_add(r, r, _p[S*j + m]);					\
							}												\
							if (naf[(S*j + m)*len + b] < 0) {				\
								C##_sub(r, r, _p[S*j + m]);					\
							}												\
						}													\
					}														\
				}															\
																			\
				/* Convert r to affine coordinates. */						\
				C##_norm(r, r);												\
			} RLC_CATCH_ANY {												\
				RLC_THROW(ERR_CAUGHT);										\
			} RLC_FINALLY {													\
				bn_free_all(q, x);											\
				for (j = 0; j < S; j++) {									\
					bn_free(_k[j]);											\
					for (i = 0; i < n; i++) {								\
						C##_free(_p[S*i + j]);								\
					}														\
				}															\
				RLC_FREE(_p);												\
				RLC_FREE(naf);												\
			}																\
		} else {															\
			const int w = RLC_MAX(2, util_bits_dig(n) - 2);					\
			const size_t c = (1 << (w - 2));								\
			C##_t s, t, u, v, *_p = RLC_ALLOCA(C##_t, c);					\
			C##_t *_q = RLC_ALLOCA(C##_t, S * n);							\
																			\
			C##_null_all(s, t, u, v);										\
																			\
			RLC_TRY {														\
				if (naf == NULL || _p == NULL || _q == NULL) {				\
					RLC_THROW(ERR_NO_MEMORY);								\
				}															\
				bn_new_all(q, x);											\
				C##_new_all(s, t, u, v);									\
				for (i = 0; i < S; i++) {									\
					bn_null(_k[i]);											\
					bn_new(_k[i]);											\
				}															\
				for (j = 0; j < c; j++) {									\
					C##_null(_p[j]);										\
					C##_new(_p[j]);											\
					C##_set_infty(_p[j]);									\
				}															\
				for (i = 0; i < S * n; i++) {								\
					C##_null(_q[i]);										\
					C##_new(_q[i]);											\
				}															\
																			\
				l = 0;														\
				C##_curve_get_ord(q);										\
				ep_curve_frbase(x);											\
				for (i = 0; i < n; i++) {									\
					C##_norm(_q[S*i], p[i]);								\
					for (j = 1; j < S; j++) {								\
						C##_psi(_q[S*i + j], _q[S*i + j - 1]);				\
					}														\
					bn_mod(_k[0], k[i], q);									\
					bn_rec_frb(_k, S, _k[0], x, q, flag);					\
					for (j = 0; j < S; j++) {								\
						_l[j] = len;										\
						bn_rec_naf(&naf[(S*i + j)*len], &_l[j], _k[j], w);	\
						if (bn_sign(_k[j]) == RLC_NEG) {					\
							for (m = 0; m < _l[j]; m++) {					\
								naf[(S*i + j)*len + m] =					\
										-naf[(S*i + j)*len + m];			\
							}												\
						}													\
						l = RLC_MAX(l, _l[j]);								\
					}														\
				}															\
				/* The endomorphism may return projective points. */		\
				C##_norm_sim(_q, (const C##_t *)_q, S * n);					\
																			\
				C##_set_infty(s);											\
				for (int b = l - 1; b >= 0; b--) {							\
					for (j = 0; j < n; j++) {								\
						for (m = 0; m < S; m++) {							\
							ptr = naf[(S*j + m)*len + b];					\
							if (ptr != 0) {									\
								C##_copy(t, _q[S*j + m]);					\
								if (ptr < 0) {								\
									ptr = -ptr;								\
									C##_neg(t, t);							\
								}											\
								C##_add(_p[ptr/2], _p[ptr/2], t);			\
							}												\
						}													\
					}														\
																			\
					C##_set_infty(u);										\
					C##_set_infty(v);										\
					for (int d = c - 1; d >= 0; d--) {						\
						C##_add(u, u, _p[d]);								\
						if (d == 0) {										\
							C##_dbl(v, v);									\
						}													\
						C##_add(v, v, u);									\
						C##_set_infty(_p[d]);								\
					}														\
					C##_dbl(s, s);											\
					C##_add(s, s, v);										\
				}															\
																			\
				/* Convert r to affine coordinates. */						\
				C##_norm(r, s);												\
			} RLC_CATCH_ANY {												\
				RLC_THROW(ERR_CAUGHT);										\
			} RLC_FINALLY {													\
				bn_free_all(q, x);											\
				C##_free_all(s, t, u, v);									\
				for (i = 0; i < S; i++) {									\
					bn_free(_k[i]);											\
				}															\
				for (j = 0; j < c; j++) {									\
					C##_free(_p[j]);										\
				}															\
				for (i = 0; i < S * n; i++) {								\
					C##_free(_q[i]);										\
				}															\
				RLC_FREE(_p);												\
				RLC_FREE(_q);												\
				RLC_FREE(naf);												\
			}																\
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

/**
 * Defines a template for point multiplication using the left-to-right w-NAF
 * method, with an endomorphism when the curve has one.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] E			- the endomorphism method, glv or gls.
 */
#define TMPL_EP_MUL_LWNAF(C, E)												\
	void C##_mul_lwnaf(C##_t r, const C##_t p, const bn_t k) {				\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (ep_curve_is_endom()) {											\
			C##_mul_##E##_imp(r, p, k);										\
			return;															\
		}																	\
																			\
		C##_mul_naf_imp(r, p, k);											\
	}

/**
 * Defines a template for point multiplication using the left-to-right regular
 * recoding method, with an endomorphism when the curve has one.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] E			- the endomorphism method, glv or gls.
 */
#define TMPL_EP_MUL_LWREG(C, E)												\
	void C##_mul_lwreg(C##_t r, const C##_t p, const bn_t k) {				\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (ep_curve_is_endom()) {											\
			C##_mul_reg_##E(r, p, k);										\
			return;															\
		}																	\
																			\
		C##_mul_reg_imp(r, p, k);											\
	}

/**
 * Selects the GLS multiplication: the w-NAF template, or the curve's own
 * implementation defined before the bundle.
 */
#define TMPL_EP_MUL_GLS_IMP_WNAF	TMPL_EP_MUL_GLS_IMP
#define TMPL_EP_MUL_GLS_IMP_OWN(C, S)	/* Provided by the curve. */

/**
 * Defines a template for all point multiplications of an elliptic curve over
 * an extension field with a GLS endomorphism: variable-base, fixed-base and
 * simultaneous methods, and their dispatchers.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 * @param[in] S			- the dimension of the GLS decomposition.
 * @param[in] T			- the number of groups for regular recoding.
 * @param[in] G			- the GLS multiplication, WNAF or OWN.
 */
#define TMPL_EPX_MUL(C, F, S, T, G)											\
	TMPL_EP_MUL_GLS_IMP_##G(C, S)											\
	TMPL_EP_MUL_REG_GLS(C, F, S, T)											\
	TMPL_EP_MUL_NAF_IMP(C)													\
	TMPL_EP_MUL_REG_IMP(C, F)												\
	TMPL_EP_MUL_SIM_ENDOM_GLS(C, S)											\
	TMPL_EP_MUL_SIM_PLAIN(C)												\
	TMPL_EP_MUL_BASIC(C)													\
	TMPL_EP_MUL_MONTY(C, F)													\
	TMPL_EP_MUL_LWNAF(C, gls)												\
	TMPL_EP_MUL_LWREG(C, gls)												\
	TMPL_EP_MUL_GEN(C)														\
	TMPL_EP_MUL_DIG(C)														\
	TMPL_EP_MUL_FIX_BASIC(C, plain)											\
	TMPL_EC_MUL_FIX_LWREG(C, F, plain, 1, RLC_FP_BITS)						\
	TMPL_EP_MUL_COMBD(C)													\
	TMPL_EP_MUL_SIM(C)														\
	TMPL_EP_MUL_SIM_GEN(C)													\
	TMPL_EP_MUL_SIM_DIG(C)													\
	TMPL_EP_MUL_SIM_LOT(C, S)
