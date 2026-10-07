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
 * Templates for exponentiation in cyclotomic subgroups of extension fields.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for exponentiation in the cyclotomic subgroup, using w-NAF
 * for dense exponents and compressed squarings for sparse ones.
 *
 * @param[in] F			- the extension field prefix.
 */
#define TMPL_EXP_CYC(F)														\
	void F##_exp_cyc(F##_t c, const F##_t a, const bn_t b) {				\
		size_t l, w = bn_ham(b);											\
																			\
		if (bn_is_zero(b)) {												\
			return F##_set_dig(c, 1);										\
		}																	\
																			\
		if ((bn_bits(b) > RLC_DIG) && ((w << 3) > bn_bits(b))) {			\
			F##_t r, s, t[1 << (RLC_WIDTH - 2)];							\
			int8_t naf[RLC_FP_BITS + 1], *k;								\
																			\
			w = RLC_WIDTH;													\
																			\
			F##_null_all(r, s);												\
																			\
			RLC_TRY {														\
				F##_new_all(r, s);											\
				for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {			\
					F##_null(t[i]);											\
					F##_new(t[i]);											\
				}															\
																			\
				/* Precompute odd powers of a. */							\
				F##_copy(t[0], a);											\
				F##_sqr_cyc(r, a);											\
				for (int i = 1; i < (1 << (w - 2)); i++) {					\
					F##_mul(t[i], t[i - 1], r);								\
				}															\
																			\
				l = RLC_FP_BITS + 1;										\
				F##_set_dig(r, 1);											\
				bn_rec_naf(naf, &l, b, w);									\
																			\
				k = naf + l - 1;											\
				for (int i = l - 1; i >= 0; i--, k--) {						\
					F##_sqr_cyc(r, r);										\
																			\
					if (*k > 0) {											\
						F##_mul(r, r, t[*k / 2]);							\
					}														\
					if (*k < 0) {											\
						F##_inv_cyc(s, t[-*k / 2]);							\
						F##_mul(r, r, s);									\
					}														\
				}															\
																			\
				if (bn_sign(b) == RLC_NEG) {								\
					F##_inv_cyc(c, r);										\
				} else {													\
					F##_copy(c, r);											\
				}															\
			} RLC_CATCH_ANY {												\
				RLC_THROW(ERR_CAUGHT);										\
			}																\
			RLC_FINALLY {													\
				F##_free_all(r, s);											\
				for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {			\
					F##_free(t[i]);											\
				}															\
			}																\
		} else {															\
			size_t j, k;													\
			F##_t t, *u = RLC_ALLOCA(F##_t, w);								\
																			\
			F##_null(t);													\
																			\
			RLC_TRY {														\
				if (u == NULL) {											\
					RLC_THROW(ERR_NO_MEMORY);								\
				}															\
				for (size_t i = 0; i < w; i++) {							\
					F##_null(u[i]);											\
					F##_new(u[i]);											\
				}															\
				F##_new(t);													\
																			\
				j = 0;														\
				F##_copy(t, a);												\
				for (size_t i = 1; i < bn_bits(b); i++) {					\
					F##_sqr_pck(t, t);										\
					if (bn_get_bit(b, i)) {									\
						F##_copy(u[j++], t);								\
					}														\
				}															\
																			\
				if (!bn_is_even(b)) {										\
					j = 0;													\
					k = w - 1;												\
				} else {													\
					j = 1;													\
					k = w;													\
				}															\
																			\
				F##_back_cyc_sim(u, u, k);									\
																			\
				if (!bn_is_even(b)) {										\
					F##_copy(c, a);											\
				} else {													\
					F##_copy(c, u[0]);										\
				}															\
																			\
				for (size_t i = j; i < k; i++) {							\
					F##_mul(c, c, u[i]);									\
				}															\
																			\
				if (bn_sign(b) == RLC_NEG) {								\
					F##_inv_cyc(c, c);										\
				}															\
			}																\
			RLC_CATCH_ANY {													\
				RLC_THROW(ERR_CAUGHT);										\
			}																\
			RLC_FINALLY {													\
				for (size_t i = 0; i < w; i++) {							\
					F##_free(u[i]);											\
				}															\
				F##_free(t);												\
				RLC_FREE(u);												\
			}																\
		}																	\
	}

/**
 * Defines a template for exponentiation in the cyclotomic subgroup by a sparse
 * exponent, using compressed squarings and simultaneous decompression.
 *
 * @param[in] F			- the extension field prefix.
 */
#define TMPL_EXP_CYC_SPS(F)													\
	void F##_exp_cyc_sps(F##_t c, const F##_t a, const int *b, size_t len,	\
			int sign) {														\
		size_t i, j, k, w = len;											\
		F##_t t, *u = RLC_ALLOCA(F##_t, w);									\
																			\
		if (len == 0) {														\
			RLC_FREE(u);													\
			F##_set_dig(c, 1);												\
			return;															\
		}																	\
																			\
		F##_null(t);														\
																			\
		RLC_TRY {															\
			if (u == NULL) {												\
				RLC_THROW(ERR_NO_MEMORY);									\
			}																\
			for (i = 0; i < w; i++) {										\
				F##_null(u[i]);												\
				F##_new(u[i]);												\
			}																\
			F##_new(t);														\
																			\
			F##_copy(t, a);													\
			if (b[0] == 0) {												\
				for (j = 0, i = 1; i < len; i++) {							\
					k = (b[i] < 0 ? -b[i] : b[i]);							\
					for (; j < k; j++) {									\
						F##_sqr_pck(t, t);									\
					}														\
					if (b[i] < 0) {											\
						F##_inv_cyc(u[i - 1], t);							\
					} else {												\
						F##_copy(u[i - 1], t);								\
					}														\
				}															\
																			\
				F##_back_cyc_sim(u, u, w - 1);								\
																			\
				F##_copy(c, a);												\
				for (i = 0; i < w - 1; i++) {								\
					F##_mul(c, c, u[i]);									\
				}															\
			} else {														\
				for (j = 0, i = 0; i < len; i++) {							\
					k = (b[i] < 0 ? -b[i] : b[i]);							\
					for (; j < k; j++) {									\
						F##_sqr_pck(t, t);									\
					}														\
					if (b[i] < 0) {											\
						F##_inv_cyc(u[i], t);								\
					} else {												\
						F##_copy(u[i], t);									\
					}														\
				}															\
																			\
				F##_back_cyc_sim(u, u, w);									\
																			\
				F##_copy(c, u[0]);											\
				for (i = 1; i < w; i++) {									\
					F##_mul(c, c, u[i]);									\
				}															\
			}																\
																			\
			if (sign == RLC_NEG) {											\
				F##_inv_cyc(c, c);											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			for (i = 0; i < w; i++) {										\
				F##_free(u[i]);												\
			}																\
			F##_free(t);													\
			RLC_FREE(u);													\
		}																	\
	}

/**
 * Defines a template for simultaneous exponentiation in the cyclotomic
 * subgroup, using interleaved w-NAF recodings of the exponents.
 *
 * @param[in] F			- the extension field prefix.
 * @param[in] SQR		- the squaring function for cyclotomic elements.
 */
#define TMPL_EXP_CYC_SIM(F, SQR)											\
	void F##_exp_cyc_sim(F##_t e, const F##_t a, const bn_t b,				\
			const F##_t c, const bn_t d) {									\
		int n0, n1;															\
		int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;		\
		F##_t r, t0[1 << (RLC_WIDTH - 2)];									\
		F##_t s, t1[1 << (RLC_WIDTH - 2)];									\
		size_t l, l0, l1;													\
																			\
		if (bn_is_zero(b)) {												\
			return F##_exp_cyc(e, c, d);									\
		}																	\
																			\
		if (bn_is_zero(d)) {												\
			return F##_exp_cyc(e, a, b);									\
		}																	\
																			\
		F##_null_all(r, s);													\
																			\
		RLC_TRY {															\
			F##_new_all(r, s);												\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {				\
				F##_null(t0[i]);											\
				F##_null(t1[i]);											\
				F##_new(t0[i]);												\
				F##_new(t1[i]);												\
			}																\
																			\
			/* Precompute odd powers of a and c. */							\
			F##_copy(t0[0], a);												\
			SQR(r, a);														\
			for (int i = 1; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_mul(t0[i], t0[i - 1], r);								\
			}																\
			F##_copy(t1[0], c);												\
			SQR(r, c);														\
			for (int i = 1; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_mul(t1[i], t1[i - 1], r);								\
			}																\
																			\
			l0 = l1 = RLC_FP_BITS + 1;										\
			bn_rec_naf(naf0, &l0, b, RLC_WIDTH);							\
			bn_rec_naf(naf1, &l1, d, RLC_WIDTH);							\
																			\
			l = RLC_MAX(l0, l1);											\
			if (bn_sign(b) == RLC_NEG) {									\
				for (size_t i = 0; i < l0; i++) {							\
					naf0[i] = -naf0[i];										\
				}															\
			}																\
			if (bn_sign(d) == RLC_NEG) {									\
				for (size_t i = 0; i < l1; i++) {							\
					naf1[i] = -naf1[i];										\
				}															\
			}																\
																			\
			_k = naf0 + l - 1;												\
			_m = naf1 + l - 1;												\
																			\
			F##_set_dig(r, 1);												\
			for (int i = l - 1; i >= 0; i--, _k--, _m--) {					\
				SQR(r, r);													\
																			\
				n0 = *_k;													\
				n1 = *_m;													\
																			\
				if (n0 > 0) {												\
					F##_mul(r, r, t0[n0 / 2]);								\
				}															\
				if (n0 < 0) {												\
					F##_inv_cyc(s, t0[-n0 / 2]);							\
					F##_mul(r, r, s);										\
				}															\
				if (n1 > 0) {												\
					F##_mul(r, r, t1[n1 / 2]);								\
				}															\
				if (n1 < 0) {												\
					F##_inv_cyc(s, t1[-n1 / 2]);							\
					F##_mul(r, r, s);										\
				}															\
			}																\
																			\
			F##_copy(e, r);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free_all(r, s);												\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_free(t0[i]);											\
				F##_free(t1[i]);											\
			}																\
		}																	\
	}
