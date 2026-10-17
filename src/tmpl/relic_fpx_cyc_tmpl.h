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
 * Defines a template for exponentiation in the cyclotomic subgroup using w-NAF,
 * for extension fields without compressed squarings.
 *
 * @param[in] F			- the extension field prefix.
 * @param[in] SQR		- the squaring function for cyclotomic elements.
 */
#define TMPL_EXP_CYC_NAF(F, SQR)											\
	void F##_exp_cyc(F##_t c, const F##_t a, const bn_t b) {				\
		size_t l, w = RLC_WIDTH;											\
		F##_t r, s, t[1 << (RLC_WIDTH - 2)];								\
		int8_t naf[RLC_FP_BITS + 1], *k;									\
																			\
		if (bn_is_zero(b)) {												\
			return F##_set_dig(c, 1);										\
		}																	\
																			\
		if (bn_bits(b) <= RLC_DIG) {										\
			w = 2;															\
		}																	\
																			\
		F##_null_all(r, s);													\
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
			F##_null(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			F##_new_all(r, s);												\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_new(t[i]);												\
			}																\
																			\
			/* Precompute odd powers of a. */								\
			F##_copy(t[0], a);												\
			SQR(r, a);														\
			for (int i = 1; i < (1 << (w - 2)); i++) {						\
				F##_mul(t[i], t[i - 1], r);									\
			}																\
																			\
			l = RLC_FP_BITS + 1;											\
			F##_set_dig(r, 1);												\
			bn_rec_naf(naf, &l, b, w);										\
																			\
			k = naf + l - 1;												\
			for (int i = l - 1; i >= 0; i--, k--) {							\
				SQR(r, r);													\
																			\
				if (*k > 0) {												\
					F##_mul(r, r, t[*k / 2]);								\
				}															\
				if (*k < 0) {												\
					F##_inv_cyc(s, t[-*k / 2]);								\
					F##_mul(r, r, s);										\
				}															\
			}																\
																			\
			if (bn_sign(b) == RLC_NEG) {									\
				F##_inv_cyc(c, r);											\
			} else {														\
				F##_copy(c, r);												\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(r, s);												\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_free(t[i]);												\
			}																\
		}																	\
	}

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
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
				F##_null(t[i]);												\
			}																\
																			\
			RLC_TRY {														\
				F##_new_all(r, s);											\
				for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {			\
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
			/* Collect the positions of the nonzero bits of the exponent. */\
			int *e = RLC_ALLOCA(int, w);									\
			size_t j = 0;													\
																			\
			if (e == NULL) {												\
				RLC_THROW(ERR_NO_MEMORY);									\
				return;														\
			}																\
			for (size_t i = 0; i < bn_bits(b); i++) {						\
				if (bn_get_bit(b, i)) {										\
					e[j++] = i;												\
				}															\
			}																\
			F##_exp_cyc_sps(c, a, e, w, bn_sign(b));						\
			RLC_FREE(e);													\
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
		if (u == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		F##_null(t);														\
		for (i = 0; i < w; i++) {											\
			F##_null(u[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			for (i = 0; i < w; i++) {										\
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
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {					\
			F##_null(t0[i]);												\
			F##_null(t1[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			F##_new_all(r, s);												\
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {				\
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

/**
 * Defines a template for testing if an element of a quadratic extension
 * field is unitary, that is, has norm one.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_TEST_CYC_QUAD(X)											\
	int X##_test_cyc(const X##_t a) {										\
		X##_t t;															\
		int result = 0;														\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
			X##_inv_cyc(t, a);												\
			X##_mul(t, t, a);												\
			result = ((X##_cmp_dig(t, 1) == RLC_EQ) ? 1 : 0);				\
		}																	\
		RLC_CATCH_ANY {														\
			result = 0;														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
																			\
		return result;														\
	}

/**
 * Defines a template for mapping an element of a quadratic extension field
 * to the subgroup of unitary elements.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_CONV_CYC_QUAD(X)											\
	void X##_conv_cyc(X##_t c, const X##_t a) {								\
		X##_t t;															\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
																			\
			/* t = a^{-1}. */												\
			X##_inv(t, a);													\
			/* c = a^(p^4). */												\
			X##_inv_cyc(c, a);												\
			/* c = a^(p^4 - 1). */											\
			X##_mul(c, c, t);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}

/**
 * Defines a template for testing if an extension field element is in
 * the cyclotomic subgroup, where F is a sixth of the embedding degree.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] F			- the Frobenius power for the test.
 */
#define TMPL_FPX_TEST_CYC(X, F)												\
	int X##_test_cyc(const X##_t a) {										\
		X##_t t0, t1;														\
		int result = 0;														\
																			\
		X##_null_all(t0, t1);												\
																			\
		RLC_TRY {															\
			X##_new_all(t0, t1);											\
																			\
			/* Check if a^(p^(2F) - p^F + 1) == 1. */						\
			X##_frb(t0, a, 2 * (F));										\
			X##_mul(t0, t0, a);												\
			X##_frb(t1, a, (F));											\
																			\
			/* Zero satisfies the equation, but it is not invertible. */	\
			result = !X##_is_zero(a) && (X##_cmp(t0, t1) == RLC_EQ);		\
		}																	\
		RLC_CATCH_ANY {														\
			result = 0;														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free_all(t0, t1);											\
		}																	\
																			\
		return result;														\
	}

/**
 * Defines a template for mapping an extension field element to the
 * cyclotomic subgroup, where F is a sixth of the embedding degree.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] F			- the Frobenius power for the map.
 */
#define TMPL_FPX_CONV_CYC(X, F)												\
	void X##_conv_cyc(X##_t c, const X##_t a) {								\
		X##_t t;															\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
																			\
			/* First, compute c = a^(p^(3F) - 1). */						\
			/* t = a^{-1}. */												\
			X##_inv(t, a);													\
			/* c = a^(p^(3F)). */											\
			X##_inv_cyc(c, a);												\
			/* c = a^(p^(3F) - 1). */										\
			X##_mul(c, c, t);												\
																			\
			/* Second, compute c^(p^F + 1). */								\
			/* t = c^(p^F). */												\
			X##_frb(t, c, (F));												\
																			\
			/* c = c^(p^F + 1). */											\
			X##_mul(c, c, t);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}

/**
 * Defines a template for compressing elements of the cyclotomic subgroup in an
 * extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 */
#define TMPL_FPX_PCK_QC(X, Z)												\
	void X##_pck(X##_t c, const X##_t a) {									\
		X##_copy(c, a);														\
		if (X##_test_cyc(c)) {												\
			Z##_zero(c[0][0]);												\
			Z##_zero(c[1][1]);												\
		}																	\
	}

/**
 * Defines a template for decompressing elements of the cyclotomic subgroup
 * in an extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 */
#define TMPL_FPX_UPK_QC(X, Z)												\
	int X##_upk(X##_t c, const X##_t a) {									\
		if (Z##_is_zero(a[0][0]) && Z##_is_zero(a[1][1])) {					\
			X##_back_cyc(c, a);												\
			if (X##_test_cyc(c)) {											\
				return 1;													\
			} else {														\
				return 0;													\
			}																\
		} else {															\
			X##_copy(c, a);													\
			return 1;														\
		}																	\
	}

/**
 * Defines a template for compressing elements of the cyclotomic subgroup in an
 * extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 */
#define TMPL_FPX_PCK_CQ(X, Z)												\
	void X##_pck(X##_t c, const X##_t a) {									\
		X##_copy(c, a);														\
		if (X##_test_cyc(c)) {												\
			Z##_zero(c[0][0]);												\
			Z##_zero(c[0][1]);												\
		}																	\
	}

/**
 * Defines a template for decompressing elements of the cyclotomic subgroup
 * in an extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 */
#define TMPL_FPX_UPK_CQ(X, Z)												\
	int X##_upk(X##_t c, const X##_t a) {									\
		if (Z##_is_zero(a[0][0]) && Z##_is_zero(a[0][1])) {					\
			X##_back_cyc(c, a);												\
			if (X##_test_cyc(c)) {											\
				return 1;													\
			} else {														\
				return 0;													\
			}																\
		} else {															\
			X##_copy(c, a);													\
			return 1;														\
		}																	\
	}

/**
 * Defines a template for decompressing elements of the cyclotomic
 * subgroup in an extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_BACK_CYC_QC(X, Z, NOR)										\
	void X##_back_cyc(X##_t c, const X##_t a) {								\
		Z##_t t0, t1, t2;													\
																			\
		Z##_null_all(t0, t1, t2);											\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2);										\
																			\
			int f = Z##_is_zero(a[1][0]);									\
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */							\
			Z##_copy(t2, a[0][1]);											\
			Z##_copy_sec(t2, a[1][2], f);									\
			/* t0 = g4^2. */												\
			Z##_mul(t0, a[0][1], t2);										\
			Z##_dbl(t2, t0);												\
			Z##_copy_sec(t0, t2, f);										\
			/* t1 = 3 * g4^2 - 2 * g3. */									\
			Z##_sub(t1, t0, a[0][2]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(t1, t1, t0);											\
			/* t0 = E * g5^2 + t1. */										\
			Z##_sqr(t2, a[1][2]);											\
			NOR(t0, t2);													\
			Z##_add(t0, t0, t1);											\
			/* t1 = (4 * g2). */											\
			Z##_dbl(t1, a[1][0]);											\
			Z##_dbl(t1, t1);												\
			Z##_copy_sec(t1, a[0][2], f);									\
			/* All kept coefficients zero: decompress to unity. */			\
			f = Z##_is_zero(a[0][1]) && Z##_is_zero(a[0][2]) &&				\
					Z##_is_zero(a[1][0]) && Z##_is_zero(a[1][2]);			\
			Z##_set_dig(t2, 1);												\
			Z##_copy_sec(t1, t2, f);										\
																			\
			/* t1 = 1/g3 or 1/(4*g2), depending on the above. */			\
			Z##_inv(t1, t1);												\
			/* c_1 = g1. */													\
			Z##_mul(c[1][1], t0, t1);										\
																			\
			/* t1 = g3 * g4. */												\
			Z##_mul(t1, a[0][2], a[0][1]);									\
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */								\
			Z##_sqr(t2, c[1][1]);											\
			Z##_sub(t2, t2, t1);											\
			Z##_dbl(t2, t2);												\
			Z##_sub(t2, t2, t1);											\
			/* t1 = g2 * g5. */												\
			Z##_mul(t1, a[1][0], a[1][2]);									\
			/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */			\
			Z##_add(t2, t2, t1);											\
			NOR(c[0][0], t2);												\
			fp_add_dig(((fp_t *)c[0][0])[0], ((fp_t *)c[0][0])[0], 1);		\
																			\
			Z##_copy(c[0][1], a[0][1]);										\
			Z##_copy(c[0][2], a[0][2]);										\
			Z##_copy(c[1][0], a[1][0]);										\
			Z##_copy(c[1][2], a[1][2]);										\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2);										\
		}																	\
	}

/**
 * Defines a template for simultaneously decompressing elements of the
 * cyclotomic subgroup in an extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_BACK_CYC_SIM_QC(X, Z, NOR)									\
	void X##_back_cyc_sim(X##_t c[], const X##_t a[], int n) {				\
	    Z##_t *t = RLC_ALLOCA(Z##_t, n * 3);								\
	    Z##_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;			\
																			\
		if (n == 0) {														\
			RLC_FREE(t);													\
			return;															\
		}																	\
																			\
		if (t == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		for (int i = 0; i < n; i++) {										\
			Z##_null(t0[i]);												\
			Z##_null(t1[i]);												\
			Z##_null(t2[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			for (int i = 0; i < n; i++) {									\
				Z##_new(t0[i]);												\
				Z##_new(t1[i]);												\
				Z##_new(t2[i]);												\
			}																\
																			\
			for (int i = 0; i < n; i++) {									\
				int f = Z##_is_zero(a[i][1][0]);							\
				/* If f, t0 = 2 * g4 * g5, t1 = g3. */						\
				Z##_copy(t2[i], a[i][0][1]);								\
				Z##_copy_sec(t2[i], a[i][1][2], f);							\
				/* t0 = g4^2. */											\
				Z##_mul(t0[i], a[i][0][1], t2[i]);							\
				Z##_dbl(t2[i], t0[i]);										\
				Z##_copy_sec(t0[i], t2[i], f);								\
				/* t1 = 3 * g4^2 - 2 * g3. */								\
				Z##_sub(t1[i], t0[i], a[i][0][2]);							\
				Z##_dbl(t1[i], t1[i]);										\
				Z##_add(t1[i], t1[i], t0[i]);								\
				/* t0 = E * g5^2 + t1. */									\
				Z##_sqr(t2[i], a[i][1][2]);									\
				NOR(t0[i], t2[i]);											\
				Z##_add(t0[i], t0[i], t1[i]);								\
				/* t1 = (4 * g2). */										\
				Z##_dbl(t1[i], a[i][1][0]);									\
				Z##_dbl(t1[i], t1[i]);										\
				Z##_copy_sec(t1[i], a[i][0][2], f);							\
				/* All kept coefficients zero: decompress to unity. */		\
				f = Z##_is_zero(a[i][0][1]) && Z##_is_zero(a[i][0][2]) &&	\
						Z##_is_zero(a[i][1][0]) && Z##_is_zero(a[i][1][2]);	\
				Z##_set_dig(t2[i], 1);										\
				Z##_copy_sec(t1[i], t2[i], f);								\
			}																\
																			\
			/* t1 = 1 / t1. */												\
			Z##_inv_sim(t1, t1, n);											\
																			\
			for (int i = 0; i < n; i++) {									\
				/* t0 = g1. */												\
				Z##_mul(c[i][1][1], t0[i], t1[i]);							\
																			\
				/* t1 = g3 * g4. */											\
				Z##_mul(t1[i], a[i][0][2], a[i][0][1]);						\
				/* t2 = 2 * g1^2 - 3 * g3 * g4. */							\
				Z##_sqr(t2[i], c[i][1][1]);									\
				Z##_sub(t2[i], t2[i], t1[i]);								\
				Z##_dbl(t2[i], t2[i]);										\
				Z##_sub(t2[i], t2[i], t1[i]);								\
				/* t1 = g2 * g5. */											\
				Z##_mul(t1[i], a[i][1][0], a[i][1][2]);						\
				/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */		\
				Z##_add(t2[i], t2[i], t1[i]);								\
				NOR(c[i][0][0], t2[i]);										\
				fp_add_dig(((fp_t *)c[i][0][0])[0], ((fp_t *)c[i][0][0])[0],\
						1);													\
																			\
				Z##_copy(c[i][0][1], a[i][0][1]);							\
				Z##_copy(c[i][0][2], a[i][0][2]);							\
				Z##_copy(c[i][1][0], a[i][1][0]);							\
				Z##_copy(c[i][1][2], a[i][1][2]);							\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			for (int i = 0; i < n; i++) {									\
				Z##_free(t0[i]);											\
				Z##_free(t1[i]);											\
				Z##_free(t2[i]);											\
			}																\
			RLC_FREE(t);													\
		}																	\
	}

/**
 * Defines a template for decompressing elements of the cyclotomic
 * subgroup in an extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_BACK_CYC_CQ(X, Z, NOR)										\
	void X##_back_cyc(X##_t c, const X##_t a) {								\
		Z##_t t0, t1, t2;													\
																			\
		Z##_null_all(t0, t1, t2);											\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2);										\
																			\
			int f = Z##_is_zero(a[1][0]);									\
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */							\
			Z##_copy(t2, a[2][0]);											\
			Z##_copy_sec(t2, a[2][1], f);									\
			/* t0 = g4^2. */												\
			Z##_mul(t0, a[2][0], t2);										\
			Z##_dbl(t2, t0);												\
			Z##_copy_sec(t0, t2, f);										\
			/* t1 = 3 * g4^2 - 2 * g3. */									\
			Z##_sub(t1, t0, a[1][1]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(t1, t1, t0);											\
			/* t0 = E * g5^2 + t1. */										\
			Z##_sqr(t2, a[2][1]);											\
			NOR(t0, t2);													\
			Z##_add(t0, t0, t1);											\
			/* t1 = (4 * g2). */											\
			Z##_dbl(t1, a[1][0]);											\
			Z##_dbl(t1, t1);												\
			Z##_copy_sec(t1, a[1][1], f);									\
			/* All kept coefficients zero: decompress to unity. */			\
			f = Z##_is_zero(a[1][0]) && Z##_is_zero(a[1][1]) &&				\
					Z##_is_zero(a[2][0]) && Z##_is_zero(a[2][1]);			\
			Z##_set_dig(t2, 1);												\
			Z##_copy_sec(t1, t2, f);										\
																			\
			Z##_inv(t1, t1);												\
			/* c_1 = g1. */													\
			Z##_mul(c[0][1], t0, t1);										\
																			\
			/* t1 = g3 * g4. */												\
			Z##_mul(t1, a[1][1], a[2][0]);									\
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */								\
			Z##_sqr(t2, c[0][1]);											\
			Z##_sub(t2, t2, t1);											\
			Z##_dbl(t2, t2);												\
			Z##_sub(t2, t2, t1);											\
			/* t1 = g2 * g5. */												\
			Z##_mul(t1, a[1][0], a[2][1]);									\
			/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */			\
			Z##_add(t2, t2, t1);											\
			NOR(c[0][0], t2);												\
			fp_add_dig(((fp_t *)c[0][0])[0], ((fp_t *)c[0][0])[0], 1);		\
																			\
			Z##_copy(c[1][0], a[1][0]);										\
			Z##_copy(c[1][1], a[1][1]);										\
			Z##_copy(c[2][0], a[2][0]);										\
			Z##_copy(c[2][1], a[2][1]);										\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2);										\
		}																	\
	}

/**
 * Defines a template for simultaneously decompressing elements of the
 * cyclotomic subgroup in an extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_BACK_CYC_SIM_CQ(X, Z, NOR)									\
	void X##_back_cyc_sim(X##_t c[], const X##_t a[], int n) {				\
	    Z##_t *t = RLC_ALLOCA(Z##_t, n * 3);								\
	    Z##_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;			\
																			\
		if (n == 0) {														\
			RLC_FREE(t);													\
			return;															\
		}																	\
																			\
		if (t == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		for (int i = 0; i < n; i++) {										\
			Z##_null(t0[i]);												\
			Z##_null(t1[i]);												\
			Z##_null(t2[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			for (int i = 0; i < n; i++) {									\
				Z##_new(t0[i]);												\
				Z##_new(t1[i]);												\
				Z##_new(t2[i]);												\
			}																\
																			\
			for (int i = 0; i < n; i++) {									\
				int f = Z##_is_zero(a[i][1][0]);							\
				/* If f, t0 = 2 * g4 * g5, t1 = g3. */						\
				Z##_copy(t2[i], a[i][2][0]);								\
				Z##_copy_sec(t2[i], a[i][2][1], f);							\
				/* t0 = g4^2. */											\
				Z##_mul(t0[i], a[i][2][0], t2[i]);							\
				Z##_dbl(t2[i], t0[i]);										\
				Z##_copy_sec(t0[i], t2[i], f);								\
				/* t1 = 3 * g4^2 - 2 * g3. */								\
				Z##_sub(t1[i], t0[i], a[i][1][1]);							\
				Z##_dbl(t1[i], t1[i]);										\
				Z##_add(t1[i], t1[i], t0[i]);								\
				/* t0 = E * g5^2 + t1. */									\
				Z##_sqr(t2[i], a[i][2][1]);									\
				NOR(t0[i], t2[i]);											\
				Z##_add(t0[i], t0[i], t1[i]);								\
				/* t1 = (4 * g2). */										\
				Z##_dbl(t1[i], a[i][1][0]);									\
				Z##_dbl(t1[i], t1[i]);										\
				Z##_copy_sec(t1[i], a[i][1][1], f);							\
				/* All kept coefficients zero: decompress to unity. */		\
				f = Z##_is_zero(a[i][1][0]) && Z##_is_zero(a[i][1][1]) &&	\
						Z##_is_zero(a[i][2][0]) && Z##_is_zero(a[i][2][1]);	\
				Z##_set_dig(t2[i], 1);										\
				Z##_copy_sec(t1[i], t2[i], f);								\
			}																\
																			\
			/* t1 = 1 / t1. */												\
			Z##_inv_sim(t1, t1, n);											\
																			\
			for (int i = 0; i < n; i++) {									\
				/* t0 = g1. */												\
				Z##_mul(c[i][0][1], t0[i], t1[i]);							\
																			\
				/* t1 = g3 * g4. */											\
				Z##_mul(t1[i], a[i][1][1], a[i][2][0]);						\
				/* t2 = 2 * g1^2 - 3 * g3 * g4. */							\
				Z##_sqr(t2[i], c[i][0][1]);									\
				Z##_sub(t2[i], t2[i], t1[i]);								\
				Z##_dbl(t2[i], t2[i]);										\
				Z##_sub(t2[i], t2[i], t1[i]);								\
				/* t1 = g2 * g5. */											\
				Z##_mul(t1[i], a[i][1][0], a[i][2][1]);						\
				/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */		\
				Z##_add(t2[i], t2[i], t1[i]);								\
				NOR(c[i][0][0], t2[i]);										\
				fp_add_dig(((fp_t *)c[i][0][0])[0], ((fp_t *)c[i][0][0])[0],\
						1);													\
																			\
				Z##_copy(c[i][1][0], a[i][1][0]);							\
				Z##_copy(c[i][1][1], a[i][1][1]);							\
				Z##_copy(c[i][2][0], a[i][2][0]);							\
				Z##_copy(c[i][2][1], a[i][2][1]);							\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			for (int i = 0; i < n; i++) {									\
				Z##_free(t0[i]);											\
				Z##_free(t1[i]);											\
				Z##_free(t2[i]);											\
			}																\
			RLC_FREE(t);													\
		}																	\
	}

/**
 * Defines a template for torus-based compression at the maximum rate in a
 * quadratic extension X = H[w]/(w^2 - v) of a subfield, for elements in the
 * cyclotomic subgroup.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] H			- the subfield of half the degree.
 */
#define TMPL_FPX_PCK_MAX(X, H)												\
	void X##_pck_max(X##_t c, const X##_t a) {								\
		X##_copy(c, a);														\
		if (X##_cmp_dig(a, 1) == RLC_EQ) {									\
			/* The torus has no representative for unity, so use zero,		\
			 * since it otherwise decompresses to -1, which is not in the	\
			 * subgroup. */													\
			X##_zero(c);													\
		} else if (X##_test_cyc(c)) {										\
			if (H##_is_zero(a[1])) {										\
				/* Only -1 is left with a_1 = 0, and the torus has no room	\
				 * for it once unity takes zero. */							\
				RLC_THROW(ERR_NO_VALID);									\
			} else {														\
				/* Use torus-based compression from Section 4.1 in "On		\
				 * Compressible Pairings and Their Computation" by Naehrig	\
				 * et al. */												\
				fp_add_dig(((fp_t *)c[0])[0], ((fp_t *)c[0])[0], 1);		\
				H##_inv(c[1], a[1]);										\
				H##_mul(c[0], c[0], c[1]);									\
				H##_zero(c[1]);												\
			}																\
		}																	\
	}																		\
																			\
	int X##_upk_max(X##_t c, const X##_t a) {								\
		H##_t t0, t1;														\
																			\
		if (X##_is_zero(a)) {												\
			X##_set_dig(c, 1);												\
			return 1;														\
		}																	\
		if (!H##_is_zero(a[1])) {											\
			X##_copy(c, a);													\
			return 1;														\
		}																	\
																			\
		H##_null(t0);														\
		H##_null(t1);														\
																			\
		RLC_TRY {															\
			H##_new(t0);													\
			H##_new(t1);													\
																			\
			/* Decompress g = (a0 + w)/(a0 - w) from Section 2 in			\
			 * "Compression in finite fields and torus-based cryptography"	\
			 * by Rubin-Silverberg, computed with w^2 = v as				\
			 * ((a0^2 + v) + 2 * a0 * w)/(a0^2 - v). */						\
			H##_set_dig(t1, 1);												\
			H##_mul_art(t1, t1);											\
			H##_sqr(t0, a[0]);												\
			H##_dbl(c[1], a[0]);											\
			H##_add(c[0], t0, t1);											\
			H##_sub(t0, t0, t1);											\
			H##_inv(t0, t0);												\
			H##_mul(c[0], c[0], t0);										\
			H##_mul(c[1], c[1], t0);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			H##_free(t0);													\
			H##_free(t1);													\
		}																	\
																			\
		return X##_test_cyc(c);												\
	}

/**
 * Defines a template for cyclotomic cubing in an extension field built as
 * quadratic over cubic. Seeing a as A + B * w + C * w^2 over the quadratic
 * extension of Z by z = w^3, the relation a^(p^(k/2) + 1) = 1 gives
 * A * conj(A) = 1 - z * (B * conj(C) - conj(B) * C),
 * conj(A) * B - A * conj(B) = -z * N(C) and A * conj(C) + conj(A) * C = N(B),
 * hence a^3 = 9A(A^2 - conj(A)) + 1 + 3(B(3A^2 - 2conj(A)) - z * N(C)) * w
 * + 3(C(3A^2 - 2conj(A)) + N(B)) * w^2, at the cost of three multiplications
 * and a squaring over the quadratic extension and two norms.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_CUB_CYC_QC(X, Z, NOR)										\
	void X##_cub_cyc_basic(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5, t6, t7;								\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5, t6, t7);						\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5, t6, t7);					\
																			\
			/* Now a is seen as A + B * w + C * w^2, for A = a00 + a11 * z,	\
			 * B = a10 + a02 * z and C = a01 + a12 * z, with z = w^3. */	\
																			\
			/* (t0, t1) = A^2. */											\
			Z##_sqr(t2, a[0][0]);											\
			Z##_sqr(t3, a[1][1]);											\
			Z##_add(t1, a[0][0], a[1][1]);									\
			Z##_sqr(t1, t1);												\
			Z##_sub(t1, t1, t2);											\
			Z##_sub(t1, t1, t3);											\
			NOR(t0, t3);													\
			Z##_add(t0, t0, t2);											\
																			\
			/* (t2, t3) = 3A^2 - 2conj(A), (t0, t1) = A^2 - conj(A). */		\
			Z##_dbl(t2, t0);												\
			Z##_add(t2, t2, t0);											\
			Z##_dbl(t4, a[0][0]);											\
			Z##_sub(t2, t2, t4);											\
			Z##_dbl(t3, t1);												\
			Z##_add(t3, t3, t1);											\
			Z##_dbl(t4, a[1][1]);											\
			Z##_add(t3, t3, t4);											\
			Z##_sub(t0, t0, a[0][0]);										\
			Z##_add(t1, t1, a[1][1]);										\
																			\
			/* A' = 9 * A * (A^2 - conj(A)) + 1, the last use of A. */		\
			Z##_mul(t4, a[0][0], t0);										\
			Z##_mul(t5, a[1][1], t1);										\
			Z##_add(t6, a[0][0], a[1][1]);									\
			Z##_add(t7, t0, t1);											\
			Z##_mul(t6, t6, t7);											\
			Z##_sub(t6, t6, t4);											\
			Z##_sub(t6, t6, t5);											\
			NOR(t7, t5);													\
			Z##_add(t4, t4, t7);											\
			Z##_dbl(t0, t4);												\
			Z##_dbl(t0, t0);												\
			Z##_dbl(t0, t0);												\
			Z##_add(t4, t4, t0);											\
			Z##_set_dig(t0, 1);												\
			Z##_add(c[0][0], t4, t0);										\
			Z##_dbl(t0, t6);												\
			Z##_dbl(t0, t0);												\
			Z##_dbl(t0, t0);												\
			Z##_add(c[1][1], t6, t0);										\
																			\
			/* t0 = N(B) and t1 = N(C), the norms down to Z. */				\
			Z##_sqr(t0, a[1][0]);											\
			Z##_sqr(t1, a[0][2]);											\
			NOR(t5, t1);													\
			Z##_sub(t0, t0, t5);											\
			Z##_sqr(t1, a[0][1]);											\
			Z##_sqr(t5, a[1][2]);											\
			NOR(t7, t5);													\
			Z##_sub(t1, t1, t7);											\
																			\
			/* B' = 3 * (B * (3A^2 - 2conj(A)) - z * N(C)). */				\
			Z##_mul(t4, a[1][0], t2);										\
			Z##_mul(t5, a[0][2], t3);										\
			Z##_add(t6, a[1][0], a[0][2]);									\
			Z##_add(t7, t2, t3);											\
			Z##_mul(t6, t6, t7);											\
			Z##_sub(t6, t6, t4);											\
			Z##_sub(t6, t6, t5);											\
			NOR(t7, t5);													\
			Z##_add(t4, t4, t7);											\
			Z##_sub(t6, t6, t1);											\
			Z##_dbl(t7, t4);												\
			Z##_add(c[1][0], t7, t4);										\
			Z##_dbl(t7, t6);												\
			Z##_add(c[0][2], t7, t6);										\
																			\
			/* C' = 3 * (C * (3A^2 - 2conj(A)) + N(B)). */					\
			Z##_mul(t4, a[0][1], t2);										\
			Z##_mul(t5, a[1][2], t3);										\
			Z##_add(t6, a[0][1], a[1][2]);									\
			Z##_add(t7, t2, t3);											\
			Z##_mul(t6, t6, t7);											\
			Z##_sub(t6, t6, t4);											\
			Z##_sub(t6, t6, t5);											\
			NOR(t7, t5);													\
			Z##_add(t4, t4, t7);											\
			Z##_add(t4, t4, t0);											\
			Z##_dbl(t7, t4);												\
			Z##_add(c[0][1], t7, t4);										\
			Z##_dbl(t7, t6);												\
			Z##_add(c[1][2], t7, t6);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6, t7);					\
		}																	\
	}

/**
 * Defines a template for cyclotomic cubing with lazy reduction in an
 * extension field built as quadratic over cubic, with the formula of the basic
 * version. The products over the quadratic extension use Karatsuba without
 * reduction, and the norms are folded into the coefficients they update.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] D			- the prefix of the double-precision subfield type.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] MULU		- the multiplication in the subfield without reduction.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_FPX_CUB_CYC_LAZYR_QC(X, Z, D, B, BD, N, Q, MULU, SQRU)			\
	void X##_cub_cyc_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5;										\
		D##_t u0, u1, u2, u3, u4, u5, u6, u7;								\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5);								\
		D##_null_all(u0, u1, u2, u3, u4, u5, u6, u7);						\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5);							\
			D##_new_all(u0, u1, u2, u3, u4, u5, u6, u7);					\
																			\
			/* Now a is seen as A + B * w + C * w^2, for A = a00 + a11 * z,	\
			 * B = a10 + a02 * z and C = a01 + a12 * z, with z = w^3. The	\
			 * squares for the norms of B and C come first, so that c can	\
			 * alias a. */													\
			SQRU(u4, a[1][0]);												\
			SQRU(u5, a[0][2]);												\
			SQRU(u6, a[0][1]);												\
			SQRU(u7, a[1][2]);												\
																			\
			/* (t0, t1) = A^2. */											\
			SQRU(u0, a[0][0]);												\
			SQRU(u1, a[1][1]);												\
			Z##_add(t1, a[0][0], a[1][1]);									\
			SQRU(u2, t1);													\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			TMPL_DV_RDCN(B, BD, N, t0, u3);									\
			TMPL_DV_ADDC(B, BD, N, u0, u0, u1);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u0);								\
			TMPL_DV_RDCN(B, BD, N, t1, u2);									\
																			\
			/* (t2, t3) = 3A^2 - 2conj(A), (t0, t1) = A^2 - conj(A). */		\
			Z##_dbl(t2, t0);												\
			Z##_add(t2, t2, t0);											\
			Z##_dbl(t4, a[0][0]);											\
			Z##_sub(t2, t2, t4);											\
			Z##_dbl(t3, t1);												\
			Z##_add(t3, t3, t1);											\
			Z##_dbl(t4, a[1][1]);											\
			Z##_add(t3, t3, t4);											\
			Z##_sub(t0, t0, a[0][0]);										\
			Z##_add(t1, t1, a[1][1]);										\
																			\
			/* A' = 9 * A * (A^2 - conj(A)) + 1, the last use of A. */		\
			MULU(u0, a[0][0], t0);											\
			MULU(u1, a[1][1], t1);											\
			Z##_add(t4, a[0][0], a[1][1]);									\
			Z##_add(t5, t0, t1);											\
			MULU(u2, t4, t5);												\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u0);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u1);								\
			TMPL_DV_RDCN(B, BD, N, t5, u2);									\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			TMPL_DV_RDCN(B, BD, N, t4, u3);									\
			Z##_dbl(t0, t4);												\
			Z##_dbl(t0, t0);												\
			Z##_dbl(t0, t0);												\
			Z##_add(t4, t4, t0);											\
			Z##_set_dig(t0, 1);												\
			Z##_add(c[0][0], t4, t0);										\
			Z##_dbl(t0, t5);												\
			Z##_dbl(t0, t0);												\
			Z##_dbl(t0, t0);												\
			Z##_add(c[1][1], t5, t0);										\
																			\
			/* B' = 3 * (B * (3A^2 - 2conj(A)) - z * N(C)), where			\
			 * N(C) = C_0^2 - v * C_1^2 for the generator v of Z. */		\
			MULU(u0, a[1][0], t2);											\
			MULU(u1, a[0][2], t3);											\
			Z##_add(t4, a[1][0], a[0][2]);									\
			Z##_add(t5, t2, t3);											\
			MULU(u2, t4, t5);												\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u0);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u1);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u6);								\
			TMPL_DV_NADD(B, BD, N, Q, u3, u2, u7);							\
			TMPL_DV_RDCN(B, BD, N, t5, u3);									\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			TMPL_DV_RDCN(B, BD, N, t4, u3);									\
			Z##_dbl(t0, t4);												\
			Z##_add(c[1][0], t0, t4);										\
			Z##_dbl(t0, t5);												\
			Z##_add(c[0][2], t0, t5);										\
																			\
			/* C' = 3 * (C * (3A^2 - 2conj(A)) + N(B)). */					\
			MULU(u0, a[0][1], t2);											\
			MULU(u1, a[1][2], t3);											\
			Z##_add(t4, a[0][1], a[1][2]);									\
			Z##_add(t5, t2, t3);											\
			MULU(u2, t4, t5);												\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u0);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u1);								\
			TMPL_DV_RDCN(B, BD, N, t5, u2);									\
			TMPL_DV_ADDC(B, BD, N, u0, u0, u4);								\
			TMPL_DV_SUBC(B, BD, N, u1, u1, u5);								\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			TMPL_DV_RDCN(B, BD, N, t4, u3);									\
			Z##_dbl(t0, t4);												\
			Z##_add(c[0][1], t0, t4);										\
			Z##_dbl(t0, t5);												\
			Z##_add(c[1][2], t0, t5);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5);							\
			D##_free_all(u0, u1, u2, u3, u4, u5, u6, u7);					\
		}																	\
	}

/**
 * Selects the inversion templates, for general elements and for elements in
 * the cyclotomic subgroup, and the compression at the maximum rate of a
 * quadratic-over-cubic (QC) or a cubic-over-quadratic (CQ) tower.
 */
#define TMPL_FPX_INV_CYC_QC			TMPL_FPX_INV_CYC_QUAD
#define TMPL_FPX_INV_CYC_CQ			TMPL_FPX_INV_CYC_CUBIC
#define TMPL_FPX_INV_QC				TMPL_FPX_INV_QUAD
#define TMPL_FPX_INV_CQ				TMPL_FPX_INV_CUBIC
#define TMPL_FPX_PCK_MAX_QC			TMPL_FPX_PCK_MAX
#define TMPL_FPX_PCK_MAX_CQ(X, H)	/* No quadratic torus in this tower. */
#define TMPL_FPX_CUB_CYC_CQ(X, Z, NOR)	/* Only quadratic over cubic. */

/**
 * Defines a template for inversion and the arithmetic in the cyclotomic
 * subgroup of an extension field with compressed squarings: cyclotomic
 * inversion and exponentiation, conversion, membership testing,
 * decompression, sparse and simultaneous exponentiation, and compression,
 * including at the maximum rate in quadratic-over-cubic towers.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] H			- the subfield of half the degree.
 * @param[in] S			- the subfield used in compression, of degree k/6.
 * @param[in] M			- the multiplication by the non-residue in S.
 * @param[in] T			- the shape of the tower (QC or CQ).
 */
#define TMPL_FPX_CYC(X, H, S, M, T)											\
	TMPL_FPX_INV_##T(X, H, H##_mul_art)										\
	TMPL_FPX_INV_CYC_##T(X, H)												\
	TMPL_FPX_EXP_CYC(X)														\
	TMPL_FPX_EXP_DIG(X)														\
	TMPL_FPX_CONV_CYC(X, (int)(sizeof(S##_t) / sizeof(fp_t)))				\
	TMPL_FPX_TEST_CYC(X, (int)(sizeof(S##_t) / sizeof(fp_t)))				\
	TMPL_FPX_BACK_CYC_##T(X, S, M)											\
	TMPL_FPX_BACK_CYC_SIM_##T(X, S, M)										\
	TMPL_FPX_CUB_CYC_##T(X, S, M)											\
	TMPL_EXP_CYC(X)															\
	TMPL_EXP_CYC_SIM(X, X##_sqr_cyc)										\
	TMPL_EXP_CYC_SPS(X)														\
	TMPL_FPX_PCK_##T(X, S)													\
	TMPL_FPX_UPK_##T(X, S)													\
	TMPL_FPX_PCK_MAX_##T(X, H)

/**
 * Defines a template for inversion, simultaneous inversion and the arithmetic
 * in the cyclotomic subgroup of an extension field built as a tower of
 * quadratic extensions: cyclotomic inversion and exponentiation, conversion,
 * membership testing, w-NAF and simultaneous exponentiation, and compression
 * at the maximum rate.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] H			- the subfield of half the degree.
 */
#define TMPL_FPX_CYC_T2(X, H)												\
	TMPL_FPX_INV_QUAD(X, H, H##_mul_art)									\
	TMPL_FPX_INV_SIM(X)														\
	TMPL_FPX_INV_CYC_QUAD(X, H)												\
	TMPL_FPX_EXP_CYC(X)														\
	TMPL_FPX_EXP_DIG(X)														\
	TMPL_FPX_CONV_CYC_QUAD(X)												\
	TMPL_FPX_TEST_CYC_QUAD(X)												\
	TMPL_EXP_CYC_NAF(X, X##_sqr_cyc)										\
	TMPL_EXP_CYC_SIM(X, X##_sqr_cyc)										\
	TMPL_FPX_PCK_MAX(X, H)
