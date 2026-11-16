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
 * Templates for modular exponentiation over the representation of elements
 * under the modular reduction, and the operations on them.
 *
 * @ingroup tmpl
 */

#ifndef RLC_BN_MXP_TMPL_H
#define RLC_BN_MXP_TMPL_H

#include "relic_core.h"
#if BN_MOD == BN_RENUS
#include "relic_rns_low.h"
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*
 * The exponentiations are written once against a representation R of the
 * elements: the type R_T of elements, the type R_V of the value precomputed
 * from the modulus, and the conversions and operations on them. In the macros,
 * X, Y, Z and T are elements, A and C integers converted to and from them, M
 * is the modulus and B the condition of a swap. The positional representation
 * MXP_POS keeps integers under the configured reduction, and MXP_RNS keeps
 * residues in a Residue Number System.
 */
#define MXP_POS_T					bn_t
#define MXP_POS_V					bn_t
#define MXP_POS_NULL(X)				bn_null(X)
#define MXP_POS_NEW(X, V)			bn_new(X)
#define MXP_POS_FREE(X)				bn_free(X)
#define MXP_POS_GROW(X, M)			bn_grow(X, (M)->alloc)
#define MXP_POS_COPY(X, Y, V)		bn_copy(X, Y)
#define MXP_POS_SWAP(X, Y, B, V)	bn_swap_sec(X, Y, B)
#define MXP_POS_MUL(X, Y, Z, M, V)											\
	bn_mul(X, Y, Z);														\
	MXP_POS_RDC(X, X, M, V)
#define MXP_POS_SQR(X, Y, M, V)												\
	bn_sqr(X, Y);															\
	MXP_POS_RDC(X, X, M, V)
/* A step of the ladder: X = X * Y and Y = Y^2, with the products in T so that
 * X and Y keep their size for the swaps. */
#define MXP_POS_STEP(X, Y, T, M, V)											\
	bn_mul(T, X, Y);														\
	MXP_POS_RDC(X, T, M, V);												\
	bn_sqr(T, Y);															\
	MXP_POS_RDC(Y, T, M, V)
/* Positional exponentiation reduces by Montgomery reduction also under RENUS,
 * where the reduction of other uses is Barrett's, as it is faster. */
#if BN_MOD == BN_MONTY || BN_MOD == BN_RENUS
#define MXP_POS_PRE(V, M)			bn_mod_pre_monty(V, M)
#define MXP_POS_RDC(X, Y, M, V)		bn_mod_monty(X, Y, M, V)
#define MXP_POS_CONV(X, A, M, V)	bn_mod_monty_conv(X, A, M)
#define MXP_POS_BACK(C, X, M, V)	bn_mod_monty_back(C, X, M)
#define MXP_POS_ONE(X, M, V)												\
	bn_set_dig(X, 1);														\
	bn_mod_monty_conv(X, X, M)
#else
#define MXP_POS_PRE(V, M)			bn_mod_pre(V, M)
#define MXP_POS_RDC(X, Y, M, V)		bn_mod(X, Y, M, V)
/* The reductions expect operands in [0, m). */
#define MXP_POS_CONV(X, A, M, V)	bn_mod_basic(X, A, M)
#define MXP_POS_BACK(C, X, M, V)	bn_copy(C, X)
#define MXP_POS_ONE(X, M, V)		bn_set_dig(X, 1)
#endif

/**
 * Runs a positional exponentiation G on the given arguments, followed by the
 * value precomputed from the modulus M.
 *
 * @param[in] G				- the positional exponentiation.
 * @param[in] M				- the modulus.
 */
#define BN_MXP_POS(G, M, ...)												\
	do {																	\
		bn_t _u;															\
		bn_null(_u);														\
		RLC_TRY {															\
			bn_new(_u);														\
			MXP_POS_PRE(_u, M);												\
			G(__VA_ARGS__, _u);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free(_u);													\
		}																	\
	} while (0)

#if BN_MOD == BN_RENUS

/*
 * Room of the contexts for exponentiation: products of values below (n + 1)N
 * need 2 log2(n + 1) bits of it, so 16 bits cover bases of up to 255 moduli.
 */
#define BN_MXP_ROOM		16

#define MXP_RNS_T					dv_t
#define MXP_RNS_V					const rns_st *
#define MXP_RNS_NULL(X)				dv_null(X)
#define MXP_RNS_NEW(X, V)			dv_new(X)
#define MXP_RNS_FREE(X)				dv_free(X)
#define MXP_RNS_GROW(X, M)			(void)(X)
#define MXP_RNS_CONV(X, A, M, V)	rns_set_bn(X, A, V)
#define MXP_RNS_BACK(C, X, M, V)	rns_get_bn(C, X, V)
#define MXP_RNS_ONE(X, M, V)		dv_copy(X, (V)->one, 2 * (V)->o)
#define MXP_RNS_COPY(X, Y, V)		dv_copy(X, Y, 2 * (V)->o)
#define MXP_RNS_SWAP(X, Y, B, V)	dv_swap_sec(X, Y, 2 * (V)->o, B)
#define MXP_RNS_MUL(X, Y, Z, M, V)	rns_mulm_low(X, Y, Z, V)
#define MXP_RNS_SQR(X, Y, M, V)		rns_mulm_low(X, Y, Y, V)
/* A step of the ladder: X = X * Y and Y = Y^2, with T unused. */
#define MXP_RNS_STEP(X, Y, T, M, V)											\
	(void)(T);																\
	rns_mulm_low(X, X, Y, V);												\
	rns_mulm_low(Y, Y, Y, V)

/**
 * Runs the exponentiation F##_rns in a Residue Number System when a context
 * for the modulus M is available, and F##_pos otherwise.
 *
 * @param[in] F				- the prefix of the exponentiation.
 * @param[in] M				- the modulus.
 */
#define BN_MXP_RUN(F, M, ...)												\
	do {																	\
		const rns_st *_c = rns_lookup(M, BN_MXP_ROOM);						\
		if (_c != NULL) {													\
			F##_rns(__VA_ARGS__, _c);										\
		} else {															\
			BN_MXP_POS(F##_pos, M, __VA_ARGS__);							\
		}																	\
	} while (0)

#else

/**
 * Runs the positional exponentiation F##_pos.
 *
 * @param[in] F				- the prefix of the exponentiation.
 * @param[in] M				- the modulus.
 */
#define BN_MXP_RUN(F, M, ...)		BN_MXP_POS(F##_pos, M, __VA_ARGS__)

#endif

/**
 * Defines a template for exponentiation by the binary method in a
 * representation R, with the precomputed value u of the modulus.
 *
 * @param[in] S			- the suffix of the function.
 * @param[in] R			- the representation.
 */
#define TMPL_BN_MXP_BASIC(S, R)												\
	static void bn_mxp_basic_##S(bn_t c, const bn_t a, const bn_t b,		\
			const bn_t m, R##_V u) {										\
		int i, l;															\
		R##_T r, t;															\
		bn_t z;																\
																			\
		R##_NULL(r);														\
		R##_NULL(t);														\
		bn_null(z);															\
																			\
		RLC_TRY {															\
			R##_NEW(r, u);													\
			R##_NEW(t, u);													\
			bn_new(z);														\
																			\
			l = bn_bits(b);													\
																			\
			R##_CONV(t, a, m, u);											\
			R##_COPY(r, t, u);												\
			for (i = l - 2; i >= 0; i--) {									\
				R##_SQR(r, r, m, u);										\
				if (bn_get_bit(b, i)) {										\
					R##_MUL(r, r, t, m, u);									\
				}															\
			}																\
			R##_BACK(z, r, m, u);											\
																			\
			/* Check the sign before writing c, which may alias b. */		\
			if (bn_sign(b) == RLC_NEG) {									\
				bn_mod_inv(c, z, m);										\
			} else {														\
				bn_copy(c, z);												\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			R##_FREE(r);													\
			R##_FREE(t);													\
			bn_free(z);														\
		}																	\
	}

/**
 * Defines a template for exponentiation by the sliding window method in a
 * representation R, with the precomputed value u of the modulus.
 *
 * @param[in] S			- the suffix of the function.
 * @param[in] R			- the representation.
 */
#define TMPL_BN_MXP_SLIDE(S, R)												\
	static void bn_mxp_slide_##S(bn_t c, const bn_t a, const bn_t b,		\
			const bn_t m, R##_V u) {										\
		R##_T *tab, t;														\
		bn_t z;																\
		size_t l, w = 1;													\
		uint8_t *win = RLC_ALLOCA(uint8_t, bn_bits(b));						\
																			\
		if (win == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
																			\
		R##_NULL(t);														\
		bn_null(z);															\
																			\
		/* Find window size. */												\
		l = bn_bits(b);														\
		if (l <= 21) {														\
			w = 2;															\
		} else if (l <= 32) {												\
			w = 3;															\
		} else if (l <= 128) {												\
			w = 4;															\
		} else if (l <= 256) {												\
			w = 5;															\
		} else if (l <= 512) {												\
			w = 6;															\
		} else {															\
			w = 7;															\
		}																	\
																			\
		tab = RLC_ALLOCA(R##_T, (1 << (w - 1)));							\
		if (tab == NULL) {													\
			RLC_FREE(win);													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {				\
			R##_NULL(tab[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {			\
				R##_NEW(tab[i], u);											\
			}																\
			R##_NEW(t, u);													\
			bn_new(z);														\
																			\
			R##_CONV(t, a, m, u);											\
																			\
			R##_COPY(tab[0], t, u);											\
			R##_SQR(t, tab[0], m, u);										\
			/* Create table. */												\
			for (size_t i = 1; i < ((size_t)1 << (w - 1)); i++) {			\
				R##_MUL(tab[i], tab[i - 1], t, m, u);						\
			}																\
																			\
			R##_ONE(t, m, u);												\
																			\
			bn_rec_slw(win, &l, b, w);										\
			for (size_t i = 0; i < l; i++) {								\
				if (win[i] == 0) {											\
					R##_SQR(t, t, m, u);									\
				} else {													\
					for (size_t j = 0; j < util_bits_dig(win[i]); j++) {	\
						R##_SQR(t, t, m, u);								\
					}														\
					R##_MUL(t, t, tab[win[i] >> 1], m, u);					\
				}															\
			}																\
																			\
			R##_BACK(z, t, m, u);											\
																			\
			if (bn_sign(b) == RLC_NEG) {									\
				bn_mod_inv(c, z, m);										\
			} else {														\
				bn_copy(c, z);												\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {			\
				R##_FREE(tab[i]);											\
			}																\
			R##_FREE(t);													\
			bn_free(z);														\
			RLC_FREE(win);													\
			RLC_FREE(tab);													\
		}																	\
	}

/**
 * Defines a template for exponentiation by the Montgomery powering ladder
 * in a representation R, with the precomputed value u of the modulus.
 *
 * @param[in] S			- the suffix of the function.
 * @param[in] R			- the representation.
 */
#define TMPL_BN_MXP_MONTY(S, R)												\
	static void bn_mxp_monty_##S(bn_t c, const bn_t a, const bn_t b,		\
			const bn_t m, R##_V u) {										\
		R##_T tab[2], t;													\
		bn_t z;																\
		int i, j;															\
																			\
		R##_NULL(tab[0]);													\
		R##_NULL(tab[1]);													\
		R##_NULL(t);														\
		bn_null(z);															\
																			\
		RLC_TRY {															\
			R##_NEW(tab[0], u);												\
			R##_NEW(tab[1], u);												\
			R##_NEW(t, u);													\
			bn_new(z);														\
																			\
			R##_ONE(tab[0], m, u);											\
			R##_CONV(tab[1], a, m, u);										\
																			\
			R##_GROW(tab[0], m);											\
			R##_GROW(tab[1], m);											\
			for (i = bn_bits(b) - 1; i >= 0; i--) {							\
				j = bn_get_bit(b, i);										\
				R##_SWAP(tab[0], tab[1], j ^ 1, u);							\
				R##_STEP(tab[0], tab[1], t, m, u);							\
				R##_SWAP(tab[0], tab[1], j ^ 1, u);							\
			}																\
																			\
			R##_BACK(z, tab[0], m, u);										\
																			\
			if (bn_sign(b) == RLC_NEG) {									\
				bn_mod_inv(c, z, m);										\
			} else {														\
				bn_copy(c, z);												\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			R##_FREE(t);													\
			R##_FREE(tab[1]);												\
			R##_FREE(tab[0]);												\
			bn_free(z);														\
		}																	\
	}

/**
 * Defines a template for exponentiation by a digit in a representation R,
 * with the precomputed value u of the modulus.
 *
 * @param[in] S			- the suffix of the function.
 * @param[in] R			- the representation.
 */
#define TMPL_BN_MXP_DIG(S, R)												\
	static void bn_mxp_dig_##S(bn_t c, const bn_t a, dig_t b, const bn_t m,	\
			R##_V u) {														\
		int i, l;															\
		R##_T r, t;															\
		bn_t z;																\
																			\
		R##_NULL(r);														\
		R##_NULL(t);														\
		bn_null(z);															\
																			\
		RLC_TRY {															\
			R##_NEW(r, u);													\
			R##_NEW(t, u);													\
			bn_new(z);														\
																			\
			l = util_bits_dig(b);											\
																			\
			R##_CONV(t, a, m, u);											\
			R##_COPY(r, t, u);												\
			for (i = l - 2; i >= 0; i--) {									\
				R##_SQR(r, r, m, u);										\
				if (b & ((dig_t)1 << i)) {									\
					R##_MUL(r, r, t, m, u);									\
				}															\
			}																\
			R##_BACK(z, r, m, u);											\
																			\
			/* Write c last, as it may alias m. The digit is unsigned. */	\
			bn_copy(c, z);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			R##_FREE(r);													\
			R##_FREE(t);													\
			bn_free(z);														\
		}																	\
	}

/**
 * Defines a template for simultaneous exponentiation of n bases in a
 * representation R, with the precomputed value u of the modulus.
 *
 * @param[in] S			- the suffix of the function.
 * @param[in] R			- the representation.
 */
#define TMPL_BN_MXP_SIM_FEW(S, R)											\
	static void bn_mxp_sim_few_##S(bn_t c, const bn_t *a, const bn_t *b,	\
			const bn_t m, size_t n, R##_V u) {								\
		R##_T *t = NULL, r;													\
		bn_t z;																\
		size_t l;															\
		dig_t parities;														\
																			\
		R##_NULL(r);														\
		bn_null(z);															\
		t = RLC_ALLOCA(R##_T, 1 << n);										\
		if (t == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return;															\
		}																	\
		for (size_t i = 0; i < ((size_t)1 << n); i++) {						\
			R##_NULL(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			for (size_t i = 0; i < ((size_t)1 << n); i++) {					\
				R##_NEW(t[i], u);											\
			}																\
			R##_NEW(r, u);													\
			bn_new(z);														\
																			\
			/* Precompute all 2^n combinations. */							\
			R##_ONE(t[0], m, u);											\
			for (size_t i = 0; i < n; i++) {								\
				/* A zero exponent never selects combinations with a[i]. */	\
				if (!bn_is_zero(b[i])) {									\
					const uint_t star = 1 << i;								\
					/* A negative exponent is a power of the inverse. */	\
					if (bn_sign(b[i]) == RLC_NEG) {							\
						bn_mod_inv(z, a[i], m);								\
						R##_CONV(t[star], z, m, u);							\
					} else {												\
						R##_CONV(t[star], a[i], m, u);						\
					}														\
					for (size_t j = star + 1; j < (star << 1); j++) {		\
						R##_MUL(t[j], t[star], t[j - star], m, u);			\
					}														\
				}															\
			}																\
																			\
			l = bn_bits(b[0]);												\
			for (size_t j = 1; j < n; j++) {								\
				l = RLC_MAX(l, bn_bits(b[j]));								\
			}																\
																			\
			/* Accumulate in r, since c may alias m. */						\
			R##_COPY(r, t[0], u);											\
			for (int i = l - 1; i >= 0; i--) {								\
				R##_SQR(r, r, m, u);										\
				/* Multiply by the combination of bases with a bit set. */	\
				parities = bn_get_bit(b[0], i);								\
				for (size_t j = 1; j < n; j++) {							\
					parities |= (uint_t)(bn_get_bit(b[j], i)) << j;			\
				}															\
				if (parities) {												\
					R##_MUL(r, r, t[parities], m, u);						\
				}															\
			}																\
			R##_BACK(z, r, m, u);											\
			bn_copy(c, z);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			for (size_t i = 0; i < ((size_t)1 << n); i++) {					\
				R##_FREE(t[i]);												\
			}																\
			RLC_FREE(t);													\
			R##_FREE(r);													\
			bn_free(z);														\
		}																	\
	}

#endif /* !RLC_BN_MXP_TMPL_H */
