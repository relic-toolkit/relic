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
#include "relic_ec_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Decomposes the scalar M modulo N into the subscalars K of the regular signed
 * comb, with the GLV endomorphism or without one.
 */
#define TMPL_EP_MUL_FIX_REC_glv(K, M, N)									\
	bn_rec_glv(K[0], K[1], M, N, ep_curve_get_v1(), ep_curve_get_v2())
#define TMPL_EP_MUL_FIX_REC_plain(K, M, N)	bn_copy(K[0], M)

/**
 * Bounds the bit length of the subscalars, with a margin for making them odd.
 */
#define TMPL_EP_MUL_FIX_LEN_glv(N)			(RLC_CEIL(bn_bits(N), 2) + 2)
#define TMPL_EP_MUL_FIX_LEN_plain(N)		bn_bits(N)

/**
 * Gives the dimension of the decomposition, which is S only for curves with an
 * endomorphism, and applies the endomorphism to a point. The plain versions
 * never reach the endomorphism, so curves without one need not provide it.
 */
#define TMPL_EP_MUL_FIX_DIM_glv(S)			(ep_curve_is_endom() ? S : 1)
#define TMPL_EP_MUL_FIX_DIM_plain(S)		1
#define TMPL_EP_MUL_FIX_PSI_glv(C, R, P)	C##_psi(R, P)
#define TMPL_EP_MUL_FIX_PSI_plain(C, R, P)	C##_copy(R, P)

/**
 * Multiplies two points simultaneously, with the endomorphism when the curve
 * has one. The plain version never calls the endomorphism method.
 */
#define TMPL_EP_MUL_SIM_IMP_glv(C, R, P, K, Q, M)							\
	if (ep_curve_is_endom()) {												\
		C##_mul_sim_endom(R, P, K, Q, M);									\
	} else {																\
		C##_mul_sim_plain(R, P, K, Q, M);									\
	}
#define TMPL_EP_MUL_SIM_IMP_plain(C, R, P, K, Q, M)							\
	C##_mul_sim_plain(R, P, K, Q, M)

/**
 * Returns the dimension of the GLS decomposition, which is lower for the
 * supersingular curve over Fp^4, as its order has fewer digits in base u.
 *
 * @param[in] S			- the dimension of the GLS decomposition.
 */
#define TMPL_EP_MUL_DIM(S)													\
	(ep_curve_is_pairf() == EP_SS3 ?										\
		RLC_MIN((size_t)S, (size_t)ep_curve_frdim()) : (size_t)S)

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
		size_t s = TMPL_EP_MUL_DIM(S);										\
		bn_t n, _k[S], u;													\
		int8_t naf[S][RLC_FP_BITS + 1];										\
		C##_t q, t[S][1 << (RLC_WIDTH - 2)];								\
																			\
		bn_null_all(n, u);													\
		C##_null(q);														\
		for (size_t i = 0; i < S; i++) {									\
			bn_null(_k[i]);													\
			for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {			\
				C##_null(t[i][j]);											\
			}																\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
			C##_new(q);														\
			for (size_t i = 0; i < S; i++) {								\
				bn_new(_k[i]);												\
				for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {		\
					C##_new(t[i][j]);										\
				}															\
			}																\
																			\
			C##_curve_get_ord(n);											\
			ep_curve_frbase(u);												\
			bn_mod(_k[0], k, n);											\
			bn_rec_frb(_k, s, _k[0], u, n, ep_curve_is_pairf() == EP_BN);	\
																			\
			l = 0;															\
			for (size_t i = 0; i < s; i++) {								\
				l = RLC_MAX(l, bn_bits(_k[i]));								\
			}																\
			if (l < bn_bits(u) / 2) {										\
				w = 2;														\
			}																\
																			\
			l = 0;															\
			for (size_t i = 0; i < s; i++) {								\
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
				for (size_t i = 0; i < s; i++) {							\
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
		int8_t even[T] = { 0 }, col, sac[T][(S / T) * (RLC_FP_BITS + 1)];	\
		C##_t q[S], t[T][1 << (S / T - 1)];									\
		/* Fewer dimensions if the order has fewer digits in base u, kept in\
		 * groups of S / T and thus in fewer groups, c = s / g. */			\
		size_t s = TMPL_EP_MUL_DIM(S);										\
		size_t g = RLC_MIN((size_t)S / T, s), c = s / g;					\
																			\
		bn_null_all(n, u);													\
		for (int i = 0; i < S; i++) {										\
			bn_null(_k[i]);													\
			C##_null(q[i]);													\
		}																	\
		for (int i = 0; i < (int)c; i++) {									\
			for (int j = 0; j < (1 << (S / T - 1)); j++) {					\
				C##_null(t[i][j]);											\
			}																\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
			for (int i = 0; i < S; i++) {									\
				bn_new(_k[i]);												\
				C##_new(q[i]);												\
			}																\
			for (int i = 0; i < (int)c; i++) {								\
				for (int j = 0; j < (1 << (S / T - 1)); j++) {				\
					C##_new(t[i][j]);										\
				}															\
			}																\
																			\
			C##_curve_get_ord(n);											\
			ep_curve_frbase(u);												\
			bn_mod(_k[0], k, n);											\
			bn_rec_frb(_k, s, _k[0], u, n, flag);							\
																			\
			C##_norm(q[0], p);												\
			for (size_t i = 1; i < s; i++) {								\
				C##_psi(q[i], q[i - 1]);									\
			}																\
			for (size_t i = 0; i < s; i++) {								\
				C##_neg(r, q[i]);											\
				F##_copy_sec(q[i]->y, r->y, bn_sign(_k[i]) == RLC_NEG);		\
				bn_abs(_k[i], _k[i]);										\
			}																\
			for (int i = 0; i < (int)c; i++) {								\
				even[i] = bn_is_even(_k[i * g]);							\
				bn_add_dig(_k[i * g], _k[i * g], even[i]);					\
			}																\
																			\
			for (int i = 0; i < (int)c; i++) {								\
				C##_copy(t[i][0], q[i * g]);								\
				for (int j = 1; j < (1 << (g - 1)); j++) {					\
					l = util_bits_dig(j);									\
					C##_add(t[i][j], t[i][j ^ (1 << (l - 1))],				\
							q[l + i * g]);									\
				}															\
				/* The endomorphism may return projective points. */		\
				l = (t[i][0]->coord == EC_AFFIN);								\
				C##_norm_sim(t[i] + l, (const C##_t *)t[i] + l,				\
						(1 << (g - 1)) - l);								\
				l = RLC_FP_BITS + 1;										\
				bn_rec_sac(sac[i], &l, _k + i * g, u, c, g,					\
						bn_bits(n), flag);									\
			}																\
																			\
			F##_set_dig(q[1]->z, 1);										\
			q[1]->coord = EC_AFFIN;											\
			C##_set_infty(r);												\
			for (int j = l - 1; j >= 0; j--) {								\
				C##_dbl(r, r);												\
				for (int i = 0; i < (int)c; i++) {							\
					col = 0;												\
					for (int m = g - 1; m > 0; m--) {						\
						col <<= 1;											\
						col += sac[i][m * l + j];							\
					}														\
					for (int m = 0; m < (1 << (g - 1)); m++) {				\
						F##_copy_sec(q[1]->x, t[i][m]->x, m == col);		\
						F##_copy_sec(q[1]->y, t[i][m]->y, m == col);		\
					}														\
					/* Scratch points that are never the head of a group. */\
					C##_neg(q[s - 1], q[1]);								\
					F##_copy_sec(q[1]->y, q[s - 1]->y, sac[i][j]);			\
					C##_add(r, r, q[1]);									\
				}															\
			}																\
																			\
			for (int i = 0; i < (int)c; i++) {								\
				C##_sub(q[1], r, q[i * g]);									\
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
			for (int i = 0; i < (int)c; i++) {								\
				for (int j = 0; j < (1 << (S / T - 1)); j++) {				\
					C##_free(t[i][j]);										\
				}															\
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
		for (size_t _j = 0; _j < E; _j++) {									\
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
		for (int i = 0; i < S; i++) {										\
			bn_null(_k[i]);													\
			bn_null(_m[i]);													\
		}																	\
		for (int i = 0; i < (S << (RLC_WIDTH - 2)); i++) {					\
			C##_null(_p[i]);												\
			C##_null(_q[i]);												\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, u);												\
			C##_new(v);														\
			for (int i = 0; i < S; i++) {									\
				bn_new(_k[i]);												\
				bn_new(_m[i]);												\
			}																\
			for (int i = 0; i < (S << (RLC_WIDTH - 2)); i++) {				\
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
			if (_p[e]->coord != EC_AFFIN) {									\
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
 * @param[in] E			- the endomorphism method, glv or plain.
 */
#define TMPL_EP_MUL_SIM(C, E)												\
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
			TMPL_EP_MUL_SIM_IMP_##E(C, r, p, _k, q, _m);					\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			bn_free_all(n, _k, _m);											\
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
			RLC_FREE(naf);													\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		bn_null_all(q, x);													\
																			\
		if (n <= 10) {														\
			C##_t *_p = RLC_ALLOCA(C##_t, S * n);							\
																			\
			if (naf == NULL || _p == NULL) {								\
				RLC_FREE(naf);												\
				RLC_FREE(_p);												\
				RLC_THROW(ERR_NO_MEMORY);									\
				return;														\
			}																\
																			\
			for (j = 0; j < S; j++) {										\
				bn_null(_k[j]);												\
				for (i = 0; i < n; i++) {									\
					C##_null(_p[S*i + j]);									\
				}															\
			}																\
																			\
			RLC_TRY {														\
				bn_new_all(q, x);											\
				for (j = 0; j < S; j++) {									\
					bn_new(_k[j]);											\
					for (i = 0; i < n; i++) {								\
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
			if (naf == NULL || _p == NULL || _q == NULL) {					\
				RLC_FREE(naf);												\
				RLC_FREE(_p);												\
				RLC_FREE(_q);												\
				RLC_THROW(ERR_NO_MEMORY);									\
				return;														\
			}																\
																			\
			C##_null_all(s, t, u, v);										\
			for (i = 0; i < S; i++) {										\
				bn_null(_k[i]);												\
			}																\
			for (j = 0; j < c; j++) {										\
				C##_null(_p[j]);											\
			}																\
			for (i = 0; i < S * n; i++) {									\
				C##_null(_q[i]);											\
			}																\
																			\
			RLC_TRY {														\
				bn_new_all(q, x);											\
				C##_new_all(s, t, u, v);									\
				for (i = 0; i < S; i++) {									\
					bn_new(_k[i]);											\
				}															\
				for (j = 0; j < c; j++) {									\
					C##_new(_p[j]);											\
					C##_set_infty(_p[j]);									\
				}															\
				for (i = 0; i < S * n; i++) {								\
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

#ifdef EP_PRECO
#define TMPL_EP_MUL_GEN(C)		TMPL_EC_MUL_GEN(C, preco)
#else
#define TMPL_EP_MUL_GEN(C)		TMPL_EC_MUL_GEN(C, plain)
#endif

/**
 * Defines a template for point multiplication using the left-to-right w-NAF
 * method, with an endomorphism when the curve has one.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] E			- the endomorphism method, glv or gls.
 */
/**
 * Tests if the endomorphism of the GLV or GLS method is available. The
 * supersingular curve over Fp^4 has one, [p], even if the base curve has not.
 */
#define TMPL_EP_MUL_ENDOM_glv		ep_curve_is_endom()
#define TMPL_EP_MUL_ENDOM_gls												\
	(ep_curve_is_endom() || ep_curve_is_pairf() == EP_SS3)

#define TMPL_EP_MUL_LWNAF(C, E)												\
	void C##_mul_lwnaf(C##_t r, const C##_t p, const bn_t k) {				\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (TMPL_EP_MUL_ENDOM_##E) {										\
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
		if (TMPL_EP_MUL_ENDOM_##E) {										\
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
	TMPL_EC_MUL_NAF_IMP(C, RLC_FP_BITS)										\
	TMPL_EC_MUL_REG_IMP(C, RLC_FP_BITS)										\
	TMPL_EP_MUL_SIM_ENDOM_GLS(C, S)											\
	TMPL_EC_MUL_SIM_PLAIN(C, RLC_FP_BITS)									\
	TMPL_EC_MUL_BASIC(C)													\
	TMPL_EC_MUL_MONTY(C)													\
	TMPL_EP_MUL_LWNAF(C, gls)												\
	TMPL_EP_MUL_LWREG(C, gls)												\
	TMPL_EP_MUL_GEN(C)														\
	TMPL_EC_MUL_DIG(C)														\
	TMPL_EC_MUL_FIX_BASIC(C, plain)											\
	TMPL_EC_MUL_FIX_LWREG(C, plain, 1, RLC_FP_BITS)							\
	TMPL_EC_MUL_COMBD(C)													\
	TMPL_EP_MUL_SIM(C, glv)													\
	TMPL_EC_MUL_SIM_GEN(C)													\
	TMPL_EC_MUL_SIM_DIG(C)													\
	TMPL_EP_MUL_SIM_LOT(C, S)
