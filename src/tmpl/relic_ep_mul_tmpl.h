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
			/* The first doubling would be of the point at infinity. */		\
			C##_set_infty(r);												\
			for (int j = l - 1; j >= 0; j--) {								\
				if (j < (int)l - 1) {										\
					C##_dbl(r, r);											\
				}															\
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
			/* The first digit initializes the accumulator, which only		\
			 * depends on the loop counters. */								\
			for (int j = l - 1; j >= 0; j--) {								\
				if (j < (int)l - 1) {										\
					C##_dbl(r, r);											\
				}															\
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
					if (j == (int)l - 1 && i == 0) {						\
						C##_copy(r, q[1]);									\
					} else {												\
						C##_add(r, r, q[1]);								\
					}														\
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
 * Defines templates for the tau-adic methods on curves y^2 = x^3 + b with an
 * endomorphism w(x, y) = (beta * x, y) of order 3, where tau = 1 - w: the map
 * tau and the table of base digits times P and their images under tau, and
 * separately the evaluation of e interleaved tau-adic NAFs or regular
 * expansions given by bn_rec_etnaf() and bn_rec_retnaf(), the k-th on the
 * k-th table.
 *
 * The map tau(P) = P - w(P) applies the 3-isogeny (X : Y : Z) ->
 * (X(Y^2 + 3bZ^2) : Y(Y^2 - 9bZ^2) : Z(Y^2 - bZ^2)) from y^2 = x^3 + b to
 * y^2 = x^3 - 27b and the isomorphism back that multiplies X by c1 = 1 - beta
 * and Z by c3 = (1 - beta)^3. The formula is complete. In the table of 2s
 * entries, entry i < s is the i-th base digit times P and entry s + i is its
 * image under tau, in affine coordinates. The images under w are computed when
 * needed, as w(x, y) = (beta * x, y) and w^2(x, y) = (-x - beta * x, y). The
 * NAF reads the k-th table at entries 6k to 6k + 5 and the regular method at
 * entries 12k to 12k + 11.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_TW_TAB(C, F)											\
	static void C##_tw_tau(C##_t r, const C##_t p, const F##_t c1,			\
			const F##_t c3) {												\
		F##_t t0, t1, t2, t3, t4;											\
																			\
		F##_null_all(t0, t1, t2, t3, t4);									\
																			\
		RLC_TRY {															\
			F##_new_all(t0, t1, t2, t3, t4);								\
																			\
			F##_sqr(t0, p->y);												\
			F##_sqr(t1, p->z);												\
			C##_curve_mul_b(t1, t1);										\
			F##_dbl(t2, t1);												\
			F##_add(t2, t2, t1);											\
			F##_add(t3, t0, t2);											\
			F##_mul(t3, t3, p->x);											\
			F##_mul(t3, t3, c1);											\
			F##_dbl(t4, t2);												\
			F##_add(t2, t2, t4);											\
			F##_sub(t4, t0, t2);											\
			F##_mul(t4, t4, p->y);											\
			F##_sub(t0, t0, t1);											\
			F##_mul(t0, t0, p->z);											\
			F##_mul(r->z, t0, c3);											\
			F##_copy(r->x, t3);												\
			F##_copy(r->y, t4);												\
			r->coord = EC_PROJC;												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(t0, t1, t2, t3, t4);								\
		}																	\
	}																		\
																			\
	static void C##_tw_tab(C##_t *t, const C##_t p, int s,					\
			const F##_t beta) {												\
		F##_t c1, c3;														\
		C##_t u;															\
																			\
		F##_null_all(c1, c3);												\
		C##_null(u);														\
																			\
		RLC_TRY {															\
			F##_new_all(c1, c3);											\
			C##_new(u);														\
																			\
			F##_set_dig(c1, 1);												\
			F##_sub(c1, c1, beta);											\
			F##_sqr(c3, c1);												\
			F##_mul(c3, c3, c1);											\
																			\
			/* Compute P, 2P, P + tau(P) and, for six bases, P - 2tau(P),	\
			 * 2P + tau(P) and P + 2tau(P), keeping tau(P) and tau(2P) as	\
			 * the first images. */											\
			C##_norm(t[0], p);												\
			C##_dbl_projc(t[1], t[0]);										\
			C##_tw_tau(t[s], t[0], c1, c3);									\
			C##_add_projc(t[2], t[0], t[s]);								\
			C##_tw_tau(t[s + 1], t[1], c1, c3);								\
			if (s == 6) {													\
				C##_add_projc(t[4], t[1], t[s]);							\
				C##_add_projc(t[5], t[0], t[s + 1]);						\
				C##_neg(u, t[s + 1]);										\
				C##_add_projc(t[3], t[0], u);								\
			}																\
			for (int i = 2; i < s; i++) {									\
				C##_tw_tau(t[s + i], t[i], c1, c3);							\
			}																\
			C##_norm_sim(t + 1, (const C##_t *)t + 1, 2 * s - 1);			\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			F##_free_all(c1, c3);											\
			C##_free(u);													\
		}																	\
	}

/**
 * Defines a template for the evaluation of e interleaved tau-adic NAFs from
 * bn_rec_etnaf() with Horner's rule in base tau^2 = -3w, on tables of 6 points
 * per expansion from C##_tw_tab(), in variable time.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_TW_NAF(C, F)											\
	static void C##_tw_naf(C##_t r, C##_t *t,								\
			int8_t naf[][RLC_FP_BITS + 1], const size_t *len, int e,		\
			const F##_t beta) {												\
		int d, f, j, first = 1;												\
		size_t l = 0;														\
		C##_t q;															\
																			\
		C##_null(q);														\
																			\
		RLC_TRY {															\
			C##_new(q);														\
																			\
			for (int i = 0; i < e; i++) {									\
				l = RLC_MAX(l, len[i]);										\
			}																\
			/* Horner's rule in base 3: digit d at position i is multiplied	\
			 * by tau^i = (-w)^m * 3^m * tau^(i - 2m) for m = i / 2, and the\
			 * unit (-w)^m only changes the unit of the digit. */			\
			C##_set_infty(r);												\
			for (int m = ((int)l - 1) / 2; m >= 0 && l > 0; m--) {			\
				if (!first) {												\
					C##_tpl(r, r);											\
				}															\
				for (int i = 2 * m; i < RLC_MIN(2 * m + 2, (int)l); i++) {	\
					for (int k = 0; k < e; k++) {							\
						if (i >= (int)len[k] || naf[k][i] == 0) {			\
							continue;										\
						}													\
						d = naf[k][i] - 1;									\
						f = (d % 3 + m) % 3;								\
						j = d / 6 + 3 * (i - 2 * m);						\
						/* w(x, y) = (beta * x, y) and						\
						 * w^2(x, y) = (-x - beta * x, y). */				\
						C##_copy(q, t[6 * k + j]);							\
						if (f != 0) {										\
							TMPL_EP_MUL_TW_BETA_##F(q->x, q->x, beta);		\
						}													\
						if (f == 2) {										\
							F##_add(q->x, q->x, t[6 * k + j]->x);			\
							F##_neg(q->x, q->x);							\
						}													\
						if (((d % 6) / 3) ^ (m & 1)) {						\
							C##_neg(q, q);									\
						}													\
						if (first) {										\
							C##_copy(r, q);									\
							first = 0;										\
						} else {											\
							C##_add(r, r, q);								\
						}													\
					}														\
				}															\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			C##_free(q);													\
		}																	\
	}

/**
 * Defines a template for the evaluation of e interleaved regular tau-adic
 * expansions from bn_rec_retnaf() with Horner's rule in base tau^2 = -3w, on
 * tables of 12 points per expansion from C##_tw_tab(), read by scanning them,
 * in constant time. The formulas are those of the configured coordinates, and
 * the evaluation is free of exceptions in projective coordinates, where they
 * are complete.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MUL_TW_REG(C, F)											\
	static void C##_tw_reg(C##_t r, C##_t *t,								\
			int8_t reg[][RLC_FP_BITS + 1], const int8_t *c, int len,		\
			int e, const F##_t beta) {										\
		int d, f, g, top = 3 * len;											\
		dig_t s;															\
		C##_t q, u;															\
																			\
		C##_null_all(q, u);													\
																			\
		RLC_TRY {															\
			C##_new_all(q, u);												\
																			\
			/* Horner's rule in base 3 as in the NAF, now with a digit at	\
			 * every position multiple of 3, read in constant time from the	\
			 * table by scanning it. */										\
			F##_set_dig(u->z, 1);											\
			u->coord = EC_AFFIN;												\
			for (int m = top / 2; m >= 0; m--) {							\
				if (m < top / 2) {											\
					C##_tpl(r, r);												\
				}															\
				for (int i = 2 * m; i <= RLC_MIN(2 * m + 1, top); i++) {	\
					if (i % 3 != 0) {										\
						continue;											\
					}														\
					for (int k = 0; k < e; k++) {							\
						d = reg[k][i / 3];									\
						/* Split the secret digit d < 36 into the			\
						 * base digit d / 6 and the unit g = d % 6,			\
						 * with sign g / 3 and power of w g % 3,			\
						 * without divisions. */							\
						g = d - 6 * ((d * 43) >> 8);						\
						d = (d * 43) >> 8;									\
						s = ((g * 11) >> 5) ^ (m & 1);						\
						f = g - 3 * ((g * 11) >> 5) + m % 3;				\
						f -= 3 & -(f >= 3);									\
						/* Select x and y in the entries of the right		\
						 * parity, then w^f(x) as w(x) = beta * x and		\
						 * w^2(x) = -x - w(x). */							\
						for (int j = 0; j < 6; j++) {						\
							int o = j + 6 * (i - 2 * m);					\
							F##_copy_sec(u->x, t[12 * k + o]->x, j == d);	\
							F##_copy_sec(u->y, t[12 * k + o]->y, j == d);	\
						}													\
						TMPL_EP_MUL_TW_BETA_##F(q->x, u->x, beta);			\
						F##_add(q->y, u->x, q->x);							\
						F##_neg(q->y, q->y);								\
						F##_copy_sec(u->x, q->x, f == 1);					\
						F##_copy_sec(u->x, q->y, f == 2);					\
						F##_neg(q->y, u->y);								\
						F##_copy_sec(u->y, q->y, s);						\
						if (m == top / 2 && k == 0) {						\
							C##_copy(r, u);									\
						} else {											\
							C##_add(r, r, u);									\
						}													\
					}														\
				}															\
			}																\
			/* Undo the increments of the recodings. */						\
			for (int k = 0; k < e; k++) {									\
				C##_neg(u, t[12 * k]);										\
				C##_add(q, r, u);												\
				F##_copy_sec(r->x, q->x, c[k]);								\
				F##_copy_sec(r->y, q->y, c[k]);								\
				F##_copy_sec(r->z, q->z, c[k]);								\
			}																\
			/* Convert r to affine coordinates. */							\
			C##_norm(r, r);													\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			C##_free_all(q, u);												\
		}																	\
	}

/**
 * Gives the base prime field coordinate of an element of an extension field.
 */
#define TMPL_EP_MUL_TW_FP_fp2(X)		(X)[0]
#define TMPL_EP_MUL_TW_FP_fp3(X)		(X)[0]
#define TMPL_EP_MUL_TW_FP_fp4(X)		(X)[0][0]
#define TMPL_EP_MUL_TW_FP_fp8(X)		(X)[0][0][0]
#define TMPL_EP_MUL_TW_FP_fp9(X)		(X)[0][0]

/**
 * Multiplies an element of the field by beta, which lies in the base prime
 * field, coordinate by coordinate.
 */
#define TMPL_EP_MUL_TW_BETA_fp(C, A, B)		fp_mul(C, A, B)
#define TMPL_EP_MUL_TW_BETA_fp2(C, A, B)	fp2_mul_fp(C, A, (B)[0])
#define TMPL_EP_MUL_TW_BETA_fp3(C, A, B)	fp3_mul_fp(C, A, (B)[0])
#define TMPL_EP_MUL_TW_BETA_fp4(C, A, B)	fp4_mul_fp(C, A, (B)[0][0])
#define TMPL_EP_MUL_TW_BETA_fp8(C, A, B)	fp8_mul_fp(C, A, (B)[0][0][0])
#define TMPL_EP_MUL_TW_BETA_fp9(C, A, B)	fp9_mul_fp(C, A, (B)[0][0])

/**
 * Defines templates for the tau-adic NAF and regular methods on a curve over
 * an extension field with a GLS endomorphism psi, when psi^H acts on the
 * points as a small element u of Z[w]. The decomposition
 * k = k_0 + ... + k_(S-1) psi^(S-1) regroups as the sum of
 * (k_i + k_(i + H) * u) * psi^i for i < H, and the H expansions are
 * interleaved on tables of psi^i(P). Curves where the decomposition has
 * another dimension than 2H, or where u is not small, use the w-NAF and
 * regular methods.
 *
 * @param[in] C			- the curve.
 * @param[in] F			- the field prefix.
 * @param[in] S			- the dimension of the GLS decomposition.
 * @param[in] H			- the power of psi acting as an element of Z[w].
 */
#define TMPL_EP_MUL_TW_GLS(C, F, S, H)										\
	static int C##_mul_tw_imp(C##_t r, const C##_t p, const bn_t k,			\
			int reg) {														\
		const int s = (reg ? 6 : 3);										\
		int8_t c[H], naf[H][RLC_FP_BITS + 1];								\
		size_t l, len[H];													\
		int j, u0, u1, e, aff, result = RLC_ERR;							\
		dig_t d, d0, d1;													\
		bn_t n, x, _k[S], a, b, m0, m1;										\
		F##_t beta;															\
		C##_t q, *t = RLC_ALLOCA(C##_t, 2 * s * H);							\
																			\
		if (t == NULL) {													\
			RLC_THROW(ERR_NO_MEMORY);										\
			return RLC_ERR;													\
		}																	\
																			\
		bn_null_all(n, x, a, b, m0, m1);									\
		F##_null(beta);														\
		C##_null(q);														\
		for (int i = 0; i < S; i++) {										\
			bn_null(_k[i]);													\
		}																	\
		for (int i = 0; i < 2 * s * H; i++) {								\
			C##_null(t[i]);													\
		}																	\
																			\
		RLC_TRY {															\
			bn_new_all(n, x, a, b, m0, m1);									\
			F##_new(beta);													\
			C##_new(q);														\
			for (int i = 0; i < S; i++) {									\
				bn_new(_k[i]);												\
			}																\
			for (int i = 0; i < 2 * s * H; i++) {							\
				C##_new(t[i]);												\
			}																\
																			\
			/* psi acts as x, or as 6x^2 on BN curves, and w acts on this	\
			 * curve as the conjugate w^2 of its eigenvalue on the curve	\
			 * over the prime field, since w preserves both eigenspaces of	\
			 * the Frobenius. Hence psi^H acts as							\
			 * m0 + m1 * w^2 = (m0 - m1) - m1 * w, for m0 and m1 the		\
			 * decomposition of its eigenvalue along the lattice of w. */	\
			C##_curve_get_ord(n);											\
			ep_curve_frbase(x);												\
			if (ep_curve_is_pairf() == EP_BN) {								\
				bn_sqr(a, x);												\
				bn_mul_dig(a, a, 6);										\
			} else {														\
				bn_copy(a, x);												\
			}																\
			bn_set_dig(b, 1);												\
			for (j = 0; j < H; j++) {										\
				bn_mul(b, b, a);											\
				bn_mod(b, b, n);											\
			}																\
			bn_rec_glv(m0, m1, b, n, ep_curve_get_v1(), ep_curve_get_v2());	\
			bn_sub(m0, m0, m1);												\
			bn_neg(m1, m1);													\
			bn_get_dig(&d0, m0);											\
			bn_get_dig(&d1, m1);											\
			u0 = (bn_sign(m0) == RLC_NEG ? -(int)d0 : (int)d0);				\
			u1 = (bn_sign(m1) == RLC_NEG ? -(int)d1 : (int)d1);				\
																			\
			/* 1 + |u0 + u1 * w| is at most 2^e, for e the bits of the		\
			 * ceiling of the square root of its norm. */					\
			e = 0;															\
			if (bn_bits(m0) <= 8 && bn_bits(m1) <= 8) {						\
				d = 1;														\
				while (d * d < (dig_t)(u0 * u0 - u0 * u1 + u1 * u1)) {		\
					d++;													\
				}															\
				e = util_bits_dig(d);										\
			}																\
																			\
			/* The regular method only pays off when psi^H is a unit. */	\
			if (e == 1 || (e > 1 && !reg)) {								\
				F##_zero(beta);												\
				fp_copy(TMPL_EP_MUL_TW_FP_##F(beta), ep_curve_get_beta());	\
				C##_tw_tab(t, p, s, beta);									\
																			\
				/* The Frobenius decomposition gives subscalars below 2^3|x|\
				 * on BN curves; otherwise, base-|x| digits below |x|, but	\
				 * for the last one below n / |x|^(S - 1). The coefficients	\
				 * regrouped along psi^H are below 2^l in absolute value, so\
				 * the regular expansions need more than					\
				 * 2 * (l + 0.06) / log2(27) digits. */						\
				if (ep_curve_is_pairf() == EP_BN) {							\
					l = bn_bits(x) + 3 + e;									\
				} else {													\
					bn_abs(a, x);											\
					bn_copy(b, n);											\
					for (int i = 1; i < S; i++) {							\
						bn_div(b, b, a);									\
					}														\
					l = RLC_MAX(bn_bits(b), bn_bits(x)) + e;				\
				}															\
				bn_mod(_k[0], k, n);										\
				bn_rec_frb(_k, S, _k[0], x, n,								\
						ep_curve_is_pairf() == EP_BN);						\
				for (int i = 0; i < H; i++) {								\
					/* k_i + k_(i + H) * (u0 + u1 * w) = a + b * w. */		\
					bn_mul_dig(m0, _k[i + H], d0);							\
					if (u0 < 0) {											\
						bn_neg(m0, m0);										\
					}														\
					bn_add(a, _k[i], m0);									\
					bn_mul_dig(b, _k[i + H], d1);							\
					if (u1 < 0) {											\
						bn_neg(b, b);										\
					}														\
					if (reg) {												\
						len[i] = (20000 * l + 1200) / 47549 + 1;			\
						bn_rec_retnaf(naf[i], &c[i], len[i], a, b);			\
					} else {												\
						len[i] = RLC_FP_BITS + 1;							\
						bn_rec_etnaf(naf[i], &len[i], a, b);				\
					}														\
				}															\
				/* psi commutes with w and tau, so it maps the table of P to\
				 * one of psi(P), and the images under w follow from beta.	\
				 * When psi leaves affine coordinates, building the table of\
				 * psi(P) is cheaper. */									\
				C##_psi(q, t[0]);											\
				aff = (q->coord == EC_AFFIN);									\
				for (int i = 1; i < H; i++) {								\
					if (aff) {												\
						for (int m = 0; m < 2 * s; m++) {					\
							C##_psi(t[2 * s * i + m],						\
									t[2 * s * (i - 1) + m]);				\
						}													\
					} else {												\
						if (i > 1) {										\
							C##_psi(q, t[2 * s * (i - 1)]);					\
						}													\
						C##_tw_tab(t + 2 * s * i, q, s, beta);				\
					}														\
				}															\
				if (reg) {													\
					C##_tw_reg(r, t, naf, c, len[0], H, beta);				\
				} else {													\
					C##_tw_naf(r, t, naf, len, H, beta);					\
				}															\
				result = RLC_OK;											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free_all(n, x, a, b, m0, m1);								\
			F##_free(beta);													\
			C##_free(q);													\
			for (int i = 0; i < S; i++) {									\
				bn_free(_k[i]);												\
			}																\
			for (int i = 0; i < 2 * s * H; i++) {							\
				C##_free(t[i]);												\
			}																\
			RLC_FREE(t);													\
		}																	\
		return result;														\
	}																		\
	void C##_mul_twnaf(C##_t r, const C##_t p, const bn_t k) {				\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (S != 2 * H || !ep_curve_is_endom() ||							\
				C##_curve_opt_a() != RLC_ZERO ||							\
				C##_mul_tw_imp(r, p, k, 0) != RLC_OK) {						\
			C##_mul_lwnaf(r, p, k);											\
		}																	\
	}																		\
																			\
	void C##_mul_twreg(C##_t r, const C##_t p, const bn_t k) {				\
		if (bn_is_zero(k) || C##_is_infty(p)) {								\
			C##_set_infty(r);												\
			return;															\
		}																	\
																			\
		if (S != 2 * H || !ep_curve_is_endom() ||							\
				C##_curve_opt_a() != RLC_ZERO ||							\
				C##_mul_tw_imp(r, p, k, 1) != RLC_OK) {						\
			C##_mul_lwreg(r, p, k);											\
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
