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
 * Templates for the residue symbols by jumps of division steps in rings of
 * integers, as the cubic and quartic symbols.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for the residue symbols by jumps of division steps in the
 * ring Z[w] with w^2 = -S * w - 1, the Eisenstein integers for S = 1 and the
 * Gaussian integers for S = 0, as the static functions:
 *
 * - P_init(w, a), which starts the symbol of a nonzero element with f = pi and
 *   g = a - q * pi, of norm below p, for q the rounded a / pi from the scaled
 *   inverse of pi, in constant time;
 * - P_top(x, w, len), which reads 64 bits of each coordinate of f and g in len
 *   digits from 29 bits below the top one of all, in variable time, to compare
 *   their norms;
 * - P_shrink(w, len), which returns the number of digits that f and g need, in
 *   variable time: they do not grow, but a coordinate may double, so the
 *   largest stays below 2^(RLC_DIG * len - 3), and digits that come back are
 *   sign-extended;
 * - P_symbol(a, ct, k), which computes the symbol by jumps of up to k combined
 *   divsteps, a fixed number of them in constant time or until g is 0, with -1
 *   for zero, running P_jump(c, w, d, e, n, len) of the instantiating file;
 *   without constant time, before each jump, P_tail(w, len, e) of that file
 *   may finish the symbol from small f and g, adding to e and returning 1, or
 *   return 0 to continue by jumps.
 *
 * @param[in] P			- the prefix of the functions.
 * @param[in] D			- the number of digits of the coordinates.
 * @param[in] I			- the number of iterations in constant time.
 * @param[in] X			- the prefix of the context fields of the symbol.
 * @param[in] S			- the coefficient of w in -w^2 - 1.
 * @param[in] M			- the reduction of an exponent modulo the order.
 */
#define TMPL_FP_SMB(P, D, I, X, S, M)										\
	static void P##_init(dig_t w[4][D], const fp_t a) {						\
		ctx_t *ctx = core_get();											\
		dig_t g[RLC_FP_DIGS + 1], *x = w[2], *y = w[3];						\
		dig_t q[2][D], h[2 * (RLC_FP_DIGS + 1)], z[D], t[D], c;				\
		const dig_t *u = ctx->X##_pi[0], *v = ctx->X##_pi[1];				\
																			\
		/* The stored digits of a, the integer a * R mod p in Montgomery	\
		 * form, whose symbol is that of a times that of R. */				\
		dv_copy(g, a, RLC_FP_DIGS);											\
		g[RLC_FP_DIGS] = 0;													\
		dv_zero(z, D);														\
		for (int j = 0; j < 2; j++) {										\
			bn_muln_low(h, g, ctx->X##_inv[j], RLC_FP_DIGS + 1);			\
			dv_copy(q[j], h + RLC_FP_DIGS + 1, D);							\
			/* Round with the top bit of the fraction, propagating the		\
			 * carry through all digits so that the time does not depend	\
			 * on it. */													\
			c = h[RLC_FP_DIGS] >> (RLC_DIG - 1);							\
			for (size_t i = 0; i < D; i++) {								\
				q[j][i] += c;												\
				c = (q[j][i] < c);											\
			}																\
			/* The signs of the inverse are public. */						\
			if (ctx->X##_sgn[j] == RLC_NEG) {								\
				bn_subn_low(q[j], z, q[j], D);								\
			}																\
		}																	\
		/* q * pi = (q0 * u - q1 * v) + (q0 * v + q1 * (u - S * v)) * w,	\
		 * as w^2 = -S * w - 1. */											\
		dv_copy(x, g, D);													\
		dv_zero(y, D);														\
		bn_muln_low(h, q[0], u, D);											\
		bn_subn_low(x, x, h, D);											\
		bn_muln_low(h, q[1], v, D);											\
		bn_addn_low(x, x, h, D);											\
		bn_muln_low(h, q[0], v, D);											\
		bn_subn_low(y, y, h, D);											\
		if (S) {															\
			bn_subn_low(t, u, v, D);										\
		}																	\
		bn_muln_low(h, q[1], (S ? t : u), D);								\
		bn_subn_low(y, y, h, D);											\
		/* The coordinates of pi also fit in D digits. */					\
		dv_copy(w[0], u, D);												\
		dv_copy(w[1], v, D);												\
	}																		\
																			\
	static void P##_top(int64_t x[4], dig_t w[4][D], size_t len) {			\
		dig_t z = 0, d;														\
		uint64_t v;															\
		size_t b, l, q, r;													\
																			\
		/* The position b of 29 bits below the top one of the				\
		 * coordinates. */													\
		for (l = len; l > 0 && z == 0; l--) {								\
			for (int i = 0; i < 4; i++) {									\
				z |= w[i][l - 1] ^ -(w[i][len - 1] >> (RLC_DIG - 1));		\
			}																\
		}																	\
		b = RLC_DIG * l + util_bits_dig(z);									\
		b = (b > 29 ? b - 29 : 0);											\
		/* The 64 bits from position b, with the sign above the top			\
		 * digit. */														\
		q = b / RLC_DIG;													\
		r = b % RLC_DIG;													\
		for (int i = 0; i < 4; i++) {										\
			v = 0;															\
			for (size_t k = 0; k * RLC_DIG < 64 + r; k++) {					\
				d = (q + k < len ? w[i][q + k] :							\
						-(w[i][len - 1] >> (RLC_DIG - 1)));					\
				if (k == 0) {												\
					v |= (uint64_t)(d >> r);								\
				} else {													\
					v |= (uint64_t)d << (k * RLC_DIG - r);					\
				}															\
			}																\
			x[i] = (int64_t)v;												\
		}																	\
	}																		\
																			\
	static size_t P##_shrink(dig_t w[4][D], size_t len) {					\
		dig_t s;															\
		size_t t = 1;														\
																			\
		for (int j = 0; j < 4; j++) {										\
			s = -(w[j][len - 1] >> (RLC_DIG - 1));							\
			for (size_t l = len; l > 0; l--) {								\
				if ((w[j][l - 1] ^ s) != 0) {								\
					t = RLC_MAX(t, l +										\
							(((w[j][l - 1] ^ s) >> (RLC_DIG - 3)) != 0));	\
					break;													\
				}															\
			}																\
		}																	\
		t = RLC_MIN(t, (size_t)D);											\
		for (int j = 0; j < 4; j++) {										\
			s = -(w[j][len - 1] >> (RLC_DIG - 1));							\
			for (size_t l = len; l < t; l++) {								\
				w[j][l] = s;												\
			}																\
		}																	\
		return t;															\
	}																		\
																			\
	static int P##_symbol(const fp_t a, int ct, int k) {					\
		dig_t w[4][D], c[4][D], z = 0;										\
		int64_t d = 1, e = 0;												\
		size_t len = D;														\
		int zero;															\
																			\
		for (size_t j = 0; j < RLC_FP_DIGS; j++) {							\
			z |= a[j];														\
		}																	\
		zero = (z == 0);													\
		if (!ct && zero) {													\
			return -1;														\
		}																	\
																			\
		P##_init(w, a);														\
		for (int i = 0, n; i < I; i += n) {									\
			n = RLC_MIN(k, I - i);											\
			/* Without constant time, stop once g is 0. */					\
			if (!ct) {														\
				z = 0;														\
				for (size_t j = 0; j < len; j++) {							\
					z |= w[2][j] | w[3][j];									\
				}															\
				if (z == 0) {												\
					break;													\
				}															\
			}																\
			/* Without constant time, finish small f and g otherwise. */	\
			if (!ct && P##_tail(w, len, &e)) {								\
				break;														\
			}																\
			/* A fixed number of digits in constant time, so that the		\
			 * compiler can specialize the loops for it. */					\
			if (ct) {														\
				P##_jump(c, w, &d, &e, n, D);								\
			} else {														\
				P##_jump(c, w, &d, &e, n, len);								\
			}																\
			for (int j = 0; j < 4; j++) {									\
				dv_copy(w[j], c[j], len);									\
			}																\
			/* Without constant time, keep only the digits that f and g		\
			 * need. */														\
			if (!ct) {														\
				len = P##_shrink(w, len);									\
			}																\
		}																	\
		/* g is now 0 and f a primary unit, so the symbol is the root of	\
		 * unity to the power e, divided by that of R in Montgomery			\
		 * form; zero has none. */											\
		return (int)M(e - core_get()->X##_r) | -zero;						\
	}
