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
 * Defines a template for the residue symbol by jumps of up to k combined
 * divsteps, a fixed number of them in constant time or until g is 0, with -1
 * for zero, as P_symbol(a, ct, k), and for P_shrink(w, len), which returns the
 * number of digits that f and g need, in variable time: they do not grow, but
 * a coordinate may double, so the largest stays below 2^(RLC_DIG * len - 3),
 * and digits that come back are sign-extended. The symbol starts from
 * P_init(w, a) and runs P_jump(c, w, d, e, n, len), which the instantiating
 * file defines.
 *
 * @param[in] P			- the prefix of the functions.
 * @param[in] D			- the number of digits of the coordinates.
 * @param[in] I			- the number of iterations in constant time.
 * @param[in] R			- the context field of the exponent of R.
 * @param[in] M			- the reduction of an exponent modulo the order.
 */
#define TMPL_FP_SMB(P, D, I, R, M)											\
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
		return (int)M(e - core_get()->R) | -zero;							\
	}
