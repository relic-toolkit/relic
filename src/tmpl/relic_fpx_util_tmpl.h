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
 * Templates for basic arithmetic and utilities in extension fields.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for addition, subtraction, negation and doubling in an extension field built as an
 * extension of degree N of a subfield.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] N			- the degree of the extension over the subfield.
 */
#define TMPL_FPX_ADD(X, S, N)												\
	void X##_add(X##_t c, const X##_t a, const X##_t b) {					\
		for (int i = 0; i < (N); i++) {										\
			S##_add(c[i], a[i], b[i]);										\
		}																	\
	}																		\
																			\
	void X##_sub(X##_t c, const X##_t a, const X##_t b) {					\
		for (int i = 0; i < (N); i++) {										\
			S##_sub(c[i], a[i], b[i]);										\
		}																	\
	}																		\
																			\
	void X##_neg(X##_t c, const X##_t a) {									\
		for (int i = 0; i < (N); i++) {										\
			S##_neg(c[i], a[i]);											\
		}																	\
	}																		\
																			\
	void X##_dbl(X##_t c, const X##_t a) {									\
		for (int i = 0; i < (N); i++) {										\
			S##_dbl(c[i], a[i]);											\
		}																	\
	}

/**
 * Defines a template for comparison in an extension field built as an
 * extension of degree N of a subfield.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] N			- the degree of the extension over the subfield.
 */
#define TMPL_FPX_CMP(X, S, N)												\
	int X##_cmp(const X##_t a, const X##_t b) {								\
		for (int i = 0; i < (N); i++) {										\
			if (S##_cmp(a[i], b[i]) != RLC_EQ) {							\
				return RLC_NE;												\
			}																\
		}																	\
		return RLC_EQ;														\
	}																		\
																			\
	int X##_cmp_dig(const X##_t a, const dig_t b) {							\
		if (S##_cmp_dig(a[0], b) != RLC_EQ) {								\
			return RLC_NE;													\
		}																	\
		for (int i = 1; i < (N); i++) {										\
			if (!S##_is_zero(a[i])) {										\
				return RLC_NE;												\
			}																\
		}																	\
		return RLC_EQ;														\
	}

/**
 * Defines a template for copying, assignment, testing,
 * sampling and printing in an extension field built as an
 * extension of degree N of a subfield.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] N			- the degree of the extension over the subfield.
 */
#define TMPL_FPX_UTIL(X, S, N)												\
	void X##_copy(X##_t c, const X##_t a) {									\
		for (int i = 0; i < (N); i++) {										\
			S##_copy(c[i], a[i]);											\
		}																	\
	}																		\
																			\
	void X##_copy_sec(X##_t c, const X##_t a, dig_t bit) {					\
		for (int i = 0; i < (N); i++) {										\
			S##_copy_sec(c[i], a[i], bit);									\
		}																	\
	}																		\
																			\
	void X##_zero(X##_t a) {												\
		for (int i = 0; i < (N); i++) {										\
			S##_zero(a[i]);													\
		}																	\
	}																		\
																			\
	int X##_is_zero(const X##_t a) {										\
		for (int i = 0; i < (N); i++) {										\
			if (!S##_is_zero(a[i])) {										\
				return 0;													\
			}																\
		}																	\
		return 1;															\
	}																		\
																			\
	void X##_set_dig(X##_t a, const dig_t b) {								\
		S##_set_dig(a[0], b);												\
		for (int i = 1; i < (N); i++) {										\
			S##_zero(a[i]);													\
		}																	\
	}																		\
																			\
	void X##_rand(X##_t a) {												\
		for (int i = 0; i < (N); i++) {										\
			S##_rand(a[i]);													\
		}																	\
	}																		\
																			\
	void X##_print(const X##_t a) {											\
		for (int i = 0; i < (N); i++) {										\
			S##_print(a[i]);												\
		}																	\
	}
