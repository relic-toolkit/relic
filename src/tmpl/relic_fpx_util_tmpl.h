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
 * Defines a template for addition, subtraction, negation and doubling in an
 * extension field of degree N over a subfield.
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
 * Defines a template for comparison in an extension field of degree N over a
 * subfield.
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
 * Defines a template for copying, assignment, testing, sampling and printing in
 * an extension field of degree N over a subfield.
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

/**
 * Defines a template for serialization in an extension field without
 * compression.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] N			- the degree of the extension over the subfield.
 * @param[in] K			- the number of prime field coefficients.
 */
#define TMPL_FPX_BIN(X, S, N, K)											\
	int X##_size_bin(const X##_t a, int pack) {								\
		(void)a;															\
		(void)pack;															\
		return (K) * RLC_FP_BYTES;											\
	}																		\
																			\
	void X##_read_bin(X##_t a, const uint8_t *bin, size_t len) {			\
		const size_t s = ((K) / (N)) * RLC_FP_BYTES;						\
																			\
		if (len != (N) * s) {												\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		for (int i = 0; i < (N); i++) {										\
			S##_read_bin(a[i], bin + i * s, s);								\
		}																	\
	}																		\
																			\
	void X##_write_bin(uint8_t *bin, size_t len, const X##_t a, int pack) {	\
		const size_t s = ((K) / (N)) * RLC_FP_BYTES;						\
																			\
		(void)pack;															\
		if (len != (N) * s) {												\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		for (int i = 0; i < (N); i++) {										\
			S##_write_bin(bin + i * s, s, a[i], 0);							\
		}																	\
	}

/**
 * Defines a template for serialization in a quadratic extension field,
 * compressing unitary elements to one coefficient and the sign of the other.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] K			- the number of prime field coefficients.
 */
#define TMPL_FPX_BIN_T2(X, S, K)											\
	int X##_size_bin(const X##_t a, int pack) {								\
		if (pack && X##_test_cyc(a)) {										\
			return ((K) / 2) * RLC_FP_BYTES + 1;							\
		}																	\
		return (K) * RLC_FP_BYTES;											\
	}																		\
																			\
	void X##_read_bin(X##_t a, const uint8_t *bin, size_t len) {			\
		const size_t h = ((K) / 2) * RLC_FP_BYTES;							\
		S##_t t;															\
																			\
		if (len != h + 1 && len != 2 * h) {									\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		if (len == 2 * h) {													\
			S##_read_bin(a[0], bin, h);										\
			S##_read_bin(a[1], bin + h, h);									\
			return;															\
		}																	\
		if (bin[h] > 1) {													\
			RLC_THROW(ERR_NO_VALID);										\
			return;															\
		}																	\
																			\
		S##_null(t);														\
																			\
		RLC_TRY {															\
			S##_new(t);														\
																			\
			/* Unitary elements have a_0^2 - a_1^2 * v^2 = 1, thus recover	\
			 * a_0 = sqrt(1 + a_1^2 * v^2) and fix its sign. */				\
			S##_read_bin(a[1], bin, h);										\
			S##_sqr(t, a[1]);												\
			S##_mul_art(t, t);												\
			fp_add_dig(((fp_t *)t)[0], ((fp_t *)t)[0], 1);					\
			if (!S##_srt(a[0], t)) {										\
				RLC_THROW(ERR_NO_VALID);									\
			}																\
			if (util_sign((const fp_t *)a[0], (K) / 2) != bin[h]) {			\
				S##_neg(a[0], a[0]);										\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free(t);													\
		}																	\
	}																		\
																			\
	void X##_write_bin(uint8_t *bin, size_t len, const X##_t a, int pack) {	\
		const size_t h = ((K) / 2) * RLC_FP_BYTES;							\
																			\
		if (pack && X##_test_cyc(a)) {										\
			if (len != h + 1) {												\
				RLC_THROW(ERR_NO_BUFFER);									\
				return;														\
			}																\
			/* Keep a_1 and the sign of a_0. */								\
			S##_write_bin(bin, h, a[1], 0);									\
			bin[h] = util_sign((const fp_t *)a[0], (K) / 2);				\
			return;															\
		}																	\
		if (len != 2 * h) {													\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		S##_write_bin(bin, h, a[0], 0);										\
		S##_write_bin(bin + h, h, a[1], 0);									\
	}

/**
 * Defines a template for serialization in an extension field built as
 * quadratic over cubic, compressing elements in the cyclotomic subgroup.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] K			- the number of prime field coefficients.
 */
#define TMPL_FPX_BIN_QC(X, S, Z, K)											\
	int X##_size_bin(const X##_t a, int pack) {								\
		if (pack && X##_test_cyc(a)) {										\
			return (2 * (K) / 3) * RLC_FP_BYTES;							\
		}																	\
		return (K) * RLC_FP_BYTES;											\
	}																		\
																			\
	void X##_read_bin(X##_t a, const uint8_t *bin, size_t len) {			\
		const size_t z = ((K) / 6) * RLC_FP_BYTES;							\
		const size_t s = ((K) / 2) * RLC_FP_BYTES;							\
																			\
		if (len != 4 * z && len != 2 * s) {									\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		if (len == 4 * z) {													\
			/* Compressed elements keep four of the six coefficients. */	\
			Z##_zero(a[0][0]);												\
			Z##_zero(a[1][1]);												\
			Z##_read_bin(a[0][1], bin + 0 * z, z);							\
			Z##_read_bin(a[0][2], bin + 1 * z, z);							\
			Z##_read_bin(a[1][0], bin + 2 * z, z);							\
			Z##_read_bin(a[1][2], bin + 3 * z, z);							\
			X##_back_cyc(a, a);												\
		} else {															\
			for (int i = 0; i < 2; i++) {									\
				S##_read_bin(a[i], bin + i * s, s);							\
			}																\
		}																	\
	}																		\
																			\
	void X##_write_bin(uint8_t *bin, size_t len, const X##_t a, int pack) {	\
		const size_t z = ((K) / 6) * RLC_FP_BYTES;							\
		const size_t s = ((K) / 2) * RLC_FP_BYTES;							\
																			\
		if (pack && X##_test_cyc(a)) {										\
			if (len != 4 * z) {												\
				RLC_THROW(ERR_NO_BUFFER);									\
				return;														\
			}																\
			/* Compressed elements keep four of the six coefficients. */	\
			Z##_write_bin(bin + 0 * z, z, a[0][1], 0);						\
			Z##_write_bin(bin + 1 * z, z, a[0][2], 0);						\
			Z##_write_bin(bin + 2 * z, z, a[1][0], 0);						\
			Z##_write_bin(bin + 3 * z, z, a[1][2], 0);						\
			return;															\
		}																	\
		if (len != 2 * s) {													\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		for (int i = 0; i < 2; i++) {										\
			S##_write_bin(bin + i * s, s, a[i], 0);							\
		}																	\
	}

/**
 * Defines a template for serialization in an extension field built as
 * cubic over quadratic, compressing elements in the cyclotomic subgroup.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] K			- the number of prime field coefficients.
 */
#define TMPL_FPX_BIN_CQ(X, S, Z, K)											\
	int X##_size_bin(const X##_t a, int pack) {								\
		if (pack && X##_test_cyc(a)) {										\
			return (2 * (K) / 3) * RLC_FP_BYTES;							\
		}																	\
		return (K) * RLC_FP_BYTES;											\
	}																		\
																			\
	void X##_read_bin(X##_t a, const uint8_t *bin, size_t len) {			\
		const size_t z = ((K) / 6) * RLC_FP_BYTES;							\
		const size_t s = ((K) / 3) * RLC_FP_BYTES;							\
																			\
		if (len != 4 * z && len != 3 * s) {									\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		if (len == 4 * z) {													\
			/* Compressed elements keep four of the six coefficients. */	\
			Z##_zero(a[0][0]);												\
			Z##_zero(a[0][1]);												\
			Z##_read_bin(a[1][0], bin + 0 * z, z);							\
			Z##_read_bin(a[1][1], bin + 1 * z, z);							\
			Z##_read_bin(a[2][0], bin + 2 * z, z);							\
			Z##_read_bin(a[2][1], bin + 3 * z, z);							\
			X##_back_cyc(a, a);												\
		} else {															\
			for (int i = 0; i < 3; i++) {									\
				S##_read_bin(a[i], bin + i * s, s);							\
			}																\
		}																	\
	}																		\
																			\
	void X##_write_bin(uint8_t *bin, size_t len, const X##_t a, int pack) {	\
		const size_t z = ((K) / 6) * RLC_FP_BYTES;							\
		const size_t s = ((K) / 3) * RLC_FP_BYTES;							\
																			\
		if (pack && X##_test_cyc(a)) {										\
			if (len != 4 * z) {												\
				RLC_THROW(ERR_NO_BUFFER);									\
				return;														\
			}																\
			/* Compressed elements keep four of the six coefficients. */	\
			Z##_write_bin(bin + 0 * z, z, a[1][0], 0);						\
			Z##_write_bin(bin + 1 * z, z, a[1][1], 0);						\
			Z##_write_bin(bin + 2 * z, z, a[2][0], 0);						\
			Z##_write_bin(bin + 3 * z, z, a[2][1], 0);						\
			return;															\
		}																	\
		if (len != 3 * s) {													\
			RLC_THROW(ERR_NO_BUFFER);										\
			return;															\
		}																	\
		for (int i = 0; i < 3; i++) {										\
			S##_write_bin(bin + i * s, s, a[i], 0);							\
		}																	\
	}
