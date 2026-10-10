/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Tests for elliptic curves defined over extensions of prime fields.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

/**
 * Defines the tests for an elliptic curve over an extension field: memory,
 * utilities, arithmetic, multiplication methods, hashing and endomorphisms.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_TEST_EPX(C, F)													\
static int test_##C##_memory(void) {										\
	err_t e = ERR_CAUGHT;													\
	int code = RLC_ERR;														\
	C##_t a;																\
																			\
	C##_null(a);															\
																			\
	RLC_TRY {																\
		TEST_CASE("memory can be allocated") {								\
			C##_new(a);														\
			C##_free(a);													\
		} TEST_END;															\
	} RLC_CATCH(e) {														\
		switch (e) {														\
			case ERR_NO_MEMORY:												\
				util_print("FATAL ERROR!\n");								\
				RLC_ERROR(end);												\
				break;														\
		}																	\
	}																		\
	(void)a;																\
	code = RLC_OK;															\
  end:																		\
	return code;															\
}																			\
																			\
static int test_##C##_util(void) {											\
	int l, code = RLC_ERR;													\
	C##_t a, b, c, t[3];													\
	uint8_t bin[2 * (sizeof(F##_t) / sizeof(fp_t)) * RLC_FP_BYTES + 1];		\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
	for (int j = 0; j < 3; j++) {											\
		C##_null(t[j]);														\
	}																		\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
		for (int j = 0; j < 3; j++) {										\
			C##_new(t[j]);													\
		}																	\
																			\
		TEST_CASE("copy and comparison are consistent") {					\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_rand(c);													\
			/* Compare points in affine coordinates. */						\
			if (C##_cmp(a, c) != RLC_EQ) {									\
				C##_copy(c, a);												\
				TEST_ASSERT(C##_cmp(c, a) == RLC_EQ, end);					\
			}																\
			if (C##_cmp(b, c) != RLC_EQ) {									\
				C##_copy(c, b);												\
				TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);					\
			}																\
			/* Compare with one point in projective. */						\
			C##_dbl(c, a);													\
			C##_norm(c, c);													\
			C##_dbl(a, a);													\
			TEST_ASSERT(C##_cmp(c, a) == RLC_EQ, end);						\
			TEST_ASSERT(C##_cmp(a, c) == RLC_EQ, end);						\
			/* Compare with two points in projective. */					\
			C##_dbl(c, c);													\
			C##_dbl(a, a);													\
			TEST_ASSERT(C##_cmp(c, a) == RLC_EQ, end);						\
			TEST_ASSERT(C##_cmp(a, c) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("negation and comparison are consistent") {				\
			C##_rand(a);													\
			C##_neg(b, a);													\
			TEST_ASSERT(C##_cmp(a, b) != RLC_EQ, end);						\
			C##_neg(b, b);													\
			TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);						\
			C##_neg(b, a);													\
			C##_add(a, a, b);												\
			C##_set_infty(b);												\
			TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("assignment to random and comparison are consistent") {	\
			C##_rand(a);													\
			C##_set_infty(c);												\
			TEST_ASSERT(C##_cmp(a, c) != RLC_EQ, end);						\
			TEST_ASSERT(C##_cmp(c, a) != RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("assignment to infinity and infinity test are consistent") {\
			C##_set_infty(a);												\
			TEST_ASSERT(C##_is_infty(a), end);								\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("validity test is correct") {								\
			C##_set_infty(a);												\
			TEST_ASSERT(C##_on_curve(a), end);								\
			C##_rand(a);													\
			TEST_ASSERT(C##_on_curve(a), end);								\
			F##_rand(a->x);													\
			TEST_ASSERT(!C##_on_curve(a), end);								\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("blinding is consistent") {								\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_blind(b, a);												\
			TEST_ASSERT(C##_on_curve(b), end);								\
			TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);						\
			C##_blind(a, a);												\
			TEST_ASSERT(C##_on_curve(a), end);								\
			TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("simultaneous normalization is correct") {				\
			C##_rand(a);													\
			C##_dbl(t[0], a);												\
			C##_set_infty(t[1]);											\
			C##_rand(b);													\
			C##_dbl(t[2], b);												\
			C##_dbl(a, a);													\
			C##_dbl(b, b);													\
			C##_norm_sim(t, (const C##_t *)t, 3);							\
			TEST_ASSERT(C##_cmp(t[0], a) == RLC_EQ, end);					\
			TEST_ASSERT(C##_is_infty(t[1]), end);							\
			TEST_ASSERT(C##_cmp(t[2], b) == RLC_EQ, end);					\
			TEST_ASSERT(t[0]->coord == BASIC && t[2]->coord == BASIC, end);	\
		} TEST_END;															\
																			\
		TEST_CASE("reading and writing a point are consistent") {			\
			for (int j = 0; j < 2; j++) {									\
				C##_set_infty(a);											\
				l = C##_size_bin(a, j);										\
				C##_write_bin(bin, l, a, j);								\
				C##_read_bin(b, bin, l);									\
				TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);					\
				C##_rand(a);												\
				l = C##_size_bin(a, j);										\
				C##_write_bin(bin, l, a, j);								\
				C##_read_bin(b, bin, l);									\
				TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);					\
				C##_rand(a);												\
				C##_dbl(a, a);												\
				l = C##_size_bin(a, j);										\
				C##_norm(a, a);												\
				C##_write_bin(bin, l, a, j);								\
				C##_read_bin(b, bin, l);									\
				TEST_ASSERT(C##_cmp(a, b) == RLC_EQ, end);					\
			}																\
		}																	\
		TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	for (int j = 0; j < 3; j++) {											\
		C##_free(t[j]);														\
	}																		\
	return code;															\
}																			\
																			\
static int test_##C##_addition(void) {										\
	int code = RLC_ERR;														\
	C##_t a, b, c, d, e;													\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
	C##_null(d);															\
	C##_null(e);															\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
		C##_new(d);															\
		C##_new(e);															\
																			\
		TEST_CASE("point addition is commutative") {						\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_add(d, a, b);												\
			C##_add(e, b, a);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition is associative") {						\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_rand(c);													\
			C##_add(d, a, b);												\
			C##_add(d, d, c);												\
			C##_add(e, b, c);												\
			C##_add(e, e, a);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition has identity") {							\
			C##_rand(a);													\
			C##_set_infty(d);												\
			C##_add(e, a, d);												\
			TEST_ASSERT(C##_cmp(a, e) == RLC_EQ, end);						\
			C##_add(e, d, a);												\
			TEST_ASSERT(C##_cmp(a, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition has inverse") {							\
			C##_rand(a);													\
			C##_neg(d, a);													\
			C##_add(e, a, d);												\
			TEST_ASSERT(C##_is_infty(e), end);								\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in affine coordinates is correct") {		\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_add(d, a, b);												\
			C##_add_basic(e, a, b);											\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in projective coordinates is correct") {	\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_rand(c);													\
			C##_add_projc(a, a, b);											\
			C##_add_projc(b, b, c);											\
			/* a and b in projective coordinates. */						\
			C##_add_projc(d, a, b);											\
			/* normalize before mixing coordinates. */						\
			C##_norm(a, a);													\
			C##_norm(b, b);													\
			C##_add(e, a, b);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {\
			C##_rand(a);													\
			C##_rand(b);													\
			/* a in projective, b in affine coordinates. */					\
			C##_add_projc(a, a, b);											\
			C##_add_projc(d, a, b);											\
			/* a in affine coordinates. */									\
			C##_norm(a, a);													\
			C##_add(e, a, b);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {\
			C##_rand(a);													\
			C##_rand(b);													\
			/* a and b in affine coordinates. */							\
			C##_add(d, a, b);												\
			C##_add_projc(e, a, b);											\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in jacobian coordinates is correct") {	\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_rand(c);													\
			C##_add_jacob(a, a, b);											\
			C##_add_jacob(b, b, c);											\
			/* a and b in projective coordinates. */						\
			C##_add_jacob(d, a, b);											\
			C##_norm(a, a);													\
			C##_norm(b, b);													\
			C##_add(e, a, b);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {\
			C##_rand(a);													\
			C##_rand(b);													\
			/* a in projective, b in affine coordinates. */					\
			C##_add_jacob(a, a, b);											\
			C##_add_jacob(d, a, b);											\
			/* a in affine coordinates. */									\
			C##_norm(a, a);													\
			C##_add(e, a, b);												\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_norm(a, a);													\
			C##_norm(b, b);													\
			/* a and b in affine coordinates. */							\
			C##_add(d, a, b);												\
			C##_add_jacob(e, a, b);											\
			TEST_ASSERT(C##_cmp(d, e) == RLC_EQ, end);						\
		} TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	C##_free(d);															\
	C##_free(e);															\
	return code;															\
}																			\
																			\
static int test_##C##_subtraction(void) {									\
	int code = RLC_ERR;														\
	C##_t a, b, c, d;														\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
	C##_null(d);															\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
		C##_new(d);															\
																			\
		TEST_CASE("point subtraction is anti-commutative") {				\
			C##_rand(a);													\
			C##_rand(b);													\
			C##_sub(c, a, b);												\
			C##_sub(d, b, a);												\
			C##_neg(d, d);													\
			TEST_ASSERT(C##_cmp(c, d) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("point subtraction has identity") {						\
			C##_rand(a);													\
			C##_set_infty(c);												\
			C##_sub(d, a, c);												\
			TEST_ASSERT(C##_cmp(d, a) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("point subtraction has inverse") {						\
			C##_rand(a);													\
			C##_sub(c, a, a);												\
			TEST_ASSERT(C##_is_infty(c), end);								\
		}																	\
		TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	C##_free(d);															\
	return code;															\
}																			\
																			\
static int test_##C##_doubling(void) {										\
	int code = RLC_ERR;														\
	C##_t a, b, c;															\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
																			\
		TEST_CASE("point doubling is correct") {							\
			C##_rand(a);													\
			C##_add(b, a, a);												\
			C##_dbl(c, a);													\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point doubling in affine coordinates is correct") {		\
			C##_rand(a);													\
			C##_dbl(b, a);													\
			C##_dbl_basic(c, a);											\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point doubling in projective coordinates is correct") {	\
			C##_rand(a);													\
			/* a in projective coordinates. */								\
			C##_dbl_projc(a, a);											\
			C##_dbl_projc(b, a);											\
			C##_norm(a, a);													\
			C##_dbl(c, a);													\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {\
			C##_rand(a);													\
			C##_dbl_projc(b, a);											\
			C##_norm(b, b);													\
			C##_dbl(c, a);													\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point doubling in jacobian coordinates is correct") {	\
			C##_rand(a);													\
			/* a in projective coordinates. */								\
			C##_dbl_jacob(a, a);											\
			C##_dbl_jacob(b, a);											\
			C##_norm(a, a);													\
			C##_dbl(c, a);													\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {\
			C##_rand(a);													\
			C##_dbl_jacob(b, a);											\
			C##_norm(b, b);													\
			C##_dbl(c, a);													\
			TEST_ASSERT(C##_cmp(b, c) == RLC_EQ, end);						\
		} TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	return code;															\
}																			\
																			\
static int test_##C##_multiplication(void) {								\
	int code = RLC_ERR;														\
	bn_t n, k;																\
	C##_t p, q, r;															\
																			\
	bn_null(n);																\
	bn_null(k);																\
	C##_null(p);															\
	C##_null(q);															\
	C##_null(r);															\
																			\
	RLC_TRY {																\
		bn_new(n);															\
		bn_new(k);															\
		C##_new(p);															\
		C##_new(q);															\
		C##_new(r);															\
																			\
		C##_curve_get_gen(p);												\
		C##_curve_get_ord(n);												\
																			\
		TEST_ONCE("generator has the right order") {						\
			TEST_ASSERT(C##_on_curve(p), end);								\
			C##_mul(r, p, n);												\
			TEST_ASSERT(C##_is_infty(r) == 1, end);							\
		} TEST_END;															\
																			\
		TEST_CASE("generator multiplication is correct") {					\
			bn_zero(k);														\
			C##_mul_gen(r, k);												\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_gen(r, k);												\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_gen(r, k);												\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_gen(r, k);												\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_gen(q, k);												\
			/* Add a multiple of n beyond the bit length of the field. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_gen(r, k);												\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("binary point multiplication is correct") {				\
			bn_zero(k);														\
			C##_mul_basic(r, p, k);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_basic(r, p, k);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			C##_rand(p);													\
			C##_mul_basic(r, p, n);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_basic(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_basic(r, p, k);											\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_basic(q, p, k);											\
			/* Add a multiple of n beyond the bit length of the field. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_basic(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("montgomery ladder point multiplication is correct") {	\
			bn_zero(k);														\
			C##_mul_monty(r, p, k);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_monty(r, p, k);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			C##_rand(p);													\
			C##_mul_monty(r, p, n);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_monty(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_monty(r, p, k);											\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_monty(q, p, k);											\
			/* Add a multiple of n beyond the bit length of the field. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_monty(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("left-to-right w-naf point multiplication is correct") {	\
			bn_zero(k);														\
			C##_mul_lwnaf(r, p, k);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_lwnaf(r, p, k);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			C##_rand(p);													\
			C##_mul_lwnaf(r, p, n);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_lwnaf(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_lwnaf(r, p, k);											\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_lwnaf(q, p, k);											\
			/* Add a multiple of n beyond the bit length of the field. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_lwnaf(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("left-to-right regular point multiplication is correct") {\
			bn_zero(k);														\
			C##_mul_lwreg(r, p, k);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_lwreg(r, p, k);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			C##_rand(p);													\
			C##_mul_lwreg(r, p, n);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_lwreg(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_lwreg(r, p, k);											\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_lwreg(q, p, k);											\
			/* Add a multiple of n beyond the bit length of the field. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_lwreg(r, p, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
																			\
		TEST_CASE("point multiplication by digit is correct") {				\
			C##_mul_dig(r, p, 0);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_dig(r, p, 1);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand(k, RLC_POS, RLC_DIG);									\
			C##_mul(q, p, k);												\
			C##_mul_dig(r, p, k->dp[0]);									\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	bn_free(n);																\
	bn_free(k);																\
	C##_free(p);															\
	C##_free(q);															\
	C##_free(r);															\
	return code;															\
}																			\
																			\
static int test_##C##_fixed(void) {											\
	int code = RLC_ERR;														\
	bn_t n, k;																\
	C##_t p, q, r, t[RLC_EPX_TABLE_MAX];									\
																			\
	bn_null(n);																\
	bn_null(k);																\
	C##_null(p);															\
	C##_null(q);															\
	C##_null(r);															\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {							\
		C##_null(t[i]);														\
	}																		\
																			\
	RLC_TRY {																\
		bn_new(n);															\
		bn_new(k);															\
		C##_new(p);															\
		C##_new(q);															\
		C##_new(r);															\
																			\
		C##_curve_get_gen(p);												\
		C##_curve_get_ord(n);												\
																			\
		for (int i = 0; i < RLC_EP_TABLE; i++) {							\
			C##_new(t[i]);													\
		}																	\
		TEST_CASE("fixed point multiplication is correct") {				\
			C##_rand(p);													\
			C##_mul_pre(t, p);												\
			bn_zero(k);														\
			C##_mul_fix(r, t, k);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_fix(r, t, n);											\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_fix(r, t, k);											\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(q, p, k);												\
			C##_mul_fix(q, t, k);											\
			C##_mul(r, p, k);												\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_fix(r, t, k);											\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_fix(q, t, k);											\
			/* Add a multiple of n beyond the bit length of the table. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_fix(r, t, k);											\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
		for (int i = 0; i < RLC_EP_TABLE; i++) {							\
			C##_free(t[i]);													\
		}																	\
																			\
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {						\
			C##_new(t[i]);													\
		}																	\
		TEST_CASE("binary fixed point multiplication is correct") {			\
			C##_rand(p);													\
			C##_mul_pre_basic(t, p);										\
			bn_zero(k);														\
			C##_mul_fix_basic(r, t, k);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_fix_basic(r, t, n);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_fix_basic(r, t, k);										\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(r, p, k);												\
			C##_mul_fix_basic(q, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_fix_basic(r, t, k);										\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_fix_basic(q, t, k);										\
			/* Add a multiple of n beyond the bit length of the table. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_fix_basic(r, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {						\
			C##_free(t[i]);													\
		}																	\
																			\
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {						\
			C##_new(t[i]);													\
		}																	\
		TEST_CASE("single-table comb fixed point multiplication is correct") {\
			C##_rand(p);													\
			C##_mul_pre_combs(t, p);										\
			bn_zero(k);														\
			C##_mul_fix_combs(r, t, k);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_fix_combs(r, t, n);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_fix_combs(r, t, k);										\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(r, p, k);												\
			C##_mul_fix_combs(q, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_fix_combs(r, t, k);										\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_fix_combs(q, t, k);										\
			/* Add a multiple of n beyond the bit length of the table. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_fix_combs(r, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {						\
			C##_free(t[i]);													\
		}																	\
																			\
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {						\
			C##_new(t[i]);													\
		}																	\
		TEST_CASE("double-table comb fixed point multiplication is correct") {\
			C##_rand(p);													\
			C##_mul_pre_combd(t, p);										\
			bn_zero(k);														\
			C##_mul_fix_combd(r, t, k);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_fix_combd(r, t, n);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_fix_combd(r, t, k);										\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(r, p, k);												\
			C##_mul_fix_combd(q, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_fix_combd(r, t, k);										\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_fix_combd(q, t, k);										\
			/* Add a multiple of n beyond the bit length of the table. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_fix_combd(r, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {						\
			C##_free(t[i]);													\
		}																	\
																			\
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {						\
			C##_new(t[i]);													\
		}																	\
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {\
			C##_rand(p);													\
			C##_mul_pre_lwnaf(t, p);										\
			bn_zero(k);														\
			C##_mul_fix_lwnaf(r, t, k);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			C##_mul_fix_lwnaf(r, t, n);										\
			TEST_ASSERT(C##_is_infty(r), end);								\
			bn_set_dig(k, 1);												\
			C##_mul_fix_lwnaf(r, t, k);										\
			TEST_ASSERT(C##_cmp(p, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul(r, p, k);												\
			C##_mul_fix_lwnaf(q, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_neg(k, k);													\
			C##_mul_fix_lwnaf(r, t, k);										\
			C##_neg(r, r);													\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
			bn_rand_mod(k, n);												\
			C##_mul_fix_lwnaf(q, t, k);										\
			/* Add a multiple of n beyond the bit length of the table. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k, k, n);												\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_fix_lwnaf(r, t, k);										\
			TEST_ASSERT(C##_cmp(q, r) == RLC_EQ, end);						\
		} TEST_END;															\
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {						\
			C##_free(t[i]);													\
		}																	\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(p);															\
	C##_free(q);															\
	C##_free(r);															\
	bn_free(n);																\
	bn_free(k);																\
	return code;															\
}																			\
																			\
static int test_##C##_simultaneous(void) {									\
	int code = RLC_ERR;														\
	bn_t n, k[17];															\
	C##_t p[17], r;															\
																			\
	bn_null(n);																\
	C##_null(r);															\
	RLC_TRY {																\
		bn_new(n);															\
		C##_new(r);															\
		for (int i = 0; i <= 16; i++) {										\
			bn_null(k[i]);													\
			bn_new(k[i]);													\
			C##_null(p[i]);													\
			C##_new(p[i]);													\
		}																	\
																			\
		C##_curve_get_gen(p[0]);											\
		C##_curve_get_ord(n);												\
																			\
		TEST_CASE("simultaneous point multiplication is correct") {			\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim(r, p[0], k[0], p[0], k[1]);							\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul(p[1], p[0], k[0]);										\
			C##_mul_sim(r, p[0], k[0], p[0], k[1]);							\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			bn_add(k[0], k[0], n);											\
			bn_add(k[1], k[1], n);											\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			C##_mul_sim_lot(p[1], p, k, 2);									\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			C##_mul_sim(r, p[0], k[0], p[1], k[1]);							\
			/* Add a multiple of n beyond the bit length of the scalars. */	\
			bn_lsh(n, n, RLC_DIG);											\
			bn_add(k[0], k[0], n);											\
			bn_add(k[1], k[1], n);											\
			bn_rsh(n, n, RLC_DIG);											\
			C##_mul_sim_lot(p[1], p, k, 2);									\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("basic simultaneous point multiplication is correct") {	\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim_basic(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul(p[1], p[0], k[0]);										\
			C##_mul_sim_basic(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim_basic(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim_basic(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_basic(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim_trick(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul(p[1], p[0], k[0]);										\
			C##_mul_sim_trick(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim_trick(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim_trick(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_trick(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("interleaving for simultaneous multiplication is correct") {\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim_inter(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul(p[1], p[0], k[0]);										\
			C##_mul_sim_inter(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim_inter(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim_inter(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_inter(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("jsf for simultaneous multiplication is correct") {		\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim_joint(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul(p[1], p[0], k[0]);										\
			C##_mul_sim_joint(r, p[0], k[0], p[0], k[1]);					\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim_joint(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim_joint(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_joint(r, p[0], k[0], p[1], k[1]);					\
			C##_mul(p[0], p[0], k[0]);										\
			C##_mul(p[1], p[1], k[1]);										\
			C##_add(p[1], p[1], p[0]);										\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("simultaneous multiplication with generator is correct") {\
			bn_zero(k[0]);													\
			bn_rand_mod(k[1], n);											\
			C##_mul(p[1], p[0], k[1]);										\
			C##_mul_sim_gen(r, k[0], p[0], k[1]);							\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_zero(k[1]);													\
			C##_mul_gen(p[1], k[0]);										\
			C##_mul_sim_gen(r, k[0], p[0], k[1]);							\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_rand_mod(k[0], n);											\
			bn_rand_mod(k[1], n);											\
			C##_mul_sim_gen(r, k[0], p[1], k[1]);							\
			C##_curve_get_gen(p[0]);										\
			C##_mul_sim(p[1], p[0], k[0], p[1], k[1]);						\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[0], k[0]);												\
			C##_mul_sim_gen(r, k[0], p[1], k[1]);							\
			C##_curve_get_gen(p[0]);										\
			C##_mul_sim(p[1], p[0], k[0], p[1], k[1]);						\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_gen(r, k[0], p[1], k[1]);							\
			C##_curve_get_gen(p[0]);										\
			C##_mul_sim(p[1], p[0], k[0], p[1], k[1]);						\
			TEST_ASSERT(C##_cmp(p[1], r) == RLC_EQ, end);					\
		} TEST_END;															\
																			\
		TEST_CASE("many simultaneous point multiplications are correct") {	\
			C##_set_infty(r);												\
			for (int j = 0; j < 16; j++) {									\
				bn_rand_mod(k[j], n);										\
				C##_rand(p[j]);												\
				C##_mul(p[16], p[j], k[j]);									\
				C##_add(r, r, p[16]);										\
				C##_mul_sim_lot(p[16], p, k, j + 1);						\
				TEST_ASSERT(C##_cmp(p[16], r) == RLC_EQ, end);				\
			}																\
			C##_mul(p[16], p[0], k[0]);										\
			C##_sub(r, r, p[16]);											\
			bn_zero(k[0]);													\
			C##_mul_sim_lot(p[16], p, k, 16);								\
			TEST_ASSERT(C##_cmp(p[16], r) == RLC_EQ, end);					\
			C##_mul(p[16], p[1], k[1]);										\
			C##_sub(r, r, p[16]);											\
			C##_sub(r, r, p[16]);											\
			bn_neg(k[1], k[1]);												\
			C##_mul_sim_lot(p[16], p, k, 16);								\
			TEST_ASSERT(C##_cmp(p[16], r) == RLC_EQ, end);					\
			bn_add(k[2], k[2], n);											\
			C##_mul_sim_lot(p[16], p, k, 16);								\
			TEST_ASSERT(C##_cmp(p[16], r) == RLC_EQ, end);					\
		} TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	bn_free(n);																\
	C##_free(r);															\
	for (int i = 0; i <= 16; i++) {											\
		bn_free(k[i]);														\
		C##_free(p[i]);														\
	}																		\
	return code;															\
}																			\
																			\
static int test_##C##_compression(void) {									\
	int code = RLC_ERR;														\
	C##_t a, b, c;															\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
																			\
		TEST_CASE("point compression is correct") {							\
			C##_rand(a);													\
			C##_pck(b, a);													\
			TEST_ASSERT(C##_upk(c, b) == 1, end);							\
			TEST_ASSERT(C##_cmp(a, c) == RLC_EQ, end);						\
		}																	\
		TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	return code;															\
}																			\
																			\
static int test_##C##_hashing(void) {										\
	int code = RLC_ERR;														\
	bn_t n;																	\
	C##_t a;																\
	uint8_t msg[5];															\
																			\
	bn_null(n);																\
	C##_null(a);															\
																			\
	RLC_TRY {																\
		bn_new(n);															\
		C##_new(a);															\
																			\
		C##_curve_get_ord(n);												\
																			\
		TEST_CASE("point hashing is correct") {								\
			rand_bytes(msg, sizeof(msg));									\
			C##_map(a, msg, sizeof(msg));									\
			TEST_ASSERT(C##_on_curve(a) == 1, end);							\
			C##_mul(a, a, n);												\
			TEST_ASSERT(C##_is_infty(a) == 1, end);							\
		}																	\
		TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	bn_free(n);																\
	C##_free(a);															\
	return code;															\
}																			\
																			\
static int test_##C##_frobenius(void) {										\
	int code = RLC_ERR;														\
	C##_t a, b, c;															\
	bn_t d, n;																\
																			\
	C##_null(a);															\
	C##_null(b);															\
	C##_null(c);															\
	bn_null(d);																\
	bn_null(n);																\
																			\
	RLC_TRY {																\
		C##_new(a);															\
		C##_new(b);															\
		C##_new(c);															\
		bn_new(d);															\
		bn_new(n);															\
																			\
		C##_curve_get_ord(n);												\
																			\
		TEST_CASE("frobenius and point multiplication are consistent") {	\
			C##_rand(a);													\
			C##_frb(b, a, 1);												\
			d->used = RLC_FP_DIGS;											\
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);					\
			bn_mod(d, d, n);												\
			C##_mul_basic(c, a, d);											\
			TEST_ASSERT(C##_cmp(c, b) == RLC_EQ, end);						\
		} TEST_END;															\
																			\
		TEST_CASE("endomorphism and point multiplication are consistent") {	\
			C##_rand(a);													\
			C##_psi(b, a);													\
			ep_curve_frbase(d);												\
			if (ep_curve_is_pairf() == EP_BN) {								\
				bn_read_raw(d, fp_prime_get(), RLC_FP_DIGS);				\
			}																\
			bn_mod(d, d, n);												\
			C##_mul_basic(c, a, d);											\
			TEST_ASSERT(C##_cmp(c, b) == RLC_EQ, end);						\
		} TEST_END;															\
	}																		\
	RLC_CATCH_ANY {															\
		util_print("FATAL ERROR!\n");										\
		RLC_ERROR(end);														\
	}																		\
	code = RLC_OK;															\
  end:																		\
	C##_free(a);															\
	C##_free(b);															\
	C##_free(c);															\
	bn_free(d);																\
	bn_free(n);																\
	return code;															\
}

TMPL_TEST_EPX(ep2, fp2)

TMPL_TEST_EPX(ep3, fp3)

TMPL_TEST_EPX(ep4, fp4)

TMPL_TEST_EPX(ep8, fp8)

TMPL_TEST_EPX(ep9, fp9)

static int hashing2(void) {
	int code = RLC_ERR;
	bn_t n;
	ep2_t a;
	uint8_t msg[5];

	bn_null(n);
	ep2_null(a);

	RLC_TRY {
		bn_new(n);
		ep2_new(a);

		ep2_curve_get_ord(n);

		TEST_CASE("basic point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map_basic(a, msg, sizeof(msg));
			TEST_ASSERT(ep2_is_infty(a) == 0, end);
			ep2_mul(a, a, n);
			TEST_ASSERT(ep2_is_infty(a) == 1, end);
		}
		TEST_END;

		TEST_CASE("simplified SWU point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map_sswum(a, msg, sizeof(msg));
			TEST_ASSERT(ep2_is_infty(a) == 0, end);
			ep2_mul(a, a, n);
			TEST_ASSERT(ep2_is_infty(a) == 1, end);
		}
		TEST_END;

		if (ep_curve_is_pairf()) {
					TEST_CASE("swift point hashing is correct") {
						rand_bytes(msg, sizeof(msg));
						ep2_map_swift(a, msg, sizeof(msg));
						TEST_ASSERT(ep2_is_infty(a) == 0, end);
						ep2_mul(a, a, n);
						TEST_ASSERT(ep2_is_infty(a) == 1, end);
					}
					TEST_END;
		}
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep2_free(a);
	return code;
}

int main(void) {
	int r0, r1, r2, r3, r4;

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the EPX module", 0);

	if (ep_param_set_any_pairf() == RLC_ERR) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	if ((r0 = ep2_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (test_ep2_memory() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_util() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (test_ep2_addition() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_subtraction() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_doubling() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_frobenius() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_multiplication() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_fixed() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_simultaneous() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_compression() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep2_hashing() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (hashing2() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r1 = ep3_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (test_ep3_memory() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_util() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (test_ep3_addition() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_subtraction() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_doubling() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_frobenius() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_multiplication() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_fixed() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_simultaneous() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_compression() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep3_hashing() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r2 = ep4_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (test_ep4_memory() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_util() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (test_ep4_addition() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_subtraction() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_doubling() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_frobenius() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_multiplication() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_fixed() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_simultaneous() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_compression() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep4_hashing() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r3 = ep8_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (test_ep8_memory() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_util() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (test_ep8_addition() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_subtraction() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_doubling() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_frobenius() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_multiplication() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_fixed() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_simultaneous() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_compression() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep8_hashing() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r4 = ep9_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (test_ep9_memory() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_util() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (test_ep9_addition() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_subtraction() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_doubling() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_frobenius() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_multiplication() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_fixed() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_simultaneous() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_compression() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (test_ep9_hashing() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (!r0 && !r1 && !r2 && !r3 && !r4) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
