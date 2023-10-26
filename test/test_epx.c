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

static int memory2(void) {
	err_t e = ERR_CAUGHT;
	int code = RLC_ERR;
	ep2_t a;

	ep2_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep2_new(a);
			ep2_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util2(void) {
	int l, code = RLC_ERR;
	ep2_t a, b, c;
	uint8_t bin[4 * RLC_FP_BYTES + 1];

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("copy and comparison are consistent") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			/* Compare points in affine coordinates. */
			if (ep2_cmp(a, c) != RLC_EQ) {
				ep2_copy(c, a);
				TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			}
			if (ep2_cmp(b, c) != RLC_EQ) {
				ep2_copy(c, b);
				TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep2_dbl(c, a);
			ep2_norm(c, c);
			ep2_dbl(a, a);
			TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep2_dbl(c, c);
			ep2_dbl(a, a);
			TEST_ASSERT(ep2_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep2_rand(a);
			ep2_neg(b, a);
			TEST_ASSERT(ep2_cmp(a, b) != RLC_EQ, end);
			ep2_neg(b, b);
			TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
			ep2_neg(b, a);
			ep2_add(a, a, b);
			ep2_set_infty(b);
			TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep2_rand(a);
			ep2_set_infty(c);
			TEST_ASSERT(ep2_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep2_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep2_set_infty(a);
			TEST_ASSERT(ep2_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep2_set_infty(a);
			TEST_ASSERT(ep2_on_curve(a), end);
			ep2_rand(a);
			TEST_ASSERT(ep2_on_curve(a), end);
			fp2_rand(a->x);
			TEST_ASSERT(!ep2_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep2_rand(a);
			ep2_blind(a, a);
			TEST_ASSERT(ep2_on_curve(a), end);
		} TEST_END;

		TEST_CASE("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ep2_set_infty(a);
				l = ep2_size_bin(a, j);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
				ep2_rand(a);
				l = ep2_size_bin(a, j);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
				ep2_rand(a);
				ep2_dbl(a, a);
				l = ep2_size_bin(a, j);
				ep2_norm(a, a);
				ep2_write_bin(bin, l, a, j);
				ep2_read_bin(b, bin, l);
				TEST_ASSERT(ep2_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

static int addition2(void) {
	int code = RLC_ERR;
	ep2_t a, b, c, d, e;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	ep2_null(d);
	ep2_null(e);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		ep2_new(d);
		ep2_new(e);

		TEST_CASE("point addition is commutative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_add(d, a, b);
			ep2_add(e, b, a);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			ep2_add(d, a, b);
			ep2_add(d, d, c);
			ep2_add(e, b, c);
			ep2_add(e, e, a);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep2_rand(a);
			ep2_set_infty(d);
			ep2_add(e, a, d);
			TEST_ASSERT(ep2_cmp(e, a) == RLC_EQ, end);
			ep2_add(e, d, a);
			TEST_ASSERT(ep2_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep2_rand(a);
			ep2_neg(d, a);
			ep2_add(e, a, d);
			TEST_ASSERT(ep2_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_add(d, a, b);
			ep2_add_basic(e, a, b);
			TEST_ASSERT(ep2_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
#if !defined(EP_MIXED) || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_rand(c);
			ep2_add_projc(a, a, b);
			ep2_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep2_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep2_norm(a, a);
			ep2_norm(b, b);
			ep2_add(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep2_rand(a);
			ep2_rand(b);
			/* a in projective, b in affine coordinates. */
			ep2_add_projc(a, a, b);
			ep2_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep2_norm(a, a);
			ep2_add(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep2_rand(a);
			ep2_rand(b);
			/* a and b in affine coordinates. */
			ep2_add(d, a, b);
			ep2_add_projc(e, a, b);
			TEST_ASSERT(ep2_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	ep2_free(d);
	ep2_free(e);
	return code;
}

static int subtraction2(void) {
	int code = RLC_ERR;
	ep2_t a, b, c, d;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	ep2_null(d);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		ep2_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep2_rand(a);
			ep2_rand(b);
			ep2_sub(c, a, b);
			ep2_sub(d, b, a);
			ep2_neg(d, d);
			TEST_ASSERT(ep2_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep2_rand(a);
			ep2_set_infty(c);
			ep2_sub(d, a, c);
			TEST_ASSERT(ep2_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep2_rand(a);
			ep2_sub(c, a, a);
			TEST_ASSERT(ep2_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	ep2_free(d);
	return code;
}

static int doubling2(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("point doubling is correct") {
			ep2_rand(a);
			ep2_add(b, a, a);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep2_rand(a);
			ep2_dbl(b, a);
			ep2_dbl_basic(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep2_rand(a);
			/* a in projective coordinates. */
			ep2_dbl_projc(a, a);
			ep2_dbl_projc(b, a);
			ep2_norm(a, a);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep2_rand(a);
			ep2_dbl_projc(b, a);
			ep2_norm(b, b);
			ep2_dbl(c, a);
			TEST_ASSERT(ep2_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

static int multiplication2(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep2_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep2_null(p);
	ep2_null(q);
	ep2_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep2_new(p);
		ep2_new(q);
		ep2_new(r);

		ep2_curve_get_gen(p);
		ep2_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep2_on_curve(p), end);
			ep2_mul(r, p, n);
			TEST_ASSERT(ep2_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_gen(r, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_gen(q, k);
			bn_add(k, k, n);
			ep2_mul_gen(r, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul_basic(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_basic(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_basic(q, p, k);
			bn_add(k, k, n);
			ep2_mul_basic(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("sliding window point multiplication is correct") {
			bn_zero(k);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul_slide(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_slide(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_slide(q, p, k);
			bn_add(k, k, n);
			ep2_mul_slide(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul_monty(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_monty(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_monty(q, p, k);
			bn_add(k, k, n);
			ep2_mul_monty(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			ep2_rand(p);
			ep2_mul_lwnaf(r, p, n);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_lwnaf(r, p, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_lwnaf(q, p, k);
			bn_add(k, k, n);
			ep2_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("point multiplication by digit is correct") {
			ep2_mul_dig(r, p, 0);
			TEST_ASSERT(ep2_is_infty(r), end);
			ep2_mul_dig(r, p, 1);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep2_mul(q, p, k);
			ep2_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep2_free(p);
	ep2_free(q);
	ep2_free(r);
	return code;
}

static int fixed2(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep2_t p, q, r, t[RLC_EPX_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep2_null(p);
	ep2_null(q);
	ep2_null(r);

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep2_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep2_new(p);
		ep2_new(q);
		ep2_new(r);

		ep2_curve_get_gen(p);
		ep2_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre(t, p);
			bn_zero(k);
			ep2_mul_fix(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(q, p, k);
			ep2_mul_fix(q, t, k);
			ep2_mul(r, p, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_fix(q, t, k);
			bn_add(k, k, n);
			ep2_mul_fix(r, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep2_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("binary fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_basic(t, p);
			bn_zero(k);
			ep2_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_basic(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_basic(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_fix_basic(q, t, k);
			bn_add(k, k, n);
			ep2_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_combs(t, p);
			bn_zero(k);
			ep2_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_combs(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_combs(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_fix_combs(q, t, k);
			bn_add(k, k, n);
			ep2_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_combd(t, p);
			bn_zero(k);
			ep2_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_combd(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_combd(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_fix_combd(q, t, k);
			bn_add(k, k, n);
			ep2_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep2_free(t[i]);
		}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep2_new(t[i]);
		}
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {
			ep2_rand(p);
			ep2_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ep2_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep2_is_infty(r), end);
			bn_set_dig(k, 1);
			ep2_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep2_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul(r, p, k);
			ep2_mul_fix_lwnaf(q, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep2_mul_fix_lwnaf(r, t, k);
			ep2_neg(r, r);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep2_mul_fix_lwnaf(q, t, k);
			bn_add(k, k, n);
			ep2_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep2_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep2_free(t[i]);
		}
#endif
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(p);
	ep2_free(q);
	ep2_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous2(void) {
	int code = RLC_ERR;
	bn_t n, k[17];
	ep2_t p[17], r;

	bn_null(n);
	ep2_null(r);
	RLC_TRY {
		bn_new(n);
		ep2_new(r);
		for (int i = 0; i <= 16; i++) {
			bn_null(k[i]);
			bn_new(k[i]);
			ep2_null(p[i]);
			ep2_new(p[i]);
		}

		ep2_curve_get_gen(p[0]);
		ep2_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			bn_add(k[0], k[0], n);
			bn_add(k[1], k[1], n);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			ep2_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep2_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

#if EP_SIM == BASIC || !defined(STRIP)
		TEST_CASE("basic simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
		TEST_CASE("interleaving for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
		TEST_CASE("jsf for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul(p[1], p[0], k[0]);
			ep2_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep2_mul(p[0], p[0], k[0]);
			ep2_mul(p[1], p[1], k[1]);
			ep2_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep2_mul(p[1], p[0], k[1]);
			ep2_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep2_mul_gen(p[1], k[0]);
			ep2_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_gen(r, k[0], p[1], k[1]);
			ep2_curve_get_gen(p[0]);
			ep2_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep2_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("many simultaneous point multiplications are correct") {
			ep2_set_infty(r);
			for (int j = 0; j < 16; j++) {
				bn_rand_mod(k[j], n);
				ep2_rand(p[j]);
				ep2_mul(p[16], p[j], k[j]);
				ep2_add(r, r, p[16]);
				ep2_mul_sim_lot(p[16], p, k, j + 1);
				TEST_ASSERT(ep2_cmp(p[16], r) == RLC_EQ, end);
			}
			ep2_mul(p[16], p[0], k[0]);
			ep2_sub(r, r, p[16]);
			bn_zero(k[0]);
			ep2_mul_sim_lot(p[16], p, k, 16);
			TEST_ASSERT(ep2_cmp(p[16], r) == RLC_EQ, end);
			ep2_mul(p[16], p[1], k[1]);
			ep2_sub(r, r, p[16]);
			ep2_sub(r, r, p[16]);
			bn_neg(k[1], k[1]);
			ep2_mul_sim_lot(p[16], p, k, 16);
			TEST_ASSERT(ep2_cmp(p[16], r) == RLC_EQ, end);
			bn_add(k[2], k[2], n);
			ep2_mul_sim_lot(p[16], p, k, 16);
			TEST_ASSERT(ep2_cmp(p[16], r) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep2_free(r);
	for (int i = 0; i <= 16; i++) {
		bn_free(k[i]);
		ep2_free(p[i]);
	}
	return code;
}

static int compression2(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);

		TEST_CASE("point compression is correct") {
			ep2_rand(a);
			ep2_pck(b, a);
			TEST_ASSERT(ep2_upk(c, b) == 1, end);
			TEST_ASSERT(ep2_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	return code;
}

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

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map(a, msg, sizeof(msg));
			TEST_ASSERT(ep2_on_curve(a) == 1, end);
			ep2_mul(a, a, n);
			TEST_ASSERT(ep2_is_infty(a) == 1, end);
		}
		TEST_END;

#if EP_MAP == BASIC || !defined(STRIP)
		TEST_CASE("basic point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map_basic(a, msg, sizeof(msg));
			TEST_ASSERT(ep2_is_infty(a) == 0, end);
			ep2_mul(a, a, n);
			TEST_ASSERT(ep2_is_infty(a) == 1, end);
		}
		TEST_END;
#endif

#if EP_MAP == SSWUM || !defined(STRIP)
		TEST_CASE("simplified SWU point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep2_map_sswum(a, msg, sizeof(msg));
			TEST_ASSERT(ep2_is_infty(a) == 0, end);
			ep2_mul(a, a, n);
			TEST_ASSERT(ep2_is_infty(a) == 1, end);
		}
		TEST_END;
#endif

		if (ep_curve_is_pairf()) {
			#if EP_MAP == SWIFT || !defined(STRIP)
					TEST_CASE("swift point hashing is correct") {
						rand_bytes(msg, sizeof(msg));
						ep2_map_swift(a, msg, sizeof(msg));
						TEST_ASSERT(ep2_is_infty(a) == 0, end);
						ep2_mul(a, a, n);
						TEST_ASSERT(ep2_is_infty(a) == 1, end);
					}
					TEST_END;
			#endif
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

static int frobenius2(void) {
	int code = RLC_ERR;
	ep2_t a, b, c;
	bn_t d, n;

	ep2_null(a);
	ep2_null(b);
	ep2_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep2_new(a);
		ep2_new(b);
		ep2_new(c);
		bn_new(d);
		bn_new(n);

		ep2_curve_get_ord(n);

		TEST_CASE("frobenius and point multiplication are consistent") {
			ep2_rand(a);
			ep2_frb(b, a, 1);
			d->used = RLC_FP_DIGS;
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_mod(d, d, n);
			ep2_mul_basic(c, a, d);
			TEST_ASSERT(ep2_cmp(c, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep2_free(a);
	ep2_free(b);
	ep2_free(c);
	bn_free(d);
	bn_free(n);
	return code;
}

static int memory3(void) {
	err_t e;
	int code = RLC_ERR;
	ep3_t a;

	ep3_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep3_new(a);
			ep3_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util3(void) {
	int l, code = RLC_ERR;
	ep3_t a, b, c;
	uint8_t bin[8 * RLC_FP_BYTES + 1];

	ep3_null(a);
	ep3_null(b);
	ep3_null(c);

	RLC_TRY {
		ep3_new(a);
		ep3_new(b);
		ep3_new(c);

		TEST_CASE("copy and comparison are consistent") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_rand(c);
			/* Compare points in affine coordinates. */
			if (ep3_cmp(a, c) != RLC_EQ) {
				ep3_copy(c, a);
				TEST_ASSERT(ep3_cmp(c, a) == RLC_EQ, end);
			}
			if (ep3_cmp(b, c) != RLC_EQ) {
				ep3_copy(c, b);
				TEST_ASSERT(ep3_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep3_dbl(c, a);
			ep3_norm(c, c);
			ep3_dbl(a, a);
			TEST_ASSERT(ep3_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep3_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep3_dbl(c, c);
			ep3_dbl(a, a);
			TEST_ASSERT(ep3_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep3_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep3_rand(a);
			ep3_neg(b, a);
			TEST_ASSERT(ep3_cmp(a, b) != RLC_EQ, end);
			ep3_neg(b, b);
			TEST_ASSERT(ep3_cmp(a, b) == RLC_EQ, end);
			ep3_neg(b, a);
			ep3_add(a, a, b);
			ep3_set_infty(b);
			TEST_ASSERT(ep3_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep3_rand(a);
			ep3_set_infty(c);
			TEST_ASSERT(ep3_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep3_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep3_set_infty(a);
			TEST_ASSERT(ep3_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep3_set_infty(a);
			TEST_ASSERT(ep3_on_curve(a), end);
			ep3_rand(a);
			TEST_ASSERT(ep3_on_curve(a), end);
			fp3_rand(a->x);
			TEST_ASSERT(!ep3_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep3_rand(a);
			ep3_blind(a, a);
			TEST_ASSERT(ep3_on_curve(a), end);
		} TEST_END;

		TEST_CASE("reading and writing a point are consistent") {
			ep3_set_infty(a);
			l = ep3_size_bin(a, 0);
			ep3_write_bin(bin, l, a, 0);
			ep3_read_bin(b, bin, l);
			TEST_ASSERT(ep3_cmp(a, b) == RLC_EQ, end);
			ep3_rand(a);
			l = ep3_size_bin(a, 0);
			ep3_write_bin(bin, l, a, 0);
			ep3_read_bin(b, bin, l);
			TEST_ASSERT(ep3_cmp(a, b) == RLC_EQ, end);
			ep3_rand(a);
			ep3_dbl(a, a);
			l = ep3_size_bin(a, 0);
			ep3_norm(a, a);
			ep3_write_bin(bin, l, a, 0);
			ep3_read_bin(b, bin, l);
			TEST_ASSERT(ep3_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(a);
	ep3_free(b);
	ep3_free(c);
	return code;
}

static int addition3(void) {
	int code = RLC_ERR;
	ep3_t a, b, c, d, e;

	ep3_null(a);
	ep3_null(b);
	ep3_null(c);
	ep3_null(d);
	ep3_null(e);

	RLC_TRY {
		ep3_new(a);
		ep3_new(b);
		ep3_new(c);
		ep3_new(d);
		ep3_new(e);

		TEST_CASE("point addition is commutative") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_add(d, a, b);
			ep3_add(e, b, a);
			TEST_ASSERT(ep3_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_rand(c);
			ep3_add(d, a, b);
			ep3_add(d, d, c);
			ep3_add(e, b, c);
			ep3_add(e, e, a);
			TEST_ASSERT(ep3_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep3_rand(a);
			ep3_set_infty(d);
			ep3_add(e, a, d);
			TEST_ASSERT(ep3_cmp(e, a) == RLC_EQ, end);
			ep3_add(e, d, a);
			TEST_ASSERT(ep3_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep3_rand(a);
			ep3_neg(d, a);
			ep3_add(e, a, d);
			TEST_ASSERT(ep3_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_add(d, a, b);
			ep3_add_basic(e, a, b);
			TEST_ASSERT(ep3_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
#if !defined(EP_MIXED) || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_rand(c);
			ep3_add_projc(a, a, b);
			ep3_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep3_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep3_norm(a, a);
			ep3_norm(b, b);
			ep3_add(e, a, b);
			TEST_ASSERT(ep3_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep3_rand(a);
			ep3_rand(b);
			/* a in projective, b in affine coordinates. */
			ep3_add_projc(a, a, b);
			ep3_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep3_norm(a, a);
			ep3_add(e, a, b);
			TEST_ASSERT(ep3_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep3_rand(a);
			ep3_rand(b);
			/* a and b in affine coordinates. */
			ep3_add(d, a, b);
			ep3_add_projc(e, a, b);
			TEST_ASSERT(ep3_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(a);
	ep3_free(b);
	ep3_free(c);
	ep3_free(d);
	ep3_free(e);
	return code;
}

static int subtraction3(void) {
	int code = RLC_ERR;
	ep3_t a, b, c, d;

	ep3_null(a);
	ep3_null(b);
	ep3_null(c);
	ep3_null(d);

	RLC_TRY {
		ep3_new(a);
		ep3_new(b);
		ep3_new(c);
		ep3_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep3_rand(a);
			ep3_rand(b);
			ep3_sub(c, a, b);
			ep3_sub(d, b, a);
			ep3_neg(d, d);
			TEST_ASSERT(ep3_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep3_rand(a);
			ep3_set_infty(c);
			ep3_sub(d, a, c);
			TEST_ASSERT(ep3_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep3_rand(a);
			ep3_sub(c, a, a);
			TEST_ASSERT(ep3_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(a);
	ep3_free(b);
	ep3_free(c);
	ep3_free(d);
	return code;
}

static int doubling3(void) {
	int code = RLC_ERR;
	ep3_t a, b, c;

	ep3_null(a);
	ep3_null(b);
	ep3_null(c);

	RLC_TRY {
		ep3_new(a);
		ep3_new(b);
		ep3_new(c);

		TEST_CASE("point doubling is correct") {
			ep3_rand(a);
			ep3_add(b, a, a);
			ep3_dbl(c, a);
			TEST_ASSERT(ep3_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep3_rand(a);
			ep3_dbl(b, a);
			ep3_dbl_basic(c, a);
			TEST_ASSERT(ep3_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep3_rand(a);
			/* a in projective coordinates. */
			ep3_dbl_projc(a, a);
			ep3_dbl_projc(b, a);
			ep3_norm(a, a);
			ep3_dbl(c, a);
			TEST_ASSERT(ep3_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep3_rand(a);
			ep3_dbl_projc(b, a);
			ep3_norm(b, b);
			ep3_dbl(c, a);
			TEST_ASSERT(ep3_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(a);
	ep3_free(b);
	ep3_free(c);
	return code;
}

static int multiplication3(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep3_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep3_null(p);
	ep3_null(q);
	ep3_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep3_new(p);
		ep3_new(q);
		ep3_new(r);

		ep3_curve_get_gen(p);
		ep3_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep3_on_curve(p), end);
			ep3_mul(r, p, n);
			TEST_ASSERT(ep3_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep3_mul_gen(r, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_gen(r, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_gen(r, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_gen(r, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul_gen(q, k);
			bn_add(k, k, n);
			ep3_mul_gen(r, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep3_mul_basic(r, p, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_basic(r, p, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			ep3_rand(p);
			ep3_mul(r, p, n);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_basic(r, p, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_basic(r, p, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("sliding window point multiplication is correct") {
			bn_zero(k);
			ep3_mul_slide(r, p, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_slide(r, p, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			ep3_rand(p);
			ep3_mul(r, p, n);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_slide(r, p, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_slide(r, p, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep3_mul_monty(r, p, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_monty(r, p, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			ep3_rand(p);
			ep3_mul(r, p, n);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_monty(r, p, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_monty(r, p, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep3_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			ep3_rand(p);
			ep3_mul(r, p, n);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_lwnaf(r, p, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("multiplication by digit is correct") {
			ep3_mul_dig(r, p, 0);
			TEST_ASSERT(ep3_is_infty(r), end);
			ep3_mul_dig(r, p, 1);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep3_mul(q, p, k);
			ep3_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep3_free(p);
	ep3_free(q);
	ep3_free(r);
	return code;
}

static int fixed3(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep3_t p, q, r, t[RLC_EPX_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep3_null(p);
	ep3_null(q);
	ep3_null(r);

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep3_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep3_new(p);
		ep3_new(q);
		ep3_new(r);

		ep3_curve_get_gen(p);
		ep3_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep3_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep3_rand(p);
			ep3_mul_pre(t, p);
			bn_zero(k);
			ep3_mul_fix(r, t, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_fix(r, t, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(q, p, k);
			ep3_mul_fix(q, t, k);
			ep3_mul(r, p, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_fix(r, t, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep3_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep3_new(t[i]);
		}
		TEST_CASE("binary fixed point multiplication is correct") {
			ep3_rand(p);
			ep3_mul_pre_basic(t, p);
			bn_zero(k);
			ep3_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(r, p, k);
			ep3_mul_fix_basic(q, t, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_fix_basic(r, t, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep3_free(t[i]);
		}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep3_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep3_rand(p);
			ep3_mul_pre_combs(t, p);
			bn_zero(k);
			ep3_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(r, p, k);
			ep3_mul_fix_combs(q, t, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_fix_combs(r, t, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep3_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep3_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep3_rand(p);
			ep3_mul_pre_combd(t, p);
			bn_zero(k);
			ep3_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(r, p, k);
			ep3_mul_fix_combd(q, t, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_fix_combd(r, t, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep3_free(t[i]);
		}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep3_new(t[i]);
		}
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {
			ep3_rand(p);
			ep3_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ep3_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep3_is_infty(r), end);
			bn_set_dig(k, 1);
			ep3_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep3_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep3_mul(r, p, k);
			ep3_mul_fix_lwnaf(q, t, k);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep3_mul_fix_lwnaf(r, t, k);
			ep3_neg(r, r);
			TEST_ASSERT(ep3_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep3_free(t[i]);
		}
#endif
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(p);
	ep3_free(q);
	ep3_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous3(void) {
	int code = RLC_ERR;
	bn_t n, k[2];
	ep3_t p[2], r;

	bn_null(n);
	bn_null(k[0]);
	bn_null(k[1]);
	ep3_null(p[0]);
	ep3_null(p[1]);
	ep3_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k[0]);
		bn_new(k[1]);
		ep3_new(p[0]);
		ep3_new(p[1]);
		ep3_new(r);

		ep3_curve_get_gen(p[0]);
		ep3_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul(p[1], p[0], k[0]);
			ep3_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			ep3_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep3_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

#if EP_SIM == BASIC || !defined(STRIP)
		TEST_CASE("basic simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul(p[1], p[0], k[0]);
			ep3_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul(p[1], p[0], k[0]);
			ep3_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
		TEST_CASE("interleaving for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul(p[1], p[0], k[0]);
			ep3_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
		TEST_CASE("jsf for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul(p[1], p[0], k[0]);
			ep3_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep3_mul(p[0], p[0], k[0]);
			ep3_mul(p[1], p[1], k[1]);
			ep3_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep3_mul(p[1], p[0], k[1]);
			ep3_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep3_mul_gen(p[1], k[0]);
			ep3_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep3_mul_sim_gen(r, k[0], p[1], k[1]);
			ep3_curve_get_gen(p[0]);
			ep3_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep3_mul_sim_gen(r, k[0], p[1], k[1]);
			ep3_curve_get_gen(p[0]);
			ep3_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep3_mul_sim_gen(r, k[0], p[1], k[1]);
			ep3_curve_get_gen(p[0]);
			ep3_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep3_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k[0]);
	bn_free(k[1]);
	ep3_free(p[0]);
	ep3_free(p[1]);
	ep3_free(r);
	return code;
}

static int hashing3(void) {
	int code = RLC_ERR;
	bn_t n;
	ep3_t p;
	uint8_t msg[5];

	bn_null(n);
	ep3_null(p);

	RLC_TRY {
		bn_new(n);
		ep3_new(p);

		ep3_curve_get_ord(n);

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep3_map(p, msg, sizeof(msg));
			TEST_ASSERT(ep3_is_infty(p) == 0, end);
			ep3_mul(p, p, n);
			TEST_ASSERT(ep3_is_infty(p) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep3_free(p);
	return code;
}

static int frobenius3(void) {
	int code = RLC_ERR;
	ep3_t a, b, c;
	bn_t d, n;

	ep3_null(a);
	ep3_null(b);
	ep3_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep3_new(a);
		ep3_new(b);
		ep3_new(c);
		bn_new(d);
		bn_new(n);

		ep3_curve_get_ord(n);

		TEST_CASE("frobenius and point multiplication are consistent") {
			ep3_rand(a);
			ep3_frb(b, a, 1);
			d->used = RLC_FP_DIGS;
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_mod(d, d, n);
			ep3_mul_basic(c, a, d);
			TEST_ASSERT(ep3_cmp(c, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep3_free(a);
	ep3_free(b);
	ep3_free(c);
	bn_free(d);
	bn_free(n);
	return code;
}

static int memory4(void) {
	err_t e = ERR_CAUGHT;
	int code = RLC_ERR;
	ep4_t a;

	ep4_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep4_new(a);
			ep4_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util4(void) {
	int l, code = RLC_ERR;
	ep4_t a, b, c;
	uint8_t bin[8 * RLC_FP_BYTES + 1];

	ep4_null(a);
	ep4_null(b);
	ep4_null(c);

	RLC_TRY {
		ep4_new(a);
		ep4_new(b);
		ep4_new(c);

		TEST_CASE("copy and comparison are consistent") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_rand(c);
			/* Compare points in affine coordinates. */
			if (ep4_cmp(a, c) != RLC_EQ) {
				ep4_copy(c, a);
				TEST_ASSERT(ep4_cmp(c, a) == RLC_EQ, end);
			}
			if (ep4_cmp(b, c) != RLC_EQ) {
				ep4_copy(c, b);
				TEST_ASSERT(ep4_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep4_dbl(c, a);
			ep4_norm(c, c);
			ep4_dbl(a, a);
			TEST_ASSERT(ep4_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep4_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep4_dbl(c, c);
			ep4_dbl(a, a);
			TEST_ASSERT(ep4_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep4_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep4_rand(a);
			ep4_neg(b, a);
			TEST_ASSERT(ep4_cmp(a, b) != RLC_EQ, end);
			ep4_neg(b, b);
			TEST_ASSERT(ep4_cmp(a, b) == RLC_EQ, end);
			ep4_neg(b, a);
			ep4_add(a, a, b);
			ep4_set_infty(b);
			TEST_ASSERT(ep4_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep4_rand(a);
			ep4_set_infty(c);
			TEST_ASSERT(ep4_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep4_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep4_set_infty(a);
			TEST_ASSERT(ep4_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep4_set_infty(a);
			TEST_ASSERT(ep4_on_curve(a), end);
			ep4_rand(a);
			TEST_ASSERT(ep4_on_curve(a), end);
			fp4_rand(a->x);
			TEST_ASSERT(!ep4_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep4_rand(a);
			ep4_blind(a, a);
			TEST_ASSERT(ep4_on_curve(a), end);
		} TEST_END;

		TEST_CASE("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ep4_set_infty(a);
				l = ep4_size_bin(a, j);
				ep4_write_bin(bin, l, a, j);
				ep4_read_bin(b, bin, l);
				TEST_ASSERT(ep4_cmp(a, b) == RLC_EQ, end);
				ep4_rand(a);
				l = ep4_size_bin(a, j);
				ep4_write_bin(bin, l, a, j);
				ep4_read_bin(b, bin, l);
				TEST_ASSERT(ep4_cmp(a, b) == RLC_EQ, end);
				ep4_rand(a);
				ep4_dbl(a, a);
				l = ep4_size_bin(a, j);
				ep4_norm(a, a);
				ep4_write_bin(bin, l, a, j);
				ep4_read_bin(b, bin, l);
				TEST_ASSERT(ep4_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(a);
	ep4_free(b);
	ep4_free(c);
	return code;
}

static int addition4(void) {
	int code = RLC_ERR;
	ep4_t a, b, c, d, e;

	ep4_null(a);
	ep4_null(b);
	ep4_null(c);
	ep4_null(d);
	ep4_null(e);

	RLC_TRY {
		ep4_new(a);
		ep4_new(b);
		ep4_new(c);
		ep4_new(d);
		ep4_new(e);

		TEST_CASE("point addition is commutative") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_add(d, a, b);
			ep4_add(e, b, a);
			TEST_ASSERT(ep4_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_rand(c);
			ep4_add(d, a, b);
			ep4_add(d, d, c);
			ep4_add(e, b, c);
			ep4_add(e, e, a);
			TEST_ASSERT(ep4_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep4_rand(a);
			ep4_set_infty(d);
			ep4_add(e, a, d);
			TEST_ASSERT(ep4_cmp(e, a) == RLC_EQ, end);
			ep4_add(e, d, a);
			TEST_ASSERT(ep4_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep4_rand(a);
			ep4_neg(d, a);
			ep4_add(e, a, d);
			TEST_ASSERT(ep4_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_add(d, a, b);
			ep4_add_basic(e, a, b);
			TEST_ASSERT(ep4_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
#if !defined(EP_MIXED) || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_rand(c);
			ep4_add_projc(a, a, b);
			ep4_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep4_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep4_norm(a, a);
			ep4_norm(b, b);
			ep4_add(e, a, b);
			TEST_ASSERT(ep4_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep4_rand(a);
			ep4_rand(b);
			/* a in projective, b in affine coordinates. */
			ep4_add_projc(a, a, b);
			ep4_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep4_norm(a, a);
			ep4_add(e, a, b);
			TEST_ASSERT(ep4_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep4_rand(a);
			ep4_rand(b);
			/* a and b in affine coordinates. */
			ep4_add(d, a, b);
			ep4_add_projc(e, a, b);
			TEST_ASSERT(ep4_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(a);
	ep4_free(b);
	ep4_free(c);
	ep4_free(d);
	ep4_free(e);
	return code;
}

static int subtraction4(void) {
	int code = RLC_ERR;
	ep4_t a, b, c, d;

	ep4_null(a);
	ep4_null(b);
	ep4_null(c);
	ep4_null(d);

	RLC_TRY {
		ep4_new(a);
		ep4_new(b);
		ep4_new(c);
		ep4_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep4_rand(a);
			ep4_rand(b);
			ep4_sub(c, a, b);
			ep4_sub(d, b, a);
			ep4_neg(d, d);
			TEST_ASSERT(ep4_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep4_rand(a);
			ep4_set_infty(c);
			ep4_sub(d, a, c);
			TEST_ASSERT(ep4_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep4_rand(a);
			ep4_sub(c, a, a);
			TEST_ASSERT(ep4_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(a);
	ep4_free(b);
	ep4_free(c);
	ep4_free(d);
	return code;
}

static int doubling4(void) {
	int code = RLC_ERR;
	ep4_t a, b, c;

	ep4_null(a);
	ep4_null(b);
	ep4_null(c);

	RLC_TRY {
		ep4_new(a);
		ep4_new(b);
		ep4_new(c);

		TEST_CASE("point doubling is correct") {
			ep4_rand(a);
			ep4_add(b, a, a);
			ep4_dbl(c, a);
			TEST_ASSERT(ep4_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep4_rand(a);
			ep4_dbl(b, a);
			ep4_dbl_basic(c, a);
			TEST_ASSERT(ep4_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep4_rand(a);
			/* a in projective coordinates. */
			ep4_dbl_projc(a, a);
			ep4_dbl_projc(b, a);
			ep4_norm(a, a);
			ep4_dbl(c, a);
			TEST_ASSERT(ep4_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep4_rand(a);
			ep4_dbl_projc(b, a);
			ep4_norm(b, b);
			ep4_dbl(c, a);
			TEST_ASSERT(ep4_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(a);
	ep4_free(b);
	ep4_free(c);
	return code;
}

static int multiplication4(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep4_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep4_null(p);
	ep4_null(q);
	ep4_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep4_new(p);
		ep4_new(q);
		ep4_new(r);

		ep4_curve_get_gen(p);
		ep4_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep4_on_curve(p), end);
			ep4_mul(r, p, n);
			TEST_ASSERT(ep4_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep4_mul_gen(r, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_gen(r, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_gen(r, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_gen(r, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul_gen(q, k);
			bn_add(k, k, n);
			ep4_mul_gen(r, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep4_mul_basic(r, p, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_basic(r, p, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			ep4_rand(p);
			ep4_mul(r, p, n);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_basic(r, p, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_basic(r, p, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("sliding window point multiplication is correct") {
			bn_zero(k);
			ep4_mul_slide(r, p, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_slide(r, p, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			ep4_rand(p);
			ep4_mul(r, p, n);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_slide(r, p, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_slide(r, p, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep4_mul_monty(r, p, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_monty(r, p, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			ep4_rand(p);
			ep4_mul(r, p, n);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_monty(r, p, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_monty(r, p, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep4_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			ep4_rand(p);
			ep4_mul(r, p, n);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_lwnaf(r, p, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("multiplication by digit is correct") {
			ep4_mul_dig(r, p, 0);
			TEST_ASSERT(ep4_is_infty(r), end);
			ep4_mul_dig(r, p, 1);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep4_mul(q, p, k);
			ep4_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep4_free(p);
	ep4_free(q);
	ep4_free(r);
	return code;
}

static int fixed4(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep4_t p, q, r, t[RLC_EPX_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep4_null(p);
	ep4_null(q);
	ep4_null(r);

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep4_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep4_new(p);
		ep4_new(q);
		ep4_new(r);

		ep4_curve_get_gen(p);
		ep4_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep4_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep4_rand(p);
			ep4_mul_pre(t, p);
			bn_zero(k);
			ep4_mul_fix(r, t, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_fix(r, t, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(q, p, k);
			ep4_mul_fix(q, t, k);
			ep4_mul(r, p, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_fix(r, t, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep4_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep4_new(t[i]);
		}
		TEST_CASE("binary fixed point multiplication is correct") {
			ep4_rand(p);
			ep4_mul_pre_basic(t, p);
			bn_zero(k);
			ep4_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(r, p, k);
			ep4_mul_fix_basic(q, t, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_fix_basic(r, t, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep4_free(t[i]);
		}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep4_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep4_rand(p);
			ep4_mul_pre_combs(t, p);
			bn_zero(k);
			ep4_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(r, p, k);
			ep4_mul_fix_combs(q, t, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_fix_combs(r, t, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep4_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep4_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep4_rand(p);
			ep4_mul_pre_combd(t, p);
			bn_zero(k);
			ep4_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(r, p, k);
			ep4_mul_fix_combd(q, t, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_fix_combd(r, t, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep4_free(t[i]);
		}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep4_new(t[i]);
		}
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {
			ep4_rand(p);
			ep4_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ep4_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep4_is_infty(r), end);
			bn_set_dig(k, 1);
			ep4_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep4_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep4_mul(r, p, k);
			ep4_mul_fix_lwnaf(q, t, k);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep4_mul_fix_lwnaf(r, t, k);
			ep4_neg(r, r);
			TEST_ASSERT(ep4_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep4_free(t[i]);
		}
#endif
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(p);
	ep4_free(q);
	ep4_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous4(void) {
	int code = RLC_ERR;
	bn_t n, k[2];
	ep4_t p[2], r;

	bn_null(n);
	bn_null(k[0]);
	bn_null(k[1]);
	ep4_null(p[0]);
	ep4_null(p[1]);
	ep4_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k[0]);
		bn_new(k[1]);
		ep4_new(p[0]);
		ep4_new(p[1]);
		ep4_new(r);

		ep4_curve_get_gen(p[0]);
		ep4_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul(p[1], p[0], k[0]);
			ep4_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			ep4_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep4_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

#if EP_SIM == BASIC || !defined(STRIP)
		TEST_CASE("basic simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul(p[1], p[0], k[0]);
			ep4_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul(p[1], p[0], k[0]);
			ep4_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
		TEST_CASE("interleaving for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul(p[1], p[0], k[0]);
			ep4_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
		TEST_CASE("jsf for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul(p[1], p[0], k[0]);
			ep4_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep4_mul(p[0], p[0], k[0]);
			ep4_mul(p[1], p[1], k[1]);
			ep4_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep4_mul(p[1], p[0], k[1]);
			ep4_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep4_mul_gen(p[1], k[0]);
			ep4_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep4_mul_sim_gen(r, k[0], p[1], k[1]);
			ep4_curve_get_gen(p[0]);
			ep4_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep4_mul_sim_gen(r, k[0], p[1], k[1]);
			ep4_curve_get_gen(p[0]);
			ep4_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep4_mul_sim_gen(r, k[0], p[1], k[1]);
			ep4_curve_get_gen(p[0]);
			ep4_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep4_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k[0]);
	bn_free(k[1]);
	ep4_free(p[0]);
	ep4_free(p[1]);
	ep4_free(r);
	return code;
}

static int hashing4(void) {
	int code = RLC_ERR;
	bn_t n;
	ep4_t p;
	uint8_t msg[5];

	bn_null(n);
	ep4_null(p);

	RLC_TRY {
		bn_new(n);
		ep4_new(p);

		ep4_curve_get_ord(n);

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep4_map(p, msg, sizeof(msg));
			TEST_ASSERT(ep4_on_curve(p) == 1, end);
			ep4_mul(p, p, n);
			TEST_ASSERT(ep4_is_infty(p) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep4_free(p);
	return code;
}

static int frobenius4(void) {
	int code = RLC_ERR;
	ep4_t a, b, c;
	bn_t d, n;

	ep4_null(a);
	ep4_null(b);
	ep4_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep4_new(a);
		ep4_new(b);
		ep4_new(c);
		bn_new(d);
		bn_new(n);

		ep4_curve_get_ord(n);

		TEST_CASE("frobenius and point multiplication are consistent") {
			ep4_rand(a);
			ep4_frb(b, a, 1);
			d->used = RLC_FP_DIGS;
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_mod(d, d, n);
			ep4_mul_basic(c, a, d);
			TEST_ASSERT(ep4_cmp(c, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep4_free(a);
	ep4_free(b);
	ep4_free(c);
	bn_free(d);
	bn_free(n);
	return code;
}

static int memory8(void) {
	err_t e = ERR_CAUGHT;
	int code = RLC_ERR;
	ep8_t a;

	ep8_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep8_new(a);
			ep8_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util8(void) {
	int l, code = RLC_ERR;
	ep8_t a, b, c;
	uint8_t bin[16 * RLC_FP_BYTES + 1];

	ep8_null(a);
	ep8_null(b);
	ep8_null(c);

	RLC_TRY {
		ep8_new(a);
		ep8_new(b);
		ep8_new(c);

		TEST_CASE("copy and comparison are consistent") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_rand(c);
			/* Compare points in affine coordinates. */
			if (ep8_cmp(a, c) != RLC_EQ) {
				ep8_copy(c, a);
				TEST_ASSERT(ep8_cmp(c, a) == RLC_EQ, end);
			}
			if (ep8_cmp(b, c) != RLC_EQ) {
				ep8_copy(c, b);
				TEST_ASSERT(ep8_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep8_dbl(c, a);
			ep8_norm(c, c);
			ep8_dbl(a, a);
			TEST_ASSERT(ep8_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep8_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep8_dbl(c, c);
			ep8_dbl(a, a);
			TEST_ASSERT(ep8_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep8_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep8_rand(a);
			ep8_neg(b, a);
			TEST_ASSERT(ep8_cmp(a, b) != RLC_EQ, end);
			ep8_neg(b, b);
			TEST_ASSERT(ep8_cmp(a, b) == RLC_EQ, end);
			ep8_neg(b, a);
			ep8_add(a, a, b);
			ep8_set_infty(b);
			TEST_ASSERT(ep8_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep8_rand(a);
			ep8_set_infty(c);
			TEST_ASSERT(ep8_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep8_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep8_set_infty(a);
			TEST_ASSERT(ep8_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep8_set_infty(a);
			TEST_ASSERT(ep8_on_curve(a), end);
			ep8_rand(a);
			TEST_ASSERT(ep8_on_curve(a), end);
			fp8_rand(a->x);
			TEST_ASSERT(!ep8_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep8_rand(a);
			ep8_blind(a, a);
			TEST_ASSERT(ep8_on_curve(a), end);
		} TEST_END;

		TEST_CASE("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ep8_set_infty(a);
				l = ep8_size_bin(a, j);
				ep8_write_bin(bin, l, a, j);
				ep8_read_bin(b, bin, l);
				TEST_ASSERT(ep8_cmp(a, b) == RLC_EQ, end);
				ep8_rand(a);
				l = ep8_size_bin(a, j);
				ep8_write_bin(bin, l, a, j);
				ep8_read_bin(b, bin, l);
				TEST_ASSERT(ep8_cmp(a, b) == RLC_EQ, end);
				ep8_rand(a);
				ep8_dbl(a, a);
				l = ep8_size_bin(a, j);
				ep8_norm(a, a);
				ep8_write_bin(bin, l, a, j);
				ep8_read_bin(b, bin, l);
				TEST_ASSERT(ep8_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(a);
	ep8_free(b);
	ep8_free(c);
	return code;
}

static int addition8(void) {
	int code = RLC_ERR;
	ep8_t a, b, c, d, e;

	ep8_null(a);
	ep8_null(b);
	ep8_null(c);
	ep8_null(d);
	ep8_null(e);

	RLC_TRY {
		ep8_new(a);
		ep8_new(b);
		ep8_new(c);
		ep8_new(d);
		ep8_new(e);

		TEST_CASE("point addition is commutative") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_add(d, a, b);
			ep8_add(e, b, a);
			TEST_ASSERT(ep8_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_rand(c);
			ep8_add(d, a, b);
			ep8_add(d, d, c);
			ep8_add(e, b, c);
			ep8_add(e, e, a);
			TEST_ASSERT(ep8_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep8_rand(a);
			ep8_set_infty(d);
			ep8_add(e, a, d);
			TEST_ASSERT(ep8_cmp(e, a) == RLC_EQ, end);
			ep8_add(e, d, a);
			TEST_ASSERT(ep8_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep8_rand(a);
			ep8_neg(d, a);
			ep8_add(e, a, d);
			TEST_ASSERT(ep8_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_add(d, a, b);
			ep8_add_basic(e, a, b);
			TEST_ASSERT(ep8_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
#if !defined(EP_MIXED) || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_rand(c);
			ep8_add_projc(a, a, b);
			ep8_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep8_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep8_norm(a, a);
			ep8_norm(b, b);
			ep8_add(e, a, b);
			TEST_ASSERT(ep8_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep8_rand(a);
			ep8_rand(b);
			/* a in projective, b in affine coordinates. */
			ep8_add_projc(a, a, b);
			ep8_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep8_norm(a, a);
			ep8_add(e, a, b);
			TEST_ASSERT(ep8_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep8_rand(a);
			ep8_rand(b);
			/* a and b in affine coordinates. */
			ep8_add(d, a, b);
			ep8_add_projc(e, a, b);
			TEST_ASSERT(ep8_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(a);
	ep8_free(b);
	ep8_free(c);
	ep8_free(d);
	ep8_free(e);
	return code;
}

static int subtraction8(void) {
	int code = RLC_ERR;
	ep8_t a, b, c, d;

	ep8_null(a);
	ep8_null(b);
	ep8_null(c);
	ep8_null(d);

	RLC_TRY {
		ep8_new(a);
		ep8_new(b);
		ep8_new(c);
		ep8_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep8_rand(a);
			ep8_rand(b);
			ep8_sub(c, a, b);
			ep8_sub(d, b, a);
			ep8_neg(d, d);
			TEST_ASSERT(ep8_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep8_rand(a);
			ep8_set_infty(c);
			ep8_sub(d, a, c);
			TEST_ASSERT(ep8_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep8_rand(a);
			ep8_sub(c, a, a);
			TEST_ASSERT(ep8_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(a);
	ep8_free(b);
	ep8_free(c);
	ep8_free(d);
	return code;
}

static int doubling8(void) {
	int code = RLC_ERR;
	ep8_t a, b, c;

	ep8_null(a);
	ep8_null(b);
	ep8_null(c);

	RLC_TRY {
		ep8_new(a);
		ep8_new(b);
		ep8_new(c);

		TEST_CASE("point doubling is correct") {
			ep8_rand(a);
			ep8_add(b, a, a);
			ep8_dbl(c, a);
			TEST_ASSERT(ep8_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep8_rand(a);
			ep8_dbl(b, a);
			ep8_dbl_basic(c, a);
			TEST_ASSERT(ep8_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep8_rand(a);
			/* a in projective coordinates. */
			ep8_dbl_projc(a, a);
			ep8_dbl_projc(b, a);
			ep8_norm(a, a);
			ep8_dbl(c, a);
			TEST_ASSERT(ep8_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep8_rand(a);
			ep8_dbl_projc(b, a);
			ep8_norm(b, b);
			ep8_dbl(c, a);
			TEST_ASSERT(ep8_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(a);
	ep8_free(b);
	ep8_free(c);
	return code;
}

static int multiplication8(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep8_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep8_null(p);
	ep8_null(q);
	ep8_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep8_new(p);
		ep8_new(q);
		ep8_new(r);

		ep8_curve_get_gen(p);
		ep8_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep8_on_curve(p), end);
			ep8_mul(r, p, n);
			TEST_ASSERT(ep8_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep8_mul_gen(r, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_gen(r, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_gen(r, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_gen(r, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul_gen(q, k);
			bn_add(k, k, n);
			ep8_mul_gen(r, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep8_mul_basic(r, p, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_basic(r, p, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			ep8_rand(p);
			ep8_mul(r, p, n);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_basic(r, p, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_basic(r, p, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("sliding window point multiplication is correct") {
			bn_zero(k);
			ep8_mul_slide(r, p, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_slide(r, p, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			ep8_rand(p);
			ep8_mul(r, p, n);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_slide(r, p, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_slide(r, p, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep8_mul_monty(r, p, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_monty(r, p, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			ep8_rand(p);
			ep8_mul(r, p, n);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_monty(r, p, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_monty(r, p, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep8_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			ep8_rand(p);
			ep8_mul(r, p, n);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_lwnaf(r, p, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("multiplication by digit is correct") {
			ep8_mul_dig(r, p, 0);
			TEST_ASSERT(ep8_is_infty(r), end);
			ep8_mul_dig(r, p, 1);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep8_mul(q, p, k);
			ep8_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep8_free(p);
	ep8_free(q);
	ep8_free(r);
	return code;
}

static int fixed8(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep8_t p, q, r, t[RLC_EPX_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep8_null(p);
	ep8_null(q);
	ep8_null(r);

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep8_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep8_new(p);
		ep8_new(q);
		ep8_new(r);

		ep8_curve_get_gen(p);
		ep8_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep8_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep8_rand(p);
			ep8_mul_pre(t, p);
			bn_zero(k);
			ep8_mul_fix(r, t, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_fix(r, t, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(q, p, k);
			ep8_mul_fix(q, t, k);
			ep8_mul(r, p, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_fix(r, t, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep8_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep8_new(t[i]);
		}
		TEST_CASE("binary fixed point multiplication is correct") {
			ep8_rand(p);
			ep8_mul_pre_basic(t, p);
			bn_zero(k);
			ep8_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_fix_basic(r, t, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(r, p, k);
			ep8_mul_fix_basic(q, t, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_fix_basic(r, t, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep8_free(t[i]);
		}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep8_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep8_rand(p);
			ep8_mul_pre_combs(t, p);
			bn_zero(k);
			ep8_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_fix_combs(r, t, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(r, p, k);
			ep8_mul_fix_combs(q, t, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_fix_combs(r, t, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBS; i++) {
			ep8_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep8_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep8_rand(p);
			ep8_mul_pre_combd(t, p);
			bn_zero(k);
			ep8_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_fix_combd(r, t, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(r, p, k);
			ep8_mul_fix_combd(q, t, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_fix_combd(r, t, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep8_free(t[i]);
		}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep8_new(t[i]);
		}
		TEST_CASE("left-to-right w-naf fixed point multiplication is correct") {
			ep8_rand(p);
			ep8_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ep8_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep8_is_infty(r), end);
			bn_set_dig(k, 1);
			ep8_mul_fix_lwnaf(r, t, k);
			TEST_ASSERT(ep8_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep8_mul(r, p, k);
			ep8_mul_fix_lwnaf(q, t, k);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep8_mul_fix_lwnaf(r, t, k);
			ep8_neg(r, r);
			TEST_ASSERT(ep8_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWNAF; i++) {
			ep8_free(t[i]);
		}
#endif
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(p);
	ep8_free(q);
	ep8_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous8(void) {
	int code = RLC_ERR;
	bn_t n, k[2];
	ep8_t p[2], r;

	bn_null(n);
	bn_null(k[0]);
	bn_null(k[1]);
	ep8_null(p[0]);
	ep8_null(p[1]);
	ep8_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k[0]);
		bn_new(k[1]);
		ep8_new(p[0]);
		ep8_new(p[1]);
		ep8_new(r);

		ep8_curve_get_gen(p[0]);
		ep8_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul(p[1], p[0], k[0]);
			ep8_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			ep8_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep8_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

#if EP_SIM == BASIC || !defined(STRIP)
		TEST_CASE("basic simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul(p[1], p[0], k[0]);
			ep8_mul_sim_basic(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim_basic(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
		TEST_CASE("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul(p[1], p[0], k[0]);
			ep8_mul_sim_trick(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim_trick(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
		TEST_CASE("interleaving for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul(p[1], p[0], k[0]);
			ep8_mul_sim_inter(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim_inter(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
		TEST_CASE("jsf for simultaneous multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul(p[1], p[0], k[0]);
			ep8_mul_sim_joint(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim_joint(r, p[0], k[0], p[1], k[1]);
			ep8_mul(p[0], p[0], k[0]);
			ep8_mul(p[1], p[1], k[1]);
			ep8_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep8_mul(p[1], p[0], k[1]);
			ep8_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep8_mul_gen(p[1], k[0]);
			ep8_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep8_mul_sim_gen(r, k[0], p[1], k[1]);
			ep8_curve_get_gen(p[0]);
			ep8_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep8_mul_sim_gen(r, k[0], p[1], k[1]);
			ep8_curve_get_gen(p[0]);
			ep8_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep8_mul_sim_gen(r, k[0], p[1], k[1]);
			ep8_curve_get_gen(p[0]);
			ep8_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep8_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k[0]);
	bn_free(k[1]);
	ep8_free(p[0]);
	ep8_free(p[1]);
	ep8_free(r);
	return code;
}

static int hashing8(void) {
	int code = RLC_ERR;
	bn_t n;
	ep8_t p;
	uint8_t msg[5];

	bn_null(n);
	ep8_null(p);

	RLC_TRY {
		bn_new(n);
		ep8_new(p);

		ep8_curve_get_ord(n);

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep8_map(p, msg, sizeof(msg));
			TEST_ASSERT(ep8_on_curve(p) == 1, end);
			ep8_mul(p, p, n);
			TEST_ASSERT(ep8_is_infty(p) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	ep8_free(p);
	return code;
}

static int frobenius8(void) {
	int code = RLC_ERR;
	ep8_t a, b, c;
	bn_t d, n;

	ep8_null(a);
	ep8_null(b);
	ep8_null(c);
	bn_null(d);
	bn_null(n);

	RLC_TRY {
		ep8_new(a);
		ep8_new(b);
		ep8_new(c);
		bn_new(d);
		bn_new(n);

		ep8_curve_get_ord(n);

		TEST_CASE("frobenius and point multiplication are consistent") {
			ep8_rand(a);
			ep8_frb(b, a, 1);
			d->used = RLC_FP_DIGS;
			dv_copy(d->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_mod(d, d, n);
			ep8_mul_basic(c, a, d);
			TEST_ASSERT(ep8_cmp(c, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep8_free(a);
	ep8_free(b);
	ep8_free(c);
	bn_free(d);
	bn_free(n);
	return code;
}

int main(void) {
	int r0, r1, r2, r3;

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

		if (memory2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (util2() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (addition2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (subtraction2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (doubling2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (frobenius2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (multiplication2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (fixed2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (simultaneous2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (compression2() != RLC_OK) {
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

		if (memory3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (util3() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (addition3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (subtraction3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (doubling3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (frobenius3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (multiplication3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (fixed3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (simultaneous3() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (hashing3() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r2 = ep4_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (memory4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (util4() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (addition4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (subtraction4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (doubling4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (frobenius4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (multiplication4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (fixed4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (simultaneous4() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (hashing4() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if ((r3 = ep8_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);

		if (memory8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (util8() != RLC_OK) {
			core_clean();
			return 1;
		}

		util_banner("Arithmetic:", 1);

		if (addition8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (subtraction8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (doubling8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (frobenius8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (multiplication8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (fixed8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (simultaneous8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (hashing8() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (!r0 && !r1 && !r2 && !r3) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
