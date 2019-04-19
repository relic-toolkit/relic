/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Tests for arithmetic on prime Edwards elliptic curves.
 *
 * @version $Id$
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

static int memory(void) {
	err_t e;
	int code = RLC_ERR;
	ed_t a;

	ed_null(a);

	TRY {
		TEST_BEGIN("memory can be allocated") {
			ed_new(a);
			ed_free(a);
		} TEST_END;
	} CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

int util(void) {
	int l, code = RLC_ERR;
	ed_t a, b, c;
	uint8_t bin[2 * RLC_FP_BYTES + 1];

	ed_null(a);
	ed_null(b);
	ed_null(c);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);

		TEST_BEGIN("copy and comparison are consistent") {
			ed_rand(a);
			ed_rand(b);
			ed_rand(c);
			/* Compare points in affine coordinates. */
			if (ed_cmp(a, c) != RLC_EQ) {
				ed_copy(c, a);
				TEST_ASSERT(ed_cmp(c, a) == RLC_EQ, end);
			}
			if (ed_cmp(b, c) != RLC_EQ) {
				ed_copy(c, b);
				TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ed_dbl(c, a);
			ed_norm(c, c);
			ed_dbl(a, a);
			TEST_ASSERT(ed_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ed_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ed_dbl(c, c);
			ed_dbl(a, a);
			TEST_ASSERT(ed_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ed_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("negation and comparison are consistent") {
			ed_rand(a);
			ed_neg(b, a);
			TEST_ASSERT(ed_cmp(a, b) != RLC_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("assignment to random and comparison are consistent") {
			ed_rand(a);
			ed_set_infty(c);
			TEST_ASSERT(ed_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ed_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("assignment to infinity and infinity test are consistent") {
			ed_set_infty(a);
			TEST_ASSERT(ed_is_infty(a), end);
		}
		TEST_END;

		TEST_BEGIN("validity test is correct") {
			ed_set_infty(a);
			TEST_ASSERT(ed_is_valid(a), end);
			ed_rand(a);
			TEST_ASSERT(ed_is_valid(a), end);
			fp_rand(a->x);
			TEST_ASSERT(!ed_is_valid(a), end);
		}
		TEST_END;

		TEST_BEGIN("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ed_set_infty(a);
				l = ed_size_bin(a, j);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == RLC_EQ, end);
				ed_rand(a);
				l = ed_size_bin(a, j);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == RLC_EQ, end);
				ed_rand(a);
				ed_dbl(a, a);
				l = ed_size_bin(a, j);
				ed_norm(a, a);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	return code;
}

int addition(void) {
	int code = RLC_ERR;
	ed_t a, b, c, d, e;

	ed_null(a);
	ed_null(b);
	ed_null(c);
	ed_null(d);
	ed_null(e);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);
		ed_new(d);
		ed_new(e);

		TEST_BEGIN("point addition is commutative") {
			ed_rand(a);
			ed_rand(b);
			ed_add(d, a, b);
			ed_add(e, b, a);
			TEST_ASSERT(ed_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition is associative") {
			ed_rand(a);
			ed_rand(b);
			ed_rand(c);
			ed_add(d, a, b);
			ed_add(d, d, c);
			ed_add(e, b, c);
			ed_add(e, e, a);
			TEST_ASSERT(ed_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition has identity") {
			ed_rand(a);
			ed_set_infty(d);
			ed_add(e, a, d);
			TEST_ASSERT(ed_cmp(e, a) == RLC_EQ, end);
			ed_add(e, d, a);
			TEST_ASSERT(ed_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition has inverse") {
			ed_rand(a);
			ed_neg(d, a);
			ed_add(e, a, d);
			TEST_ASSERT(ed_is_infty(e), end);
		} TEST_END;

#if ED_ADD == BASIC || !defined(STRIP)
		TEST_BEGIN("point addition in affine coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_add(d, a, b);
			ed_norm(d, d);
			ed_add_basic(e, a, b);
			TEST_ASSERT(ed_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_ADD == PROJC
		TEST_BEGIN("point addition in projective coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_add_projc(a, a, b);
			ed_rand(b);
			ed_rand(c);
			ed_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ed_add_projc(d, a, b);
			ed_norm(d, d);
			ed_print(d);
			ed_norm(a, a);
			ed_norm(b, b);
			printf("\n");
			ed_print(a);
			ed_print(b);
			printf("\n");
			ed_add_extnd(e, a, b);
			ed_norm(e, e);
			ed_print(e);
			TEST_ASSERT(ed_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#elif ED_ADD == EXTND
		TEST_BEGIN("point addition in extended coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_add_extnd(a, a, b);
			ed_rand(b);
			ed_rand(c);
			ed_add_extnd(b, b, c);
			/* a and b in projective coordinates. */
			ed_add_extnd(d, a, b);
			ed_norm(d, d);
			ed_norm(a, a);
			ed_norm(b, b);
			ed_add(e, a, b);
			ed_norm(e, e);
			TEST_ASSERT(ed_cmp(e, d) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	ed_free(d);
	ed_free(e);
	return code;
}

int subtraction(void) {
	int code = RLC_ERR;
	ed_t a, b, c, d;

	ed_null(a);
	ed_null(b);
	ed_null(c);
	ed_null(d);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);
		ed_new(d);

		TEST_BEGIN("point subtraction is anti-commutative") {
			ed_rand(a);
			ed_rand(b);
			ed_sub(c, a, b);
			ed_sub(d, b, a);
			ed_neg(d, d);
			TEST_ASSERT(ed_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("point subtraction has identity") {
			ed_rand(a);
			ed_set_infty(c);
			ed_sub(d, a, c);
			TEST_ASSERT(ed_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("point subtraction has inverse") {
			ed_rand(a);
			ed_sub(c, a, a);
			TEST_ASSERT(ed_is_infty(c), end);
		}
		TEST_END;

#if ED_ADD == BASIC || !defined(STRIP)
		TEST_BEGIN("point subtraction in affine coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_sub(c, a, b);
			ed_norm(c, c);
			ed_sub_basic(d, a, b);
			TEST_ASSERT(ed_cmp(c, d) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_ADD == PROJC
		TEST_BEGIN("point subtraction in projective coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_add_projc(a, a, b);
			ed_rand(b);
			ed_rand(c);
			ed_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ed_sub_projc(c, a, b);
			ed_norm(c, c);
			ed_norm(a, a);
			ed_norm(b, b);
			ed_sub(d, a, b);
			ed_norm(d, d);
			TEST_ASSERT(ed_cmp(c, d) == RLC_EQ, end);
		} TEST_END;
#elif ED_ADD == EXTND
		TEST_BEGIN("point subtraction in extended coordinates is correct") {
			ed_rand(a);
			ed_rand(b);
			ed_add_extnd(a, a, b);
			ed_rand(b);
			ed_rand(c);
			ed_add_extnd(b, b, c);
			/* a and b in projective coordinates. */
			ed_sub_extnd(c, a, b);
			ed_norm(c, c);
			ed_norm(a, a);
			ed_norm(b, b);
			ed_sub(d, a, b);
			ed_norm(d, d);
			TEST_ASSERT(ed_cmp(c, d) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	ed_free(d);
	return code;
}

int doubling(void) {
	int code = RLC_ERR;
	ed_t a, b, c;

	ed_null(a);
	ed_null(b);
	ed_null(c);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);

		TEST_BEGIN("point doubling is correct") {
			ed_rand(a);
			ed_add(b, a, a);
			ed_dbl(c, a);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if ED_ADD == BASIC || !defined(STRIP)
		TEST_BEGIN("point doubling in affine coordinates is correct") {
			ed_rand(a);
			ed_dbl(b, a);
			ed_norm(b, b);
			ed_dbl_basic(c, a);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_ADD == PROJC || !defined(STRIP)
		TEST_BEGIN("point doubling in projective coordinates is correct") {
			ed_rand(a);
			ed_dbl_projc(a, a);
			/* a in projective coordinates. */
			ed_dbl_projc(b, a);
			ed_norm(b, b);
			ed_norm(a, a);
			ed_dbl(c, a);
			ed_norm(c, c);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_BEGIN("point doubling in mixed coordinates (z1 = 1) is correct") {
			ed_rand(a);
			ed_dbl_projc(b, a);
			ed_norm(b, b);
			ed_dbl(c, a);
			ed_norm(c, c);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_ADD == EXTND || !defined(STRIP)
		TEST_BEGIN("point doubling in extended coordinates is correct") {
			ed_rand(a);
			ed_dbl_extnd(a, a);
			/* a in projective coordinates. */
			ed_dbl_extnd(b, a);
			ed_norm(b, b);
			ed_norm(a, a);
			ed_dbl(c, a);
			ed_norm(c, c);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_BEGIN("point extended in mixed coordinates (z1 = 1) is correct") {
			ed_rand(a);
			ed_dbl_extnd(b, a);
			ed_norm(b, b);
			ed_dbl(c, a);
			ed_norm(c, c);
			TEST_ASSERT(ed_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	return code;
}

static int multiplication(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ed_t p, q, r;

	bn_null(n);
	bn_null(k);
	ed_null(p);
	ed_null(q);
	ed_null(r);

	TRY {
		bn_new(n);
		bn_new(k);
		ed_new(p);
		ed_new(q);
		ed_new(r);

		ed_curve_get_gen(p);
		ed_curve_get_ord(n);

		TEST_BEGIN("generator has the right order") {
			TEST_ASSERT(ed_is_valid(p), end);
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r) == 1, end);
		} TEST_END;

		TEST_BEGIN("generator multiplication is correct") {
			bn_zero(k);
			ed_mul_gen(r, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_gen(r, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_gen(r, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_gen(r, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if ED_MUL == BASIC || !defined(STRIP)
		TEST_BEGIN("binary point multiplication is correct") {
			bn_zero(k);
			ed_mul_basic(r, p, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_basic(r, p, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			ed_rand(p);
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_basic(r, p, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_basic(r, p, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_MUL == MONTY || !defined(STRIP)
		TEST_BEGIN("sliding window point multiplication is correct") {
			bn_zero(k);
			ed_mul_slide(r, p, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_slide(r, p, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			ed_rand(p);
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_slide(r, p, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_slide(r, p, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if ED_MUL == MONTY || !defined(STRIP)
		TEST_BEGIN("montgomery laddering point multiplication is correct") {
			bn_zero(k);
			ed_mul_monty(r, p, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_monty(r, p, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			ed_rand(p);
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_monty(r, p, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_monty(r, p, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if ED_MUL == LWNAF || !defined(STRIP)
		TEST_BEGIN("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ed_mul_lwnaf(r, p, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_lwnaf(r, p, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			ed_rand(p);
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_lwnaf(r, p, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_lwnaf(r, p, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_BEGIN("multiplication by digit is correct") {
			ed_mul_dig(r, p, 0);
			TEST_ASSERT(ed_is_infty(r), end);
			ed_mul_dig(r, p, 1);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ed_mul(q, p, k);
			ed_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ed_free(p);
	ed_free(q);
	ed_free(r);
	return code;
}

static int fixed(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ed_t p, q, r, t[RLC_ED_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ed_null(p);
	ed_null(q);
	ed_null(r);

	for (int i = 0; i < RLC_ED_TABLE_MAX; i++) {
		ed_null(t[i]);
	}

	TRY {
		ed_new(p);
		ed_new(q);
		ed_new(r);
		bn_new(n);
		bn_new(k);

		ed_curve_get_gen(p);
		ed_curve_get_ord(n);

		for (int i = 0; i < RLC_ED_TABLE; i++) {
			ed_new(t[i]);
		}
		TEST_BEGIN("fixed point multiplication is correct") {
			ed_rand(p);
			ed_mul_pre(t, p);
			bn_zero(k);
			ed_mul_fix(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_fix(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(q, p, k);
			ed_mul_fix(q, (const ed_t *)t, k);
			ed_mul(r, p, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_fix(r, (const ed_t *)t, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_ED_TABLE; i++) {
			ed_free(t[i]);
		}

#if ED_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_ED_TABLE_BASIC; i++) {
			ed_new(t[i]);
		}
		TEST_BEGIN("binary fixed point multiplication is correct") {
			ed_rand(p);
			ed_mul_pre_basic(t, p);
			bn_zero(k);
			ed_mul_fix_basic(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_fix_basic(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(r, p, k);
			ed_mul_fix_basic(q, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_fix_basic(r, (const ed_t *)t, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_ED_TABLE_BASIC; i++) {
			ed_free(t[i]);
		}
#endif

#if ED_FIX == COMBS || !defined(STRIP)
		for (int i = 0; i < RLC_ED_TABLE_COMBS; i++) {
			ed_new(t[i]);
		}
		TEST_BEGIN("single-table comb fixed point multiplication is correct") {
			ed_rand(p);
			ed_mul_pre_combs(t, p);
			bn_zero(k);
			ed_mul_fix_combs(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_fix_combs(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(r, p, k);
			ed_mul_fix_combs(q, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_fix_combs(r, (const ed_t *)t, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_ED_TABLE_COMBS; i++) {
			ed_free(t[i]);
		}
#endif

#if ED_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_ED_TABLE_COMBD; i++) {
			ed_new(t[i]);
		}
		TEST_BEGIN("double-table comb fixed point multiplication is correct") {
			ed_rand(p);
			ed_mul_pre_combd(t, p);
			bn_zero(k);
			ed_mul_fix_combd(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_fix_combd(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(r, p, k);
			ed_mul_fix_combd(q, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_fix_combd(r, (const ed_t *)t, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_ED_TABLE_COMBD; i++) {
			ed_free(t[i]);
		}
#endif

#if ED_FIX == LWNAF || !defined(STRIP)
		for (int i = 0; i < RLC_ED_TABLE_LWNAF; i++) {
			ed_new(t[i]);
		}
		TEST_BEGIN("left-to-right w-naf fixed point multiplication is correct") {
			ed_rand(p);
			ed_mul_pre_lwnaf(t, p);
			bn_zero(k);
			ed_mul_fix_lwnaf(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_is_infty(r), end);
			bn_set_dig(k, 1);
			ed_mul_fix_lwnaf(r, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ed_mul(r, p, k);
			ed_mul_fix_lwnaf(q, (const ed_t *)t, k);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_fix_lwnaf(r, (const ed_t *)t, k);
			ed_neg(r, r);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_ED_TABLE_LWNAF; i++) {
			ed_free(t[i]);
		}
#endif
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(p);
	ed_free(q);
	ed_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous(void) {
	int code = RLC_ERR;
	bn_t n, k, l;
	ed_t p, q, r;

	bn_null(n);
	bn_null(k);
	bn_null(l);
	ed_null(p);
	ed_null(q);
	ed_null(r);

	TRY {
		bn_new(n);
		bn_new(k);
		bn_new(l);
		ed_new(p);
		ed_new(q);
		ed_new(r);

		ed_curve_get_gen(p);
		ed_curve_get_ord(n);

		TEST_BEGIN("simultaneous point multiplication is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul(q, p, k);
			ed_mul_sim(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if ED_SIM == BASIC || !defined(STRIP)
		TEST_BEGIN("basic simultaneous point multiplication is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim_basic(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul(q, p, k);
			ed_mul_sim_basic(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim_basic(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim_basic(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim_basic(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_SIM == TRICK || !defined(STRIP)
		TEST_BEGIN("shamir's trick for simultaneous multiplication is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim_trick(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul(q, p, k);
			ed_mul_sim_trick(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim_trick(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim_trick(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim_trick(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_SIM == INTER || !defined(STRIP)
		TEST_BEGIN("interleaving for simultaneous multiplication is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim_inter(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul(q, p, k);
			ed_mul_sim_inter(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim_inter(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim_inter(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim_inter(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if ED_SIM == JOINT || !defined(STRIP)
		TEST_BEGIN("jsf for simultaneous multiplication is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim_joint(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul(q, p, k);
			ed_mul_sim_joint(r, p, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim_joint(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim_joint(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim_joint(r, p, k, q, l);
			ed_mul(p, p, k);
			ed_mul(q, q, l);
			ed_add(q, q, p);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

		TEST_BEGIN("simultaneous multiplication with generator is correct") {
			bn_zero(k);
			bn_rand_mod(l, n);
			ed_mul(q, p, l);
			ed_mul_sim_gen(r, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_zero(l);
			ed_mul_gen(q, k);
			ed_mul_sim_gen(r, k, p, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			bn_rand_mod(l, n);
			ed_mul_sim_gen(r, k, q, l);
			ed_curve_get_gen(p);
			ed_mul_sim(q, p, k, q, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ed_mul_sim_gen(r, k, q, l);
			ed_curve_get_gen(p);
			ed_mul_sim(q, p, k, q, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
			bn_neg(l, l);
			ed_mul_sim_gen(r, k, q, l);
			ed_curve_get_gen(p);
			ed_mul_sim(q, p, k, q, l);
			TEST_ASSERT(ed_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	bn_free(l);
	ed_free(p);
	ed_free(q);
	ed_free(r);
	return code;
}

static int compression(void) {
	int code = RLC_ERR;
	ed_t a, b, c;

	ed_null(a);
	ed_null(b);
	ed_null(c);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);

		TEST_BEGIN("point compression is correct") {
			ed_rand(a);
			ed_pck(b, a);
			TEST_ASSERT(ed_upk(c, b) == 1, end);
			TEST_ASSERT(ed_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	return code;
}

static int hashing(void) {
	int code = RLC_ERR;
	ed_t a;
	bn_t n;
	uint8_t msg[5];

	ed_null(a);
	bn_null(n);

	TRY {
		ed_new(a);
		bn_new(n);

		ed_curve_get_ord(n);

		TEST_BEGIN("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ed_map(a, msg, sizeof(msg));
			ed_mul(a, a, n);
			TEST_ASSERT(ed_is_infty(a) == 1, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = RLC_OK;
  end:
	ed_free(a);
	bn_free(n);
	return code;
}

int test(void) {
	ed_param_print();

	util_banner("Utilities:", 1);

	if (memory() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (util() != RLC_OK) {
		return RLC_ERR;
	}

	util_banner("Arithmetic:", 1);

	if (addition() != RLC_OK) {
		return RLC_ERR;
	}

	if (subtraction() != RLC_OK) {
		return RLC_ERR;
	}

	if (doubling() != RLC_OK) {
		return RLC_ERR;
	}

	if (multiplication() != RLC_OK) {
		return RLC_ERR;
	}

	if (fixed() != RLC_OK) {
		return RLC_ERR;
	}

	if (simultaneous() != RLC_OK) {
		return RLC_ERR;
	}

	if (hashing() != RLC_OK) {
		return RLC_ERR;
	}

	if (compression() != RLC_OK) {
		return RLC_ERR;
	}

	return RLC_OK;
}

int main(void) {
	int r0 = RLC_ERR, r1 = RLC_ERR, r2 = RLC_ERR, r3 = RLC_ERR;

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the ED module:", 0);

	if (r0 == RLC_ERR && r1 == RLC_ERR && r2 == RLC_ERR && r3 == RLC_ERR) {
		if (ed_param_set_any() == RLC_ERR) {
			THROW(ERR_NO_CURVE);
			core_clean();
			return 0;
		} else {
			if (test() != RLC_OK) {
				core_clean();
				return 1;
			}
		}
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
