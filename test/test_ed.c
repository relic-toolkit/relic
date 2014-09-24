/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2014 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
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
	int code = STS_ERR;
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
	code = STS_OK;
  end:
	return code;
}

int addition(void) {
	int code = STS_ERR;
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

		TEST_BEGIN("base point is valid point on the curve") {
			ed_curve_get_gen(a);
			TEST_ASSERT(ed_is_valid(a) != 0, end);
		} TEST_END;

		TEST_BEGIN("identity element is a valid point on the curve") {
			ed_set_infty(a);
			TEST_ASSERT(ed_is_valid(a) != 0, end);
		} TEST_END;

		TEST_BEGIN("random generated point is on curve") {
			ed_null(a);
			ed_rand(a);
			TEST_ASSERT(ed_is_valid(a) != 0, end);
		} TEST_END;

		TEST_BEGIN("point addition is commutative") {
			ed_rand(a);
			ed_rand(b);
			ed_add(d, a, b);
			ed_add(e, b, a);
			ed_norm(d, d);
			ed_norm(e, e);
			TEST_ASSERT(ed_cmp(d, e) == CMP_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition is associative") {
			ed_rand(a);
			ed_rand(b);
			ed_rand(c);
			ed_add(d, a, b);
			ed_add(d, d, c);
			ed_add(e, b, c);
			ed_add(e, e, a);
			ed_norm(d, d);
			ed_norm(e, e);
			TEST_ASSERT(ed_cmp(d, e) == CMP_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition has identity") {
			ed_rand(a);
			ed_set_infty(d);
			ed_add(e, a, d);
			TEST_ASSERT(ed_cmp(e, a) == CMP_EQ, end);
			ed_add(e, d, a);
			TEST_ASSERT(ed_cmp(e, a) == CMP_EQ, end);
		} TEST_END;

		TEST_BEGIN("double negation works") {
			ed_rand(a);
			ed_neg(b, a);
			ed_neg(b, b);
			TEST_ASSERT(ed_cmp(a, b) == CMP_EQ, end);
		} TEST_END;

		TEST_BEGIN("point addition has inverse") {
			ed_rand(a);
			ed_neg(d, a);
			ed_add(e, a, d);
			ed_set_infty(b);
			TEST_ASSERT(ed_is_infty(e), end);
		} TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = STS_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	ed_free(d);
	ed_free(e);
	return code;
}

int util(void) {
	int code = STS_ERR;
	ed_t a, b, c;

	ed_null(a);
	ed_null(b);
	ed_null(c);

	TRY {
		ed_new(a);
		ed_new(b);
		ed_new(c);

		TEST_BEGIN("negation and comparison are consistent") {
			ed_rand(a);
			ed_neg(b, a);
			TEST_ASSERT(ed_cmp(a, b) != CMP_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("assignment to random and comparison are consistent") {
			ed_rand(a);
			ed_set_infty(c);
			TEST_ASSERT(ed_cmp(a, c) != CMP_EQ, end);
			TEST_ASSERT(ed_cmp(c, a) != CMP_EQ, end);
		}
		TEST_END;

		TEST_BEGIN("assignment to infinity and infinity test are consistent") {
			ed_set_infty(a);
			TEST_ASSERT(ed_is_infty(a), end);
		}
		TEST_END;

		TEST_BEGIN("validity test is correct") {
			ed_rand(a);
			TEST_ASSERT(ed_is_valid(a), end);
			fp_rand(a->x);
			TEST_ASSERT(!ed_is_valid(a), end);
		}
		TEST_END;

		/*
		TEST_BEGIN("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ed_set_infty(a);
				l = ed_size_bin(a, j);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == CMP_EQ, end);
				ed_rand(a);
				l = ed_size_bin(a, j);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == CMP_EQ, end);
				ed_rand(a);
				ed_dbl(a, a);
				l = ed_size_bin(a, j);
				ed_norm(a, a);
				ed_write_bin(bin, l, a, j);
				ed_read_bin(b, bin, l);
				TEST_ASSERT(ed_cmp(a, b) == CMP_EQ, end);
			}
		}
		TEST_END;*/
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = STS_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	return code;
}

int doubling(void) {
	int code = STS_ERR;
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
			ed_norm(b, b);
			ed_dbl(c, a);
			ed_norm(c, c);
			TEST_ASSERT(ed_cmp(b, c) == CMP_EQ, end);
		} TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = STS_OK;
  end:
	ed_free(a);
	ed_free(b);
	ed_free(c);
	return code;
}

static int multiplication(void) {
	int code = STS_ERR;
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
			ed_mul(r, p, n);
			TEST_ASSERT(ed_is_infty(r) == 1, end);
		} TEST_END;

		TEST_BEGIN("generator multiplication is correct") {
			bn_rand(k, BN_POS, bn_bits(n));
			bn_mod(k, k, n);
			ed_mul(q, p, k);
			ed_mul_gen(r, k);
			TEST_ASSERT(ed_cmp(q, r) == CMP_EQ, end);
		} TEST_END;

		TEST_BEGIN("multiplication by digit is correct") {
			bn_rand(k, BN_POS, BN_DIGIT);
			ed_mul(q, p, k);
			ed_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ed_cmp(q, r) == CMP_EQ, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = STS_OK;
  end:
	bn_free(n);
	bn_free(k);
	ed_free(p);
	ed_free(q);
	ed_free(r);
	return code;
}
#if 0
static int compression(void) {
	int code = STS_ERR;
	ep_t a, b, c;

	ep_null(a);
	ep_null(b);
	ep_null(c);

	TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);

		TEST_BEGIN("point compression is correct") {
			ep_rand(a);
			ep_pck(b, a);
			TEST_ASSERT(ep_upk(c, b) == 1, end);
			TEST_ASSERT(ep_cmp(a, c) == CMP_EQ, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = STS_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	return code;
}

static int hashing(void) {
	int code = STS_ERR;
	ep_t a;
	bn_t n;
	uint8_t msg[5];

	ep_null(a);
	bn_null(n);

	TRY {
		ep_new(a);
		bn_new(n);

		ep_curve_get_ord(n);

		TEST_BEGIN("point hashing is correct") {
			rand_bytes(msg, sizeof(msg));
			ep_map(a, msg, sizeof(msg));
			ep_mul(a, a, n);
			TEST_ASSERT(ep_is_infty(a) == 1, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = STS_OK;
  end:
	ep_free(a);
	bn_free(n);
	return code;
}
#endif

int test_x_coordinate_recovery() {
	int code = STS_ERR;
	fp_t y;
	fp_t x;
	fp_t d;
	fp_t expected_x;

	fp_null(y);
	fp_null(x);
	fp_null(d);
	fp_null(expected_x);

	TRY {
		fp_new(y);
		fp_new(x);
		fp_new(d);
		fp_new(expected_x);

		TEST_BEGIN("x coordinate recovery is working") {
			fp_read_str(expected_x, "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", sizeof("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a") - 1, 16);
			fp_read_str(y, "6666666666666666666666666666666666666666666666666666666666666658", sizeof("6666666666666666666666666666666666666666666666666666666666666658") - 1, 16);
			fp_read_str(d, "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", sizeof("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3") - 1, 16);

			ed_recover_x(x, y, d);

			TEST_ASSERT(fp_cmp(expected_x, x) == CMP_EQ, end);
		}
		TEST_END;
	}
	CATCH_ANY {
		ERROR(end);
	}
	code = STS_OK;
  end:
  	// free stuff
  	fp_free(expected_x);
  	fp_free(d);
  	fp_free(x);
  	fp_free(y);
	return code;
}

int test(void) {
	ed_param_print();

	util_banner("Memory:", 1);
	if (memory() != STS_OK) {
		core_clean();
		return 1;
	}

	if (test_x_coordinate_recovery() != STS_OK) {
		return STS_ERR;
	}

	util_banner("Arithmetic:", 1);

	if (addition() != STS_OK) {
		return STS_ERR;
	}

	util_banner("Utilities:", 1);
	if (util() != STS_OK) {
		return STS_ERR;
	}

	util_banner("Doubling:", 1);
	if (doubling() != STS_OK) {
		return STS_ERR;
	}

	util_banner("Multiplication:", 1);
	if (multiplication() != STS_OK) {
		return STS_ERR;
	}

	#if 0
		if (fixed() != STS_OK) {
			return STS_ERR;
		}

		if (simultaneous() != STS_OK) {
			return STS_ERR;
		}

		if (compression() != STS_OK) {
			return STS_ERR;
		}

		if (hashing() != STS_OK) {
			return STS_ERR;
		}
	#endif

	return STS_OK;
}

int main(void) {
	int r0 = STS_ERR, r1 = STS_ERR, r2 = STS_ERR, r3 = STS_ERR;

	if (core_init() != STS_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the ED module:", 0);

	if (r0 == STS_ERR && r1 == STS_ERR && r2 == STS_ERR && r3 == STS_ERR) {
		if (ed_param_set_any() == STS_ERR) {
			THROW(ERR_NO_CURVE);
			core_clean();
			return 0;
		} else {
			if (test() != STS_OK) {
				core_clean();
				return 1;
			}
		}
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
