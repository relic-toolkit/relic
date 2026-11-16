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
 * Tests for the Residue Number System module.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"
#include "relic_rns_low.h"

/* Room of the contexts in the tests, in bits. */
#define ROOM	16

/* Sizes of the moduli in the tests, in bits. */
static const int sizes[] = { 128, 256, 1024, BN_PRECI };

static int memory(void) {
	int code = RLC_ERR;
	rns_t c;

	RLC_TRY {
		TEST_CASE("contexts can be allocated") {
			rns_new(c, RLC_RNS_SIZE(256, ROOM), RLC_CEIL(256, RLC_DIG));
			TEST_ASSERT(err_get_code() == RLC_OK, end);
			rns_free(c);
		} TEST_END;

		TEST_CASE("sizes beyond the limits are rejected") {
			TEST_ERR(rns_new(c, RLC_RNS_MAX + 1, 1));
			TEST_ASSERT(err_get_code() == RLC_ERR, end);
			TEST_ERR(rns_new(c, 1, RLC_BN_DIGS + 1));
			TEST_ASSERT(err_get_code() == RLC_ERR, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	return code;
}

static int arith(int bits) {
	int code = RLC_ERR;
	const size_t d = RLC_CEIL(bits, RLC_DIG);
	rns_t c;
	bn_t a, b, e, m, n;
	dig_t *x = NULL, *y = NULL, *z = NULL, v[RLC_BN_DIGS], w[RLC_BN_DIGS];

	bn_null_all(a, b, e, m, n);
	c->mem = NULL;

	RLC_TRY {
		bn_new_all(a, b, e, m, n);

		/* A random odd modulus of the given size. */
		bn_rand(n, RLC_POS, bits);
		bn_set_bit(n, bits - 1, 1);
		bn_set_bit(n, 0, 1);
		rns_new(c, RLC_RNS_SIZE(bits, ROOM), d);
		x = RLC_ALLOCA(dig_t, 2 * c->o);
		y = RLC_ALLOCA(dig_t, 2 * c->o);
		z = RLC_ALLOCA(dig_t, 2 * c->o);
		if (x == NULL || y == NULL || z == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		util_print("(%d-bit modulus, %d moduli per base)\n", bits, (int)c->n);

		TEST_CASE("precomputation is consistent") {
			rns_pre(c, n, ROOM);
			TEST_ASSERT(err_get_code() == RLC_OK, end);
			/* The moduli of both bases are odd and distinct. */
			for (size_t k = 1; k < c->n; k++) {
				TEST_ASSERT(c->m[k] & 1 && c->m[k] != c->m[k - 1], end);
				TEST_ASSERT(c->m[c->o + k] != c->m[c->o + k - 1], end);
			}
		} TEST_END;

		TEST_CASE("exact conversion is consistent") {
			bn_rand(a, RLC_POS, bits + ROOM);
			rns_conv(x, a, c);
			rns_back(b, x, c);
			TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
			bn_neg(a, a);
			rns_conv(x, a, c);
			rns_back(b, x, c);
			TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("positional conversion is correct") {
			bn_rand_mod(a, n);
			bn_write_raw(v, d, a);
			rns_set(x, v, c);
			rns_get(w, x, c);
			TEST_ASSERT(dv_cmp(v, w, d) == RLC_EQ, end);
			/* Zero and N - 1. */
			dv_zero(v, d);
			rns_set(x, v, c);
			rns_get(w, x, c);
			TEST_ASSERT(dv_cmp(v, w, d) == RLC_EQ, end);
			bn_sub_dig(a, n, 1);
			bn_write_raw(v, d, a);
			rns_set(x, v, c);
			rns_get(w, x, c);
			TEST_ASSERT(dv_cmp(v, w, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("integer conversion is correct") {
			/* Any sign and size, reduced modulo N on the way in. */
			bn_rand(a, RLC_NEG, 2 * bits);
			rns_set_bn(x, a, c);
			rns_get_bn(b, x, c);
			bn_mod(e, a, n);
			TEST_ASSERT(bn_cmp(b, e) == RLC_EQ, end);
			bn_rand_mod(a, n);
			rns_set_bn(x, a, c);
			rns_get_bn(b, x, c);
			TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("montgomery multiplication is correct") {
			bn_rand_mod(a, n);
			bn_rand_mod(b, n);
			bn_write_raw(v, d, a);
			rns_set(x, v, c);
			bn_write_raw(v, d, b);
			rns_set(y, v, c);
			rns_mulm_low(z, x, y, c);
			rns_get(w, z, c);
			bn_read_raw(e, w, d);
			bn_mul(m, a, b);
			bn_mod(m, m, n);
			TEST_ASSERT(bn_cmp(e, m) == RLC_EQ, end);
			/* Products of products stay within the bounds. */
			rns_mulm_low(z, z, z, c);
			rns_get(w, z, c);
			bn_read_raw(e, w, d);
			bn_sqr(m, m);
			bn_mod(m, m, n);
			TEST_ASSERT(bn_cmp(e, m) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("zero test is correct") {
			dv_zero(v, d);
			rns_set(x, v, c);
			TEST_ASSERT(rns_is_zero(x, c) == 1, end);
			/* N itself is zero modulo N. */
			bn_write_raw(v, d, n);
			rns_set(x, v, c);
			TEST_ASSERT(rns_is_zero(x, c) == 1, end);
			do {
				bn_rand_mod(a, n);
			} while (bn_is_zero(a));
			bn_write_raw(v, d, a);
			rns_set(x, v, c);
			TEST_ASSERT(rns_is_zero(x, c) == 0, end);
			/* A product with zero is zero. */
			dv_zero(v, d);
			rns_set(y, v, c);
			rns_mulm_low(z, x, y, c);
			TEST_ASSERT(rns_is_zero(z, c) == 1, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	RLC_FREE(x);
	RLC_FREE(y);
	RLC_FREE(z);
	rns_free(c);
	bn_free_all(a, b, e, m, n);
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the RNS module:\n", 0);

	if (RLC_WSIZE < 32) {
		util_banner("The module needs digits of at least 32 bits.\n", 0);
		core_clean();
		return 0;
	}

	if (memory() != RLC_OK) {
		core_clean();
		return 1;
	}

	for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
		if (sizes[k] <= BN_PRECI && arith(sizes[k]) != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
