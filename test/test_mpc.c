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
 * Tests for the error-management routines.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_err.h"
#include "relic_test.h"

static int triple(void) {
	int code = RLC_ERR;
	bn_t n, t, u;
	mt_t tri[2];

	bn_null(n);
	bn_null(t);
	bn_null(u);
	mt_null(tri[0]);
	mt_null(tri[1]);

	TRY {
		bn_new(n);
		bn_new(t);
		bn_new(u);
		mt_new(tri[0]);
		mt_new(tri[1]);

		bn_gen_prime(n, RLC_BN_BITS);

		TEST_BEGIN("multiplication triples are generated correctly") {
			mt_gen(tri, n);
			bn_add(t, tri[0]->a, tri[1]->a);
			bn_mod(t, t, n);
			bn_add(u, tri[0]->b, tri[1]->b);
			bn_mod(u, u, n);
			bn_mul(t, t, u);
			bn_mod(t, t, n);
			bn_mul(u, tri[0]->c, tri[1]->c);
			bn_mod(u, u, n);
			TEST_ASSERT(bn_cmp(t, u) == RLC_EQ, end);
		} TEST_END;
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		bn_free(t);
		bn_free(u);
		mt_free(tri[0]);
		mt_free(tri[1]);
	}

	code = RLC_OK;
  end:
	return code;
}

int main(void) {

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the MPC module:\n", 0);

	if (triple()) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
