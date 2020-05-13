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
			bn_add(u, tri[0]->c, tri[1]->c);
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

static int pairing(void) {
	int j, code = RLC_ERR;
	g1_t d[2], p[2];
	g2_t e[2], q[2];
	gt_t e1, e2, r[2];
	bn_t k, n;
	pt_t t[2];

	gt_null(e1);
	gt_null(e2);
	bn_null(k);
	bn_null(n);

	TRY {
		gt_new(e1);
		gt_new(e2);
		bn_new(k);
		bn_new(n);

		for (j = 0; j < 2; j++) {
			g1_null(d[j]);
			g2_null(e[j]);
			g1_null(p[j]);
			g2_null(q[j]);
			gt_null(r[j]);
			pt_null(t[j]);
			pt_null(t[j]);
			g1_new(d[j]);
			g2_new(e[j]);
			g1_new(p[j]);
			g2_new(q[j]);
			gt_new(r[j]);
			pt_new(t[j]);
		}

		g1_get_ord(n);

		TEST_BEGIN("pairing triples are consistent") {
			pc_map_tri(t);
			g1_add(t[0]->a, t[0]->a, t[1]->a);
			g1_norm(t[0]->a, t[0]->a);
			g2_add(t[0]->b, t[0]->b, t[1]->b);
			g2_norm(t[0]->b, t[0]->b);
			gt_mul(t[1]->c, t[0]->c, t[1]->c);
			pc_map(t[0]->c, t[0]->a, t[0]->b);
			TEST_ASSERT(gt_cmp(t[0]->c, t[1]->c) == RLC_EQ, end);
			/* Regenerate triple. */
			pc_map_tri(t);
			/* Generate random inputs. */
			g1_rand(p[0]);
			g2_rand(q[0]);
			pc_map(e1, p[0], q[0]);
			/* Secret share inputs. */
			g1_rand(p[1]);
			g1_sub(p[0], p[0], p[1]);
			g1_norm(p[0], p[0]);
			g2_rand(q[1]);
			g2_sub(q[0], q[0], q[1]);
			g2_norm(q[0], q[0]);
			/* Compute public values locally. */
			pc_map_lcl(d[0], e[0], p[0], q[0], t[0]);
			pc_map_lcl(d[1], e[1], p[1], q[1], t[1]);
			/* Broadcast public values. */
			pc_map_bct(d, e);
			TEST_ASSERT(g1_cmp(d[0], d[1]) == RLC_EQ, end);
			TEST_ASSERT(g2_cmp(e[0], e[1]) == RLC_EQ, end);
			pc_map_mpc(r[0], p[0], q[0], t[0], d[0], e[0], 0);
			pc_map_mpc(r[1], p[1], q[1], t[1], d[1], e[1], 1);
			gt_mul(e2, r[0], r[1]);
			TEST_ASSERT(gt_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	CATCH_ANY {
		util_print("FATAL ERROR!\n");
		ERROR(end);
	}
	code = RLC_OK;
  end:
	gt_free(e1);
	gt_free(e2);
	bn_free(k);
	bn_free(n);
	for (j = 0; j < 2; j++) {
		g1_free(d[j]);
		g2_free(e[j]);
		g1_free(p[j]);
		g2_free(q[j]);
		gt_free(r[j]);
		pt_free(t[j]);
	}
	return code;
}

int main(void) {

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the MPC module:\n", 0);
	util_banner("Utilities:", 1);

#if defined(WITH_BN)
	if (triple()) {
		core_clean();
		return 1;
	}
#endif

#if defined(WITH_PC)
	if (pc_param_set_any() != RLC_OK) {
		THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	pc_param_print();

	util_banner("Arithmetic:", 1);

	if (pairing()) {
		core_clean();
		return 1;
	}
#endif

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
