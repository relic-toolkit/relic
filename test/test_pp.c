/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Tests for pairings defined over prime elliptic curves.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"
#include "relic_bench.h"

static int addition1(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p, q, r, s;
	fp_t e1, e2, e3;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep_null(q);
	ep_null(r);
	ep_null(s);
	fp_null(e1);
	fp_null(e2);
	fp_null(e3);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep_new(q);
		ep_new(r);
		ep_new(s);
		fp_new(e1);
		fp_new(e2);
		fp_new(e3);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			pp_add_k1(e1, e2, r, q, p);
			pp_norm_k1(r, r);
			ep_add(s, s, q);
			ep_norm(s, s);
			TEST_ASSERT(ep_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp_zero(e1);
			fp_zero(e2);
			pp_add_k1(e1, e2, r, q, p);
			fp_inv(e2, e2);
			fp_mul(e1, e1, e2);
			pp_add_k1_basic(e2, e3, s, q, p);
			fp_inv(e3, e3);
			fp_mul(e2, e2, e3);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp_zero(e1);
			fp_zero(e2);
			pp_add_k1(e1, e2, r, q, p);
			fp_inv(e2, e2);
			fp_mul(e1, e1, e2);
			pp_exp_k1(e1, e1);
			pp_add_k1_projc(e2, e3, s, q, p);
			fp_inv(e3, e3);
			fp_mul(e2, e2, e3);
			pp_exp_k1(e2, e2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep_free(q);
	ep_free(r);
	ep_free(s);
	fp_free(e1);
	fp_free(e2);
	fp_free(e3);
	return code;
}

static int doubling1(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p, q, r, s;
	fp_t e1, e2, e3;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep_null(q);
	ep_null(r);
	ep_null(s);
	fp_null(e1);
	fp_null(e2);
	fp_null(e3);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep_new(q);
		ep_new(r);
		ep_new(s);
		fp_new(e1);
		fp_new(e2);
		fp_new(e3);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp_sqr(e3, q->z);
			pp_dbl_k1(e1, e2, r, e3, q, e3, p);
			pp_norm_k1(r, r);
			ep_dbl(s, q);
			ep_norm(s, s);
			TEST_ASSERT(ep_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp_zero(e1);
			fp_zero(e2);
			fp_sqr(e3, q->z);
			pp_dbl_k1(e1, e2, r, e3, q, e3, p);
			fp_inv(e2, e2);
			fp_mul(e1, e1, e2);
			pp_exp_k1(e1, e1);
			pp_dbl_k1_basic(e2, e3, r, q, p);
			fp_inv(e3, e3);
			fp_mul(e2, e2, e3);
			pp_exp_k1(e2, e2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp_zero(e1);
			fp_zero(e2);
			fp_sqr(e3, q->z);
			pp_dbl_k1(e1, e2, r, e3, q, e3, p);
			fp_inv(e2, e2);
			fp_mul(e1, e1, e2);			
			pp_exp_k1(e1, e1);
			fp_set_dig(e3, 1);
			pp_dbl_k1_projc(e2, e3, r, e3, q, e3, p);
			fp_inv(e3, e3);
			fp_mul(e2, e2, e3);
			pp_exp_k1(e2, e2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep_free(q);
	ep_free(r);
	ep_free(s);
	fp_free(e1);
	fp_free(e2);
	fp_free(e3);
	return code;
}

static int pairing1(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2], q[2], r;
	fp_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(r);
	fp_null(e1);
	fp_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(r);
		fp_new(e1);
		fp_new(e2);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep_null(q[j]);
			ep_new(p[j]);
			ep_new(q[j]);
		}

		ep_curve_get_ord(n);
		TEST_CASE("final exponentiation is correct") {
			fp_rand(e1);
			pp_exp_k1(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			fp_exp(e2, e1, n);
			TEST_ASSERT(fp_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			/* Self-pairings are non-trivial and bilinear with the distortion map. */
			ep_rand(p[0]);
			pp_map_k1(e1, p[0], p[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_dbl(q[0], p[0]);
			ep_norm(q[0], q[0]);
			pp_map_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_k1(e1, p[0], r);
			pp_map_k1(e2, p[0], q[0]);
			fp_exp(e2, e2, k);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k1(e2, p[0], q[0]);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

        TEST_CASE("multi-pairing is correct") {
            ep_rand(p[i % 2]);
            ep_rand(q[i % 2]);
            pp_map_k1(e1, p[i % 2], q[i % 2]);
            ep_rand(p[1 - (i % 2)]);
            ep_set_infty(q[1 - (i % 2)]);
            pp_map_sim_k1(e2, p, q, 2);
            TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
            ep_set_infty(p[1 - (i % 2)]);
            ep_rand(q[1 - (i % 2)]);
            pp_map_sim_k1(e2, p, q, 2);
            TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
            ep_set_infty(q[i % 2]);
            pp_map_sim_k1(e2, p, q, 2);
            TEST_ASSERT(fp_cmp_dig(e2, 1) == RLC_EQ, end);
            ep_rand(p[0]);
            ep_rand(q[0]);
            pp_map_k1(e1, p[0], q[0]);
            ep_rand(p[1]);
            ep_rand(q[1]);
            pp_map_k1(e2, p[1], q[1]);
            fp_mul(e1, e1, e2);
            pp_map_sim_k1(e2, p, q, 2);
            TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
        } TEST_END;

		TEST_CASE("tate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_tatep_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_tatep_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_tatep_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			/* Self-pairings are non-trivial and bilinear with the distortion map. */
			ep_rand(p[0]);
			pp_map_tatep_k1(e1, p[0], p[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_dbl(q[0], p[0]);
			ep_norm(q[0], q[0]);
			pp_map_tatep_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_tatep_k1(e1, p[0], r);
			pp_map_tatep_k1(e2, p[0], q[0]);
			fp_exp(e2, e2, k);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_tatep_k1(e2, p[0], q[0]);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_tatep_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_tatep_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep_rand(q[i % 2]);
			pp_map_tatep_k1(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep_set_infty(q[1 - (i % 2)]);
			pp_map_sim_tatep_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep_rand(q[1 - (i % 2)]);
			pp_map_sim_tatep_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(q[i % 2]);
			pp_map_sim_tatep_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_tatep_k1(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep_rand(q[1]);
			pp_map_tatep_k1(e2, p[1], q[1]);
			fp_mul(e1, e1, e2);
			pp_map_sim_tatep_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing non-degeneracy is correct") {
			ep_set_infty(p[0]);
			ep_rand(q[0]);
			pp_map_weilp_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_weilp_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_weilp_k1(e1, p[0], q[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			/* Self-pairings are non-trivial and bilinear with the distortion map. */
			ep_rand(p[0]);
			pp_map_weilp_k1(e1, p[0], p[0]);
			TEST_ASSERT(fp_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_dbl(q[0], p[0]);
			ep_norm(q[0], q[0]);
			pp_map_weilp_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_weilp_k1(e1, p[0], r);
			pp_map_weilp_k1(e2, p[0], q[0]);
			fp_exp(e2, e2, k);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_weilp_k1(e2, p[0], q[0]);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_weilp_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_weilp_k1(e2, p[0], q[0]);
			fp_sqr(e1, e1);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep_rand(q[i % 2]);
			pp_map_weilp_k1(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep_set_infty(q[1 - (i % 2)]);
			pp_map_sim_weilp_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep_rand(q[1 - (i % 2)]);
			pp_map_sim_weilp_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(q[i % 2]);
			pp_map_sim_weilp_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_weilp_k1(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep_rand(q[1]);
			pp_map_weilp_k1(e2, p[1], q[1]);
			fp_mul(e1, e1, e2);
			pp_map_sim_weilp_k1(e2, p, q, 2);
			TEST_ASSERT(fp_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(r);
	fp_free(e1);
	fp_free(e2);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep_free(q[j]);
	}

    return code;
}

static int addition2(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p, q, r, s;
	fp2_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep_null(q);
	ep_null(r);
	ep_null(s);
	fp2_null(e1);
	fp2_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep_new(q);
		ep_new(r);
		ep_new(s);
		fp2_new(e1);
		fp2_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			pp_add_k2(e1, r, q, p);
			pp_norm_k2(r, r);
			ep_add(s, s, q);
			ep_norm(s, s);
			TEST_ASSERT(ep_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_add_k2(e1, r, q, p);
			pp_exp_k2(e1, e1);
			pp_add_k2_basic(e2, s, q, p);
			pp_exp_k2(e2, e2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_add_k2(e1, r, q, p);
			pp_exp_k2(e1, e1);
			pp_add_k2_projc(e2, s, q, p);
			pp_exp_k2(e2, e2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller addition is consistent") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_add_k2_projc(e1, r, q, p);
			pp_add_k2_projc_basic(e2, s, q, p);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller addition is consistent") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			ep_copy(s, r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_add_k2_projc(e1, r, q, p);
			pp_add_k2_projc_lazyr(e2, s, q, p);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep_free(q);
	ep_free(r);
	ep_free(s);
	fp2_free(e1);
	fp2_free(e2);
	return code;
}

static int doubling2(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p, q, r, s;
	fp2_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep_null(q);
	ep_null(r);
	ep_null(s);
	fp2_null(e1);
	fp2_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep_new(q);
		ep_new(r);
		ep_new(s);
		fp2_new(e1);
		fp2_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			pp_dbl_k2(e1, r, q, p);
			pp_norm_k2(r, r);
			ep_dbl(s, q);
			ep_norm(s, s);
			TEST_ASSERT(ep_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_dbl_k2(e1, r, q, p);
			pp_exp_k2(e1, e1);
			pp_dbl_k2_basic(e2, r, q, p);
			pp_exp_k2(e2, e2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_dbl_k2(e1, r, q, p);
			pp_exp_k2(e1, e1);
			pp_dbl_k2_projc(e2, r, q, p);
			pp_exp_k2(e2, e2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller doubling is correct") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_dbl_k2_projc(e1, r, q, p);
			pp_dbl_k2_projc_basic(e2, r, q, p);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller doubling is consistent") {
			ep_rand(p);
			ep_rand(q);
			ep_rand(r);
			fp2_zero(e1);
			fp2_zero(e2);
			pp_dbl_k2_projc(e1, r, q, p);
			pp_dbl_k2_projc_lazyr(e2, r, q, p);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep_free(q);
	ep_free(r);
	ep_free(s);
	fp2_free(e1);
	fp2_free(e2);
	return code;
}

static int pairing2(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2], q[2], r;
	fp2_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(r);
	fp2_null(e1);
	fp2_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(r);
		fp2_new(e1);
		fp2_new(e2);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep_null(q[j]);
			ep_new(p[j]);
			ep_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp2_rand(e1);
			pp_exp_k2(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp2_cmp_dig(e1, 1) != RLC_EQ, end);
			fp2_exp(e2, e1, n);
			TEST_ASSERT(fp2_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_k2(e1, p[0], r);
			pp_map_k2(e2, p[0], q[0]);
			fp2_exp(e2, e2, k);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k2(e2, p[0], q[0]);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

        TEST_CASE("multi-pairing is correct") {
            ep_rand(p[i % 2]);
            ep_rand(q[i % 2]);
            pp_map_k2(e1, p[i % 2], q[i % 2]);
            ep_rand(p[1 - (i % 2)]);
            ep_set_infty(q[1 - (i % 2)]);
            pp_map_sim_k2(e2, p, q, 2);
            TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
            ep_set_infty(p[1 - (i % 2)]);
            ep_rand(q[1 - (i % 2)]);
            pp_map_sim_k2(e2, p, q, 2);
            TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
            ep_set_infty(q[i % 2]);
            pp_map_sim_k2(e2, p, q, 2);
            TEST_ASSERT(fp2_cmp_dig(e2, 1) == RLC_EQ, end);
            ep_rand(p[0]);
            ep_rand(q[0]);
            pp_map_k2(e1, p[0], q[0]);
            ep_rand(p[1]);
            ep_rand(q[1]);
            pp_map_k2(e2, p[1], q[1]);
            fp2_mul(e1, e1, e2);
            pp_map_sim_k2(e2, p, q, 2);
            TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
        } TEST_END;

		TEST_CASE("tate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_tatep_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_tatep_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_tatep_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_tatep_k2(e1, p[0], r);
			pp_map_tatep_k2(e2, p[0], q[0]);
			fp2_exp(e2, e2, k);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_tatep_k2(e2, p[0], q[0]);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_tatep_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_tatep_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep_rand(q[i % 2]);
			pp_map_tatep_k2(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep_set_infty(q[1 - (i % 2)]);
			pp_map_sim_tatep_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep_rand(q[1 - (i % 2)]);
			pp_map_sim_tatep_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(q[i % 2]);
			pp_map_sim_tatep_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_tatep_k2(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep_rand(q[1]);
			pp_map_tatep_k2(e2, p[1], q[1]);
			fp2_mul(e1, e1, e2);
			pp_map_sim_tatep_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_weilp_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_weilp_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_set_infty(q[0]);
			pp_map_weilp_k2(e1, p[0], q[0]);
			TEST_ASSERT(fp2_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing is bilinear") {
			ep_rand(p[0]);
			ep_rand(q[0]);
			bn_rand_mod(k, n);
			ep_mul(r, q[0], k);
			pp_map_weilp_k2(e1, p[0], r);
			pp_map_weilp_k2(e2, p[0], q[0]);
			fp2_exp(e2, e2, k);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_weilp_k2(e2, p[0], q[0]);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_weilp_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(q[0], q[0]);
			pp_map_weilp_k2(e2, p[0], q[0]);
			fp2_sqr(e1, e1);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep_rand(q[i % 2]);
			pp_map_weilp_k2(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep_set_infty(q[1 - (i % 2)]);
			pp_map_sim_weilp_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep_rand(q[1 - (i % 2)]);
			pp_map_sim_weilp_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(q[i % 2]);
			pp_map_sim_weilp_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep_rand(q[0]);
			pp_map_weilp_k2(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep_rand(q[1]);
			pp_map_weilp_k2(e2, p[1], q[1]);
			fp2_mul(e1, e1, e2);
			pp_map_sim_weilp_k2(e2, p, q, 2);
			TEST_ASSERT(fp2_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(r);
	fp2_free(e1);
	fp2_free(e2);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep_free(q[j]);
	}

    return code;
}

static int doubling8(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep2_t q, r, s;
	fp8_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep2_null(q);
	ep2_null(r);
	ep2_null(s);
	fp8_null(e1);
	fp8_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep2_new(q);
		ep2_new(r);
		ep2_new(s);
		fp8_new(e1);
		fp8_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_rand(r);
			pp_dbl_k8(e1, r, q, p);
			pp_norm_k8(r, r);
			ep2_dbl(s, q);
			ep2_norm(s, s);
			TEST_ASSERT(ep2_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_rand(r);
			fp8_zero(e1);
			fp8_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k8_basic(e2, r, q, p);
			pp_exp_k8(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_neg(p->x, p->x);
#endif
			pp_dbl_k8(e1, r, q, p);
			pp_exp_k8(e1, e1);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_rand(r);
			fp8_zero(e1);
			fp8_zero(e2);
			/* Precompute. */
			fp_neg(p->x, p->x);
			pp_dbl_k8_projc(e2, r, q, p);
			pp_exp_k8(e2, e2);
#if EP_ADD == BASIC
			/* Revert and fix precomputing. */
			fp_neg(p->x, p->x);
			fp_neg(p->y, p->y);
#endif
			pp_dbl_k8(e1, r, q, p);
			pp_exp_k8(e1, e1);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller doubling is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp8_zero(e1);
			fp8_zero(e2);
			pp_dbl_k8_projc(e1, r, q, p);
			pp_dbl_k8_projc_basic(e2, r, q, p);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller doubling is consistent") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp8_zero(e1);
			fp8_zero(e2);
			pp_dbl_k8_projc(e1, r, q, p);
			pp_dbl_k8_projc_lazyr(e2, r, q, p);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep2_free(q);
	ep2_free(r);
	ep2_free(s);
	fp8_free(e1);
	fp8_free(e2);
	return code;
}

static int addition8(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep2_t q, r, s;
	fp8_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep2_null(q);
	ep2_null(r);
	ep2_null(s);
	fp8_null(e1);
	fp8_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep2_new(q);
		ep2_new(r);
		ep2_new(s);
		fp8_new(e1);
		fp8_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_dbl(r, q);
			ep2_norm(r, r);
			ep2_copy(s, r);
			pp_add_k8(e1, r, q, p);
			pp_norm_k8(r, r);
			ep2_add(s, s, q);
			ep2_norm(s, s);
			TEST_ASSERT(ep2_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_dbl(r, q);
			ep2_norm(r, r);
			ep2_copy(s, r);
			fp8_zero(e1);
			fp8_zero(e2);
#if EP_ADD == PROJC
			/* Precompute. */
			fp_neg(p->x, p->x);
#else
			fp_neg(p->y, p->y);
#endif
			pp_add_k8(e1, r, q, p);
			pp_exp_k8(e1, e1);
#if EP_ADD == PROJC
			/* Revert precompute. */
			fp_neg(p->x, p->x);
			fp_neg(p->y, p->y);
#endif
			pp_add_k8_basic(e2, s, q, p);
			pp_exp_k8(e2, e2);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep2_curve_get_gen(q);
			ep2_dbl(r, q);
			ep2_norm(r, r);
			ep2_copy(s, r);
			fp8_zero(e1);
			fp8_zero(e2);
#if EP_ADD == PROJC
			/* Precompute. */
			fp_neg(p->x, p->x);
#else
			fp_neg(p->y, p->y);
#endif
			pp_add_k8(e1, r, q, p);
			pp_exp_k8(e1, e1);
#if EP_ADD == BASIC
			fp_neg(p->x, p->x);
			fp_neg(p->y, p->y);
#endif
			pp_add_k8_projc(e2, s, q, p);
			pp_exp_k8(e2, e2);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep2_free(q);
	ep2_free(r);
	ep2_free(s);
	fp8_free(e1);
	fp8_free(e2);
	return code;
}

static int pairing8(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep2_t q[2], r;
	fp8_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp8_null(e1);
	fp8_null(e2);
	ep2_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp8_new(e1);
		fp8_new(e2);
		ep2_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep2_null(q[j]);
			ep_new(p[j]);
			ep2_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp8_rand(e1);
			pp_exp_k8(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp8_cmp_dig(e1, 1) != RLC_EQ, end);
			fp8_exp(e2, e1, n);
			TEST_ASSERT(fp8_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep2_curve_get_gen(q[0]);
			pp_map_oatep_k8(e1, p[0], q[0]);
			TEST_ASSERT(fp8_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_oatep_k8(e1, p[0], q[0]);
			TEST_ASSERT(fp8_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_set_infty(q[0]);
			pp_map_oatep_k8(e1, p[0], q[0]);
			TEST_ASSERT(fp8_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep2_curve_get_gen(q[0]);
			bn_rand_mod(k, n);
			ep2_mul_basic(r, q[0], k);
			pp_map_oatep_k8(e1, p[0], r);
			pp_map_oatep_k8(e2, p[0], q[0]);
			fp8_exp(e2, e2, k);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_oatep_k8(e2, p[0], q[0]);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_oatep_k8(e2, p[0], q[0]);
			fp8_sqr(e1, e1);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
			ep2_dbl(q[0], q[0]);
			pp_map_oatep_k8(e2, p[0], q[0]);
			fp8_sqr(e1, e1);
			TEST_ASSERT(fp8_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp8_free(e1);
	fp8_free(e2);
	ep2_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep2_free(q[j]);
	}
	return code;
}

static int doubling12(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep2_t q, r, s;
	fp12_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep2_null(q);
	ep2_null(r);
	ep2_null(s);
	fp12_null(e1);
	fp12_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep2_new(q);
		ep2_new(r);
		ep2_new(s);
		fp12_new(e1);
		fp12_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			pp_dbl_k12(e1, r, q, p);
			pp_norm_k12(r, r);
			ep2_dbl(s, q);
			ep2_norm(s, s);
			TEST_ASSERT(ep2_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp12_zero(e1);
			fp12_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k12_basic(e2, r, q, p);
			pp_exp_k12(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
#endif
			pp_dbl_k12(e1, r, q, p);
			pp_exp_k12(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp12_zero(e1);
			fp12_zero(e2);
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
			pp_dbl_k12_projc(e2, r, q, p);
			pp_exp_k12(e2, e2);
#if EP_ADD == BASIC
			/* Revert precomputing. */
			fp_hlv(p->x, p->z);
#endif
			pp_dbl_k12(e1, r, q, p);
			pp_exp_k12(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller doubling is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_dbl_k12_projc(e1, r, q, p);
			pp_dbl_k12_projc_basic(e2, r, q, p);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller doubling is consistent") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_dbl_k12_projc(e1, r, q, p);
			pp_dbl_k12_projc_lazyr(e2, r, q, p);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep2_free(q);
	ep2_free(r);
	ep2_free(s);
	fp12_free(e1);
	fp12_free(e2);
	return code;
}

static int addition12(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep2_t q, r, s;
	fp12_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep2_null(q);
	ep2_null(r);
	ep2_null(s);
	fp12_null(e1);
	fp12_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep2_new(q);
		ep2_new(r);
		ep2_new(s);
		fp12_new(e1);
		fp12_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			ep2_copy(s, r);
			pp_add_k12(e1, r, q, p);
			pp_norm_k12(r, r);
			ep2_add(s, s, q);
			ep2_norm(s, s);
			TEST_ASSERT(ep2_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			ep2_copy(s, r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_add_k12(e1, r, q, p);
			pp_exp_k12(e1, e1);
			pp_add_k12_basic(e2, s, q, p);
			pp_exp_k12(e2, e2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			ep2_copy(s, r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_add_k12(e1, r, q, p);
			pp_exp_k12(e1, e1);
			pp_add_k12_projc(e2, s, q, p);
			pp_exp_k12(e2, e2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller addition is consistent") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			ep2_copy(s, r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_add_k12_projc(e1, r, q, p);
			pp_add_k12_projc_basic(e2, s, q, p);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller addition is consistent") {
			ep_rand(p);
			ep2_rand(q);
			ep2_rand(r);
			ep2_copy(s, r);
			fp12_zero(e1);
			fp12_zero(e2);
			pp_add_k12_projc(e1, r, q, p);
			pp_add_k12_projc_lazyr(e2, s, q, p);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep2_free(q);
	ep2_free(r);
	ep2_free(s);
	fp12_free(e1);
	fp12_free(e2);
	return code;
}

static int pairing12(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep2_t q[2], r;
	fp12_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp12_null(e1);
	fp12_null(e2);
	ep2_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp12_new(e1);
		fp12_new(e2);
		ep2_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep2_null(q[j]);
			ep_new(p[j]);
			ep2_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp12_rand(e1);
			pp_exp_k12(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp12_cmp_dig(e1, 1) != RLC_EQ, end);
			fp12_exp(e2, e1, n);
			TEST_ASSERT(fp12_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_set_infty(q[0]);
			pp_map_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			bn_rand_mod(k, n);
			ep2_mul(r, q[0], k);
			pp_map_k12(e1, p[0], r);
			pp_map_k12(e2, p[0], q[0]);
			fp12_exp(e2, e2, k);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k12(e2, p[0], q[0]);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_dbl(q[0], q[0]);
			pp_map_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep2_rand(q[i % 2]);
			pp_map_k12(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep2_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep2_rand(q[1 - (i % 2)]);
			pp_map_sim_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_set_infty(q[i % 2]);
			pp_map_sim_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_k12(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep2_rand(q[1]);
			pp_map_k12(e2, p[1], q[1]);
			fp12_mul(e1, e1, e2);
			pp_map_sim_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep2_copy(q[1], q[0]);
			pp_map_sim_k12(e1, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_tatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_tatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_set_infty(q[0]);
			pp_map_tatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing is bilinear") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			bn_rand_mod(k, n);
			ep2_mul(r, q[0], k);
			pp_map_tatep_k12(e1, p[0], r);
			pp_map_tatep_k12(e2, p[0], q[0]);
			fp12_exp(e2, e2, k);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_tatep_k12(e2, p[0], q[0]);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_tatep_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_dbl(q[0], q[0]);
			pp_map_tatep_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep2_rand(q[i % 2]);
			pp_map_tatep_k12(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep2_set_infty(q[1 - (i % 2)]);
			pp_map_sim_tatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep2_rand(q[1 - (i % 2)]);
			pp_map_sim_tatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_set_infty(q[i % 2]);
			pp_map_sim_tatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_tatep_k12(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep2_rand(q[1]);
			pp_map_tatep_k12(e2, p[1], q[1]);
			fp12_mul(e1, e1, e2);
			pp_map_sim_tatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep2_copy(q[1], q[0]);
			pp_map_sim_tatep_k12(e1, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_weilp_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_weilp_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_set_infty(q[0]);
			pp_map_weilp_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing is bilinear") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			bn_rand_mod(k, n);
			ep2_mul(r, q[0], k);
			pp_map_weilp_k12(e1, p[0], r);
			pp_map_weilp_k12(e2, p[0], q[0]);
			fp12_exp(e2, e2, k);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_weilp_k12(e2, p[0], q[0]);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_weilp_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_dbl(q[0], q[0]);
			pp_map_weilp_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep2_rand(q[i % 2]);
			pp_map_weilp_k12(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep2_set_infty(q[1 - (i % 2)]);
			pp_map_sim_weilp_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep2_rand(q[1 - (i % 2)]);
			pp_map_sim_weilp_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_set_infty(q[i % 2]);
			pp_map_sim_weilp_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_weilp_k12(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep2_rand(q[1]);
			pp_map_weilp_k12(e2, p[1], q[1]);
			fp12_mul(e1, e1, e2);
			pp_map_sim_weilp_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep2_copy(q[1], q[0]);
			pp_map_sim_weilp_k12(e1, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_oatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_oatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_set_infty(q[0]);
			pp_map_oatep_k12(e1, p[0], q[0]);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing is bilinear") {
			ep_rand(p[0]);
			ep2_rand(q[0]);
			bn_rand_mod(k, n);
			ep2_mul(r, q[0], k);
			pp_map_oatep_k12(e1, p[0], r);
			ep_mul(p[0], p[0], k);
			pp_map_oatep_k12(e2, p[0], q[0]);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_oatep_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_dbl(q[0], q[0]);
			pp_map_oatep_k12(e2, p[0], q[0]);
			fp12_sqr(e1, e1);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep2_rand(q[i % 2]);
			pp_map_oatep_k12(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep2_set_infty(q[1 - (i % 2)]);
			pp_map_sim_oatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep2_rand(q[1 - (i % 2)]);
			pp_map_sim_oatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep2_set_infty(q[i % 2]);
			pp_map_sim_oatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep2_rand(q[0]);
			pp_map_oatep_k12(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep2_rand(q[1]);
			pp_map_oatep_k12(e2, p[1], q[1]);
			fp12_mul(e1, e1, e2);
			pp_map_sim_oatep_k12(e2, p, q, 2);
			TEST_ASSERT(fp12_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep2_copy(q[1], q[0]);
			pp_map_sim_oatep_k12(e1, p, q, 2);
			TEST_ASSERT(fp12_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp12_free(e1);
	fp12_free(e2);
	ep2_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep2_free(q[j]);
	}
	return code;
}

static int doubling16(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep4_t q, r, s;
	fp16_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep4_null(q);
	ep4_null(r);
	ep4_null(s);
	fp16_null(e1);
	fp16_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep4_new(q);
		ep4_new(r);
		ep4_new(s);
		fp16_new(e1);
		fp16_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			pp_dbl_k16(e1, r, q, p);
			pp_norm_k16(r, r);
			ep4_dbl(s, q);
			ep4_norm(s, s);
			TEST_ASSERT(ep4_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			fp16_zero(e1);
			fp16_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k16_basic(e2, r, q, p);
			pp_exp_k16(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_neg(p->x, p->x);
#endif
			pp_dbl_k16(e1, r, q, p);
			pp_exp_k16(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			fp16_zero(e1);
			fp16_zero(e2);
			/* Precompute. */
			fp_neg(p->x, p->x);
			pp_dbl_k16_projc(e2, r, q, p);
			pp_exp_k16(e2, e2);
#if EP_ADD == BASIC
			/* Revert and fix precomputing. */
			fp_neg(p->x, p->x);
			fp_neg(p->y, p->y);
#endif
			pp_dbl_k16(e1, r, q, p);
			pp_exp_k16(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller doubling is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			fp16_zero(e1);
			fp16_zero(e2);
			pp_dbl_k16_projc(e1, r, q, p);
			pp_dbl_k16_projc_basic(e2, r, q, p);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller doubling is consistent") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			fp16_zero(e1);
			fp16_zero(e2);
			pp_dbl_k16_projc(e1, r, q, p);
			pp_dbl_k16_projc_lazyr(e2, r, q, p);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep4_free(q);
	ep4_free(r);
	ep4_free(s);
	fp16_free(e1);
	fp16_free(e2);
	return code;
}

static int addition16(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep4_t q, r, s;
	fp16_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep4_null(q);
	ep4_null(r);
	ep4_null(s);
	fp16_null(e1);
	fp16_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep4_new(q);
		ep4_new(r);
		ep4_new(s);
		fp16_new(e1);
		fp16_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep4_curve_get_gen(q);
			ep4_dbl(r, q);
			ep4_norm(r, r);
			ep4_copy(s, r);
			pp_add_k16(e1, r, q, p);
			pp_norm_k16(r, r);
			ep4_add(s, s, q);
			ep4_norm(s, s);
			TEST_ASSERT(ep4_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep4_curve_get_gen(q);
			ep4_dbl(r, q);
			ep4_norm(r, r);
			ep4_copy(s, r);
			fp16_zero(e1);
			fp16_zero(e2);
			pp_add_k16(e1, r, q, p);
			pp_exp_k16(e1, e1);
			pp_add_k16_basic(e2, s, q, p);
			pp_exp_k16(e2, e2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep4_curve_get_gen(q);
			ep4_dbl(r, q);
			ep4_norm(r, r);
			ep4_copy(s, r);
			fp16_zero(e1);
			fp16_zero(e2);
			pp_add_k16(e1, r, q, p);
			pp_exp_k16(e1, e1);
			pp_add_k16_projc(e2, s, q, p);
			pp_exp_k16(e2, e2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep4_free(q);
	ep4_free(r);
	ep4_free(s);
	fp16_free(e1);
	fp16_free(e2);
	return code;
}

static int pairing16(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep4_t q[2], r;
	fp16_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp16_null(e1);
	fp16_null(e2);
	ep4_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp16_new(e1);
		fp16_new(e2);
		ep4_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep4_null(q[j]);
			ep_new(p[j]);
			ep4_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp16_rand(e1);
			pp_exp_k16(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp16_cmp_dig(e1, 1) != RLC_EQ, end);
			fp16_exp(e2, e1, n);
			TEST_ASSERT(fp16_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_set_infty(q[0]);
			pp_map_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			bn_rand_mod(k, n);
			ep4_mul(r, q[0], k);
			pp_map_k16(e1, p[0], r);
			pp_map_k16(e2, p[0], q[0]);
			fp16_exp(e2, e2, k);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k16(e2, p[0], q[0]);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_dbl(q[0], q[0]);
			pp_map_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep4_rand(q[i % 2]);
			pp_map_k16(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep4_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep4_rand(q[1 - (i % 2)]);
			pp_map_sim_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_set_infty(q[i % 2]);
			pp_map_sim_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_k16(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep4_rand(q[1]);
			pp_map_k16(e2, p[1], q[1]);
			fp16_mul(e1, e1, e2);
			pp_map_sim_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_tatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_tatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_set_infty(q[0]);
			pp_map_tatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing is bilinear") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			bn_rand_mod(k, n);
			ep4_mul(r, q[0], k);
			pp_map_tatep_k16(e1, p[0], r);
			pp_map_tatep_k16(e2, p[0], q[0]);
			fp16_exp(e2, e2, k);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_tatep_k16(e2, p[0], q[0]);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_tatep_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_dbl(q[0], q[0]);
			pp_map_tatep_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep4_rand(q[i % 2]);
			pp_map_tatep_k16(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep4_set_infty(q[1 - (i % 2)]);
			pp_map_sim_tatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep4_rand(q[1 - (i % 2)]);
			pp_map_sim_tatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_set_infty(q[i % 2]);
			pp_map_sim_tatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_tatep_k16(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep4_rand(q[1]);
			pp_map_tatep_k16(e2, p[1], q[1]);
			fp16_mul(e1, e1, e2);
			pp_map_sim_tatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_weilp_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_weilp_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_set_infty(q[0]);
			pp_map_weilp_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing is bilinear") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			bn_rand_mod(k, n);
			ep4_mul(r, q[0], k);
			pp_map_weilp_k16(e1, p[0], r);
			pp_map_weilp_k16(e2, p[0], q[0]);
			fp16_exp(e2, e2, k);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_weilp_k16(e2, p[0], q[0]);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_weilp_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_dbl(q[0], q[0]);
			pp_map_weilp_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep4_rand(q[i % 2]);
			pp_map_weilp_k16(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep4_set_infty(q[1 - (i % 2)]);
			pp_map_sim_weilp_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep4_rand(q[1 - (i % 2)]);
			pp_map_sim_weilp_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_set_infty(q[i % 2]);
			pp_map_sim_weilp_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_weilp_k16(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep4_rand(q[1]);
			pp_map_weilp_k16(e2, p[1], q[1]);
			fp16_mul(e1, e1, e2);
			pp_map_sim_weilp_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_oatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_oatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_set_infty(q[0]);
			pp_map_oatep_k16(e1, p[0], q[0]);
			TEST_ASSERT(fp16_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing is bilinear") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			bn_rand_mod(k, n);
			ep4_mul(r, q[0], k);
			pp_map_oatep_k16(e1, p[0], r);
			ep_mul(p[0], p[0], k);
			pp_map_oatep_k16(e2, p[0], q[0]);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_oatep_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_dbl(q[0], q[0]);
			pp_map_oatep_k16(e2, p[0], q[0]);
			fp16_sqr(e1, e1);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep4_rand(q[i % 2]);
			pp_map_oatep_k16(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep4_set_infty(q[1 - (i % 2)]);
			pp_map_sim_oatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep4_rand(q[1 - (i % 2)]);
			pp_map_sim_oatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
			ep4_set_infty(q[i % 2]);
			pp_map_sim_oatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_oatep_k16(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep4_rand(q[1]);
			pp_map_oatep_k16(e2, p[1], q[1]);
			fp16_mul(e1, e1, e2);
			pp_map_sim_oatep_k16(e2, p, q, 2);
			TEST_ASSERT(fp16_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp16_free(e1);
	fp16_free(e2);
	ep4_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep4_free(q[j]);
	}
	return code;
}

static int doubling18(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep3_t q, r, s;
	fp18_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep3_null(q);
	ep3_null(r);
	ep3_null(s);
	fp18_null(e1);
	fp18_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep3_new(q);
		ep3_new(r);
		ep3_new(s);
		fp18_new(e1);
		fp18_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			pp_dbl_k18(e1, r, q, p);
			pp_norm_k18(r, r);
			ep3_dbl(s, q);
			ep3_norm(s, s);
			TEST_ASSERT(ep3_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			fp18_zero(e1);
			fp18_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k18_basic(e2, r, q, p);
			pp_exp_k18(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
#endif
			pp_dbl_k18(e1, r, q, p);
			pp_exp_k18(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			fp18_zero(e1);
			fp18_zero(e2);
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
			pp_dbl_k18_projc(e2, r, q, p);
			pp_exp_k18(e2, e2);
#if EP_ADD == BASIC
			/* Revert precomputing. */
			fp_hlv(p->x, p->z);
#endif
			pp_dbl_k18(e1, r, q, p);
			pp_exp_k18(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller doubling is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_dbl_k18_projc(e1, r, q, p);
			pp_dbl_k18_projc_basic(e2, r, q, p);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller doubling is consistent") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_dbl_k18_projc(e1, r, q, p);
			pp_dbl_k18_projc_lazyr(e2, r, q, p);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep3_free(q);
	ep3_free(r);
	ep3_free(s);
	fp18_free(e1);
	fp18_free(e2);
	return code;
}

static int addition18(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep3_t q, r, s;
	fp18_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep3_null(q);
	ep3_null(r);
	ep3_null(s);
	fp18_null(e1);
	fp18_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep3_new(q);
		ep3_new(r);
		ep3_new(s);
		fp18_new(e1);
		fp18_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			ep3_copy(s, r);
			pp_add_k18(e1, r, q, p);
			pp_norm_k18(r, r);
			ep3_add(s, s, q);
			ep3_norm(s, s);
			TEST_ASSERT(ep3_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			ep3_copy(s, r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_add_k18(e1, r, q, p);
			pp_exp_k18(e1, e1);
			pp_add_k18_basic(e2, s, q, p);
			pp_exp_k18(e2, e2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			ep3_copy(s, r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_add_k18(e1, r, q, p);
			pp_exp_k18(e1, e1);
			pp_add_k18_projc(e2, s, q, p);
			pp_exp_k18(e2, e2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("basic projective miller addition is consistent") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			ep3_copy(s, r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_add_k18_projc(e1, r, q, p);
			pp_add_k18_projc_basic(e2, s, q, p);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lazy-reduced projective miller addition is consistent") {
			ep_rand(p);
			ep3_rand(q);
			ep3_rand(r);
			ep3_copy(s, r);
			fp18_zero(e1);
			fp18_zero(e2);
			pp_add_k18_projc(e1, r, q, p);
			pp_add_k18_projc_lazyr(e2, s, q, p);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep3_free(q);
	ep3_free(r);
	ep3_free(s);
	fp18_free(e1);
	fp18_free(e2);
	return code;
}

static int pairing18(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep3_t q[2], r;
	fp18_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp18_null(e1);
	fp18_null(e2);
	ep3_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp18_new(e1);
		fp18_new(e2);
		ep3_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep3_null(q[j]);
			ep_new(p[j]);
			ep3_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp18_rand(e1);
			pp_exp_k18(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp18_cmp_dig(e1, 1) != RLC_EQ, end);
			fp18_exp(e2, e1, n);
			TEST_ASSERT(fp18_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_set_infty(q[0]);
			pp_map_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			bn_rand_mod(k, n);
			ep3_mul(r, q[0], k);
			pp_map_k18(e1, p[0], r);
			pp_map_k18(e2, p[0], q[0]);
			fp18_exp(e2, e2, k);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k18(e2, p[0], q[0]);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_dbl(q[0], q[0]);
			pp_map_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep3_rand(q[i % 2]);
			pp_map_k18(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep3_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep3_rand(q[1 - (i % 2)]);
			pp_map_sim_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_set_infty(q[i % 2]);
			pp_map_sim_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_k18(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep3_rand(q[1]);
			pp_map_k18(e2, p[1], q[1]);
			fp18_mul(e1, e1, e2);
			pp_map_sim_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_tatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_tatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_set_infty(q[0]);
			pp_map_tatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate pairing is bilinear") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			bn_rand_mod(k, n);
			ep3_mul(r, q[0], k);
			pp_map_tatep_k18(e1, p[0], r);
			pp_map_tatep_k18(e2, p[0], q[0]);
			fp18_exp(e2, e2, k);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_tatep_k18(e2, p[0], q[0]);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_tatep_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_dbl(q[0], q[0]);
			pp_map_tatep_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("tate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep3_rand(q[i % 2]);
			pp_map_tatep_k18(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep3_set_infty(q[1 - (i % 2)]);
			pp_map_sim_tatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep3_rand(q[1 - (i % 2)]);
			pp_map_sim_tatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_set_infty(q[i % 2]);
			pp_map_sim_tatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_tatep_k18(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep3_rand(q[1]);
			pp_map_tatep_k18(e2, p[1], q[1]);
			fp18_mul(e1, e1, e2);
			pp_map_sim_tatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_weilp_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_weilp_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_set_infty(q[0]);
			pp_map_weilp_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil pairing is bilinear") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			bn_rand_mod(k, n);
			ep3_mul(r, q[0], k);
			pp_map_weilp_k18(e1, p[0], r);
			pp_map_weilp_k18(e2, p[0], q[0]);
			fp18_exp(e2, e2, k);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_weilp_k18(e2, p[0], q[0]);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_weilp_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_dbl(q[0], q[0]);
			pp_map_weilp_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("weil multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep3_rand(q[i % 2]);
			pp_map_weilp_k18(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep3_set_infty(q[1 - (i % 2)]);
			pp_map_sim_weilp_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep3_rand(q[1 - (i % 2)]);
			pp_map_sim_weilp_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_set_infty(q[i % 2]);
			pp_map_sim_weilp_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_weilp_k18(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep3_rand(q[1]);
			pp_map_weilp_k18(e2, p[1], q[1]);
			fp18_mul(e1, e1, e2);
			pp_map_sim_weilp_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_oatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_oatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_set_infty(q[0]);
			pp_map_oatep_k18(e1, p[0], q[0]);
			TEST_ASSERT(fp18_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate pairing is bilinear") {
			ep_rand(p[0]);
			ep3_rand(q[0]);
			bn_rand_mod(k, n);
			ep3_mul(r, q[0], k);
			pp_map_oatep_k18(e1, p[0], r);
			ep_mul(p[0], p[0], k);
			pp_map_oatep_k18(e2, p[0], q[0]);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_oatep_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_dbl(q[0], q[0]);
			pp_map_oatep_k18(e2, p[0], q[0]);
			fp18_sqr(e1, e1);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("optimal ate multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep3_rand(q[i % 2]);
			pp_map_oatep_k18(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep3_set_infty(q[1 - (i % 2)]);
			pp_map_sim_oatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep3_rand(q[1 - (i % 2)]);
			pp_map_sim_oatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
			ep3_set_infty(q[i % 2]);
			pp_map_sim_oatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep3_rand(q[0]);
			pp_map_oatep_k18(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep3_rand(q[1]);
			pp_map_oatep_k18(e2, p[1], q[1]);
			fp18_mul(e1, e1, e2);
			pp_map_sim_oatep_k18(e2, p, q, 2);
			TEST_ASSERT(fp18_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp18_free(e1);
	fp18_free(e2);
	ep3_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep3_free(q[j]);
	}
	return code;
}

static int doubling24(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep4_t q, r, s;
	fp24_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep4_null(q);
	ep4_null(r);
	ep4_null(s);
	fp24_null(e1);
	fp24_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep4_new(q);
		ep4_new(r);
		ep4_new(s);
		fp24_new(e1);
		fp24_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			pp_dbl_k24(e1, r, q, p);
			pp_norm_k24(r, r);
			ep4_dbl(s, q);
			ep4_norm(s, s);
			TEST_ASSERT(ep4_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			fp24_zero(e1);
			fp24_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k24_basic(e2, r, q, p);
			pp_exp_k24(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
#endif
			pp_dbl_k24(e1, r, q, p);
			pp_exp_k24(e1, e1);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			fp24_zero(e1);
			fp24_zero(e2);
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
			pp_dbl_k24_projc(e2, r, q, p);
			pp_exp_k24(e2, e2);
#if EP_ADD == BASIC
			/* Revert precomputing. */
			fp_hlv(p->x, p->z);
#endif
			pp_dbl_k24(e1, r, q, p);
			pp_exp_k24(e1, e1);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep4_free(q);
	ep4_free(r);
	ep4_free(s);
	fp24_free(e1);
	fp24_free(e2);
	return code;
}

static int addition24(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep4_t q, r, s;
	fp24_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep4_null(q);
	ep4_null(r);
	ep4_null(s);
	fp24_null(e1);
	fp24_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep4_new(q);
		ep4_new(r);
		ep4_new(s);
		fp24_new(e1);
		fp24_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			ep4_copy(s, r);
			pp_add_k24(e1, r, q, p);
			pp_norm_k24(r, r);
			ep4_add(s, s, q);
			ep4_norm(s, s);
			TEST_ASSERT(ep4_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			ep4_copy(s, r);
			fp24_zero(e1);
			fp24_zero(e2);
			pp_add_k24(e1, r, q, p);
			pp_exp_k24(e1, e1);
			pp_add_k24_basic(e2, s, q, p);
			pp_exp_k24(e2, e2);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep4_rand(q);
			ep4_rand(r);
			ep4_copy(s, r);
			fp24_zero(e1);
			fp24_zero(e2);
			pp_add_k24(e1, r, q, p);
			pp_exp_k24(e1, e1);
			pp_add_k24_projc(e2, s, q, p);
			pp_exp_k24(e2, e2);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep4_free(q);
	ep4_free(r);
	ep4_free(s);
	fp24_free(e1);
	fp24_free(e2);
	return code;
}

static int pairing24(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep4_t q[2], r;
	fp24_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp24_null(e1);
	fp24_null(e2);
	ep4_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp24_new(e1);
		fp24_new(e2);
		ep4_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep4_null(q[j]);
			ep_new(p[j]);
			ep4_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp24_rand(e1);
			pp_exp_k24(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp24_cmp_dig(e1, 1) != RLC_EQ, end);
			fp24_exp(e2, e1, n);
			TEST_ASSERT(fp24_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_k24(e1, p[0], q[0]);
			TEST_ASSERT(fp24_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k24(e1, p[0], q[0]);
			TEST_ASSERT(fp24_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_set_infty(q[0]);
			pp_map_k24(e1, p[0], q[0]);
			TEST_ASSERT(fp24_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep4_rand(q[0]);
			bn_rand_mod(k, n);
			ep4_mul(r, q[0], k);
			pp_map_k24(e1, p[0], r);
			pp_map_k24(e2, p[0], q[0]);
			fp24_exp(e2, e2, k);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k24(e2, p[0], q[0]);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k24(e2, p[0], q[0]);
			fp24_sqr(e1, e1);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep4_dbl(q[0], q[0]);
			pp_map_k24(e2, p[0], q[0]);
			fp24_sqr(e1, e1);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep4_rand(q[i % 2]);
			pp_map_k24(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep4_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k24(e2, p, q, 2);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep4_rand(q[1 - (i % 2)]);
			pp_map_sim_k24(e2, p, q, 2);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep4_set_infty(q[i % 2]);
			pp_map_sim_k24(e2, p, q, 2);
			TEST_ASSERT(fp24_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep4_rand(q[0]);
			pp_map_k24(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep4_rand(q[1]);
			pp_map_k24(e2, p[1], q[1]);
			fp24_mul(e1, e1, e2);
			pp_map_sim_k24(e2, p, q, 2);
			TEST_ASSERT(fp24_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep4_copy(q[1], q[0]);
			pp_map_sim_k24(e1, p, q, 2);
			TEST_ASSERT(fp24_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp24_free(e1);
	fp24_free(e2);
	ep4_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep4_free(q[j]);
	}
	return code;
}

static int doubling48(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep8_t q, r, s;
	fp48_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep8_null(q);
	ep8_null(r);
	ep8_null(s);
	fp48_null(e1);
	fp48_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep8_new(q);
		ep8_new(r);
		ep8_new(s);
		fp48_new(e1);
		fp48_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep8_rand(q);
			ep8_rand(r);
			pp_dbl_k48(e1, r, q, p);
			pp_norm_k48(r, r);
			ep8_dbl(s, q);
			ep8_norm(s, s);
			TEST_ASSERT(ep8_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep8_rand(q);
			fp48_zero(e1);
			fp48_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k48_basic(e2, r, q, p);
			pp_exp_k48(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
#endif
			pp_dbl_k48(e1, r, q, p);
			pp_exp_k48(e1, e1);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep8_rand(q);
			fp48_zero(e1);
			fp48_zero(e2);
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
			pp_dbl_k48_projc(e2, r, q, p);
			pp_exp_k48(e2, e2);
#if EP_ADD == BASIC
			/* Revert precomputing. */
			fp_hlv(p->x, p->z);
#endif
			pp_dbl_k48(e1, r, q, p);
			pp_exp_k48(e1, e1);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep8_free(q);
	ep8_free(r);
	ep8_free(s);
	fp48_free(e1);
	fp48_free(e2);
	return code;
}

static int addition48(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep8_t q, r, s;
	fp48_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep8_null(q);
	ep8_null(r);
	ep8_null(s);
	fp48_null(e1);
	fp48_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep8_new(q);
		ep8_new(r);
		ep8_new(s);
		fp48_new(e1);
		fp48_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep8_rand(q);
			ep8_rand(r);
			ep8_copy(s, r);
			pp_add_k48(e1, r, q, p);
			pp_norm_k48(r, r);
			ep8_add(s, s, q);
			ep8_norm(s, s);
			TEST_ASSERT(ep8_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep8_rand(q);
			ep8_rand(r);
			ep8_copy(s, r);
			fp48_zero(e1);
			fp48_zero(e2);
			pp_add_k48(e1, r, q, p);
			pp_exp_k48(e1, e1);
			pp_add_k48_basic(e2, s, q, p);
			pp_exp_k48(e2, e2);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep8_rand(q);
			ep8_rand(r);
			ep8_copy(s, r);
			fp48_zero(e1);
			fp48_zero(e2);
			pp_add_k48(e1, r, q, p);
			pp_exp_k48(e1, e1);
			pp_add_k48_projc(e2, s, q, p);
			pp_exp_k48(e2, e2);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep8_free(q);
	ep8_free(r);
	ep8_free(s);
	fp48_free(e1);
	fp48_free(e2);
	return code;
}

static int pairing48(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep8_t q[2], r;
	fp48_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp48_null(e1);
	fp48_null(e2);
	ep8_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp48_new(e1);
		fp48_new(e2);
		ep8_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep8_null(q[j]);
			ep_new(p[j]);
			ep8_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp48_rand(e1);
			pp_exp_k48(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp48_cmp_dig(e1, 1) != RLC_EQ, end);
			fp48_exp(e2, e1, n);
			TEST_ASSERT(fp48_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep8_rand(q[0]);
			pp_map_k48(e1, p[0], q[0]);
			TEST_ASSERT(fp48_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k48(e1, p[0], q[0]);
			TEST_ASSERT(fp48_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep8_set_infty(q[0]);
			pp_map_k48(e1, p[0], q[0]);
			TEST_ASSERT(fp48_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep8_rand(q[0]);
			bn_rand_mod(k, n);
			ep8_mul(r, q[0], k);
			pp_map_k48(e1, p[0], r);
			pp_map_k48(e2, p[0], q[0]);
			fp48_exp(e2, e2, k);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k48(e2, p[0], q[0]);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k48(e2, p[0], q[0]);
			fp48_sqr(e1, e1);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep8_dbl(q[0], q[0]);
			pp_map_k48(e2, p[0], q[0]);
			fp48_sqr(e1, e1);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep8_rand(q[i % 2]);
			pp_map_k48(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep8_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k48(e2, p, q, 2);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep8_rand(q[1 - (i % 2)]);
			pp_map_sim_k48(e2, p, q, 2);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep8_set_infty(q[i % 2]);
			pp_map_sim_k48(e2, p, q, 2);
			TEST_ASSERT(fp48_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep8_rand(q[0]);
			pp_map_k48(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep8_rand(q[1]);
			pp_map_k48(e2, p[1], q[1]);
			fp48_mul(e1, e1, e2);
			pp_map_sim_k48(e2, p, q, 2);
			TEST_ASSERT(fp48_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep8_copy(q[1], q[0]);
			pp_map_sim_k48(e1, p, q, 2);
			TEST_ASSERT(fp48_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp48_free(e1);
	fp48_free(e2);
	ep8_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep8_free(q[j]);
	}
	return code;
}

static int doubling54(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep9_t q, r, s;
	fp54_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep9_null(q);
	ep9_null(r);
	ep9_null(s);
	fp54_null(e1);
	fp54_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep9_new(q);
		ep9_new(r);
		ep9_new(s);
		fp54_new(e1);
		fp54_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller doubling is correct") {
			ep_rand(p);
			ep9_rand(q);
			ep9_rand(r);
			pp_dbl_k54(e1, r, q, p);
			pp_norm_k54(r, r);
			ep9_dbl(s, q);
			ep9_norm(s, s);
			TEST_ASSERT(ep9_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in affine coordinates is correct") {
			ep_rand(p);
			ep9_rand(q);
			fp54_zero(e1);
			fp54_zero(e2);
			fp_neg(p->y, p->y);
			pp_dbl_k54_basic(e2, r, q, p);
			pp_exp_k54(e2, e2);
#if EP_ADD == PROJC || EP_ADD == JACOB
			/* Precompute. */
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
#endif
			pp_dbl_k54(e1, r, q, p);
			pp_exp_k54(e1, e1);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller doubling in projective coordinates is correct") {
			ep_rand(p);
			ep9_rand(q);
			fp54_zero(e1);
			fp54_zero(e2);
			/* Precompute. */
			fp_neg(p->y, p->y);
			fp_dbl(p->z, p->x);
			fp_add(p->x, p->z, p->x);
			pp_dbl_k54_projc(e2, r, q, p);
			pp_exp_k54(e2, e2);
#if EP_ADD == BASIC
			/* Revert precomputing. */
			fp_hlv(p->x, p->z);
#endif
			pp_dbl_k54(e1, r, q, p);
			pp_exp_k54(e1, e1);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep9_free(q);
	ep9_free(r);
	ep9_free(s);
	fp54_free(e1);
	fp54_free(e2);
	return code;
}

static int addition54(void) {
	int code = RLC_ERR;
	bn_t k, n;
	ep_t p;
	ep9_t q, r, s;
	fp54_t e1, e2;

	bn_null(k);
	bn_null(n);
	ep_null(p);
	ep9_null(q);
	ep9_null(r);
	ep9_null(s);
	fp54_null(e1);
	fp54_null(e2);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep9_new(q);
		ep9_new(r);
		ep9_new(s);
		fp54_new(e1);
		fp54_new(e2);

		ep_curve_get_ord(n);

		TEST_CASE("miller addition is correct") {
			ep_rand(p);
			ep9_rand(q);
			ep9_rand(r);
			ep9_copy(s, r);
			pp_add_k54(e1, r, q, p);
			pp_norm_k54(r, r);
			ep9_add(s, s, q);
			ep9_norm(s, s);
			TEST_ASSERT(ep9_cmp(r, s) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in affine coordinates is correct") {
			ep_rand(p);
			ep9_rand(q);
			ep9_rand(r);
			ep9_copy(s, r);
			fp54_zero(e1);
			fp54_zero(e2);
			pp_add_k54(e1, r, q, p);
			pp_exp_k54(e1, e1);
			pp_add_k54_basic(e2, s, q, p);
			pp_exp_k54(e2, e2);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("miller addition in projective coordinates is correct") {
			ep_rand(p);
			ep9_rand(q);
			ep9_rand(r);
			ep9_copy(s, r);
			fp54_zero(e1);
			fp54_zero(e2);
			pp_add_k54(e1, r, q, p);
			pp_exp_k54(e1, e1);
			pp_add_k54_projc(e2, s, q, p);
			pp_exp_k54(e2, e2);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep9_free(q);
	ep9_free(r);
	ep9_free(s);
	fp54_free(e1);
	fp54_free(e2);
	return code;
}

static int pairing54(void) {
	int j, code = RLC_ERR;
	bn_t k, n;
	ep_t p[2];
	ep9_t q[2], r;
	fp54_t e1, e2;

	bn_null(k);
	bn_null(n);
	fp54_null(e1);
	fp54_null(e2);
	ep9_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		fp54_new(e1);
		fp54_new(e2);
		ep9_new(r);

		for (j = 0; j < 2; j++) {
			ep_null(p[j]);
			ep9_null(q[j]);
			ep_new(p[j]);
			ep9_new(q[j]);
		}

		ep_curve_get_ord(n);

		TEST_CASE("final exponentiation is correct") {
			fp54_rand(e1);
			pp_exp_k54(e1, e1);
			/* The result is a non-trivial r-th root of unity. */
			TEST_ASSERT(fp54_cmp_dig(e1, 1) != RLC_EQ, end);
			fp54_exp(e2, e1, n);
			TEST_ASSERT(fp54_cmp_dig(e2, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing non-degeneracy is correct") {
			ep_rand(p[0]);
			ep9_rand(q[0]);
			pp_map_k54(e1, p[0], q[0]);
			TEST_ASSERT(fp54_cmp_dig(e1, 1) != RLC_EQ, end);
			ep_set_infty(p[0]);
			pp_map_k54(e1, p[0], q[0]);
			TEST_ASSERT(fp54_cmp_dig(e1, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep9_set_infty(q[0]);
			pp_map_k54(e1, p[0], q[0]);
			TEST_ASSERT(fp54_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("pairing is bilinear") {
			ep_rand(p[0]);
			ep9_rand(q[0]);
			bn_rand_mod(k, n);
			ep9_mul(r, q[0], k);
			pp_map_k54(e1, p[0], r);
			pp_map_k54(e2, p[0], q[0]);
			fp54_exp(e2, e2, k);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep_mul(p[0], p[0], k);
			pp_map_k54(e2, p[0], q[0]);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep_dbl(p[0], p[0]);
			pp_map_k54(e2, p[0], q[0]);
			fp54_sqr(e1, e1);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep9_dbl(q[0], q[0]);
			pp_map_k54(e2, p[0], q[0]);
			fp54_sqr(e1, e1);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("multi-pairing is correct") {
			ep_rand(p[i % 2]);
			ep9_rand(q[i % 2]);
			pp_map_k54(e1, p[i % 2], q[i % 2]);
			ep_rand(p[1 - (i % 2)]);
			ep9_set_infty(q[1 - (i % 2)]);
			pp_map_sim_k54(e2, p, q, 2);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep_set_infty(p[1 - (i % 2)]);
			ep9_rand(q[1 - (i % 2)]);
			pp_map_sim_k54(e2, p, q, 2);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep9_set_infty(q[i % 2]);
			pp_map_sim_k54(e2, p, q, 2);
			TEST_ASSERT(fp54_cmp_dig(e2, 1) == RLC_EQ, end);
			ep_rand(p[0]);
			ep9_rand(q[0]);
			pp_map_k54(e1, p[0], q[0]);
			ep_rand(p[1]);
			ep9_rand(q[1]);
			pp_map_k54(e2, p[1], q[1]);
			fp54_mul(e1, e1, e2);
			pp_map_sim_k54(e2, p, q, 2);
			TEST_ASSERT(fp54_cmp(e1, e2) == RLC_EQ, end);
			ep_neg(p[1], p[0]);
			ep9_copy(q[1], q[0]);
			pp_map_sim_k54(e1, p, q, 2);
			TEST_ASSERT(fp54_cmp_dig(e1, 1) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	fp54_free(e1);
	fp54_free(e2);
	ep9_free(r);

	for (j = 0; j < 2; j++) {
		ep_free(p[j]);
		ep9_free(q[j]);
	}
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the PP module", 0);

	if (ep_param_set_any_pairf() == RLC_ERR) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	ep_param_print();

	util_banner("Arithmetic", 1);

	if (ep_curve_embed() == 1) {
		if (doubling1() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition1() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing1() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 2) {
		if (doubling2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition2() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing2() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 8) {
		if (doubling8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition8() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing8() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 12) {
		if (doubling12() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition12() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing12() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 16) {
		if (doubling16() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition16() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing16() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 18) {
		if (doubling18() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition18() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing18() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 24) {
		if (doubling24() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition24() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing24() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 48) {
		if (doubling48() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition48() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing48() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	if (ep_curve_embed() == 54) {
		if (doubling54() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (addition54() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pairing54() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
