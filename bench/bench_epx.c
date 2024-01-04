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
 * Benchmarks for elliptic curves defined over extensions of prime fields.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

static void memory2(void) {
	ep2_t a[BENCH];

	BENCH_FEW("ep2_null", ep2_null(a[i]), 1);

	BENCH_FEW("ep2_new", ep2_new(a[i]), 1);
	for (int i = 0; i < BENCH; i++) {
		ep2_free(a[i]);
	}

	for (int i = 0; i < BENCH; i++) {
		ep2_new(a[i]);
	}
	BENCH_FEW("ep2_free", ep2_free(a[i]), 1);

	(void)a;
}

static void util2(void) {
	ep2_t p, q, t[2];
	uint8_t bin[4 * RLC_FP_BYTES + 1];
	int l;

	ep2_null(p);
	ep2_null(q);
	ep2_null(t[0]);
	ep2_null(t[1]);

	ep2_new(p);
	ep2_new(q);
	ep2_new(t[0]);
	ep2_new(t[1]);

	BENCH_RUN("ep2_is_infty") {
		ep2_rand(p);
		BENCH_ADD(ep2_is_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep2_set_infty") {
		ep2_rand(p);
		BENCH_ADD(ep2_set_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep2_copy") {
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_copy(p, q));
	}
	BENCH_END;

	BENCH_RUN("ep2_cmp") {
		ep2_rand(p);
		ep2_dbl(p, p);
		ep2_rand(q);
		ep2_dbl(q, q);
		BENCH_ADD(ep2_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep2_norm") {
		ep2_rand(p);
		ep2_dbl(p, p);
		BENCH_ADD(ep2_norm(p, p));
	} BENCH_END;

	BENCH_RUN("ep2_norm_sim (2)") {
		ep2_rand(t[0]);
		ep2_rand(t[1]);
		ep2_dbl(t[0], t[0]);
		ep2_dbl(t[1], t[1]);
		BENCH_ADD(ep2_norm_sim(t, t, 2));
	} BENCH_END;

	BENCH_RUN("ep2_cmp (1 norm)") {
		ep2_rand(p);
		ep2_dbl(p, p);
		ep2_rand(q);
		BENCH_ADD(ep2_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep2_cmp (2 norm)") {
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep2_rand") {
		BENCH_ADD(ep2_rand(p));
	}
	BENCH_END;

	BENCH_RUN("ep2_blind") {
		BENCH_ADD(ep2_blind(p, p));
	}
	BENCH_END;

	BENCH_RUN("ep2_on_curve") {
		ep2_rand(p);
		BENCH_ADD(ep2_on_curve(p));
	} BENCH_END;

	BENCH_RUN("ep2_size_bin (0)") {
		ep2_rand(p);
		BENCH_ADD(ep2_size_bin(p, 0));
	} BENCH_END;

	BENCH_RUN("ep2_size_bin (1)") {
		ep2_rand(p);
		BENCH_ADD(ep2_size_bin(p, 1));
	} BENCH_END;

	BENCH_RUN("ep2_write_bin (0)") {
		ep2_rand(p);
		l = ep2_size_bin(p, 0);
		BENCH_ADD(ep2_write_bin(bin, l, p, 0));
	} BENCH_END;

	BENCH_RUN("ep2_write_bin (1)") {
		ep2_rand(p);
		l = ep2_size_bin(p, 1);
		BENCH_ADD(ep2_write_bin(bin, l, p, 1));
	} BENCH_END;

	BENCH_RUN("ep2_read_bin (0)") {
		ep2_rand(p);
		l = ep2_size_bin(p, 0);
		ep2_write_bin(bin, l, p, 0);
		BENCH_ADD(ep2_read_bin(p, bin, l));
	} BENCH_END;

	BENCH_RUN("ep2_read_bin (1)") {
		ep2_rand(p);
		l = ep2_size_bin(p, 1);
		ep2_write_bin(bin, l, p, 1);
		BENCH_ADD(ep2_read_bin(p, bin, l));
	} BENCH_END;

	ep2_free(p);
	ep2_free(q);
	ep2_free(t[0]);
	ep2_free(t[1]);
}

static void arith2(void) {
	ep2_t p, q, r, t[RLC_EPX_TABLE_MAX];
	bn_t k, n, l[2];
	fp2_t s;

	ep2_null(p);
	ep2_null(q);
	ep2_null(r);
	bn_null(k);
	bn_null(n);
	fp2_null(s);
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep2_null(t[i]);
	}

	ep2_new(p);
	ep2_new(q);
	ep2_new(r);
	bn_new(k);
	bn_new(n);
	bn_new(l[0]);
	bn_new(l[1]);
	fp2_new(s);

	ep2_curve_get_ord(n);

	BENCH_RUN("ep2_add") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add(p, p, q);
		ep2_rand(q);
		ep2_rand(p);
		ep2_add(q, q, p);
		BENCH_ADD(ep2_add(r, p, q));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep2_add_basic") {
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_add_basic(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep2_add_slp_basic") {
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_add_slp_basic(r, s, p, q));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep2_add_projc") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add_projc(p, p, q);
		ep2_rand(q);
		ep2_rand(p);
		ep2_add_projc(q, q, p);
		BENCH_ADD(ep2_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep2_add_projc (z2 = 1)") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add_projc(p, p, q);
		ep2_rand(q);
		ep2_norm(q, q);
		BENCH_ADD(ep2_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep2_add_projc (z1,z2 = 1)") {
		ep2_rand(p);
		ep2_norm(p, p);
		ep2_rand(q);
		ep2_norm(q, q);
		BENCH_ADD(ep2_add_projc(r, p, q));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep2_sub") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add(p, p, q);
		ep2_rand(q);
		ep2_rand(p);
		ep2_add(q, q, p);
		BENCH_ADD(ep2_sub(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep2_dbl") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add(p, p, q);
		BENCH_ADD(ep2_dbl(r, p));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep2_dbl_basic") {
		ep2_rand(p);
		BENCH_ADD(ep2_dbl_basic(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep2_dbl_slp_basic") {
		ep2_rand(p);
		BENCH_ADD(ep2_dbl_slp_basic(r, s, p));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep2_dbl_projc") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add_projc(p, p, q);
		BENCH_ADD(ep2_dbl_projc(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep2_dbl_projc (z1 = 1)") {
		ep2_rand(p);
		ep2_norm(p, p);
		BENCH_ADD(ep2_dbl_projc(r, p));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep2_neg") {
		ep2_rand(p);
		ep2_rand(q);
		ep2_add(p, p, q);
		BENCH_ADD(ep2_neg(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep2_mul") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep2_mul(q, p, k));
	} BENCH_END;

#if EP_MUL == BASIC || !defined(STRIP)
	BENCH_RUN("ep2_mul_basic") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep2_mul_basic(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == SLIDE || !defined(STRIP)
	BENCH_RUN("ep2_mul_slide") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		BENCH_ADD(ep2_mul_slide(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
	BENCH_RUN("ep2_mul_monty") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		BENCH_ADD(ep2_mul_monty(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
	BENCH_RUN("ep2_mul_lwnaf") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		BENCH_ADD(ep2_mul_lwnaf(q, p, k));
	} BENCH_END;
#endif

	BENCH_RUN("ep2_mul_gen") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep2_mul_gen(q, k));
	} BENCH_END;

	BENCH_RUN("ep2_mul_cof") {
		ep2_rand(p);
		BENCH_ADD(ep2_mul_cof(q, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_dig") {
		bn_rand(k, RLC_POS, RLC_DIG);
		ep2_rand(p);
		BENCH_ADD(ep2_mul_dig(q, p, k->dp[0]));
	}
	BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep2_new(t[i]);
	}

	BENCH_RUN("ep2_mul_pre") {
		ep2_rand(p);
		BENCH_ADD(ep2_mul_pre(t, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_fix") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		ep2_mul_pre(t, p);
		BENCH_ADD(ep2_mul_fix(q, t, k));
	} BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep2_free(t[i]);
	}

#if EP_FIX == BASIC || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep2_new(t[i]);
	}
	BENCH_RUN("ep2_mul_pre_basic") {
		ep2_rand(p);
		BENCH_ADD(ep2_mul_pre_basic(t, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_fix_basic") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		ep2_mul_pre_basic(t, p);
		BENCH_ADD(ep2_mul_fix_basic(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep2_free(t[i]);
	}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep2_new(t[i]);
	}
	BENCH_RUN("ep2_mul_pre_combs") {
		ep2_rand(p);
		BENCH_ADD(ep2_mul_pre_combs(t, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_fix_combs") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		ep2_mul_pre_combs(t, p);
		BENCH_ADD(ep2_mul_fix_combs(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep2_free(t[i]);
	}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep2_new(t[i]);
	}
	BENCH_RUN("ep2_mul_pre_combd") {
		BENCH_ADD(ep2_mul_pre_combd(t, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_fix_combd") {
		bn_rand_mod(k, n);
		ep2_mul_pre_combd(t, p);
		BENCH_ADD(ep2_mul_fix_combd(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep2_free(t[i]);
	}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep2_new(t[i]);
	}
	BENCH_RUN("ep2_mul_pre_lwnaf") {
		ep2_rand(p);
		BENCH_ADD(ep2_mul_pre_lwnaf(t, p));
	} BENCH_END;

	BENCH_RUN("ep2_mul_fix_lwnaf") {
		bn_rand_mod(k, n);
		ep2_rand(p);
		ep2_mul_pre_lwnaf(t, p);
		BENCH_ADD(ep2_mul_fix_lwnaf(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep2_free(t[i]);
	}
#endif

	BENCH_RUN("ep2_mul_sim") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim(r, p, l[0], q, l[1]));
	} BENCH_END;

#if EP_SIM == BASIC || !defined(STRIP)
	BENCH_RUN("ep2_mul_sim_basic") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim_basic(r, p, l[0], q, l[1]));
	} BENCH_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
	BENCH_RUN("ep2_mul_sim_trick") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim_trick(r, p, l[0], q, l[1]));
	} BENCH_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
	BENCH_RUN("ep2_mul_sim_inter") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim_inter(r, p, l[0], q, l[1]));
	} BENCH_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
	BENCH_RUN("ep2_mul_sim_joint") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(p);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim_joint(r, p, l[0], q, l[1]));
	} BENCH_END;
#endif

	BENCH_RUN("ep2_mul_sim_gen") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(q);
		BENCH_ADD(ep2_mul_sim_gen(r, l[0], q, l[1]));
	} BENCH_END;

	for (int i = 0; i < 2; i++) {
		ep2_new(t[i]);
	}

	BENCH_RUN("ep2_mul_sim_lot (2)") {
		bn_rand_mod(l[0], n);
		bn_rand_mod(l[1], n);
		ep2_rand(t[0]);
		ep2_rand(t[1]);
		BENCH_ADD(ep2_mul_sim_lot(r, t, l, 2));
	} BENCH_END;

	for (int i = 0; i < 2; i++) {
		ep2_free(t[i]);
	}

	BENCH_RUN("ep2_frb") {
		ep2_rand(q);
		BENCH_ADD(ep2_frb(r, q, 1));
	} BENCH_END;

	BENCH_RUN("ep2_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map(p, msg, 5));
	} BENCH_END;

#if EP_MAP == BASIC || !defined(STRIP)
	BENCH_RUN("ep2_map_basic") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_basic(p, msg, 5));
	} BENCH_END;
#endif

#if EP_MAP == SSWUM || !defined(STRIP)
	BENCH_RUN("ep2_map_sswum") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_sswum(p, msg, 5));
	} BENCH_END;
#endif

#if EP_MAP == SWIFT || !defined(STRIP)
	BENCH_RUN("ep2_map_swift") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_swift(p, msg, 5));
	} BENCH_END;
#endif

	BENCH_RUN("ep2_pck") {
		ep2_rand(p);
		BENCH_ADD(ep2_pck(q, p));
	} BENCH_END;

	BENCH_RUN("ep2_upk") {
		ep2_rand(p);
		BENCH_ADD(ep2_upk(q, p));
	} BENCH_END;

	ep2_free(p);
	ep2_free(q);
	ep2_free(r);
	bn_free(k);
	bn_free(n);
	bn_free(l[0]);
	bn_free(l[1]);
	fp2_free(s);
}

static void memory3(void) {
	ep3_t a[BENCH];

	BENCH_FEW("ep3_null", ep3_null(a[i]), 1);

	BENCH_FEW("ep3_new", ep3_new(a[i]), 1);
	for (int i = 0; i < BENCH; i++) {
		ep3_free(a[i]);
	}

	for (int i = 0; i < BENCH; i++) {
		ep3_new(a[i]);
	}
	BENCH_FEW("ep3_free", ep3_free(a[i]), 1);

	(void)a;
}

static void util3(void) {
	ep3_t p, q, t[2];
	uint8_t bin[8 * RLC_FP_BYTES + 1];
	int l;

	ep3_null(p);
	ep3_null(q);
	ep3_null(t[0]);
	ep3_null(t[1]);

	ep3_new(p);
	ep3_new(q);
	ep3_new(t[0]);
	ep3_new(t[1]);

	BENCH_RUN("ep3_is_infty") {
		ep3_rand(p);
		BENCH_ADD(ep3_is_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep3_set_infty") {
		ep3_rand(p);
		BENCH_ADD(ep3_set_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep3_copy") {
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_copy(p, q));
	}
	BENCH_END;

	BENCH_RUN("ep3_cmp") {
		ep3_rand(p);
		ep3_dbl(p, p);
		ep3_rand(q);
		ep3_dbl(q, q);
		BENCH_ADD(ep3_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep3_norm") {
		ep3_rand(p);
		ep3_dbl(p, p);
		BENCH_ADD(ep3_norm(p, p));
	} BENCH_END;

	BENCH_RUN("ep3_norm_sim (2)") {
		ep3_rand(t[0]);
		ep3_rand(t[1]);
		ep3_dbl(t[0], t[0]);
		ep3_dbl(t[1], t[1]);
		BENCH_ADD(ep3_norm_sim(t, t, 2));
	} BENCH_END;

	BENCH_RUN("ep3_cmp (1 norm)") {
		ep3_rand(p);
		ep3_dbl(p, p);
		ep3_rand(q);
		BENCH_ADD(ep3_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep3_cmp (2 norm)") {
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep3_rand") {
		BENCH_ADD(ep3_rand(p));
	}
	BENCH_END;

	BENCH_RUN("ep3_blind") {
		BENCH_ADD(ep3_blind(p, p));
	}
	BENCH_END;

	BENCH_RUN("ep3_on_curve") {
		ep3_rand(p);
		BENCH_ADD(ep3_on_curve(p));
	} BENCH_END;

	BENCH_RUN("ep3_size_bin") {
		ep3_rand(p);
		BENCH_ADD(ep3_size_bin(p, 0));
	} BENCH_END;

	BENCH_RUN("ep3_write_bin") {
		ep3_rand(p);
		l = ep3_size_bin(p, 0);
		BENCH_ADD(ep3_write_bin(bin, l, p, 0));
	} BENCH_END;

	BENCH_RUN("ep3_read_bin") {
		ep3_rand(p);
		l = ep3_size_bin(p, 0);
		ep3_write_bin(bin, l, p, 0);
		BENCH_ADD(ep3_read_bin(p, bin, l));
	} BENCH_END;

	ep3_free(p);
	ep3_free(q);
	ep3_free(t[0]);
	ep3_free(t[1]);
}

static void arith3(void) {
	ep3_t p, q, r, t[RLC_EPX_TABLE_MAX];
	bn_t k, n, l;
	fp3_t s;

	ep3_null(p);
	ep3_null(q);
	ep3_null(r);
	bn_null(k);
	bn_null(n);
	fp3_null(s);
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep3_null(t[i]);
	}

	ep3_new(p);
	ep3_new(q);
	ep3_new(r);
	bn_new(k);
	bn_new(n);
	bn_new(l);
	fp3_new(s);

	ep3_curve_get_ord(n);

	BENCH_RUN("ep3_add") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add(p, p, q);
		ep3_rand(q);
		ep3_rand(p);
		ep3_add(q, q, p);
		BENCH_ADD(ep3_add(r, p, q));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep3_add_basic") {
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_add_basic(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep3_add_slp_basic") {
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_add_slp_basic(r, s, p, q));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep3_add_projc") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add_projc(p, p, q);
		ep3_rand(q);
		ep3_rand(p);
		ep3_add_projc(q, q, p);
		BENCH_ADD(ep3_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep3_add_projc (z2 = 1)") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add_projc(p, p, q);
		ep3_rand(q);
		ep3_norm(q, q);
		BENCH_ADD(ep3_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep3_add_projc (z1,z2 = 1)") {
		ep3_rand(p);
		ep3_norm(p, p);
		ep3_rand(q);
		ep3_norm(q, q);
		BENCH_ADD(ep3_add_projc(r, p, q));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep3_sub") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add(p, p, q);
		ep3_rand(q);
		ep3_rand(p);
		ep3_add(q, q, p);
		BENCH_ADD(ep3_sub(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep3_dbl") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add(p, p, q);
		BENCH_ADD(ep3_dbl(r, p));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep3_dbl_basic") {
		ep3_rand(p);
		BENCH_ADD(ep3_dbl_basic(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep3_dbl_slp_basic") {
		ep3_rand(p);
		BENCH_ADD(ep3_dbl_slp_basic(r, s, p));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep3_dbl_projc") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add_projc(p, p, q);
		BENCH_ADD(ep3_dbl_projc(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep3_dbl_projc (z1 = 1)") {
		ep3_rand(p);
		ep3_norm(p, p);
		BENCH_ADD(ep3_dbl_projc(r, p));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep3_neg") {
		ep3_rand(p);
		ep3_rand(q);
		ep3_add(p, p, q);
		BENCH_ADD(ep3_neg(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep3_mul") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep3_mul(q, p, k));
	} BENCH_END;

#if EP_MUL == BASIC || !defined(STRIP)
	BENCH_RUN("ep3_mul_basic") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep3_mul_basic(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == SLIDE || !defined(STRIP)
	BENCH_RUN("ep3_mul_slide") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		BENCH_ADD(ep3_mul_slide(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
	BENCH_RUN("ep3_mul_monty") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		BENCH_ADD(ep3_mul_monty(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
	BENCH_RUN("ep3_mul_lwnaf") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		BENCH_ADD(ep3_mul_lwnaf(q, p, k));
	} BENCH_END;
#endif

	BENCH_RUN("ep3_mul_gen") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep3_mul_gen(q, k));
	} BENCH_END;

	BENCH_RUN("ep3_mul_cof") {
		ep3_rand(p);
		BENCH_ADD(ep3_mul_cof(q, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_dig") {
		bn_rand(k, RLC_POS, RLC_DIG);
		ep3_rand(p);
		BENCH_ADD(ep3_mul_dig(q, p, k->dp[0]));
	}
	BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep3_new(t[i]);
	}

	BENCH_RUN("ep3_mul_pre") {
		ep3_rand(p);
		BENCH_ADD(ep3_mul_pre(t, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_fix") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		ep3_mul_pre(t, p);
		BENCH_ADD(ep3_mul_fix(q, t, k));
	} BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep3_free(t[i]);
	}

#if EP_FIX == BASIC || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep3_new(t[i]);
	}
	BENCH_RUN("ep3_mul_pre_basic") {
		ep3_rand(p);
		BENCH_ADD(ep3_mul_pre_basic(t, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_fix_basic") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		ep3_mul_pre_basic(t, p);
		BENCH_ADD(ep3_mul_fix_basic(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep3_free(t[i]);
	}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep3_new(t[i]);
	}
	BENCH_RUN("ep3_mul_pre_combs") {
		ep3_rand(p);
		BENCH_ADD(ep3_mul_pre_combs(t, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_fix_combs") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		ep3_mul_pre_combs(t, p);
		BENCH_ADD(ep3_mul_fix_combs(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep3_free(t[i]);
	}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep3_new(t[i]);
	}
	BENCH_RUN("ep3_mul_pre_combd") {
		BENCH_ADD(ep3_mul_pre_combd(t, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_fix_combd") {
		bn_rand_mod(k, n);
		ep3_mul_pre_combd(t, p);
		BENCH_ADD(ep3_mul_fix_combd(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep3_free(t[i]);
	}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep3_new(t[i]);
	}
	BENCH_RUN("ep3_mul_pre_lwnaf") {
		ep3_rand(p);
		BENCH_ADD(ep3_mul_pre_lwnaf(t, p));
	} BENCH_END;

	BENCH_RUN("ep3_mul_fix_lwnaf") {
		bn_rand_mod(k, n);
		ep3_rand(p);
		ep3_mul_pre_lwnaf(t, p);
		BENCH_ADD(ep3_mul_fix_lwnaf(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep3_free(t[i]);
	}
#endif

	BENCH_RUN("ep3_mul_sim") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim(r, p, k, q, l));
	} BENCH_END;

#if EP_SIM == BASIC || !defined(STRIP)
	BENCH_RUN("ep3_mul_sim_basic") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim_basic(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
	BENCH_RUN("ep3_mul_sim_trick") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim_trick(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
	BENCH_RUN("ep3_mul_sim_inter") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim_inter(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
	BENCH_RUN("ep3_mul_sim_joint") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(p);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim_joint(r, p, k, q, l));
	} BENCH_END;
#endif

	BENCH_RUN("ep3_mul_sim_gen") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep3_rand(q);
		BENCH_ADD(ep3_mul_sim_gen(r, k, q, l));
	} BENCH_END;

	BENCH_RUN("ep3_frb") {
		ep3_rand(q);
		BENCH_ADD(ep3_frb(r, q, 1));
	} BENCH_END;

	BENCH_RUN("ep3_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep3_map(p, msg, 5));
	} BENCH_END;

	ep3_free(p);
	ep3_free(q);
	ep3_free(r);
	bn_free(k);
	bn_free(n);
	bn_free(l);
	fp3_free(s);
}

static void memory4(void) {
	ep4_t a[BENCH];

	BENCH_FEW("ep4_null", ep4_null(a[i]), 1);

	BENCH_FEW("ep4_new", ep4_new(a[i]), 1);
	for (int i = 0; i < BENCH; i++) {
		ep4_free(a[i]);
	}

	for (int i = 0; i < BENCH; i++) {
		ep4_new(a[i]);
	}
	BENCH_FEW("ep4_free", ep4_free(a[i]), 1);

	(void)a;
}

static void util4(void) {
	ep4_t p, q, t[2];
	uint8_t bin[8 * RLC_FP_BYTES + 1];
	int l;

	ep4_null(p);
	ep4_null(q);
	ep4_null(t[0]);
	ep4_null(t[1]);

	ep4_new(p);
	ep4_new(q);
	ep4_new(t[0]);
	ep4_new(t[1]);

	BENCH_RUN("ep4_is_infty") {
		ep4_rand(p);
		BENCH_ADD(ep4_is_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep4_set_infty") {
		ep4_rand(p);
		BENCH_ADD(ep4_set_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep4_copy") {
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_copy(p, q));
	}
	BENCH_END;

	BENCH_RUN("ep4_cmp") {
		ep4_rand(p);
		ep4_dbl(p, p);
		ep4_rand(q);
		ep4_dbl(q, q);
		BENCH_ADD(ep4_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep4_norm") {
		ep4_rand(p);
		ep4_dbl(p, p);
		BENCH_ADD(ep4_norm(p, p));
	} BENCH_END;

	BENCH_RUN("ep4_norm_sim (2)") {
		ep4_rand(t[0]);
		ep4_rand(t[1]);
		ep4_dbl(t[0], t[0]);
		ep4_dbl(t[1], t[1]);
		BENCH_ADD(ep4_norm_sim(t, t, 2));
	} BENCH_END;

	BENCH_RUN("ep4_cmp (1 norm)") {
		ep4_rand(p);
		ep4_dbl(p, p);
		ep4_rand(q);
		BENCH_ADD(ep4_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep4_cmp (2 norm)") {
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep4_rand") {
		BENCH_ADD(ep4_rand(p));
	}
	BENCH_END;

	BENCH_RUN("ep4_blind") {
		BENCH_ADD(ep4_blind(p, p));
	}
	BENCH_END;

	BENCH_RUN("ep4_on_curve") {
		ep4_rand(p);
		BENCH_ADD(ep4_on_curve(p));
	} BENCH_END;

	BENCH_RUN("ep4_size_bin") {
		ep4_rand(p);
		BENCH_ADD(ep4_size_bin(p, 0));
	} BENCH_END;

	BENCH_RUN("ep4_write_bin") {
		ep4_rand(p);
		l = ep4_size_bin(p, 0);
		BENCH_ADD(ep4_write_bin(bin, l, p, 0));
	} BENCH_END;

	BENCH_RUN("ep4_read_bin") {
		ep4_rand(p);
		l = ep4_size_bin(p, 0);
		ep4_write_bin(bin, l, p, 0);
		BENCH_ADD(ep4_read_bin(p, bin, l));
	} BENCH_END;

	ep4_free(p);
	ep4_free(q);
	ep4_free(t[0]);
	ep4_free(t[1]);
}

static void arith4(void) {
	ep4_t p, q, r, t[RLC_EPX_TABLE_MAX];
	bn_t k, n, l;
	fp4_t s;

	ep4_null(p);
	ep4_null(q);
	ep4_null(r);
	bn_null(k);
	bn_null(n);
	fp4_null(s);
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep4_null(t[i]);
	}

	ep4_new(p);
	ep4_new(q);
	ep4_new(r);
	bn_new(k);
	bn_new(n);
	bn_new(l);
	fp4_new(s);

	ep4_curve_get_ord(n);

	BENCH_RUN("ep4_add") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add(p, p, q);
		ep4_rand(q);
		ep4_rand(p);
		ep4_add(q, q, p);
		BENCH_ADD(ep4_add(r, p, q));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep4_add_basic") {
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_add_basic(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep4_add_slp_basic") {
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_add_slp_basic(r, s, p, q));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep4_add_projc") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add_projc(p, p, q);
		ep4_rand(q);
		ep4_rand(p);
		ep4_add_projc(q, q, p);
		BENCH_ADD(ep4_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep4_add_projc (z2 = 1)") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add_projc(p, p, q);
		ep4_rand(q);
		ep4_norm(q, q);
		BENCH_ADD(ep4_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep4_add_projc (z1,z2 = 1)") {
		ep4_rand(p);
		ep4_norm(p, p);
		ep4_rand(q);
		ep4_norm(q, q);
		BENCH_ADD(ep4_add_projc(r, p, q));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep4_sub") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add(p, p, q);
		ep4_rand(q);
		ep4_rand(p);
		ep4_add(q, q, p);
		BENCH_ADD(ep4_sub(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep4_dbl") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add(p, p, q);
		BENCH_ADD(ep4_dbl(r, p));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep4_dbl_basic") {
		ep4_rand(p);
		BENCH_ADD(ep4_dbl_basic(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep4_dbl_slp_basic") {
		ep4_rand(p);
		BENCH_ADD(ep4_dbl_slp_basic(r, s, p));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep4_dbl_projc") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add_projc(p, p, q);
		BENCH_ADD(ep4_dbl_projc(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep4_dbl_projc (z1 = 1)") {
		ep4_rand(p);
		ep4_norm(p, p);
		BENCH_ADD(ep4_dbl_projc(r, p));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep4_neg") {
		ep4_rand(p);
		ep4_rand(q);
		ep4_add(p, p, q);
		BENCH_ADD(ep4_neg(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep4_mul") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep4_mul(q, p, k));
	} BENCH_END;

#if EP_MUL == BASIC || !defined(STRIP)
	BENCH_RUN("ep4_mul_basic") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep4_mul_basic(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == SLIDE || !defined(STRIP)
	BENCH_RUN("ep4_mul_slide") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		BENCH_ADD(ep4_mul_slide(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
	BENCH_RUN("ep4_mul_monty") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		BENCH_ADD(ep4_mul_monty(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
	BENCH_RUN("ep4_mul_lwnaf") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		BENCH_ADD(ep4_mul_lwnaf(q, p, k));
	} BENCH_END;
#endif

	BENCH_RUN("ep4_mul_gen") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep4_mul_gen(q, k));
	} BENCH_END;

	BENCH_RUN("ep4_mul_cof") {
		ep4_rand(p);
		BENCH_ADD(ep4_mul_cof(q, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_dig") {
		bn_rand(k, RLC_POS, RLC_DIG);
		ep4_rand(p);
		BENCH_ADD(ep4_mul_dig(q, p, k->dp[0]));
	}
	BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep4_new(t[i]);
	}

	BENCH_RUN("ep4_mul_pre") {
		ep4_rand(p);
		BENCH_ADD(ep4_mul_pre(t, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_fix") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		ep4_mul_pre(t, p);
		BENCH_ADD(ep4_mul_fix(q, t, k));
	} BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep4_free(t[i]);
	}

#if EP_FIX == BASIC || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep4_new(t[i]);
	}
	BENCH_RUN("ep4_mul_pre_basic") {
		ep4_rand(p);
		BENCH_ADD(ep4_mul_pre_basic(t, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_fix_basic") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		ep4_mul_pre_basic(t, p);
		BENCH_ADD(ep4_mul_fix_basic(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep4_free(t[i]);
	}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep4_new(t[i]);
	}
	BENCH_RUN("ep4_mul_pre_combs") {
		ep4_rand(p);
		BENCH_ADD(ep4_mul_pre_combs(t, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_fix_combs") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		ep4_mul_pre_combs(t, p);
		BENCH_ADD(ep4_mul_fix_combs(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep4_free(t[i]);
	}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep4_new(t[i]);
	}
	BENCH_RUN("ep4_mul_pre_combd") {
		BENCH_ADD(ep4_mul_pre_combd(t, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_fix_combd") {
		bn_rand_mod(k, n);
		ep4_mul_pre_combd(t, p);
		BENCH_ADD(ep4_mul_fix_combd(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep4_free(t[i]);
	}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep4_new(t[i]);
	}
	BENCH_RUN("ep4_mul_pre_lwnaf") {
		ep4_rand(p);
		BENCH_ADD(ep4_mul_pre_lwnaf(t, p));
	} BENCH_END;

	BENCH_RUN("ep4_mul_fix_lwnaf") {
		bn_rand_mod(k, n);
		ep4_rand(p);
		ep4_mul_pre_lwnaf(t, p);
		BENCH_ADD(ep4_mul_fix_lwnaf(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep4_free(t[i]);
	}
#endif

	BENCH_RUN("ep4_mul_sim") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim(r, p, k, q, l));
	} BENCH_END;

#if EP_SIM == BASIC || !defined(STRIP)
	BENCH_RUN("ep4_mul_sim_basic") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim_basic(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
	BENCH_RUN("ep4_mul_sim_trick") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim_trick(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
	BENCH_RUN("ep4_mul_sim_inter") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim_inter(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
	BENCH_RUN("ep4_mul_sim_joint") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(p);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim_joint(r, p, k, q, l));
	} BENCH_END;
#endif

	BENCH_RUN("ep4_mul_sim_gen") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep4_rand(q);
		BENCH_ADD(ep4_mul_sim_gen(r, k, q, l));
	} BENCH_END;

	BENCH_RUN("ep4_frb") {
		ep4_rand(q);
		BENCH_ADD(ep4_frb(r, q, 1));
	} BENCH_END;

	BENCH_RUN("ep4_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep4_map(p, msg, 5));
	} BENCH_END;

	ep4_free(p);
	ep4_free(q);
	ep4_free(r);
	bn_free(k);
	bn_free(n);
	bn_free(l);
	fp4_free(s);
}

static void memory8(void) {
	ep8_t a[BENCH];

	BENCH_FEW("ep8_null", ep8_null(a[i]), 1);

	BENCH_FEW("ep8_new", ep8_new(a[i]), 1);
	for (int i = 0; i < BENCH; i++) {
		ep8_free(a[i]);
	}

	for (int i = 0; i < BENCH; i++) {
		ep8_new(a[i]);
	}
	BENCH_FEW("ep8_free", ep8_free(a[i]), 1);

	(void)a;
}

static void util8(void) {
	ep8_t p, q, t[2];
	uint8_t bin[16 * RLC_FP_BYTES + 1];
	int l;

	ep8_null(p);
	ep8_null(q);
	ep8_null(t[0]);
	ep8_null(t[1]);

	ep8_new(p);
	ep8_new(q);
	ep8_new(t[0]);
	ep8_new(t[1]);

	BENCH_RUN("ep8_is_infty") {
		ep8_rand(p);
		BENCH_ADD(ep8_is_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep8_set_infty") {
		ep8_rand(p);
		BENCH_ADD(ep8_set_infty(p));
	}
	BENCH_END;

	BENCH_RUN("ep8_copy") {
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_copy(p, q));
	}
	BENCH_END;

	BENCH_RUN("ep8_cmp") {
		ep8_rand(p);
		ep8_dbl(p, p);
		ep8_rand(q);
		ep8_dbl(q, q);
		BENCH_ADD(ep8_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep8_norm") {
		ep8_rand(p);
		ep8_dbl(p, p);
		BENCH_ADD(ep8_norm(p, p));
	} BENCH_END;

	BENCH_RUN("ep8_norm_sim (2)") {
		ep8_rand(t[0]);
		ep8_rand(t[1]);
		ep8_dbl(t[0], t[0]);
		ep8_dbl(t[1], t[1]);
		BENCH_ADD(ep8_norm_sim(t, t, 2));
	} BENCH_END;

	BENCH_RUN("ep8_cmp (1 norm)") {
		ep8_rand(p);
		ep8_dbl(p, p);
		ep8_rand(q);
		BENCH_ADD(ep8_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep8_cmp (2 norm)") {
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_cmp(p, q));
	} BENCH_END;

	BENCH_RUN("ep8_rand") {
		BENCH_ADD(ep8_rand(p));
	}
	BENCH_END;

	BENCH_RUN("ep8_blind") {
		BENCH_ADD(ep8_blind(p, p));
	}
	BENCH_END;

	BENCH_RUN("ep8_on_curve") {
		ep8_rand(p);
		BENCH_ADD(ep8_on_curve(p));
	} BENCH_END;

	BENCH_RUN("ep8_size_bin") {
		ep8_rand(p);
		BENCH_ADD(ep8_size_bin(p, 0));
	} BENCH_END;

	BENCH_RUN("ep8_write_bin") {
		ep8_rand(p);
		l = ep8_size_bin(p, 0);
		BENCH_ADD(ep8_write_bin(bin, l, p, 0));
	} BENCH_END;

	BENCH_RUN("ep8_read_bin") {
		ep8_rand(p);
		l = ep8_size_bin(p, 0);
		ep8_write_bin(bin, l, p, 0);
		BENCH_ADD(ep8_read_bin(p, bin, l));
	} BENCH_END;

	ep8_free(p);
	ep8_free(q);
	ep8_free(t[0]);
	ep8_free(t[1]);
}

static void arith8(void) {
	ep8_t p, q, r, t[RLC_EPX_TABLE_MAX];
	bn_t k, n, l;
	fp8_t s;

	ep8_null(p);
	ep8_null(q);
	ep8_null(r);
	bn_null(k);
	bn_null(n);
	fp8_null(s);
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep8_null(t[i]);
	}

	ep8_new(p);
	ep8_new(q);
	ep8_new(r);
	bn_new(k);
	bn_new(n);
	bn_new(l);
	fp8_new(s);

	ep8_curve_get_ord(n);

	BENCH_RUN("ep8_add") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add(p, p, q);
		ep8_rand(q);
		ep8_rand(p);
		ep8_add(q, q, p);
		BENCH_ADD(ep8_add(r, p, q));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep8_add_basic") {
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_add_basic(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep8_add_slp_basic") {
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_add_slp_basic(r, s, p, q));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep8_add_projc") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add_projc(p, p, q);
		ep8_rand(q);
		ep8_rand(p);
		ep8_add_projc(q, q, p);
		BENCH_ADD(ep8_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep8_add_projc (z2 = 1)") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add_projc(p, p, q);
		ep8_rand(q);
		ep8_norm(q, q);
		BENCH_ADD(ep8_add_projc(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep8_add_projc (z1,z2 = 1)") {
		ep8_rand(p);
		ep8_norm(p, p);
		ep8_rand(q);
		ep8_norm(q, q);
		BENCH_ADD(ep8_add_projc(r, p, q));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep8_sub") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add(p, p, q);
		ep8_rand(q);
		ep8_rand(p);
		ep8_add(q, q, p);
		BENCH_ADD(ep8_sub(r, p, q));
	}
	BENCH_END;

	BENCH_RUN("ep8_dbl") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add(p, p, q);
		BENCH_ADD(ep8_dbl(r, p));
	}
	BENCH_END;

#if EP_ADD == BASIC || !defined(STRIP)
	BENCH_RUN("ep8_dbl_basic") {
		ep8_rand(p);
		BENCH_ADD(ep8_dbl_basic(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep8_dbl_slp_basic") {
		ep8_rand(p);
		BENCH_ADD(ep8_dbl_slp_basic(r, s, p));
	}
	BENCH_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
	BENCH_RUN("ep8_dbl_projc") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add_projc(p, p, q);
		BENCH_ADD(ep8_dbl_projc(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep8_dbl_projc (z1 = 1)") {
		ep8_rand(p);
		ep8_norm(p, p);
		BENCH_ADD(ep8_dbl_projc(r, p));
	}
	BENCH_END;
#endif

	BENCH_RUN("ep8_neg") {
		ep8_rand(p);
		ep8_rand(q);
		ep8_add(p, p, q);
		BENCH_ADD(ep8_neg(r, p));
	}
	BENCH_END;

	BENCH_RUN("ep8_mul") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep8_mul(q, p, k));
	} BENCH_END;

#if EP_MUL == BASIC || !defined(STRIP)
	BENCH_RUN("ep8_mul_basic") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep8_mul_basic(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == SLIDE || !defined(STRIP)
	BENCH_RUN("ep8_mul_slide") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		BENCH_ADD(ep8_mul_slide(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
	BENCH_RUN("ep8_mul_monty") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		BENCH_ADD(ep8_mul_monty(q, p, k));
	} BENCH_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
	BENCH_RUN("ep8_mul_lwnaf") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		BENCH_ADD(ep8_mul_lwnaf(q, p, k));
	} BENCH_END;
#endif

	BENCH_RUN("ep8_mul_gen") {
		bn_rand_mod(k, n);
		BENCH_ADD(ep8_mul_gen(q, k));
	} BENCH_END;

	BENCH_RUN("ep8_mul_cof") {
		ep8_rand(p);
		BENCH_ADD(ep8_mul_cof(q, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_dig") {
		bn_rand(k, RLC_POS, RLC_DIG);
		ep8_rand(p);
		BENCH_ADD(ep8_mul_dig(q, p, k->dp[0]));
	}
	BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep8_new(t[i]);
	}

	BENCH_RUN("ep8_mul_pre") {
		ep8_rand(p);
		BENCH_ADD(ep8_mul_pre(t, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_fix") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		ep8_mul_pre(t, p);
		BENCH_ADD(ep8_mul_fix(q, t, k));
	} BENCH_END;

	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {
		ep8_free(t[i]);
	}

#if EP_FIX == BASIC || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep8_new(t[i]);
	}
	BENCH_RUN("ep8_mul_pre_basic") {
		ep8_rand(p);
		BENCH_ADD(ep8_mul_pre_basic(t, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_fix_basic") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		ep8_mul_pre_basic(t, p);
		BENCH_ADD(ep8_mul_fix_basic(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {
		ep8_free(t[i]);
	}
#endif

#if EP_FIX == COMBS || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep8_new(t[i]);
	}
	BENCH_RUN("ep8_mul_pre_combs") {
		ep8_rand(p);
		BENCH_ADD(ep8_mul_pre_combs(t, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_fix_combs") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		ep8_mul_pre_combs(t, p);
		BENCH_ADD(ep8_mul_fix_combs(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBS; i++) {
		ep8_free(t[i]);
	}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep8_new(t[i]);
	}
	BENCH_RUN("ep8_mul_pre_combd") {
		BENCH_ADD(ep8_mul_pre_combd(t, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_fix_combd") {
		bn_rand_mod(k, n);
		ep8_mul_pre_combd(t, p);
		BENCH_ADD(ep8_mul_fix_combd(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {
		ep8_free(t[i]);
	}
#endif

#if EP_FIX == LWNAF || !defined(STRIP)
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep8_new(t[i]);
	}
	BENCH_RUN("ep8_mul_pre_lwnaf") {
		ep8_rand(p);
		BENCH_ADD(ep8_mul_pre_lwnaf(t, p));
	} BENCH_END;

	BENCH_RUN("ep8_mul_fix_lwnaf") {
		bn_rand_mod(k, n);
		ep8_rand(p);
		ep8_mul_pre_lwnaf(t, p);
		BENCH_ADD(ep8_mul_fix_lwnaf(q, t, k));
	} BENCH_END;
	for (int i = 0; i < RLC_EPX_TABLE_LWNAF; i++) {
		ep8_free(t[i]);
	}
#endif

	BENCH_RUN("ep8_mul_sim") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim(r, p, k, q, l));
	} BENCH_END;

#if EP_SIM == BASIC || !defined(STRIP)
	BENCH_RUN("ep8_mul_sim_basic") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim_basic(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == TRICK || !defined(STRIP)
	BENCH_RUN("ep8_mul_sim_trick") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim_trick(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == INTER || !defined(STRIP)
	BENCH_RUN("ep8_mul_sim_inter") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim_inter(r, p, k, q, l));
	} BENCH_END;
#endif

#if EP_SIM == JOINT || !defined(STRIP)
	BENCH_RUN("ep8_mul_sim_joint") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(p);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim_joint(r, p, k, q, l));
	} BENCH_END;
#endif

	BENCH_RUN("ep8_mul_sim_gen") {
		bn_rand_mod(k, n);
		bn_rand_mod(l, n);
		ep8_rand(q);
		BENCH_ADD(ep8_mul_sim_gen(r, k, q, l));
	} BENCH_END;

	BENCH_RUN("ep8_frb") {
		ep8_rand(q);
		BENCH_ADD(ep8_frb(r, q, 1));
	} BENCH_END;

	BENCH_RUN("ep8_map") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep8_map(p, msg, 5));
	} BENCH_END;

	ep8_free(p);
	ep8_free(q);
	ep8_free(r);
	bn_free(k);
	bn_free(n);
	bn_free(l);
	fp8_free(s);
}

int main(void) {
	int r0, r1, r2, r3;
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the EPX module:", 0);

	if (ep_param_set_any_pairf() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	if ((r0 = ep2_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		memory2();
		util2();

		util_banner("Arithmetic:", 1);
		arith2();
	}

	if ((r1 = ep3_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		memory3();
		util3();

		util_banner("Arithmetic:", 1);
		arith3();
	}

	if ((r2 = ep4_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		memory4();
		util4();

		util_banner("Arithmetic:", 1);
		arith4();
	}

	if ((r3 = ep8_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		memory8();
		util8();

		util_banner("Arithmetic:", 1);
		arith8();
	}

	if (!r0 && !r2 && !r1 && !r3) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	core_clean();
	return 0;
}
