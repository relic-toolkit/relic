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
 * Benchmarks for the Residue Number System module.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"
#include "relic_rns_low.h"

/* Room of the contexts in the benchmarks, in bits. */
#define ROOM	16

static void arith(int bits) {
	const size_t d = RLC_CEIL(bits, RLC_DIG);
	rns_t c;
	bn_t a, b, n, t, u;
	dig_t *x, *y, *z, v[RLC_BN_DIGS];

	bn_null_all(a, b, n, t, u);
	bn_new_all(a, b, n, t, u);

	bn_rand(n, RLC_POS, bits);
	bn_set_bit(n, bits - 1, 1);
	bn_set_bit(n, 0, 1);
	rns_new(c, RLC_RNS_SIZE(bits, ROOM), d);
	x = RLC_ALLOCA(dig_t, 2 * c->o);
	y = RLC_ALLOCA(dig_t, 2 * c->o);
	z = RLC_ALLOCA(dig_t, 2 * c->o);
	if (x == NULL || y == NULL || z == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	util_banner("Arithmetic modulo a random modulus:", 1);
	util_print("(%d bits, %d moduli per base)\n\n", bits, (int)c->n);

	BENCH_FEW("rns_pre", rns_pre(c, n, ROOM), 1);

	BENCH_RUN("rns_conv") {
		bn_rand(a, RLC_POS, bits);
		BENCH_ADD(rns_conv(x, a, c));
	} BENCH_END;

	BENCH_RUN("rns_back") {
		bn_rand(a, RLC_POS, bits);
		rns_conv(x, a, c);
		BENCH_ADD(rns_back(b, x, c));
	} BENCH_END;

#if RLC_ARITH != RLC_AVX512
	BENCH_RUN("rns_set") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		BENCH_ADD(rns_set(x, v, c));
	} BENCH_END;

	BENCH_RUN("rns_get") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(x, v, c);
		BENCH_ADD(rns_get(v, x, c));
	} BENCH_END;

	BENCH_RUN("rns_set_bn") {
		bn_rand_mod(a, n);
		BENCH_ADD(rns_set_bn(x, a, c));
	} BENCH_END;

	BENCH_RUN("rns_get_bn") {
		bn_rand_mod(a, n);
		rns_set_bn(x, a, c);
		BENCH_ADD(rns_get_bn(b, x, c));
	} BENCH_END;

	BENCH_RUN("rns_is_zero") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(x, v, c);
		BENCH_ADD(rns_is_zero(x, c));
	} BENCH_END;

	BENCH_RUN("rns_muln_low") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(x, v, c);
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(y, v, c);
		BENCH_ADD(rns_muln_low(z, x, y, c));
	} BENCH_END;

	BENCH_RUN("rns_rdcn_low") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(x, v, c);
		rns_muln_low(z, x, x, c);
		BENCH_ADD(rns_rdcn_low(y, z, c));
	} BENCH_END;

	BENCH_RUN("rns_mulm_low") {
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(x, v, c);
		bn_rand_mod(a, n);
		bn_write_raw(v, d, a);
		rns_set(y, v, c);
		BENCH_ADD(rns_mulm_low(z, x, y, c));
	} BENCH_END;
#endif

	/* The same multiplication with the reduction of the BN module. */
	bn_mod_pre(u, n);
	BENCH_RUN("bn_mul + bn_mod") {
		bn_rand_mod(a, n);
		bn_rand_mod(b, n);
		BENCH_ADD(bn_mul(t, a, b); bn_mod(t, t, n, u));
	} BENCH_END;

	RLC_FREE(x);
	RLC_FREE(y);
	RLC_FREE(z);
	rns_free(c);
	bn_free_all(a, b, n, t, u);
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the RNS module:", 0);

	if (RLC_WSIZE < 32) {
		util_banner("The module needs digits of at least 32 bits.", 0);
		core_clean();
		return 0;
	}

	arith(1024);
	if (BN_PRECI > 1024) {
		arith(BN_PRECI);
	}

	core_clean();
	return 0;
}
