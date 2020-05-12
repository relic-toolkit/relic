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
 * Benchmarks for random number generation.
 *
 * @ingroup rand
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

static void triple(void) {
	bn_t order;
	mt_t tri[2];

	bn_null(order);
	mt_null(tri[0]);
	mt_null(tri[1]);

	bn_new(order);
	mt_new(tri[0]);
	mt_new(tri[1]);

	bn_gen_prime(order, RLC_BN_BITS);

	BENCH_BEGIN("mt_gen") {
		BENCH_ADD(mt_gen(tri, order));
	} BENCH_END;

	bn_free(order);
	mt_free(order);
	mt_free(order);
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();
	util_banner("Benchmarks for the MPC module:", 0);
	util_banner("Utilities:\n", 0);
	triple();
	core_clean();
	return 0;
}
