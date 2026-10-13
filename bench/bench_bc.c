/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Benchmarks for the block cipher module.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

static void aes(void) {
	uint8_t key[32], iv[RLC_BC_LEN], in[256], out[256 + RLC_BC_LEN];
	size_t out_len, in_len;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	BENCH_RUN("bc_aes_cbc_enc (256)") {
		rand_bytes(in, sizeof(in));
		out_len = sizeof(out);
		BENCH_ADD(bc_aes_cbc_enc(out, &out_len, in, sizeof(in), key, 16, iv));
	} BENCH_END;

	BENCH_RUN("bc_aes_cbc_dec (256)") {
		rand_bytes(in, sizeof(in));
		out_len = sizeof(out);
		bc_aes_cbc_enc(out, &out_len, in, sizeof(in), key, 16, iv);
		in_len = sizeof(in);
		BENCH_ADD(bc_aes_cbc_dec(in, &in_len, out, out_len, key, 16, iv));
	} BENCH_END;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();
	util_banner("Benchmarks for the BC module:\n", 0);
	aes();
	core_clean();
	return 0;
}
