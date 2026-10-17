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
 * Benchmarks for cryptographic protocols.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

#define MAX_KEYS	2048

#include "assert.h"

static void ers(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS];
	bn_t sk[MAX_KEYS], td;
	ers_t ring[MAX_KEYS];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };

	bn_null(td);
	ec_null(pp);

	bn_new(td);
	ec_new(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_null(sk[i]);
		bn_new(sk[i]);
		ec_null(pk[i]);
		ec_new(pk[i]);
		ers_null(ring[i]);
		ers_new(ring[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	util_banner("Signature time:\n", 0);
	bench_reset();
	for (int j = 0; j < RLC_BENCH; j++)	{
		BENCH_ADD(cp_ers_sig(td, ring[0], m, 5, sk[0], pk[0], pp));
	}
	bench_compute(RLC_BENCH * RLC_BENCH);
	util_print("{\"1\": {\"time\": %lf, \"size\": null}", bench_total()/(double)1000000);

	for (int j = 1; j < MAX_KEYS; j = j << 1) {
		size = j;
		bench_before();
		for (int k = 0; k < j; k++) {
			cp_ers_ext(td, ring, &size, m, 5, pk[size]);
		}
		bench_after();
		bench_compute(1);
		util_print(", \"%d\": {\"time\": %lf, \"size\": null}", size, bench_total()/(double)1000000);
		assert(cp_ers_ver(td, ring, size, m, 5, pp));
	}
	util_print("}\n\n");

	util_banner("Verification time/signature size:\n", 0);
	/* Recompute the signature for verification. */
	cp_ers_sig(td, ring[0], m, 5, sk[0], pk[0], pp);
	bench_reset();
	for (int j = 0; j < RLC_BENCH; j++)	{
		BENCH_ADD(assert(cp_ers_ver(td, ring, 1, m, 5, pp)));
	}
	bench_compute(RLC_BENCH * RLC_BENCH);
	util_print("{\"1\": {\"time\": %lf, \"size\": %d}", bench_total()/(double)1000000, 10 * RLC_FP_BYTES);

	for (int j = 1; j < MAX_KEYS; j = j << 1) {
		size = j;
		/* Recompute the signatures for verification. */
		for (int k = 0; k < j; k++) {
			assert(cp_ers_ext(td, ring, &size, m, 5, pk[size]) == RLC_OK);
		}
		assert(cp_ers_ver(td, ring, size, m, 5, pp));
		bench_reset();
		for (int i = 0; i < RLC_BENCH; i++)	{
			BENCH_ADD(cp_ers_ver(td, ring, size, m, 5, pp));
		}
		bench_compute(RLC_BENCH * RLC_BENCH);
		/* nonce and td are shared, the rest varies per signature. */
		util_print(", \"%d\": {\"time\": %lf, \"size\": %d}", size, bench_total()/(double)1000000, 2 * RLC_FP_BYTES + size * 8 * RLC_FP_BYTES);
	}
	util_print("}\n\n");

	bn_free(td);
	ec_free(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_free(sk[i]);
		ec_free(pk[i]);
		ers_free(ring[i])
	}
}

static void smlers(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS];
	bn_t sk[MAX_KEYS], td[MAX_KEYS], y[MAX_KEYS];
	smlers_t ring[MAX_KEYS];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };

	ec_null(pp);
	ec_new(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_null_all(y[i], td[i], sk[i]);
		bn_new_all(y[i], td[i], sk[i]);
		ec_null(pk[i]);
		ec_new(pk[i]);
		smlers_null(ring[i]);
		smlers_new(ring[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	util_banner("Signature time:\n", 0);
	for (int l = 1; l <= 8; l = l << 1) {
		util_print("- Threshold %d:\n {", l);
		for (int j = l; j <= MAX_KEYS; j = j << 1) {
			bench_reset();
			bench_before();
			size = 1;
			for (int k = 0; k < 1; k++) {
				cp_smlers_sig(td[0], ring[0], m, 5, sk[0], pk[0], pp);
			}
			for (int k = 1; k < j; k++) {
				cp_smlers_ext(td[0], ring, &size, m, 5, pk[size]);
			}
			bench_after();
			bench_compute(1);
			util_print("\"%d\": {\"time\": %lf, \"size\": null}", j, l * bench_total()/(double)1000000);
			if (j < MAX_KEYS) {
				util_print(", ");
			}
			for (int k = 0; k < l; k++) {
				assert(cp_smlers_ver(td[0], ring, size, m, 5, pp));
			}
		}
		util_print("}\n\n");
	}

	util_banner("Verification time/signature size:\n", 0);
	for (int l = 1; l <= 8; l = l << 1) {
		util_print("- Threshold %d:\n {", l);
		for (int j = l; j <= MAX_KEYS; j = j << 1) {
			size = 1;
			for (int k = 0; k < 1; k++) {
				cp_smlers_sig(td[0], ring[0], m, 5, sk[0], pk[0], pp);
			}
			for (int k = 1; k < j; k++) {
				cp_smlers_ext(td[0], ring, &size, m, 5, pk[size]);
			}
			bench_reset();
			bench_before();
			for (int i = 0; i < RLC_BENCH; i++)	{
				for (int k = 0; k < l; k++) {
					cp_smlers_ver(td[0], ring, size, m, 5, pp);
				}
			}
			bench_after();
			bench_compute(RLC_BENCH);
			util_print("\"%d\": {\"time\": %lf, \"size\": %d}", j, bench_total()/(double)1000000, l * (2 * RLC_FP_BYTES + size * 10 * RLC_FP_BYTES));
			if (j < MAX_KEYS) {
				util_print(", ");
			}
		}
		util_print("}\n\n");
	}

	ec_free(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_free_all(td[i], y[i], sk[i]);
		ec_free(pk[i]);
		smlers_free(ring[i]);
	}
}

#undef MAX_KEYS
#define MAX_KEYS	2048
#define MIN_KEYS	64

static void etrs(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS], com[MAX_KEYS];
	bn_t sk[MAX_KEYS], td[MAX_KEYS], y[MAX_KEYS];
	etrs_t ring[MAX_KEYS];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };

	ec_null(pp);
	ec_new(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_null_all(y[i], td[i], sk[i]);
		bn_new_all(y[i], td[i], sk[i]);
		ec_null_all(pk[i], com[i]);
		ec_new_all(pk[i], com[i]);
		etrs_null(ring[i]);
		etrs_new(ring[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	util_banner("Signature time:\n", 0);

	util_print("- Threshold 1:\n {");
	bench_reset();
	for (int i = 0; i < RLC_BENCH; i++)	{
		BENCH_ADD(cp_etrs_sig(td, y, 1, ring[0], com, m, 5, sk[0], pk[0], pp));
	}
	bench_compute(RLC_BENCH * RLC_BENCH);
	util_print("\"1\": {\"time\": %lf, \"size\": null}", bench_total()/(double)1000000);
	assert(cp_etrs_ver(1, td, y, 1, ring, 1, com, m, 5, pp));

	for (int j = 2; j <= MAX_KEYS; j = j << 1) {
		bench_reset();
		bench_before();
		for (int i = 0; i < RLC_BENCH; i++)	{
			cp_etrs_sig(td, y, j, ring[0], com, m, 5, sk[0], pk[0], pp);
		}
		bench_after();
		bench_compute(RLC_BENCH);
		util_print(", \"%d\": {\"time\": %lf, \"size\": null}", j, bench_total()/(double)1000000);
		assert(cp_etrs_ver(1, td, y, j, ring, 1, com, m, 5, pp));
	}
	util_print("}\n\n");

	for (int l = 2; l <= 8; l = l << 1) {
		util_print("- Threshold %d:\n {", l);
		for (int j = l; j <= MAX_KEYS; j = j << 1) {
			bench_reset();
			bench_before();
			size = 1;
			cp_etrs_sig(td, y, j, ring[0], com, m, 5, sk[0], pk[0], pp);
			for (int k = 1; k < l; k++) {
				cp_etrs_uni(td, y, j, ring, &size, com, m, 5, sk[k], pk[k]);
			}
			for (int k = l; k < j; k++) {
				cp_etrs_ext(td, y, j, ring, &size, com, m, 5, pk[size]);
			}
			bench_after();
			bench_compute(1);
			util_print("\"%d\": {\"time\": %lf, \"size\": null}", j, bench_total()/(double)1000000);
			if (j < MAX_KEYS) {
				util_print(", ");
			}
			assert(cp_etrs_ver(l, td, y, j, ring, size, com, m, 5, pp));
		}
		util_print("}\n\n");
	}

	util_banner("Verification time/signature size:\n", 0);
	for (int l = 1; l <= 8; l = l << 1) {
		util_print("- Threshold %d:\n {", l);
		for (int j = l; j <= MAX_KEYS; j = j << 1) {
			size = 1;
			cp_etrs_sig(td, y, j, ring[0], com, m, 5, sk[0], pk[0], pp);
			for (int k = 1; k < l; k++) {
				cp_etrs_uni(td, y, j, ring, &size, com, m, 5, sk[k], pk[k]);
			}
			for (int k = l; k < j; k++) {
				cp_etrs_ext(td, y, j, ring, &size, com, m, 5, pk[size]);
			}
			bench_reset();
			bench_before();
			for (int i = 0; i < RLC_BENCH; i++)	{
				cp_etrs_ver(l, td, y, j, ring, size, com, m, 5, pp);
			}
			bench_after();
			bench_compute(RLC_BENCH);
			util_print("\"%d\": {\"time\": %lf, \"size\": %d}", j, bench_total()/(double)1000000, size * 13 * RLC_FP_BYTES + j * 2 * RLC_FP_BYTES);
			if (j < MAX_KEYS) {
				util_print(", ");
			}
		}
		util_print("}\n\n");
	}

	ec_free(pp);
	for (int i = 0; i < MAX_KEYS; i++) {
		bn_free_all(td[i], y[i], sk[i]);
		ec_free_all(pk[i], com[i]);
		etrs_free(ring[i])
	}
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	if (ec_param_set_any() == RLC_OK) {
		util_banner("ERS module", 1);
		ers();
		util_banner("SMLERS module", 1);
		smlers();
		util_banner("ETRS module", 1);
		etrs();
	} else {
		RLC_THROW(ERR_NO_CURVE);
	}

	core_clean();
	return 0;
}
