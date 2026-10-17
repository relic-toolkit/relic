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
 * Benchmarks for cryptographic protocols based on accumulators.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

#define M	256			/* Number of server messages (larger). */
#define N	8			/* Number of client messages. */

static void psi(void) {
	bn_t g, n, q, r, p[M], x[M], v[N], w[N], y[N], z[M];
	g1_t u[M], ss;
	g2_t d[M + 1], s[M + 1];
	gt_t t[M];
	crt_t crt;
	size_t len;

	bn_new(g);
	bn_new(n);
	bn_new(q);
	bn_new(r);
	g1_new(ss);
	for (int i = 0; i < M; i++) {
		bn_null(p[i]);
		bn_null(x[i]);
		bn_null(z[i]);
		g2_null(d[i]);
		g2_null(s[i]);
		bn_new(p[i]);
		bn_new(x[i]);
		bn_new(z[i]);
		g2_new(d[i]);
		g2_new(s[i]);
	}
	g2_null(d[M]);
	g2_new(d[M]);
	g2_null(s[M]);
	g2_new(s[M]);
	for (int i = 0; i < N; i++) {
		bn_null(v[i]);
		bn_null(w[i]);
		bn_null(y[i]);
		g1_null(u[i]);
		gt_null(t[i]);
		bn_new(v[i]);
		bn_new(w[i]);
		bn_new(y[i]);
		g1_new(u[i]);
		gt_new(t[i]);
	}
	crt_new(crt);

	pc_get_ord(q);
	for (int j = 0; j < M; j++) {
		bn_rand_mod(x[j], q);
	}
	for (int j = 0; j < N; j++) {
		bn_rand_mod(y[j], q);
	}

	BENCH_ONE("cp_rsapsi_gen", cp_rsapsi_gen(g, n, RLC_BN_BITS), 1);

	BENCH_RUN("cp_rsapsi_ask (M)") {
		BENCH_ADD(cp_rsapsi_ask(q, r, p, g, n, x, M));
	} BENCH_END;

	BENCH_RUN("cp_rsapsi_ans (N)") {
		BENCH_ADD(cp_rsapsi_ans(v, w, q, g, n, y, N));
	} BENCH_END;

	BENCH_RUN("cp_rsapsi_int") {
		BENCH_ADD(cp_rsapsi_int(z, &len, r, p, n, x, M, v, w, N));
	} BENCH_END;

	BENCH_ONE("cp_shipsi_gen", cp_shipsi_gen(g, crt, RLC_BN_BITS), 1);

	BENCH_RUN("cp_shipsi_ask (M)") {
		BENCH_ADD(cp_shipsi_ask(q, r, p, g, crt->n, x, M));
	} BENCH_END;

	BENCH_RUN("cp_shipsi_ans (N)") {
		BENCH_ADD(cp_shipsi_ans(v, w[0], q, g, crt, y, N));
	} BENCH_END;

	BENCH_RUN("cp_shipsi_int") {
		BENCH_ADD(cp_shipsi_int(z, &len, r, p, crt->n, x, M, v, w[0], N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_gen (M)") {
		BENCH_ADD(cp_pbpsi_gen(q, ss, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ask (M)") {
		BENCH_ADD(cp_pbpsi_ask(d, r, x, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ans (N)") {
		BENCH_ADD(cp_pbpsi_ans(t, u, ss, d[0], y, N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_int") {
		BENCH_ADD(cp_pbpsi_int(z, &len, d, x, M, t, u, N));
	} BENCH_END;

	bn_free(g);
	bn_free(n);
	bn_free(q);
	bn_free(r);
	g1_free(ss);
	for (int i = 0; i < M; i++) {
		bn_free(p[i]);
		bn_free(x[i]);
		bn_free(z[i]);
		g2_free(d[i]);
		g2_free(s[i]);
	}
	g2_free(d[M]);
	g2_free(s[M]);
	for (int i = 0; i < N; i++) {
		bn_free(v[i]);
		bn_free(w[i]);
		bn_free(y[i]);
		g1_free(u[i]);
		gt_free(t[i]);
	}
	crt_free(crt);
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

	if (pc_param_set_any() == RLC_OK) {
		util_banner("Protocols based on accumulators:\n", 0);
		psi();
	}

	core_clean();
	return 0;
}
