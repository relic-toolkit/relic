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
 * or <https://www.apache.org/licenses/>
 */

/**
 * @file
 *
 * Benchmarks for arithmetic on binary quadratic forms.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

/**
 * Size in bits of the conductor, which is also the size of the exponents in the
 * kernel of the projection onto the maximal order.
 */
#define BENCH_QF_COND	256
/**
 * Size in bits of the other factor of the fundamental discriminant, chosen so
 * that the non-maximal discriminant reaches the width a 128-bit security level
 * calls for.
 */
#define BENCH_QF_PRIME	(1024 + BENCH_QF_COND)

static void util(void) {
	qf_t a, b;

	qf_null(a);
	qf_null(b);

	qf_new(a);
	qf_new(b);

	BENCH_RUN("qf_copy") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_copy(b, a));
	} BENCH_END;

	BENCH_RUN("qf_neg") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_neg(b, a));
	} BENCH_END;

	BENCH_RUN("qf_cmp") {
		qf_rand(a, &(core_get()->qf_d));
		qf_rand(b, &(core_get()->qf_d));
		BENCH_ADD(qf_cmp(a, b));
	} BENCH_END;

	BENCH_RUN("qf_set_one") {
		BENCH_ADD(qf_set_one(a, &(core_get()->qf_d)));
	} BENCH_END;

	BENCH_RUN("qf_is_one") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_is_one(a));
	} BENCH_END;

	qf_free(a);
	qf_free(b);
}

static void arith(void) {
	qf_t a, b, c, fd, fe, fde;
	bn_t m, n, class;
	size_t j, sd, se;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	qf_null(fd);
	qf_null(fe);
	qf_null(fde);
	bn_null(m);
	bn_null(n);
	bn_null(class);

	qf_new(a);
	qf_new(b);
	qf_new(c);
	qf_new(fd);
	qf_new(fe);
	qf_new(fde);
	bn_new(m);
	bn_new(n);
	bn_new(class);

	/* the class number is about the square root of the discriminant */
	bn_abs(class, &(core_get()->qf_d));
	bn_rsh(class, class, bn_bits(class) / 2);

	BENCH_RUN("qf_norm") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_norm(b, a));
	} BENCH_END;

	BENCH_RUN("qf_rdc") {
		/*
		 * Composition reduces its own result, so its output would exercise only
		 * the test that exits immediately. Exchanging the outer coefficients of
		 * a reduced form keeps the discriminant and leaves a form that fails
		 * both reduction conditions, which is what the loop is meant to fix.
		 */
		qf_rand(a, &(core_get()->qf_d));
		bn_copy(m, a->a);
		bn_copy(a->a, a->c);
		bn_copy(a->c, m);
		BENCH_ADD(qf_rdc(b, a));
	} BENCH_END;

	BENCH_RUN("qf_com") {
		qf_rand(a, &(core_get()->qf_d));
		qf_rand(b, &(core_get()->qf_d));
		BENCH_ADD(qf_com(c, a, b, 0, &(core_get()->qf_b)));
	} BENCH_END;

	BENCH_RUN("qf_dup") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_dup(b, a, &(core_get()->qf_b)));
	} BENCH_END;

	BENCH_RUN("qf_exp") {
		qf_rand(a, &(core_get()->qf_d));
		bn_rand_mod(n, class);
		BENCH_ADD(qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b)));
	} BENCH_END;

	BENCH_RUN("qf_exp_sim") {
		qf_rand(a, &(core_get()->qf_d));
		qf_rand(b, &(core_get()->qf_d));
		bn_rand_mod(m, class);
		bn_rand_mod(n, class);
		BENCH_ADD(qf_exp_sim(c, a, m, b, n, &(core_get()->qf_d), &(core_get()->qf_b)));
	} BENCH_END;

	/*
	 * The four-way comb reads the exponent in blocks at offsets 0, se, sd and
	 * sd + se, so the tables hold the base raised to those powers of two and the
	 * offsets have to span the exponent. Building them is part of a fixed-base
	 * precomputation and is therefore left off the clock.
	 */
	bn_rand_mod(n, class);
	se = (bn_bits(class) + 3) / 4 + 1;
	sd = 2 * se;
	qf_rand(a, &(core_get()->qf_d));
	qf_copy(fe, a);
	for (j = 0; j < se; j++) {
		qf_dup(fe, fe, &(core_get()->qf_b));
	}
	qf_copy(fd, a);
	for (j = 0; j < sd; j++) {
		qf_dup(fd, fd, &(core_get()->qf_b));
	}
	qf_copy(fde, fd);
	for (j = 0; j < se; j++) {
		qf_dup(fde, fde, &(core_get()->qf_b));
	}

	BENCH_RUN("qf_exp_fix") {
		bn_rand_mod(n, class);
		BENCH_ADD(qf_exp_fix(b, a, n, sd, se, fe, fd, fde, &(core_get()->qf_d), &(core_get()->qf_b)));
	} BENCH_END;

	qf_free(a);
	qf_free(b);
	qf_free(c);
	qf_free(fd);
	qf_free(fe);
	qf_free(fde);
	bn_free(m);
	bn_free(n);
	bn_free(class);
}

static void orders(void) {
	qf_t a, b;
	bn_t m, n;

	qf_null(a);
	qf_null(b);
	bn_null(m);
	bn_null(n);

	qf_new(a);
	qf_new(b);
	bn_new(m);
	bn_new(n);

	/*
	 * These three take their argument in place, and BENCH_ADD repeats the
	 * statement, so each would be applied to its own output: lifting twice
	 * multiplies the last coefficient by the conductor squared again and runs
	 * away. The restoring copy is inside the timed statement for that reason,
	 * and costs a few nanoseconds against operations that run a whole extended
	 * greatest common divisor.
	 */
	BENCH_RUN("qf_copa") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_copa(b, a));
	} BENCH_END;

	BENCH_RUN("qf_lift") {
		qf_rand(a, &(core_get()->qf_d));
		qf_phi(a, a, 1);
		BENCH_ADD(qf_lift(b, a));
	} BENCH_END;

	BENCH_RUN("qf_psi") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_psi(b, a, &(core_get()->qf_dk), &(core_get()->qf_bk)));
	} BENCH_END;


	BENCH_RUN("qf_phi") {
		qf_rand(a, &(core_get()->qf_d));
		BENCH_ADD(qf_phi(b, a, 1));
	} BENCH_END;

	BENCH_RUN("qf_kern") {
		bn_sqr(n, &(core_get()->qf_q));
		qf_set_dsc(a, n, &(core_get()->qf_q), &(core_get()->qf_d));
		bn_rand_mod(n, &(core_get()->qf_q));
		qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
		BENCH_ADD(qf_kern(m, b));
	} BENCH_END;

	BENCH_RUN("qf_map") {
		uint8_t msg[32];
		rand_bytes(msg, sizeof(msg));
		BENCH_ADD(qf_map(a, msg, sizeof(msg), &(core_get()->qf_dk),
				bn_bits(&(core_get()->qf_dk)) / 2));
	}
	BENCH_END;

	qf_free(a);
	qf_free(b);
	bn_free(m);
	bn_free(n);
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();
	util_banner("Benchmarks for the QF module:", 0);

	if (qf_group_gen(BENCH_QF_COND, BENCH_QF_PRIME) != RLC_OK) {
		core_clean();
		return 1;
	}

	util_print("\n-- Discriminant of %zu bits, conductor of %zu bits.\n\n",
			bn_bits(&(core_get()->qf_d)), bn_bits(&(core_get()->qf_q)));

	util_banner("Utilities:\n", 0);
	util();

	util_banner("Arithmetic:\n", 0);
	arith();

	util_banner("Maps between orders:\n", 0);
	orders();

	core_clean();
	return 0;
}
