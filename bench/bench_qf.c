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
#define BENCH_QF_PRIME	1024

/** Discriminant of the non-maximal order. */
static bn_t bench_d;
/** Fundamental discriminant of the maximal order. */
static bn_t bench_k;
/** Conductor relating the two. */
static bn_t bench_q;
/** A generator of the group with discriminant bench_d. */
static qf_t bench_g;
/** Bound on the exponents, roughly the size of the class number. */
static bn_t bench_n;

/**
 * Builds the pair of discriminants and a generator. Delta_K = -p*q and
 * Delta = Delta_K*q^2, with Delta_K congruent to one modulo four, which asks
 * for exactly one of the two primes to be three modulo four.
 */
static int bench_qf_setup(void) {
	int code = RLC_ERR;
	bn_t p, t, u;
	dig_t l;

	bn_null(p);
	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(p);
		bn_new(t);
		bn_new(u);

		do {
			bn_gen_prime(bench_q, BENCH_QF_COND);
		} while (bn_get_bit(bench_q, 1) != 0);
		do {
			bn_gen_prime(p, BENCH_QF_PRIME);
		} while (bn_get_bit(p, 1) == 0);

		bn_mul(bench_k, p, bench_q);
		bn_neg(bench_k, bench_k);
		bn_mul(bench_d, bench_k, bench_q);
		bn_mul(bench_d, bench_d, bench_q);

		/* the class number is about the square root of the discriminant */
		bn_abs(t, bench_d);
		bn_rsh(bench_n, t, bn_bits(t) / 2);

		for (l = 2; l < 512; l++) {
			if (l > 2 && (l % 2) == 0) {
				continue;
			}
			qf_prime(bench_g, l, bench_d);
			bn_sqr(t, bench_g->b);
			bn_mul(u, bench_g->a, bench_g->c);
			bn_lsh(u, u, 2);
			bn_sub(t, t, u);
			if (bn_cmp(t, bench_d) == RLC_EQ && !qf_is_one(bench_g)) {
				code = RLC_OK;
				break;
			}
		}
	}
	RLC_CATCH_ANY {
		code = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(t);
		bn_free(u);
	}
	return code;
}

/** Replaces f by a random element of the group, off the clock. */
static void bench_qf_rand(qf_t f) {
	bn_t n;

	bn_null(n);
	bn_new(n);
	bn_rand_mod(n, bench_n);
	qf_exp(f, bench_g, n, bench_d);
	bn_free(n);
}

static void util(void) {
	qf_t a, b;

	qf_null(a);
	qf_null(b);

	qf_new(a);
	qf_new(b);

	BENCH_RUN("qf_copy") {
		bench_qf_rand(a);
		BENCH_ADD(qf_copy(b, a));
	} BENCH_END;

	BENCH_RUN("qf_neg") {
		bench_qf_rand(a);
		BENCH_ADD(qf_neg(b, a));
	} BENCH_END;

	BENCH_RUN("qf_cmp") {
		bench_qf_rand(a);
		bench_qf_rand(b);
		BENCH_ADD(qf_cmp(a, b));
	} BENCH_END;

	BENCH_RUN("qf_set_one") {
		BENCH_ADD(qf_set_one(a, bench_d));
	} BENCH_END;

	BENCH_RUN("qf_is_one") {
		bench_qf_rand(a);
		BENCH_ADD(qf_is_one(a));
	} BENCH_END;

	qf_free(a);
	qf_free(b);
}

static void arith(void) {
	qf_t a, b, c, fd, fe, fde;
	bn_t m, n;
	size_t j, sd, se;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	qf_null(fd);
	qf_null(fe);
	qf_null(fde);
	bn_null(m);
	bn_null(n);

	qf_new(a);
	qf_new(b);
	qf_new(c);
	qf_new(fd);
	qf_new(fe);
	qf_new(fde);
	bn_new(m);
	bn_new(n);

	BENCH_RUN("qf_norm") {
		bench_qf_rand(a);
		BENCH_ADD(qf_norm(b, a));
	} BENCH_END;

	BENCH_RUN("qf_rdc") {
		/*
		 * Composition reduces its own result, so its output would exercise only
		 * the test that exits immediately. Exchanging the outer coefficients of
		 * a reduced form keeps the discriminant and leaves a form that fails
		 * both reduction conditions, which is what the loop is meant to fix.
		 */
		bench_qf_rand(a);
		bn_copy(m, a->a);
		bn_copy(a->a, a->c);
		bn_copy(a->c, m);
		BENCH_ADD(qf_rdc(b, a));
	} BENCH_END;

	BENCH_RUN("qf_com") {
		bench_qf_rand(a);
		bench_qf_rand(b);
		BENCH_ADD(qf_com(c, a, b, 0, bench_d));
	} BENCH_END;

	BENCH_RUN("qf_dup") {
		bench_qf_rand(a);
		BENCH_ADD(qf_dup(b, a, bench_d));
	} BENCH_END;

	BENCH_RUN("qf_exp") {
		bench_qf_rand(a);
		bn_rand_mod(n, bench_n);
		BENCH_ADD(qf_exp(b, a, n, bench_d));
	} BENCH_END;

	BENCH_RUN("qf_exp_sim") {
		bench_qf_rand(a);
		bench_qf_rand(b);
		bn_rand_mod(m, bench_n);
		bn_rand_mod(n, bench_n);
		BENCH_ADD(qf_exp_sim(c, a, m, b, n, bench_d));
	} BENCH_END;

	/*
	 * The four-way comb reads the exponent in blocks at offsets 0, se, sd and
	 * sd + se, so the tables hold the base raised to those powers of two and the
	 * offsets have to span the exponent. Building them is part of a fixed-base
	 * precomputation and is therefore left off the clock.
	 */
	bn_rand_mod(n, bench_n);
	se = (bn_bits(bench_n) + 3) / 4 + 1;
	sd = 2 * se;
	bench_qf_rand(a);
	qf_copy(fe, a);
	for (j = 0; j < se; j++) {
		qf_dup(fe, fe, bench_d);
	}
	qf_copy(fd, a);
	for (j = 0; j < sd; j++) {
		qf_dup(fd, fd, bench_d);
	}
	qf_copy(fde, fd);
	for (j = 0; j < se; j++) {
		qf_dup(fde, fde, bench_d);
	}

	BENCH_RUN("qf_exp_fix") {
		bn_rand_mod(n, bench_n);
		BENCH_ADD(qf_exp_fix(b, a, n, sd, se, fe, fd, fde, bench_d));
	} BENCH_END;

	qf_free(a);
	qf_free(b);
	qf_free(c);
	qf_free(fd);
	qf_free(fe);
	qf_free(fde);
	bn_free(m);
	bn_free(n);
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
		bench_qf_rand(a);
		BENCH_ADD(qf_copa(b, a, bench_q));
	} BENCH_END;

	BENCH_RUN("qf_lift") {
		bench_qf_rand(a);
		qf_phi(a, a, bench_q, bench_k, 1);
		BENCH_ADD(qf_lift(b, a, bench_q));
	} BENCH_END;

	BENCH_RUN("qf_psi") {
		bench_qf_rand(a);
		BENCH_ADD(qf_psi(b, a, bench_q, bench_k));
	} BENCH_END;


	BENCH_RUN("qf_phi") {
		bench_qf_rand(a);
		BENCH_ADD(qf_phi(b, a, bench_q, bench_k, 1));
	} BENCH_END;

	BENCH_RUN("qf_kern") {
		bn_sqr(n, bench_q);
		qf_set_dsc(a, n, bench_q, bench_d);
		bn_rand_mod(n, bench_q);
		qf_exp(b, a, n, bench_d);
		BENCH_ADD(qf_kern(m, b, bench_q, bench_k));
	} BENCH_END;

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

	bn_null(bench_d);
	bn_null(bench_k);
	bn_null(bench_q);
	bn_null(bench_n);
	qf_null(bench_g);
	bn_new(bench_d);
	bn_new(bench_k);
	bn_new(bench_q);
	bn_new(bench_n);
	qf_new(bench_g);

	if (bench_qf_setup() != RLC_OK) {
		util_print("FATAL ERROR!\n");
		core_clean();
		return 1;
	}

	util_print("\n-- Discriminant of %zu bits, conductor of %zu bits.\n\n",
			bn_bits(bench_d), bn_bits(bench_q));

	util_banner("Utilities:\n", 0);
	util();

	util_banner("Arithmetic:\n", 0);
	arith();

	util_banner("Maps between orders:\n", 0);
	orders();

	bn_free(bench_d);
	bn_free(bench_k);
	bn_free(bench_q);
	bn_free(bench_n);
	qf_free(bench_g);

	core_clean();
	return 0;
}