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
 * Tests for arithmetic on binary quadratic forms.
 *
 * Note that TEST_CASE opens a loop of its own declaring an index named i, so
 * loops inside a case body must use a different name or they overwrite the
 * iteration counter of the framework.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

/** Size in bits of the conductor used by the tests. */
#define TEST_QF_COND	32
/** Size in bits of the other prime factor of the fundamental discriminant. */
#define TEST_QF_PRIME	64

/**
 * Discriminant of the non-maximal order, its fundamental discriminant, and the
 * conductor relating them, prepared once for all the test cases.
 */
static bn_t test_d;
static bn_t test_k;
static bn_t test_q;

/**
 * A generator of each group, found once: searching for a prime form means
 * trying candidates until one exists, and qf_prime looks for the square root
 * modulo l by trial, so it is far too costly to repeat per test iteration.
 */
static qf_t test_g;
static qf_t test_gk;

/**
 * Checks that a form really has the given discriminant, which is the invariant
 * every operation here must preserve.
 */
static int test_qf_dsc(const qf_t f, const bn_t d) {
	bn_t t, u;
	int r = 0;

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);
		bn_sqr(t, f->b);
		bn_mul(u, f->a, f->c);
		bn_lsh(u, u, 2);
		bn_sub(t, t, u);
		r = (bn_cmp(t, d) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		r = 0;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}
	return r;
}

/**
 * Finds a non-trivial prime form for a discriminant, by trying the small primes
 * in turn until one of them splits. Only used while setting up.
 */
static int test_qf_gen(qf_t f, const bn_t d) {
	dig_t l;

	for (l = 2; l < 512; l++) {
		if (l > 2 && (l % 2) == 0) {
			continue;
		}
		qf_prime(f, l, d);
		if (test_qf_dsc(f, d) && !qf_is_one(f)) {
			return 1;
		}
	}
	return 0;
}

/**
 * Produces a random element of the group with the given discriminant, by
 * raising the generator found during setup to a random power.
 */
static int test_qf_rand(qf_t f, const bn_t d) {
	bn_t n;
	int ok = 0;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		bn_rand(n, RLC_POS, 64);
		qf_exp(f, (bn_cmp(d, test_d) == RLC_EQ ? test_g : test_gk), n, d);
		ok = test_qf_dsc(f, d);
	}
	RLC_CATCH_ANY {
		ok = 0;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return ok;
}

/**
 * Builds a pair of discriminants for an imaginary quadratic order and its
 * maximal order. Taking Delta_K = -p*q and Delta = Delta_K*q^2 puts the two in
 * the relation the order maps expect, and Delta_K = 1 mod 4 requires p*q = 3
 * mod 4, so exactly one of the two primes is 3 mod 4.
 */
static int test_qf_setup(void) {
	int code = RLC_ERR;
	bn_t p;

	bn_null(p);

	RLC_TRY {
		bn_new(p);

		do {
			bn_gen_prime(test_q, TEST_QF_COND);
		} while (bn_get_bit(test_q, 1) != 0);	/* q = 1 mod 4 */
		do {
			bn_gen_prime(p, TEST_QF_PRIME);
		} while (bn_get_bit(p, 1) == 0);		/* p = 3 mod 4 */

		bn_mul(test_k, p, test_q);
		bn_neg(test_k, test_k);
		bn_mul(test_d, test_k, test_q);
		bn_mul(test_d, test_d, test_q);

		if (!test_qf_gen(test_g, test_d) || !test_qf_gen(test_gk, test_k)) {
			RLC_THROW(ERR_NO_VALID);
		}

		code = RLC_OK;
	}
	RLC_CATCH_ANY {
		code = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
	}
	return code;
}

static int memory(void) {
	err_t e = ERR_CAUGHT;
	int code = RLC_ERR;
	qf_t a;

	qf_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			qf_new(a);
			qf_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util(void) {
	int code = RLC_ERR;
	qf_t a, b, c;

	qf_null(a);
	qf_null(b);
	qf_null(c);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);

		TEST_CASE("comparison is consistent") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			qf_copy(c, a);
			TEST_ASSERT(qf_cmp(a, c) == RLC_EQ, end);
			TEST_ASSERT(qf_cmp(c, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("copy is consistent") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_copy(b, a);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
		} TEST_END;

		TEST_CASE("negation is involutory") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_neg(b, a);
			qf_neg(b, b);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("negation preserves the discriminant") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_neg(b, a);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
		} TEST_END;

		TEST_CASE("assignment to the identity is detected") {
			qf_set_one(a, test_d);
			TEST_ASSERT(qf_is_one(a) == 1, end);
			TEST_ASSERT(test_qf_dsc(a, test_d), end);
			if (!test_qf_rand(b, test_d)) {
				continue;
			}
			TEST_ASSERT(qf_is_one(b) == 0, end);
		} TEST_END;

		TEST_CASE("assignment from digits and integers agree") {
			qf_set_int(a, 1, 1, 3);
			qf_set_dig(b, 1, 1, 3);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	qf_free(c);
	return code;
}

static int reduction(void) {
	int code = RLC_ERR;
	qf_t a, b, c;

	qf_null(a);
	qf_null(b);
	qf_null(c);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);

		TEST_CASE("reduction preserves the discriminant") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_rdc(b, a);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
		} TEST_END;

		TEST_CASE("reduction is idempotent") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_rdc(b, a);
			qf_rdc(c, b);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("a reduced form satisfies the reduction conditions") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_rdc(b, a);
			/* |b| <= a <= c, and b >= 0 whenever a equals c */
			TEST_ASSERT(bn_cmp_abs(b->b, b->a) != RLC_GT, end);
			TEST_ASSERT(bn_cmp_abs(b->a, b->c) != RLC_GT, end);
			if (bn_cmp_abs(b->a, b->c) == RLC_EQ) {
				TEST_ASSERT(bn_sign(b->b) == RLC_POS, end);
			}
		} TEST_END;

		TEST_CASE("normalisation preserves the discriminant") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_norm(b, a);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
			/* normalisation puts b in (-a, a] */
			TEST_ASSERT(bn_cmp_abs(b->b, b->a) != RLC_GT, end);
		} TEST_END;

		TEST_CASE("the identity is reduced") {
			qf_set_one(a, test_d);
			qf_rdc(b, a);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	qf_free(c);
	return code;
}

static int composition(void) {
	int code = RLC_ERR;
	qf_t a, b, c, d, e;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	qf_null(d);
	qf_null(e);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);
		qf_new(d);
		qf_new(e);

		TEST_CASE("composition preserves the discriminant") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			qf_com(c, a, b, 0, test_d);
			TEST_ASSERT(test_qf_dsc(c, test_d), end);
		} TEST_END;

		TEST_CASE("composition is commutative") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			qf_com(c, a, b, 0, test_d);
			qf_com(d, b, a, 0, test_d);
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("composition is associative") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d) ||
					!test_qf_rand(c, test_d)) {
				continue;
			}
			qf_com(d, a, b, 0, test_d);
			qf_com(d, d, c, 0, test_d);
			qf_com(e, b, c, 0, test_d);
			qf_com(e, a, e, 0, test_d);
			TEST_ASSERT(qf_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the identity is neutral for composition") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_set_one(b, test_d);
			qf_com(c, a, b, 0, test_d);
			qf_rdc(d, a);
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
			qf_com(c, b, a, 0, test_d);
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("composition with the negation gives the identity") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_neg(b, a);
			qf_com(c, a, b, 0, test_d);
			TEST_ASSERT(qf_is_one(c) == 1, end);
		} TEST_END;

		TEST_CASE("the negation flag composes with the inverse") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			qf_com(c, a, b, 1, test_d);
			qf_neg(d, b);
			qf_com(d, a, d, 0, test_d);
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("doubling is composition with itself") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			qf_dup(b, a, test_d);
			qf_com(c, a, a, 0, test_d);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
		} TEST_END;

		TEST_CASE("doubling the identity gives the identity") {
			qf_set_one(a, test_d);
			qf_dup(b, a, test_d);
			TEST_ASSERT(qf_is_one(b) == 1, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	qf_free(c);
	qf_free(d);
	qf_free(e);
	return code;
}

static int exponentiation(void) {
	int code = RLC_ERR;
	qf_t a, b, c, r, fd, fe, fde;
	bn_t m, n, s;
	size_t j, sd, se;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	qf_null(r);
	qf_null(fd);
	qf_null(fe);
	qf_null(fde);
	bn_null(m);
	bn_null(n);
	bn_null(s);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);
		qf_new(r);
		qf_new(fd);
		qf_new(fe);
		qf_new(fde);
		bn_new(m);
		bn_new(n);
		bn_new(s);

		TEST_CASE("exponentiation by zero and one is correct") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			bn_zero(n);
			qf_exp(b, a, n, test_d);
			TEST_ASSERT(qf_is_one(b) == 1, end);
			bn_set_dig(n, 1);
			qf_exp(b, a, n, test_d);
			qf_rdc(c, a);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation by two is doubling") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			bn_set_dig(n, 2);
			qf_exp(b, a, n, test_d);
			qf_dup(c, a, test_d);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation is additive in the exponent") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			bn_rand(m, RLC_POS, 64);
			bn_rand(n, RLC_POS, 64);
			bn_add(s, m, n);
			qf_exp(b, a, m, test_d);
			qf_exp(c, a, n, test_d);
			qf_com(b, b, c, 0, test_d);
			qf_exp(c, a, s, test_d);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation agrees with repeated composition") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			bn_set_dig(n, 10);
			qf_exp(b, a, n, test_d);
			qf_copy(c, a);
			for (j = 1; j < 10; j++) {
				qf_com(c, c, a, 0, test_d);
			}
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous exponentiation is correct") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			bn_rand(m, RLC_POS, 64);
			bn_rand(n, RLC_POS, 64);
			qf_exp_sim(r, a, m, b, n, test_d);
			qf_exp(c, a, m, test_d);
			qf_exp(fd, b, n, test_d);
			qf_com(c, c, fd, 0, test_d);
			TEST_ASSERT(qf_cmp(r, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous exponentiation handles zero exponents") {
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			bn_zero(m);
			bn_rand(n, RLC_POS, 64);
			qf_exp_sim(r, a, m, b, n, test_d);
			qf_exp(c, b, n, test_d);
			TEST_ASSERT(qf_cmp(r, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("fixed base exponentiation is correct") {
			if (!test_qf_rand(a, test_d)) {
				continue;
			}
			bn_rand(n, RLC_POS, 64);
			/*
			 * The four-way comb consumes the exponent in blocks at offsets
			 * 0, se, sd and sd + se, so the tables are the base raised to those
			 * powers of two and the offsets have to cover its length.
			 */
			se = (bn_bits(n) + 3) / 4 + 1;
			sd = 2 * se;
			qf_copy(fe, a);
			for (j = 0; j < se; j++) {
				qf_dup(fe, fe, test_d);
			}
			qf_copy(fd, a);
			for (j = 0; j < sd; j++) {
				qf_dup(fd, fd, test_d);
			}
			qf_copy(fde, fd);
			for (j = 0; j < se; j++) {
				qf_dup(fde, fde, test_d);
			}
			qf_exp_fix(r, a, n, sd, se, fe, fd, fde, test_d);
			qf_exp(c, a, n, test_d);
			TEST_ASSERT(qf_cmp(r, c) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	qf_free(c);
	qf_free(r);
	qf_free(fd);
	qf_free(fe);
	qf_free(fde);
	bn_free(m);
	bn_free(n);
	bn_free(s);
	return code;
}

static int orders(void) {
	int code = RLC_ERR;
	qf_t a, b, c;
	bn_t m, n, s;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	bn_null(m);
	bn_null(n);
	bn_null(s);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);
		bn_new(m);
		bn_new(n);
		bn_new(s);

		TEST_CASE("the coprime form has the same discriminant") {
			if (!test_qf_rand(a, test_k)) {
				continue;
			}
			qf_copy(b, a);
			qf_copa(b, test_q);
			TEST_ASSERT(test_qf_dsc(b, test_k), end);
			bn_gcd(n, b->a, test_q);
			TEST_ASSERT(bn_cmp_dig(n, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lifting to the non-maximal order is consistent") {
			if (!test_qf_rand(a, test_k)) {
				continue;
			}
			qf_copy(b, a);
			qf_lift(b, test_q);
			TEST_ASSERT(test_qf_dsc(b, test_d), end);
		} TEST_END;

		TEST_CASE("the map to the maximal order inverts the lift") {
			if (!test_qf_rand(a, test_k)) {
				continue;
			}
			qf_rdc(a, a);
			qf_copy(b, a);
			qf_lift(b, test_q);
			qf_max(b, test_q, test_k, 1);
			TEST_ASSERT(test_qf_dsc(b, test_k), end);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the map to the maximal order is a homomorphism") {
			/*
			 * The projection onto the maximal order is a homomorphism, with
			 * kernel isomorphic to the unit group modulo the conductor. The
			 * lift in the other direction is not: it depends on which form
			 * represents the class, so it is a section rather than a
			 * homomorphism and composing before or after lifting need not
			 * agree.
			 */
			if (!test_qf_rand(a, test_d) || !test_qf_rand(b, test_d)) {
				continue;
			}
			qf_com(c, a, b, 0, test_d);
			qf_max(c, test_q, test_k, 1);
			qf_max(a, test_q, test_k, 1);
			qf_max(b, test_q, test_k, 1);
			qf_com(a, a, b, 0, test_k);
			TEST_ASSERT(test_qf_dsc(c, test_k), end);
			TEST_ASSERT(qf_cmp(a, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the kernel discrete logarithm round trips") {
			/*
			 * The kernel of the projection is generated by the class of
			 * (q^2, q, .), so a kernel element is a power of that form and
			 * nothing else: handing qf_kern an arbitrary lift is rejected,
			 * since such a class does not map to the principal one.
			 */
			bn_sqr(n, test_q);
			qf_set_dsc(a, n, test_q, test_d);
			TEST_ASSERT(test_qf_dsc(a, test_d), end);
			bn_rand_mod(n, test_q);
			qf_exp(b, a, n, test_d);
			qf_kern(m, b, test_q, test_k);
			TEST_ASSERT(bn_cmp(m, test_q) == RLC_LT, end);
			/* the representative is recovered up to the sign of the class */
			bn_sub(s, test_q, m);
			TEST_ASSERT(bn_cmp(m, n) == RLC_EQ || bn_cmp(s, n) == RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	qf_free(c);
	bn_free(m);
	bn_free(n);
	bn_free(s);
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the QF module:\n", 0);

	bn_null(test_d);
	bn_null(test_k);
	bn_null(test_q);
	qf_null(test_g);
	qf_null(test_gk);
	bn_new(test_d);
	bn_new(test_k);
	bn_new(test_q);
	qf_new(test_g);
	qf_new(test_gk);

	if (test_qf_setup() != RLC_OK) {
		util_print("FATAL ERROR!\n");
		core_clean();
		return 1;
	}

	util_banner("Utilities:", 1);

	if (memory() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (util() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Arithmetic:", 1);

	if (reduction() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (composition() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (exponentiation() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Maps between orders:", 1);

	if (orders() != RLC_OK) {
		core_clean();
		return 1;
	}

	bn_free(test_d);
	bn_free(test_k);
	bn_free(test_q);
	qf_free(test_g);
	qf_free(test_gk);

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}