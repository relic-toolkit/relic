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
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

/** Size in bits of the conductor used by the tests. */
#define TEST_QF_COND	32
/** Size in bits of the other prime factor of the fundamental discriminant. */
#define TEST_QF_PRIME	(64 + TEST_QF_COND)

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
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_copy(c, a);
			TEST_ASSERT(qf_cmp(a, c) == RLC_EQ, end);
			TEST_ASSERT(qf_cmp(c, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("copy is consistent") {
			qf_rand(a, &(core_get()->qf_d));
			qf_copy(b, a);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("negation is involutory") {
			qf_rand(a, &(core_get()->qf_d));
			qf_neg(b, a);
			qf_neg(b, b);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("negation preserves the discriminant") {
			qf_rand(a, &(core_get()->qf_d));
			qf_neg(b, a);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("assignment to the identity is detected") {
			qf_set_one(a, &(core_get()->qf_d));
			TEST_ASSERT(qf_is_one(a) == 1, end);
			TEST_ASSERT(qf_has_dsc(a, &(core_get()->qf_d)), end);
			qf_rand(b, &(core_get()->qf_d));
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
			qf_rand(a, &(core_get()->qf_d));
			qf_rdc(b, a);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("reduction is idempotent") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rdc(b, a);
			qf_rdc(c, b);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("a reduced form satisfies the reduction conditions") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rdc(b, a);
			/* |b| <= a <= c, and b >= 0 whenever a equals c */
			TEST_ASSERT(bn_cmp_abs(b->b, b->a) != RLC_GT, end);
			TEST_ASSERT(bn_cmp_abs(b->a, b->c) != RLC_GT, end);
			if (bn_cmp_abs(b->a, b->c) == RLC_EQ) {
				TEST_ASSERT(bn_sign(b->b) == RLC_POS, end);
			}
		} TEST_END;

		TEST_CASE("normalisation preserves the discriminant") {
			qf_rand(a, &(core_get()->qf_d));
			qf_norm(b, a);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
			/* normalisation puts b in (-a, a] */
			TEST_ASSERT(bn_cmp_abs(b->b, b->a) != RLC_GT, end);
		} TEST_END;

		TEST_CASE("the identity is reduced") {
			qf_set_one(a, &(core_get()->qf_d));
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
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_com(c, a, b, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_has_dsc(c, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("composition is commutative") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_com(c, a, b, 0, &(core_get()->qf_b));
			qf_com(d, b, a, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("composition is associative") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_rand(c, &(core_get()->qf_d));
			qf_com(d, a, b, 0, &(core_get()->qf_b));
			qf_com(d, d, c, 0, &(core_get()->qf_b));
			qf_com(e, b, c, 0, &(core_get()->qf_b));
			qf_com(e, a, e, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("composition has a neutral element") {
			qf_rand(a, &(core_get()->qf_d));
			qf_set_one(b, &(core_get()->qf_d));
			qf_com(c, a, b, 0, &(core_get()->qf_b));
			qf_rdc(d, a);
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
			qf_com(c, b, a, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("composition with the negation gives the identity") {
			qf_rand(a, &(core_get()->qf_d));
			qf_neg(b, a);
			qf_com(c, a, b, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_is_one(c) == 1, end);
		} TEST_END;

		TEST_CASE("the negation flag composes with the inverse") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_com(c, a, b, 1, &(core_get()->qf_b));
			qf_neg(d, b);
			qf_com(d, a, d, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(c, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("doubling is composition with itself") {
			qf_rand(a, &(core_get()->qf_d));
			qf_dup(b, a, &(core_get()->qf_b));
			qf_com(c, a, a, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("doubling the identity gives the identity") {
			qf_set_one(a, &(core_get()->qf_d));
			qf_dup(b, a, &(core_get()->qf_b));
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
			qf_rand(a, &(core_get()->qf_d));
			bn_zero(n);
			qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			TEST_ASSERT(qf_is_one(b) == 1, end);
			bn_set_dig(n, 1);
			qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_rdc(c, a);
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation by two is doubling") {
			qf_rand(a, &(core_get()->qf_d));
			bn_set_dig(n, 2);
			qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_dup(c, a, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation is additive in the exponent") {
			qf_rand(a, &(core_get()->qf_d));
			bn_rand(m, RLC_POS, 64);
			bn_rand(n, RLC_POS, 64);
			bn_add(s, m, n);
			qf_exp(b, a, m, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(c, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(b, b, c, 0, &(core_get()->qf_b));
			qf_exp(c, a, s, &(core_get()->qf_d), &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("exponentiation agrees with repeated composition") {
			qf_rand(a, &(core_get()->qf_d));
			bn_set_dig(n, 10);
			qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_copy(c, a);
			for (j = 1; j < 10; j++) {
				qf_com(c, c, a, 0, &(core_get()->qf_b));
			}
			TEST_ASSERT(qf_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous exponentiation is correct") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			bn_rand(m, RLC_POS, 64);
			bn_rand(n, RLC_POS, 64);
			qf_exp_sim(r, a, m, b, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(c, a, m, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(fd, b, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(c, c, fd, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(r, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous exponentiation handles zero exponents") {
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			bn_zero(m);
			bn_rand(n, RLC_POS, 64);
			qf_exp_sim(r, a, m, b, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(c, b, n, &(core_get()->qf_d), &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(r, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("fixed base exponentiation is correct") {
			qf_rand(a, &(core_get()->qf_d));
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
			qf_exp_fix(r, a, n, sd, se, fe, fd, fde, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(c, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
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
	ctx_t *ctx = core_get();
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
			qf_rand(a, &(core_get()->qf_dk));
			qf_copa(b, a);
			TEST_ASSERT(qf_has_dsc(a, &(core_get()->qf_dk)), end);
			bn_gcd(n, b->a, &(core_get()->qf_q));
			TEST_ASSERT(bn_cmp_dig(n, 1) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("lifting to the non-maximal order is consistent") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_lift(b, a);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_d)), end);
		} TEST_END;

		TEST_CASE("the map to the maximal order inverts the lift") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rdc(a, a);
			qf_lift(b, a);
			qf_phi(b, b, 1);
			TEST_ASSERT(qf_has_dsc(b, &(core_get()->qf_dk)), end);
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
			qf_rand(a, &(core_get()->qf_d));
			qf_rand(b, &(core_get()->qf_d));
			qf_com(c, a, b, 0, &(core_get()->qf_b));
			qf_phi(c, c, 1);
			qf_phi(a, a, 1);
			qf_phi(b, b, 1);
			qf_com(a, a, b, 0, &(core_get()->qf_bk));
			TEST_ASSERT(qf_has_dsc(c, &(core_get()->qf_dk)), end);
			TEST_ASSERT(qf_cmp(a, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the kernel discrete logarithm round trips") {
			/*
			 * The kernel of the projection is generated by the class of
			 * (q^2, q, .), so a kernel element is a power of that form and
			 * nothing else: handing qf_kern an arbitrary lift is rejected,
			 * since such a class does not map to the principal one.
			 */
			bn_sqr(n, &(ctx->qf_q));
			qf_set_dsc(a, n, &(ctx->qf_q), &(core_get()->qf_d));
			TEST_ASSERT(qf_has_dsc(a, &(core_get()->qf_d)), end);
			bn_rand_mod(n, &(ctx->qf_q));
			qf_exp(b, a, n, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_kern(m, b);
			TEST_ASSERT(bn_cmp(m, &(ctx->qf_q)) == RLC_LT, end);
			/* the representative is recovered up to the sign of the class */
			bn_sub(s, &(ctx->qf_q), m);
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

static int qpower(void) {
	ctx_t *ctx = core_get();
	int code = RLC_ERR;
	qf_t a, b, c, la, lb, lc, d, e;
	bn_t m, n;

	qf_null(a);
	qf_null(b);
	qf_null(c);
	qf_null(la);
	qf_null(lb);
	qf_null(lc);
	qf_null(d);
	qf_null(e);
	bn_null(m);
	bn_null(n);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		qf_new(c);
		qf_new(la);
		qf_new(lb);
		qf_new(lc);
		qf_new(d);
		qf_new(e);
		bn_new(m);
		bn_new(n);

		TEST_CASE("the lift is not multiplicative on its own") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rand(b, &(core_get()->qf_dk));
			qf_com(c, a, b, 0, &(core_get()->qf_bk));
			qf_copa(la, a);
			qf_lift(la, la);
			qf_copa(lb, b);
			qf_lift(lb, lb);
			qf_copa(lc, c);
			qf_lift(lc, lc);
			qf_com(d, la, lb, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_has_dsc(d, &(core_get()->qf_d)), end);
			TEST_ASSERT(qf_has_dsc(lc, &(core_get()->qf_d)), end);
			TEST_ASSERT(qf_cmp(d, lc) != RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the defect of the lift lies in the kernel") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rand(b, &(core_get()->qf_dk));
			qf_com(c, a, b, 0, &(core_get()->qf_bk));
			qf_copa(la, a);
			qf_lift(la, la);
			qf_copa(lb, b);
			qf_lift(lb, lb);
			qf_copa(lc, c);
			qf_lift(lc, lc);
			/* D = lift(a)*lift(b)*lift(ab)^-1 */
			qf_com(d, la, lb, 0, &(core_get()->qf_b));
			qf_com(d, d, lc, 1, &(core_get()->qf_b));
			TEST_ASSERT(qf_has_dsc(d, &(core_get()->qf_d)), end);
			/* it projects to the identity, so it lies in ker qf_max */
			qf_phi(e, d, 1);
			TEST_ASSERT(qf_is_one(e) == 1, end);
		} TEST_END;

		TEST_CASE("the kernel logarithm reconstructs the defect") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rand(b, &(core_get()->qf_dk));
			qf_com(c, a, b, 0, &(core_get()->qf_bk));
			qf_copa(la, a);
			qf_lift(la, la);
			qf_copa(lb, b);
			qf_lift(lb, lb);
			qf_copa(lc, c);
			qf_lift(lc, lc);
			qf_com(d, la, lb, 0, &(core_get()->qf_b));
			qf_com(d, d, lc, 1, &(core_get()->qf_b));
			/* F generates the kernel, so the defect is one of its powers */
			bn_sqr(n, &(ctx->qf_q));
			qf_set_dsc(e, n, &(ctx->qf_q), &(core_get()->qf_d));
			qf_kern(m, d);
			qf_exp(e, e, m, &(core_get()->qf_d), &(core_get()->qf_b));
			if (qf_cmp(e, d) != RLC_EQ) {
				/* the logarithm comes back only up to the sign of the class */
				bn_sub(m, &(ctx->qf_q), m);
				bn_mod(m, m, &(ctx->qf_q));
				bn_sqr(n, &(ctx->qf_q));
				qf_set_dsc(e, n, &(ctx->qf_q), &(core_get()->qf_d));
				qf_exp(e, e, m, &(core_get()->qf_d), &(core_get()->qf_b));
			}
			TEST_ASSERT(qf_cmp(e, d) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the q-th power annihilates the defect") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rand(b, &(core_get()->qf_dk));
			qf_com(c, a, b, 0, &(core_get()->qf_bk));
			qf_copa(la, a);
			qf_lift(la, la);
			qf_copa(lb, b);
			qf_lift(lb, lb);
			qf_copa(lc, c);
			qf_lift(lc, lc);
			qf_com(d, la, lb, 0, &(core_get()->qf_b));
			qf_com(d, d, lc, 1, &(core_get()->qf_b));
			/* the kernel has order q, so raising to q returns the identity */
			qf_exp(e, d, &(ctx->qf_q), &(core_get()->qf_d), &(core_get()->qf_b));
			TEST_ASSERT(qf_is_one(e) == 1, end);
		} TEST_END;

		TEST_CASE("the lift composed with the q-th power is multiplicative") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rand(b, &(core_get()->qf_dk));
			qf_com(c, a, b, 0, &(core_get()->qf_bk));
			qf_psi(la, a, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_psi(lb, b, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_psi(lc, c, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(d, la, lb, 0, &(core_get()->qf_b));
			TEST_ASSERT(qf_cmp(d, lc) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the lift alone projects back to the element") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rdc(a, a);
			qf_copa(la, a);
			qf_lift(la, la);
			qf_phi(e, la, 1);
			TEST_ASSERT(qf_cmp(e, a) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the q-th power of the lift projects to the q-th power") {
			qf_rand(a, &(core_get()->qf_dk));
			qf_rdc(a, a);
			qf_psi(la, a, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_phi(e, la, 1);
			qf_exp(b, a, &(ctx->qf_q), &(core_get()->qf_dk), &(core_get()->qf_bk));
			TEST_ASSERT(qf_cmp(e, b) == RLC_EQ, end);
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
	qf_free(la);
	qf_free(lb);
	qf_free(lc);
	qf_free(d);
	qf_free(e);
	bn_free(m);
	bn_free(n);
	return code;
}

static int hashing(void) {
	int code = RLC_ERR;
	uint8_t msg[32];
	qf_t a, b;
	bn_t t;

	qf_null(a);
	qf_null(b);
	bn_null(t);

	RLC_TRY {
		qf_new(a);
		qf_new(b);
		bn_new(t);

		TEST_CASE("the hashing to class groups is deterministic") {
			rand_bytes(msg, sizeof(msg));
			qf_map(a, msg, sizeof(msg), &(core_get()->qf_dk),
					TEST_QF_PRIME / 2);
			qf_map(b, msg, sizeof(msg), &(core_get()->qf_dk),
					TEST_QF_PRIME / 2);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("the hashing lands in the class group") {
			rand_bytes(msg, sizeof(msg));
			qf_map(a, msg, sizeof(msg), &(core_get()->qf_dk),
					TEST_QF_PRIME / 2);
			TEST_ASSERT(qf_has_dsc(a, &(core_get()->qf_dk)), end);
			/* the result is reduced, so it is the canonical representative */
			qf_rdc(b, a);
			TEST_ASSERT(qf_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("distinct messages give distinct prime hashes") {
			rand_bytes(msg, sizeof(msg));
			qf_map(a, msg, sizeof(msg), &(core_get()->qf_dk),
					TEST_QF_PRIME / 2);
			msg[0] ^= 1;
			qf_map(b, msg, sizeof(msg), &(core_get()->qf_dk),
					TEST_QF_PRIME / 2);
			TEST_ASSERT(qf_cmp(a, b) != RLC_EQ, end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	qf_free(a);
	qf_free(b);
	bn_free(t);
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the QF module:\n", 0);

	if (qf_group_gen(TEST_QF_COND, TEST_QF_PRIME) != RLC_OK) {
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

	if (orders() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (qpower() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (hashing() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}