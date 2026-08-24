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
 * Implementation of the CL linearly-homomorphic encryption system.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*
 * The order that h, pk and c1 live in, as the two quantities the group law
 * needs: the discriminant, which forms are built from, and the partial
 * reduction bound, its fourth root. They are not interchangeable, and the
 * exponentiation routines take both because they do each of those things.
 */
#define clhe_dsc(c)		(c->compact ? &(core_get()->qf_dk) : &(core_get()->qf_d))
#define clhe_bnd(c)		(c->compact ? &(core_get()->qf_bk) : &(core_get()->qf_b))

/** Fill in fe, fd, fde by repeated doubling of f. */
static void clhe_precomp(qf_t fe, qf_t fd, qf_t fde, const qf_t f, size_t d,
		size_t e, const bn_t bound) {
	size_t i;

	qf_copy(fde, f);
	for (i = 0; i < d + e; i++) {
		if (i == e) {
			qf_copy(fe, fde);
		}
		if (i == d) {
			qf_copy(fd, fde);
		}
		qf_dup(fde, fde, bound);
	}
}

/**
 * f^m for k = 1.  With Lm an odd representative of 1/m mod q in (-q, q),
 * f^m = [q^2, Lm*q, (Lm^2 - Delta_K)/4].
 */
static void clhe_power_of_f(qf_t r, const clhe_t c, const bn_t m) {
	bn_t t0, t1;

	bn_null(t0);
	bn_null(t1);

	RLC_TRY {
		bn_new(t0);
		bn_new(t1);

		bn_mod(t0, m, &(core_get()->qf_q));
		if (bn_is_zero(t0)) {
			qf_set_one(r, &(core_get()->qf_d));
			return;
		}
		bn_mod_inv(t1, t0, &(core_get()->qf_q));
		if (bn_is_even(t1)) {
			bn_sub(t1, t1, &(core_get()->qf_q));
		}
		bn_sqr(r->c, t1);
		bn_sub(r->c, r->c, &(core_get()->qf_dk));
		bn_rsh(r->c, r->c, 2);
		bn_mul(r->b, t1, &(core_get()->qf_q));
		bn_sqr(r->a, &(core_get()->qf_q));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t0);
		bn_free(t1);
	}
}

/** Discrete log in F for k = 1. */
static void clhe_dlog_in_f(bn_t m, const clhe_t c, const qf_t fm) {
	bn_t t0, t1, t2;

	if (qf_is_one(fm)) {
		bn_zero(m);
		return;
	}

	bn_null(t0);
	bn_null(t1);
	bn_null(t2);

	RLC_TRY {
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);

		if (c->large_msg) {
			qf_kern(t2, fm);
			bn_copy(t2, &(core_get()->qf_q));
			if (!bn_is_zero(&(core_get()->qf_q))) {
				while (1) {
					bn_div_rem(t0, t1, t2, &(core_get()->qf_q));
					if (!bn_is_zero(t1)) {
						break;
					}
					bn_copy(t2, t0);
				}
			}
			bn_mod(m, t2, &(core_get()->qf_q));
		} else {
			/* b = q^j * u, and m = 1/u mod q */
			bn_copy(t2, fm->b);
			if (!bn_is_zero(fm->b)) {
				while (1) {
					bn_div_rem(t0, t1, t2, &(core_get()->qf_q));
					if (!bn_is_zero(t1)) {
						break;
					}
					bn_copy(t2, t0);
				}
			}
			bn_mod_inv(m, t2, &(core_get()->qf_q));
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void cp_clhe_set(clhe_t c, const bn_t q, size_t disc_bits, int compact) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		qf_group_set_cond(q, disc_bits);
		c->compact = compact;

		/* Large message variant when 4*q^2 - 1 + Delta_K > 0. */
		bn_sqr(t, q);
		bn_lsh(t, t, 2);
		bn_sub_dig(t, t, 1);
		bn_add(t, t, &(core_get()->qf_dk));
		c->large_msg = (bn_sign(t) == RLC_POS && !bn_is_zero(t));

		bn_copy(c->h->a, &(core_get()->qf_ga));
		bn_copy(c->h->b, &(core_get()->qf_gb));
		bn_copy(c->h->c, &(core_get()->qf_gc));
		if (c->compact) {
			bn_copy(c->h->a, &(core_get()->qf_gka));
			bn_copy(c->h->b, &(core_get()->qf_gkb));
			bn_copy(c->h->c, &(core_get()->qf_gkc));
		}

		/* Exponent bound: class number bound of Delta_K times 2^40. */
		qf_class(t, &(core_get()->qf_dk));
		bn_lsh(t, t, 40);
		c->d = (bn_bits(t) + 1) / 2;
		c->e = c->d / 2 + 1;
		clhe_precomp(c->h_e, c->h_d, c->h_de, c->h, c->d, c->e, clhe_bnd(c));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

void cp_clhe_gen(clhe_pk_t pk, bn_t sk, const clhe_t c) {
	bn_t bound;

	bn_null(bound);

	RLC_TRY {
		bn_new(bound);
		qf_class(bound, &(core_get()->qf_dk));
		bn_lsh(bound, bound, 40);
		bn_rand_mod(sk, bound);
		qf_exp_fix(pk->pk, c->h, sk, c->d, c->e, c->h_e, c->h_d, c->h_de,
				clhe_dsc(c), clhe_bnd(c));
		clhe_precomp(pk->pk_e, pk->pk_d, pk->pk_de, pk->pk, c->d, c->e,
				clhe_bnd(c));
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(bound);
	}
}

void cp_clhe_enc(qf_t c1, qf_t c2, const clhe_t c, const clhe_pk_t pk, const bn_t m,
		const bn_t r) {
	qf_t fm;

	qf_new(fm);
	RLC_TRY {
		qf_exp_fix(c1, c->h, r, c->d, c->e, c->h_e, c->h_d, c->h_de, clhe_dsc(c), clhe_bnd(c));
		qf_exp_fix(c2, pk->pk, r, c->d, c->e, pk->pk_e, pk->pk_d,
				pk->pk_de, clhe_dsc(c), clhe_bnd(c));
		if (c->compact) {
			qf_psi(c2, c2, &(core_get()->qf_d), &(core_get()->qf_b));
		}
		clhe_power_of_f(fm, c, m);
		qf_com(c2, c2, fm, 0, &(core_get()->qf_b));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		qf_free(fm);
	}
}

void cp_clhe_dec(bn_t m, const clhe_t c, const bn_t sk, const qf_t c1, const qf_t c2) {
	qf_t fm;

	qf_new(fm);
	RLC_TRY {
		qf_exp(fm, c1, sk, clhe_dsc(c), clhe_bnd(c));
		if (c->compact) {
			qf_psi(fm, fm, &(core_get()->qf_d), &(core_get()->qf_b));
		}
		/* fm <- c2 / c1^sk */
		qf_com(fm, c2, fm, 1, &(core_get()->qf_b));
		clhe_dlog_in_f(m, c, fm);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		qf_free(fm);
	}
}

void cp_clhe_add(qf_t r1, qf_t r2, const clhe_t c, const clhe_pk_t pk, const qf_t c1,
		const qf_t c2, const qf_t d1, const qf_t d2, const bn_t r) {
	qf_t t;

	qf_null(t);

	RLC_TRY {
		qf_new(t);
		qf_exp_fix(t, c->h, r, c->d, c->e, c->h_e, c->h_d, c->h_de, clhe_dsc(c), clhe_bnd(c));
		qf_com(t, t, c1, 0, clhe_bnd(c));
		qf_com(r1, t, d1, 0, clhe_bnd(c));
		qf_com(t, c2, d2, 0, &(core_get()->qf_b));

		qf_exp_fix(r2, pk->pk, r, c->d, c->e, pk->pk_e, pk->pk_d, pk->pk_de, clhe_dsc(c), clhe_bnd(c));
		if (c->compact) {
			qf_psi(r2, r2, &(core_get()->qf_d), &(core_get()->qf_b));
		}
		qf_com(r2, r2, t, 0, &(core_get()->qf_b));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		qf_free(t);
	}
}

void cp_clhe_mul(qf_t r1, qf_t r2, const clhe_t c, const clhe_pk_t pk, const qf_t c1,
		const qf_t c2, const bn_t s, const bn_t r) {
	qf_t t;

 	qf_null(t);

	RLC_TRY {
		qf_new(t);
		qf_exp_fix(t, c->h, r, c->d, c->e, c->h_e, c->h_d, c->h_de, clhe_dsc(c), clhe_bnd(c));
		qf_exp(r1, c1, s, clhe_dsc(c), clhe_bnd(c));
		qf_com(t, t, r1, 0, clhe_bnd(c));
 
		qf_exp_fix(r2, pk->pk, r, c->d, c->e, pk->pk_e, pk->pk_d, pk->pk_de, clhe_dsc(c), clhe_bnd(c));
		if (c->compact) {
			qf_psi(r2, r2, &(core_get()->qf_d), &(core_get()->qf_b));
		}
		qf_exp(r1, c2, s, &(core_get()->qf_d), &(core_get()->qf_b));
		qf_com(r2, r2, r1, 0, &(core_get()->qf_b));
		qf_copy(r1, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		qf_free(t);
	}
}