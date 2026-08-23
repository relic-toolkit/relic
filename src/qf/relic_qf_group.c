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
 * Implementation of the class group represented in binary quadratic form.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Finds a non-trivial prime form for a discriminant, by trying the small primes
 * in turn until one of them splits.
 */
static int qf_find_gen(qf_t f, const bn_t d) {
	for (dig_t l = 2; l < 100; l++) {
		if (l > 2 && (l % 2) == 0) {
			continue;
		}
		qf_prime(f, l, d);
		if (qf_has_dsc(f, d) && !qf_is_one(f)) {
			return 1;
		}
	}
	return 0;
}


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_group_init(void) {
	ctx_t *ctx = core_get();
	bn_make(&(ctx->qf_d), RLC_BN_DIGS);
	bn_make(&(ctx->qf_k), RLC_BN_DIGS);
	bn_make(&(ctx->qf_q), RLC_BN_DIGS);
	bn_make(&(ctx->qf_ga), RLC_BN_DIGS);
	bn_make(&(ctx->qf_gb), RLC_BN_DIGS);
	bn_make(&(ctx->qf_gc), RLC_BN_DIGS);
	bn_make(&(ctx->qf_ka), RLC_BN_DIGS);
	bn_make(&(ctx->qf_kb), RLC_BN_DIGS);
	bn_make(&(ctx->qf_kc), RLC_BN_DIGS);
}

void qf_group_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
		bn_clean(&(ctx->qf_d));
		bn_clean(&(ctx->qf_k));
		bn_clean(&(ctx->qf_q));
		bn_clean(&(ctx->qf_ga));
		bn_clean(&(ctx->qf_gb));
		bn_clean(&(ctx->qf_gc));
		bn_clean(&(ctx->qf_ka));
		bn_clean(&(ctx->qf_kb));
		bn_clean(&(ctx->qf_kc));
	}
}

/**
 * Builds a pair of discriminants for an imaginary quadratic order and its
 * maximal order. Taking Delta_K = -p*q and Delta = Delta_K*q^2 puts the two in
 * the relation the order maps expect, and Delta_K = 1 mod 4 requires p*q = 3
 * mod 4, so exactly one of the two primes is 3 mod 4.
 */
int qf_group_set(size_t cond, size_t bits) {
	ctx_t *ctx = core_get();
	int code = RLC_ERR;
	bn_t p;
	qf_t g;

	bn_null(p);
	qf_null(g);

	RLC_TRY {
		bn_new(p);
		qf_new(g);

		do {
			bn_gen_prime(&(ctx->qf_q), cond);
		} while (bn_get_bit(&(ctx->qf_q), 1) != 0);	/* q = 1 mod 4 */
		do {
			bn_gen_prime(p, bits);
		} while (bn_get_bit(p, 1) == 0);		/* p = 3 mod 4 */

		bn_mul(&(ctx->qf_k), p, &(ctx->qf_q));
		bn_neg(&(ctx->qf_k), &(ctx->qf_k));
		bn_mul(&(ctx->qf_d), &(ctx->qf_k), &(ctx->qf_q));
		bn_mul(&(ctx->qf_d), &(ctx->qf_d), &(ctx->qf_q));

		if (!qf_find_gen(g, &(ctx->qf_d))) {
			RLC_THROW(ERR_NO_VALID);
		}
		bn_copy(&(ctx->qf_ga), g->a);
		bn_copy(&(ctx->qf_gb), g->b);
		bn_copy(&(ctx->qf_gc), g->c);

		if (!qf_find_gen(g, &(ctx->qf_k))) {
			RLC_THROW(ERR_NO_VALID);
		}
		bn_copy(&(ctx->qf_ka), g->a);
		bn_copy(&(ctx->qf_kb), g->b);
		bn_copy(&(ctx->qf_kc), g->c);

		code = RLC_OK;
	}
	RLC_CATCH_ANY {
		code = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
		qf_free(g);
	}
	return code;
}
