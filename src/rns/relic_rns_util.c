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
 * Implementation of the utilities of a Residue Number System.
 *
 * @ingroup rns
 */

#include <stdlib.h>

#include "relic_core.h"
#include "relic_rns_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Tests if a context is precomputed for a modulus with the given number of
 * moduli. The modulus is public, so it is compared in variable time.
 *
 * @param[in] c				- the context.
 * @param[in] mod			- the modulus.
 * @param[in] n				- the number of moduli in each base.
 * @return 1 if the context matches, 0 otherwise.
 */
static int rns_match(const rns_st *c, const bn_t mod, size_t n) {
	return c->mem != NULL && c->n == n && c->d == mod->used &&
			dv_cmp(c->p, mod->dp, mod->used) == RLC_EQ;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_core_init(void) {
	ctx_t *ctx = core_get();

	for (int k = 0; k < 2; k++) {
		ctx->rns_cache[k].mem = NULL;
		ctx->rns_base[k].mem = NULL;
	}
	ctx->rns_last = 0;
	ctx->rns_bnext = 0;
	ctx->rns_hint = NULL;
	ctx->rns_hints = 0;
	ctx->rns_seen_d = 0;
}

void rns_core_clean(void) {
	ctx_t *ctx = core_get();

	if (ctx != NULL) {
		for (int k = 0; k < 2; k++) {
			rns_free(&(ctx->rns_cache[k]));
			rns_free(&(ctx->rns_base[k]));
		}
	}
}

const rns_st *rns_lookup(const bn_t mod, int room) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_RNS_SIZE(bn_bits(mod), room), d = mod->used;
	rns_st *c;
	int k;

	for (size_t j = 0; j < ctx->rns_hints; j++) {
		if (rns_match(&(ctx->rns_hint[j]), mod, n)) {
			return &(ctx->rns_hint[j]);
		}
	}
	for (k = 0; k < 2; k++) {
		c = &(ctx->rns_cache[k]);
		if (rns_match(c, mod, n)) {
			ctx->rns_last = k;
			return c;
		}
	}
	if (n > RLC_RNS_MAX || d > RLC_BN_DIGS) {
		return NULL;
	}
	/* Precompute only on the second use of a modulus in a row. */
	if (ctx->rns_seen_d != d || dv_cmp(ctx->rns_seen, mod->dp, d) != RLC_EQ) {
		dv_copy(ctx->rns_seen, mod->dp, d);
		ctx->rns_seen_d = d;
		return NULL;
	}
	/* Replace the least recently used context. */
	k = 1 - ctx->rns_last;
	c = &(ctx->rns_cache[k]);
	rns_free(c);
	rns_new(c, n, d);
	if (c->mem == NULL) {
		return NULL;
	}
	rns_pre(c, mod, room);
	ctx->rns_seen_d = 0;
	ctx->rns_last = k;
	return c;
}

void rns_hint(const rns_st *c, size_t n) {
	ctx_t *ctx = core_get();

	ctx->rns_hint = c;
	ctx->rns_hints = (c == NULL ? 0 : n);
}

size_t rns_size(size_t n, size_t d) {
	const size_t o = RLC_RNS_SPAN(n), w = RLC_RNS_WORDS(d);

	/* Eight tables of 2o residues, n of mi, five of o, the two extension
	 * tables, the five multiples kN, the digits of M/m_i, -M and 3N, the
	 * powers, and the digits of N. */
	return 16 * o + n + 5 * o + 2 * n * o + 10 * o + (n + 2) * (d + 1) +
			w * 2 * o + d;
}

void rns_new(rns_t c, size_t n, size_t d) {
	const size_t o = RLC_RNS_SPAN(n), l = d + 1;
	dig_t *p;

	if (n > RLC_RNS_MAX || d > RLC_BN_DIGS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	c->mem = (dig_t *)calloc(rns_size(n, d), sizeof(dig_t));
	if (c->mem == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	c->n = n;
	c->o = o;
	c->d = d;
	c->w = RLC_RNS_WORDS(d);

	/* Lay out the tables one after the other in the block. */
	p = c->mem;
	c->m = p;
	p += 2 * o;
	c->u = p;
	p += 2 * o;
	c->iv = p;
	p += 2 * o;
	c->r2 = p;
	p += 2 * o;
	c->e = p;
	p += 2 * o;
	c->ib = p;
	p += 2 * o;
	c->mi = p;
	p += n;
	c->nq = p;
	p += o;
	c->nqv = p;
	p += o;
	c->ibv = p;
	p += o;
	c->u1 = p;
	p += o;
	c->u2 = p;
	p += o;
	c->t1 = p;
	p += n * o;
	c->t2 = p;
	p += n * o;
	c->kp = p;
	p += 10 * o;
	c->mp = p;
	p += n * l;
	c->mm = p;
	p += l;
	c->p3 = p;
	p += l;
	c->pw = p;
	p += c->w * 2 * o;
	c->one = p;
	p += 2 * o;
	c->cv = p;
	p += 2 * o;
	c->p = p;
}

void rns_free(rns_t c) {
	free(c->mem);
	c->mem = NULL;
}

void rns_conv(dig_t *r, const bn_t a, const rns_t c) {
	dig_t d;

	for (size_t i = 0; i < 2 * c->o; i++) {
		if (RLC_RNS_PAD(c, i)) {
			r[i] = 0;
			continue;
		}
		/* The remainder is non-negative, so it is the residue of a also when
		 * a is negative. */
		bn_mod_dig(&d, a, c->m[i]);
		r[i] = rns_mul(d, c->e[i], c->m[i], c->u[i]);
	}
}

void rns_back(bn_t r, const dig_t *a, const rns_t c) {
	bn_t m, t;

	bn_null_all(m, t);

	RLC_TRY {
		bn_new_all(m, t);

		/* CRT in B: r = sum xi_i * (M/m_i) mod M. */
		bn_set_dig(m, 1);
		for (size_t i = 0; i < c->n; i++) {
			bn_mul_dig(m, m, c->m[i]);
		}
		bn_zero(r);
		for (size_t i = 0; i < c->n; i++) {
			bn_div_dig(t, m, c->m[i]);
			bn_mul_dig(t, t, rns_mul(a[i], c->ib[i], c->m[i], c->u[i]));
			bn_add(r, r, t);
		}
		bn_mod(r, r, m);
		/* Values above M/2 represent negative integers. */
		bn_hlv(t, m);
		if (bn_cmp(r, t) == RLC_GT) {
			bn_sub(r, r, m);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, t);
	}
}
