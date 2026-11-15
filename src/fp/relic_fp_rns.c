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
 * Implementation of prime field arithmetic in a Residue Number System.
 *
 * An element is represented by its residues modulo the RLC_FP_RNS moduli of
 * each of two bases B and B', all primes of the form 2^RLC_RNS_BITS - c. Each
 * residue is kept in Montgomery form x_i * R mod m_i, with R = 2^RLC_RNS_DIG,
 * so that products of residues are Montgomery products. In B', an element x is
 * moreover stored as x / M, as in Langowski, He and Devadas (VROOM, USENIX
 * Security 2025): a product then carries 1 / M^2, so that the division by M of
 * Montgomery reduction comes for free, and the constants around the base
 * extensions are folded into their tables.
 *
 * Multiplication is Montgomery multiplication in RNS, with M = prod(B) as the
 * Montgomery constant: the quotient is computed in B and extended to B'
 * approximately, and the result is computed in B' and extended back to B
 * exactly, as in Kawamura et al. (EUROCRYPT 2000). B must exceed the sums of
 * products to reduce divided by p, below 2^30 * p^2, and B' the reduced result,
 * below (RLC_FP_RNS + 1)p in absolute value, as the first extension skips its
 * correction. The residue-wise operations, the base extensions
 * and the reduction are at the lower level, so that backends can vectorize
 * them.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*
 * An unreduced product of elements must fit in a temporary vector.
 */
RLC_STATIC_ASSERT(RLC_FP_DLEN <= RLC_DV_DIGS, rns_dv);

/**
 * Points the context of the Residue Number System of the prime field to the
 * tables in the library context.
 *
 * @param[in] ctx			- the library context.
 */
static void fp_rns_bind(ctx_t *ctx) {
	rns_st *c = ctx->prime_rns;

	c->n = RLC_FP_RNS;
	c->o = RLC_FP_RNSO;
	c->d = RLC_FP_DIGS;
	c->w = RLC_FP_RNS_DIGS;
	c->m = ctx->rns.m;
	c->u = ctx->rns.u;
	c->iv = ctx->rns.iv;
	c->r2 = ctx->rns.r2;
	c->e = ctx->rns.e;
	c->mi = ctx->rns.mi;
	c->ib = ctx->rns.ib;
	c->nq = ctx->rns.nq;
	c->nqv = ctx->rns.nqv;
	c->ibv = ctx->rns.ibv;
	c->t1 = ctx->rns.t1[0];
	c->t2 = ctx->rns.t2[0];
	c->u1 = ctx->rns.u1;
	c->u2 = ctx->rns.u2;
	c->kp = ctx->rns.kp[0];
	c->mp = ctx->rns.mp[0];
	c->mm = ctx->rns.mm;
	c->p3 = ctx->rns.p3;
	c->pw = ctx->rns.pw[0];
	c->p = ctx->prime.dp;
	c->one = ctx->one;
	c->cv = ctx->conv;
	c->mem = NULL;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rns_pre(void) {
	ctx_t *ctx = core_get();
	bn_t m, t, u;

	bn_null_all(m, t, u);

	RLC_TRY {
		bn_new_all(m, t, u);

		fp_rns_bind(ctx);
		rns_pre(ctx->prime_rns, &(ctx->prime), RLC_FP_RNS_ROOM);

		/* The context sets M and M^2 modulo p as one and conv, so add M/2 and
		 * M/3 modulo p in Montgomery form. */
		bn_set_dig(m, 1);
		for (size_t i = 0; i < RLC_FP_RNS; i++) {
			bn_mul_dig(m, m, ctx->rns.m[i]);
		}
		bn_mod(t, m, &(ctx->prime));
		bn_add_dig(u, &(ctx->prime), 1);
		bn_hlv(u, u);
		bn_mul(u, u, t);
		bn_mod(u, u, &(ctx->prime));
		rns_conv(ctx->rns.half, u, ctx->prime_rns);
		bn_set_dig(u, 3);
		bn_mod_inv(u, u, &(ctx->prime));
		bn_mul(u, u, t);
		bn_mod(u, u, &(ctx->prime));
		rns_conv(ctx->rns.third, u, ctx->prime_rns);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, t, u);
	}
}

/*============================================================================*/

void fp_rns_get(dig_t *c, const dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, l = RLC_FP_DIGS + 1;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u, *p = fp_prime_get();
	rlc_align dig_t r[RLC_FP_LEN];
	dig_t xi[RLC_FP_RNS], s[RLC_FP_DIGS + 1], t[RLC_FP_DIGS + 1], a1, b, q;
	dbl_t lo, hi, d, e;
	int k;

	/* r = a / M is the value of a, with -p < r < (RLC_FP_RNS + 1)p. */
	fp_rns_wide(r, a);
	fp_rdc_renus(r, r);
	/* r = sum xi_i (M/m_i) - alpha M, where alpha rounds sum xi_i / m_i, as
	 * r / M is tiny. */
	for (size_t i = 0; i < n; i++) {
		xi[i] = rns_mul(r[i], ctx->rns.ib[i], m[i], u[i]);
	}
	a1 = rns_alpha(xi, n, 1);
	/* The low digits of r + 3p are enough to recover it, as it is positive.
	 * The multipliers are single digits, so sum them column by column, with
	 * the high halves of the products carried to the next column. */
	d = 0;
	for (size_t j = 0; j < l; j++) {
		lo = d + ctx->rns.p3[j];
		e = (dbl_t)a1 * ctx->rns.mm[j];
		lo += (dig_t)e;
		hi = e >> RLC_DIG;
		for (size_t i = 0; i < n; i++) {
			e = (dbl_t)xi[i] * ctx->rns.mp[i][j];
			lo += (dig_t)e;
			hi += e >> RLC_DIG;
		}
		s[j] = (dig_t)lo;
		d = (lo >> RLC_DIG) + hi;
	}
	/* Now 0 < s < (RLC_FP_RNS + 4)p, so subtract 2^k p where it fits, for
	 * 2^k at most RLC_FP_RNS + 3 from the largest down. */
	for (k = 0; (2 << k) <= RLC_FP_RNS + 3; k++);
	for (; k >= 0; k--) {
		b = 0;
		for (size_t j = 0; j < l; j++) {
			q = (j < l - 1 ? p[j] << k : 0);
			if (j > 0 && k > 0) {
				q |= p[j - 1] >> (RLC_DIG - k);
			}
			d = (dbl_t)s[j] - q - b;
			t[j] = (dig_t)d;
			b = (dig_t)(d >> RLC_DIG) & 1;
		}
		/* Keep the difference unless it wrapped around. */
		q = b - 1;
		for (size_t j = 0; j < l; j++) {
			s[j] = (t[j] & q) | (s[j] & ~q);
		}
	}
	dv_copy(c, s, RLC_FP_DIGS);
}

void fp_rns_set(dig_t *c, const dig_t *a) {
	rlc_align dig_t t[RLC_FP_LEN];

	/* The residues of a, stored as an element. */
	fp_rnsi_low(t, a);
	/* Times M^2 / M for Montgomery form. */
	fp_mulm_low(c, t, core_get()->conv);
}

#endif /* FP_RDC == FP_RENUS */
