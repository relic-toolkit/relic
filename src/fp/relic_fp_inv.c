/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the prime field inversion functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FP_INV == BASIC || !defined(STRIP)

void fp_inv_basic(fp_t c, const fp_t a) {
	bn_t e;

	bn_null(e);

	if (fp_is_zero(a)) {
		THROW(ERR_NO_VALID);
	}

	TRY {
		bn_new(e);

		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 2);

		fp_exp(c, a, e);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(e);
	}
}

#endif

#if FP_INV == BINAR || !defined(STRIP)

void fp_inv_binar(fp_t c, const fp_t a) {
	bn_t u, v, g1, g2, p;

	bn_null(u);
	bn_null(v);
	bn_null(g1);
	bn_null(g2);
	bn_null(p);

	if (fp_is_zero(a)) {
		THROW(ERR_NO_VALID);
	}

	TRY {
		bn_new(u);
		bn_new(v);
		bn_new(g1);
		bn_new(g2);
		bn_new(p);

		/* u = a, v = p, g1 = 1, g2 = 0. */
		fp_prime_back(u, a);
		p->used = RLC_FP_DIGS;
		dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_copy(v, p);
		bn_set_dig(g1, 1);
		bn_zero(g2);

		/* While (u != 1 && v != 1). */
		while (1) {
			/* While u is even do. */
			while (!(u->dp[0] & 1)) {
				/* u = u/2. */
				fp_rsh1_low(u->dp, u->dp);
				/* If g1 is even then g1 = g1/2; else g1 = (g1 + p)/2. */
				if (g1->dp[0] & 1) {
					bn_add(g1, g1, p);
				}
				bn_hlv(g1, g1);
			}

			while (u->dp[u->used - 1] == 0) {
				u->used--;
			}
			if (u->used == 1 && u->dp[0] == 1)
				break;

			/* While z divides v do. */
			while (!(v->dp[0] & 1)) {
				/* v = v/2. */
				fp_rsh1_low(v->dp, v->dp);
				/* If g2 is even then g2 = g2/2; else (g2 = g2 + p)/2. */
				if (g2->dp[0] & 1) {
					bn_add(g2, g2, p);
				}
				bn_hlv(g2, g2);
			}

			while (v->dp[v->used - 1] == 0) {
				v->used--;
			}
			if (v->used == 1 && v->dp[0] == 1)
				break;

			/* If u > v then u = u - v, g1 = g1 - g2. */
			if (bn_cmp(u, v) == RLC_GT) {
				bn_sub(u, u, v);
				bn_sub(g1, g1, g2);
			} else {
				bn_sub(v, v, u);
				bn_sub(g2, g2, g1);
			}
		}
		/* If u == 1 then return g1; else return g2. */
		if (bn_cmp_dig(u, 1) == RLC_EQ) {
			while (bn_sign(g1) == RLC_NEG) {
				bn_add(g1, g1, p);
			}
			while (bn_cmp(g1, p) != RLC_LT) {
				bn_sub(g1, g1, p);
			}
#if FP_RDC == MONTY
			fp_prime_conv(c, g1);
#else
			dv_copy(c, g1->dp, RLC_FP_DIGS);
#endif
		} else {
			while (bn_sign(g2) == RLC_NEG) {
				bn_add(g2, g2, p);
			}
			while (bn_cmp(g2, p) != RLC_LT) {
				bn_sub(g2, g2, p);
			}
#if FP_RDC == MONTY
			fp_prime_conv(c, g2);
#else
			dv_copy(c, g2->dp, RLC_FP_DIGS);
#endif
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(u);
		bn_free(v);
		bn_free(g1);
		bn_free(g2);
		bn_free(p);
	}
}

#endif

#if FP_INV == MONTY || !defined(STRIP)

void fp_inv_monty(fp_t c, const fp_t a) {
	bn_t _a, _p, u, v, x1, x2;
	const dig_t *p = NULL;
	dig_t carry;
	int i, k, flag = 0;

	bn_null(_a);
	bn_null(_p);
	bn_null(u);
	bn_null(v);
	bn_null(x1);
	bn_null(x2);

	if (fp_is_zero(a)) {
		THROW(ERR_NO_VALID);
	}

	TRY {
		bn_new(_a);
		bn_new(_p);
		bn_new(u);
		bn_new(v);
		bn_new(x1);
		bn_new(x2);

		p = fp_prime_get();

		/* u = a, v = p, x1 = 1, x2 = 0, k = 0. */
		k = 0;
		bn_set_dig(x1, 1);
		bn_zero(x2);

#if FP_RDC != MONTY
		bn_read_raw(_a, a, RLC_FP_DIGS);
		bn_read_raw(_p, p, RLC_FP_DIGS);
		bn_mod_monty_conv(u, _a, _p);
#else
		bn_read_raw(u, a, RLC_FP_DIGS);
#endif
		bn_read_raw(v, p, RLC_FP_DIGS);

		while (!bn_is_zero(v)) {
			/* If v is even then v = v/2, x1 = 2 * x1. */
			if (!(v->dp[0] & 1)) {
				fp_rsh1_low(v->dp, v->dp);
				bn_dbl(x1, x1);
			} else {
				/* If u is even then u = u/2, x2 = 2 * x2. */
				if (!(u->dp[0] & 1)) {
					fp_rsh1_low(u->dp, u->dp);
					bn_dbl(x2, x2);
					/* If v >= u,then v = (v - u)/2, x2 += x1, x1 = 2 * x1. */
				} else {
					if (bn_cmp(v, u) != RLC_LT) {
						fp_subn_low(v->dp, v->dp, u->dp);
						fp_rsh1_low(v->dp, v->dp);
						bn_add(x2, x2, x1);
						bn_dbl(x1, x1);
					} else {
						/* u = (u - v)/2, x1 += x2, x2 = 2 * x2. */
						fp_subn_low(u->dp, u->dp, v->dp);
						fp_rsh1_low(u->dp, u->dp);
						bn_add(x1, x1, x2);
						bn_dbl(x2, x2);
					}
				}
			}
			bn_trim(u);
			bn_trim(v);
			k++;
		}

		/* If x1 > p then x1 = x1 - p. */
		for (i = x1->used; i < RLC_FP_DIGS; i++) {
			x1->dp[i] = 0;
		}

		while (x1->used > RLC_FP_DIGS) {
			carry = bn_subn_low(x1->dp, x1->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_sub1_low(x1->dp + RLC_FP_DIGS, x1->dp + RLC_FP_DIGS, carry,
					x1->used - RLC_FP_DIGS);
			bn_trim(x1);
		}
		if (dv_cmp(x1->dp, fp_prime_get(), RLC_FP_DIGS) == RLC_GT) {
			fp_subn_low(x1->dp, x1->dp, fp_prime_get());
		}

		dv_copy(x2->dp, fp_prime_get_conv(), RLC_FP_DIGS);

		/* If k < Wt then x1 = x1 * R^2 * R^{-1} mod p. */
		if (k <= RLC_FP_DIGS * RLC_DIG) {
			flag = 1;
			fp_mul(x1->dp, x1->dp, x2->dp);
			k = k + RLC_FP_DIGS * RLC_DIG;
		}

		/* x1 = x1 * R^2 * R^{-1} mod p. */
		fp_mul(x1->dp, x1->dp, x2->dp);

		/* c = x1 * 2^(2Wt - k) * R^{-1} mod p. */
		fp_copy(c, x1->dp);
		dv_zero(x1->dp, RLC_FP_DIGS);
		bn_set_2b(x1, 2 * RLC_FP_DIGS * RLC_DIG - k);
		fp_mul(c, c, x1->dp);

#if FP_RDC != MONTY
		/*
		 * If we do not use Montgomery reduction, the result of inversion is
		 * a^{-1}R^3 mod p or a^{-1}R^4 mod p, depending on flag.
		 * Hence we must reduce the result three or four times.
		 */
		_a->used = RLC_FP_DIGS;
		dv_copy(_a->dp, c, RLC_FP_DIGS);
		bn_mod_monty_back(_a, _a, _p);
		bn_mod_monty_back(_a, _a, _p);
		bn_mod_monty_back(_a, _a, _p);

		if (flag) {
			bn_mod_monty_back(_a, _a, _p);
		}
		fp_zero(c);
		dv_copy(c, _a->dp, _a->used);
#endif
		(void)flag;
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(_a);
		bn_free(_p);
		bn_free(u);
		bn_free(v);
		bn_free(x1);
		bn_free(x2);
	}
}

#endif

#if FP_INV == EXGCD || !defined(STRIP)

void fp_inv_exgcd(fp_t c, const fp_t a) {
	bn_t u, v, g1, g2, p, q, r;

	bn_null(u);
	bn_null(v);
	bn_null(g1);
	bn_null(g2);
	bn_null(p);
	bn_null(q);
	bn_null(r);

	if (fp_is_zero(a)) {
		THROW(ERR_NO_VALID);
	}

	TRY {
		bn_new(u);
		bn_new(v);
		bn_new(g1);
		bn_new(g2);
		bn_new(p);
		bn_new(q);
		bn_new(r);

		/* u = a, v = p, g1 = 1, g2 = 0. */
		fp_prime_back(u, a);
		p->used = RLC_FP_DIGS;
		dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_copy(v, p);
		bn_set_dig(g1, 1);
		bn_zero(g2);

		/* While (u != 1. */
		while (bn_cmp_dig(u, 1) != RLC_EQ) {
			/* q = [v/u], r = v mod u. */
			bn_div_rem(q, r, v, u);
			/* v = u, u = r. */
			bn_copy(v, u);
			bn_copy(u, r);
			/* r = g2 - q * g1. */
			bn_mul(r, q, g1);
			bn_sub(r, g2, r);
			/* g2 = g1, g1 = r. */
			bn_copy(g2, g1);
			bn_copy(g1, r);
		}

		if (bn_sign(g1) == RLC_NEG) {
			bn_add(g1, g1, p);
		}
		fp_prime_conv(c, g1);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(u);
		bn_free(v);
		bn_free(g1);
		bn_free(g2);
		bn_free(p);
		bn_free(q);
		bn_free(r);
	}
}

#endif

#include "assert.h"

#if FP_INV == DIVST || !defined(STRIP)

#define RLC_FP_DIGS 	((int)RLC_CEIL(RLC_FP_BITS, RLC_DIG))

void fp_inv_divst(fp_t c, const fp_t a) {
	/* Compute number of iteratios based on modulus size. */
#if FP_PRIME < 46
	int d = (49 * FP_PRIME + 80)/17;
#else
	int d = (49 * FP_PRIME + 57)/17;
#endif
	int delta = 1, g0, d0;
	dig_t r1, v1, fs, gs;
	bn_t t, v0, r0;
	dv_t f, g, z, _v0, _r0, _t, u;
	fp_t precomp;

	bn_null(t);
	dv_null(f);
	dv_null(g);
	dv_null(z);
	bn_null(v0);
	bn_null(r0);
	dv_null(_v0);
	dv_null(_r0);
	dv_null(_t);
	dv_null(u);
	fp_null(precomp);

	if (fp_is_zero(a)) {
		THROW(ERR_NO_VALID);
	}

	TRY {
		bn_new(t);
		dv_new(f);
		dv_new(g);
		dv_new(z);
		bn_new(v0);
		bn_new(r0);
		dv_new(_v0);
		dv_new(_r0);
		dv_new(_t);
		dv_new(u);
		fp_new(precomp);

		bn_set_dig(t, d - 1);
		fp_set_dig(precomp, 1);
		fp_hlv(precomp, precomp);
		fp_exp(precomp, precomp, t);

		bn_zero(v0);
		bn_set_dig(r0, 1);
		dv_zero(_v0, RLC_FP_DIGS + 2);
		dv_zero(_r0, RLC_FP_DIGS + 2);
		_r0[0] = 1;
		v1 = r1 = 0;
		fp_prime_back(t, a);
		dv_zero(g, RLC_FP_DIGS);
		dv_copy(g, t->dp, t->used);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			g0 = g[0] & 1;
			d0 = g0 & (delta > 0);
			dv_swap_cond(_r0, _v0, RLC_FP_DIGS + 2, d0);
			dv_swap_cond(f, g, RLC_FP_DIGS, d0);
			delta = RLC_SEL(delta, -delta, d0);
			/* Conditionally invert r0 and g based on d0. */
			for (int j = 0; j < RLC_FP_DIGS + 2; j++) {
				_r0[j] = RLC_SEL(_r0[j], ~_r0[j], d0);
			}
			bn_add1_low(_r0, _r0, d0, RLC_FP_DIGS + 2);
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				g[j] = RLC_SEL(g[j], ~g[j], d0);
			}
			bn_add1_low(g, g, d0, RLC_FP_DIGS);
			dv_swap_cond(&fs, &gs, 1, d0);
			gs ^= d0;

			delta++;
			g0 = g[0] & 1;
			dv_copy(_t, _v0, RLC_FP_DIGS + 2);
			dv_copy_cond(_t, _r0, RLC_FP_DIGS + 2, d0);
			bn_lshb_low(_t, _t, RLC_FP_DIGS + 2, r1 - v1);
			dv_copy(u, _v0, RLC_FP_DIGS + 2);
			dv_copy_cond(u, _r0, RLC_FP_DIGS + 2, (d0 ^ 1) & g0);
			bn_addn_low(_t, _t, u, RLC_FP_DIGS + 2);

			dv_copy_cond(_r0, _t, RLC_FP_DIGS + 2, g0);

			/* We delay the conditional swaps to simplify the code above. */
			dv_swap_cond(&r1, &v1, 1, d0);

			/* We only increment r1 if g is non-zero. */
			r1 = RLC_SEL(r1, (RLC_SEL(r1, v1, r1 < v1) + 1), g[0] != 0);
			/* Compute g = (g + g0*f) div 2 by conditionally copying f to z and
			 * updating the sign of g. */
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				z[j] = f[j] & (-g0);
			}
			gs ^= g0 & (fs ^ bn_addn_low(g, g, z, RLC_FP_DIGS));
			/* Shift and restore the sign. */
			fp_rsh1_low(g, g);
			g[RLC_FP_DIGS - 1] |= (dig_t)gs << (RLC_DIG - 1);
		}
		d0 = _v0[RLC_FP_DIGS + 1] >> (RLC_DIG - 1);
		for (int j = 0; j < RLC_FP_DIGS + 2; j++) {
			_v0[j] = RLC_SEL(_v0[j], ~_v0[j], d0);
		}
		bn_add1_low(_v0, _v0, d0, RLC_FP_DIGS + 2);
		v0->used = RLC_FP_DIGS + 2;
		v0->sign = d0;
		dv_copy(v0->dp, _v0, RLC_FP_DIGS + 2);
		bn_lsh(v0, v0, d - v1 - 1);
		v0->sign ^= fs;
		fp_prime_conv(c, v0);
		fp_mul(c, c, precomp);
	} CATCH_ANY {
		THROW(ERR_CAUGHT)
	} FINALLY {
		bn_free(t);
		bn_free(v0);
		bn_free(r0);
		dv_free(f);
		dv_free(g);
		dv_free(z);
		dv_free(_v0);
		dv_free(_r0);
		dv_free(_t);
		dv_free(u);
		fp_free(precomp);
	}
}

#endif

#if FP_INV == LOWER || !defined(STRIP)

void fp_inv_lower(fp_t c, const fp_t a) {
	fp_invn_low(c, a);
}

#endif

void fp_inv_sim(fp_t *c, const fp_t *a, int n) {
	int i;
	fp_t u, *t = RLC_ALLOCA(fp_t, n);

	fp_null(u);
	for (i = 0; i < n; i++) {
		fp_null(t[i]);
	}

	TRY {
		for (i = 0; i < n; i++) {
			fp_new(t[i]);
		}
		fp_new(u);

		fp_copy(c[0], a[0]);
		fp_copy(t[0], a[0]);

		for (i = 1; i < n; i++) {
			fp_copy(t[i], a[i]);
			fp_mul(c[i], c[i - 1], a[i]);
		}

		fp_inv(u, c[n - 1]);

		for (i = n - 1; i > 0; i--) {
			fp_mul(c[i], u, c[i - 1]);
			fp_mul(u, u, t[i]);
		}
		fp_copy(c[0], u);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		for (i = 0; i < n; i++) {
			fp_free(t[i]);
		}
		fp_free(u);
	}
}
