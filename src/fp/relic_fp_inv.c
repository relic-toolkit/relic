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
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		bn_new(e);

		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 2);

		fp_exp(c, a, e);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
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
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
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
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
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
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
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
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
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
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
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
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
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

#if FP_INV == DIVST || !defined(STRIP)

void fp_inv_divst(fp_t c, const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	int d = (49 * FP_PRIME + 80) / 17;
#else
	int d = (49 * FP_PRIME + 57) / 17;
#endif
	int g0, d0;
	dig_t fs, gs, delta = 1;
	bn_t _t;
	fp_t f, g, t, u, v, r;

	bn_null(_t);
	fp_null(f);
	fp_null(g);
	fp_null(t);
	fp_null(u);
	fp_null(v);
	fp_null(r);

	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		bn_new(_t);
		fp_new(f);
		fp_new(g);
		fp_new(t);
		fp_new(u);
		fp_new(v);
		fp_new(r);

		fp_zero(v);
		fp_set_dig(r, 1);
		fp_prime_back(_t, a);
		dv_zero(g, RLC_FP_DIGS);
		dv_copy(g, _t->dp, _t->used);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			g0 = g[0] & 1;
			d0 = delta >> (RLC_DIG - 1);
			d0 = g0 & ~d0;
			/* Conditionally negate delta if d0 is set. */
			delta = (delta ^ -d0) + d0;
			/* Conditionally swap based on d0. */
			dv_swap_cond(r, v, RLC_FP_DIGS, d0);
			fp_negm_low(t, r);
			dv_swap_cond(f, g, RLC_FP_DIGS, d0);
			dv_copy_cond(r, t, RLC_FP_DIGS, d0);
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				g[j] = RLC_SEL(g[j], ~g[j], d0);
			}
			fp_add1_low(g, g, d0);
			t[0] = (fs ^ gs) & (-d0);
			fs ^= t[0];
			gs ^= t[0] ^ d0;

			delta++;
			g0 = g[0] & 1;
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				t[j] = v[j] & (-g0);
				u[j] = f[j] & (-g0);
			}
			fp_addm_low(r, r, t);
			fp_dblm_low(v, v);

			/* Compute g = (g + g0*f) div 2 by conditionally copying f to u and
			 * updating the sign of g. */
			gs ^= g0 & (fs ^ bn_addn_low(g, g, u, RLC_FP_DIGS));
			/* Shift and restore the sign. */
			fp_rsh1_low(g, g);
			g[RLC_FP_DIGS - 1] |= (dig_t)gs << (RLC_DIG - 1);
		}
		fp_neg(t, v);
		dv_copy_cond(v, t, RLC_FP_DIGS, fs);

		dv_copy(t, fp_prime_get(), RLC_FP_DIGS);
		fp_add_dig(t, t, 1);
		fp_hlv(t, t);
#if WSIZE == 8
		bn_set_dig(_t, d >> 8);
		bn_lsh(_t, _t, 8);
		bn_add_dig(_t, _t, d & 0xFF);
#else
		bn_set_dig(_t, d);
#endif
		fp_exp(t, t, _t);

		fp_mul(c, v, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		bn_free(_t);
		fp_free(f);
		fp_free(g);
		fp_free(t);
		fp_free(u);
		fp_free(v);
		fp_free(r);
	}
}

#endif

#if FP_INV == JMPDS || !defined(STRIP)

static dis_t jumpdivstep(dis_t m[4], dis_t delta, dig_t f, dig_t g, int s) {
	dig_t u = 1, v = 0, q = 0, r = 1, c0, c1;

	/* This is actually faster than my previous version, several tricks from
	 * https://github.com/bitcoin-core/secp256k1/blob/master/src/modinv64_impl.h
	 */
	for (s--; s >= 0; s--) {
		/* First handle the else part: if delta < 0, compute -(f,u,v). */
		c0 = delta >> (RLC_DIG - 1);
		c1 = -(g & 1);
		c0 &= c1;
		/* Conditionally add -(f,u,v) to (g,q,r) */
		g += ((f ^ c0) - c0) & c1;
		q += ((u ^ c0) - c0) & c1;
		r += ((v ^ c0) - c0) & c1;
		/* Now handle the 'if' part, so c0 will be (delta < 0) && (g & 1)) */
		/* delta = RLC_SEL(delta, -delta, c0 & 1) - 2 (for half-divstep), thus
		 * delta = - delta - 2 or delta - 1 */
		delta = (delta ^ c0) - 1;
		f = f + (g & c0);
		u = u + (q & c0);
		v = v + (r & c0);
		g >>= 1;
		u += u;
		v += v;
	}
	m[0] = u;
	m[1] = v;
	m[2] = q;
	m[3] = r;
	return delta;
}

static inline void bn_mul2_low(dig_t *c, const dig_t *a, dis_t digit, int size) {
	int sd = digit >> (RLC_DIG - 1);
	digit = (digit ^ sd) - sd;
	c[size] = bn_mul1_low(c, a, digit, size);
}

void fp_inv_jmpds(fp_t c, const fp_t a) {
	dis_t m[4];
	/* Compute number of iterations based on modulus size. */
	int i, d = -1, s = RLC_DIG - 2;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	int iterations = (45907 * FP_PRIME + 26313) / 19929;
	dv_t f, g, t, p, t0, t1, u0, u1, v0, v1, p01, p11;
	fp_t pre;

	dv_null(f);
	dv_null(g);
	dv_null(t);
	dv_null(p);
	dv_null(t0);
	dv_null(t1);
	dv_null(u0);
	dv_null(u1);
	dv_null(v0);
	dv_null(v1);
	dv_null(p01);
	dv_null(p11);
	fp_null(pre);

	RLC_TRY {
		dv_new(t0);
		dv_new(f);
		dv_new(t);
		dv_new(p);
		dv_new(g);
		dv_new(t1);
		dv_new(u0);
		dv_new(u1);
		dv_new(v0);
		dv_new(v1);
		dv_new(p01);
		dv_new(p11);
		fp_new(pre);

#if (FP_PRIME % WSIZE) != 0
		int j = 0;
		fp_copy(pre, core_get()->inv.dp);
#else
		fp_copy(pre, core_get()->conv.dp);
		fp_mul(pre, pre, core_get()->conv.dp);
		fp_mul(pre, pre, core_get()->inv.dp);
#endif

		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_zero(p, 2 * RLC_FP_DIGS);
		dv_zero(u0, 2 * RLC_FP_DIGS);
		dv_zero(u1, 2 * RLC_FP_DIGS);
		dv_zero(v0, 2 * RLC_FP_DIGS);
		dv_zero(v1, 2 * RLC_FP_DIGS);

		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		dv_copy(p + 1, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		d = jumpdivstep(m, d, f[0] & RLC_MASK(s), g[0] & RLC_MASK(s), s);

		t0[RLC_FP_DIGS] = bn_muls_low(t0, f, RLC_POS, m[0], RLC_FP_DIGS);
		t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_POS, m[1], RLC_FP_DIGS);
		bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

		f[RLC_FP_DIGS] = bn_muls_low(f, f, RLC_POS, m[2], RLC_FP_DIGS);
		t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_POS, m[3], RLC_FP_DIGS);
		bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

		/* Update f and g. */
		bn_rshs_low(f, t0, RLC_FP_DIGS + 1, s);
		bn_rshs_low(g, t1, RLC_FP_DIGS + 1, s);

		/* Update column vector below. */
		v1[0] = RLC_SEL(m[1], -m[1], RLC_SIGN(m[1]));
		fp_negm_low(t, v1);
		dv_copy_cond(v1, t, RLC_FP_DIGS, RLC_SIGN(m[1]));
		u1[0] = RLC_SEL(m[3], -m[3], RLC_SIGN(m[3]));
		fp_negm_low(t, u1);
		dv_copy_cond(u1, t, RLC_FP_DIGS, RLC_SIGN(m[3]));

		dv_copy(p01, v1, 2 * RLC_FP_DIGS);
		dv_copy(p11, u1, 2 * RLC_FP_DIGS);

		int loops = iterations / s;
		loops = (iterations % s == 0 ? loops - 1 : loops);

		for (i = 1; i < loops; i++) {
			d = jumpdivstep(m, d, f[0] & RLC_MASK(s), g[0] & RLC_MASK(s), s);

			t0[RLC_FP_DIGS] = bn_muls_low(t0, f, RLC_SIGN(f[RLC_FP_DIGS]), m[0], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_SIGN(g[RLC_FP_DIGS]), m[1], RLC_FP_DIGS);
			bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

			f[RLC_FP_DIGS] = bn_muls_low(f, f, RLC_SIGN(f[RLC_FP_DIGS]), m[2], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_SIGN(g[RLC_FP_DIGS]), m[3], RLC_FP_DIGS);
			bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

			/* Update f and g. */
			bn_rshs_low(f, t0, RLC_FP_DIGS + 1, s);
			bn_rshs_low(g, t1, RLC_FP_DIGS + 1, s);

#if (FP_PRIME % WSIZE) != 0
			p[j] = 0;
			dv_copy(p + j + 1, fp_prime_get(), RLC_FP_DIGS);

			/* Update column vector below. */
			bn_mul2_low(v0, p01, m[0], RLC_FP_DIGS + j);
			fp_subd_low(t, p, v0);
			dv_copy_cond(v0, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[0]));

			bn_mul2_low(v1, p11, m[1], RLC_FP_DIGS + j);
			fp_subd_low(t, p, v1);
			dv_copy_cond(v1, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[1]));

			bn_mul2_low(u0, p01, m[2], RLC_FP_DIGS + j);
			fp_subd_low(t, p, u0);
			dv_copy_cond(u0, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[2]));

			bn_mul2_low(u1, p11, m[3], RLC_FP_DIGS + j);
			fp_subd_low(t, p, u1);
			dv_copy_cond(u1, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[3]));

			j = i % RLC_FP_DIGS;
			if (j == 0) {
				fp_addd_low(t, u0, u1);
				fp_rdcn_low(p11, t);
				fp_addd_low(t, v0, v1);
				fp_rdcn_low(p01, t);
				dv_zero(v0, 2 * RLC_FP_DIGS);
				dv_zero(v1, 2 * RLC_FP_DIGS);
			} else {
				fp_addd_low(p11, u0, u1);
				fp_addd_low(p01, v0, v1);
			}
#else
			fp_zero(p);
			dv_copy(p + RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);

			/* Update column vector below. */
			bn_mul2_low(v0, p01, m[0], 2 * RLC_FP_DIGS);
			fp_subd_low(t, p, v0);
			dv_copy_cond(v0, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[0]));

			bn_mul2_low(v1, p11, m[1], 2 * RLC_FP_DIGS);
			fp_subd_low(t, p, v1);
			dv_copy_cond(v1, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[1]));

			bn_mul2_low(u0, p01, m[2], 2 * RLC_FP_DIGS);
			fp_subd_low(t, p, u0);
			dv_copy_cond(u0, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[2]));

			bn_mul2_low(u1, p11, m[3], 2 * RLC_FP_DIGS);
			fp_subd_low(t, p, u1);
			dv_copy_cond(u1, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[3]));

			fp_addc_low(t, u0, u1);
			fp_rdcn_low(p11, t);
			fp_addc_low(t, v0, v1);
			fp_rdcn_low(p01, t);
			fp_mulm_low(pre, pre, core_get()->conv.dp);
#endif
		}

		s = iterations - loops * s;
		d = jumpdivstep(m, d, f[0] & RLC_MASK(s), g[0] & RLC_MASK(s), s);

		t0[RLC_FP_DIGS] = bn_muls_low(t0, f, RLC_SIGN(f[RLC_FP_DIGS]), m[0], RLC_FP_DIGS);
		t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_SIGN(g[RLC_FP_DIGS]), m[1], RLC_FP_DIGS);
		bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

		f[RLC_FP_DIGS] = bn_muls_low(f, f, RLC_SIGN(f[RLC_FP_DIGS]), m[2], RLC_FP_DIGS);
		t1[RLC_FP_DIGS] = bn_muls_low(t1, g, RLC_SIGN(g[RLC_FP_DIGS]), m[3], RLC_FP_DIGS);
		bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

		/* Update f and g. */
		bn_rshs_low(f, t0, RLC_FP_DIGS + 1, s);
		bn_rshs_low(g, t1, RLC_FP_DIGS + 1, s);

#if (FP_PRIME % WSIZE) != 0
		p[j] = 0;
		dv_copy(p + j + 1, fp_prime_get(), RLC_FP_DIGS);

		/* Update column vector below. */
		/* Update column vector below. */
		bn_mul2_low(v0, p01, m[0], RLC_FP_DIGS + j);
		fp_subd_low(t, p, v0);
		dv_copy_cond(v0, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[0]));

		bn_mul2_low(v1, p11, m[1], RLC_FP_DIGS + j);
		fp_subd_low(t, p, v1);
		dv_copy_cond(v1, t, RLC_FP_DIGS + j + 1, RLC_SIGN(m[1]));

		fp_addd_low(t, v0, v1);
		fp_rdcn_low(p01, t);
#else
		fp_zero(p);
		dv_copy(p + RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);

		/* Update column vector below. */
		bn_mul2_low(v0, p01, m[0], 2 * RLC_FP_DIGS);
		fp_subd_low(t, p, v0);
		dv_copy_cond(v0, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[0]));

		bn_mul2_low(v1, p11, m[1], 2 * RLC_FP_DIGS);
		fp_subd_low(t, p, v1);
		dv_copy_cond(v1, t, 2 * RLC_FP_DIGS, RLC_SIGN(m[1]));

		fp_addc_low(t, v0, v1);
		fp_rdcn_low(p01, t);
#endif

		/* Negate based on sign of f at the end. */
		fp_negm_low(t, p01);
		dv_copy_cond(p01, t, RLC_FP_DIGS, f[RLC_FP_DIGS] >> (RLC_DIG - 1));
		/* Multiply by (precomp * R^j) % p, one for each iteration of the loop,
		 * one for the constant, one more to be removed by reduction. */
		fp_mul(c, p01, pre);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free(t0);
		dv_free(f);
		dv_free(t);
		dv_free(p);
		dv_free(g);
		dv_free(t1);
		dv_free(u0);
		dv_free(u1);
		dv_free(v0);
		dv_free(v1);
		dv_free(p01);
		dv_free(p11);
		fp_free(pre);
	}
}

#endif

#if FP_INV == LOWER || !defined(STRIP)

void fp_inv_lower(fp_t c, const fp_t a) {
	fp_invm_low(c, a);
}

#endif

void fp_inv_sim(fp_t *c, const fp_t *a, int n) {
	int i;
	fp_t u, *t = RLC_ALLOCA(fp_t, n);

	fp_null(u);

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < n; i++) {
			fp_null(t[i]);
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
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fp_free(t[i]);
		}
		fp_free(u);
		RLC_FREE(t);
	}
}
