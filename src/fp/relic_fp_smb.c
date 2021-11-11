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
 * Implementation of Legendre and Jacobi symbols for prime fields.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb_legen(const fp_t a) {
	bn_t t;
	int r = 0;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* t = (b - 1)/2. */
		t->sign = RLC_POS;
		t->used = RLC_FP_DIGS;
		dv_copy(t->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(t, t, 1);
		bn_hlv(t, t);

		fp_exp(t->dp, a, t);
		r = (fp_cmp_dig(t->dp, 1) == RLC_EQ);
		fp_neg(t->dp, t->dp);
		r = RLC_SEL(r, -(fp_cmp_dig(t->dp, 1) == RLC_EQ), !r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return r;
}

int fp_smb_divst(const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	int r, d = (49 * FP_PRIME + 80)/17;
#else
	int r, d = (49 * FP_PRIME + 57)/17;
#endif
	dig_t delta = 1, g0, d0, fs, gs, k, mask, s;
	bn_t _t;
	dv_t f, g, t;

	bn_null(_t);
	dv_null(f);
	dv_null(g);
	dv_null(t);

	RLC_TRY {
		bn_new(_t);
		dv_new(f);
		dv_new(g);
		dv_new(t);

#if WSIZE == 8
		bn_set_dig(_t, d >> 8);
		bn_lsh(_t, _t, 8);
		bn_add_dig(_t, _t, d & 0xFF);
#else
		bn_set_dig(_t, d);
#endif

		k = 0;
		fp_prime_back(_t, a);
		dv_zero(g, RLC_FP_DIGS);
		dv_copy(g, _t->dp, _t->used);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			d0 = g[0] & ((int)delta > 0);
			/* Conditionally negate delta if d0 is set. */
			delta = (delta ^ -d0) + d0;
			k ^= (((g[0] >> (dig_t)1) & ((f[0] >> (dig_t)1) ^ 1)) ^ (~fs & gs)) & d0;

			/* Conditionally swap and negate based on d0. */
			mask = -d0;
			s = (fs ^ gs) & mask;
			fs ^= s;
			gs ^= s ^ d0;
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				s = (f[j] ^ g[j]) & mask;
				f[j] ^= s;
				g[j] ^= s ^ (-d0);
			}
			fp_add1_low(g, g, d0);

			k ^= (f[0] >> 1) ^ (f[0] >> 2);
			k &= 1;

			delta++;
			g0 = g[0] & 1;
			for (int j = 0; j < RLC_FP_DIGS; j++) {
				t[j] = f[j] & (-g0);
			}

			/* Compute g = (g + g0*f) div 2 by conditionally copying f to u and
			 * updating the sign of g. */
			gs ^= g0 & (fs ^ bn_addn_low(g, g, t, RLC_FP_DIGS));
			/* Shift and restore the sign. */
			fp_rsh1_low(g, g);
			g[RLC_FP_DIGS - 1] |= (dig_t)gs << (RLC_DIG - 1);
		}

		for (int j = 0; j < RLC_FP_DIGS; j++) {
			t[j] = 0;
			f[j] ^= -fs;
		}
		t[0] = 1;
		fp_add1_low(f, f, fs);

		r = dv_cmp_const(f, t, RLC_FP_DIGS) == RLC_NE;
		r = RLC_SEL(r, 1, k == 0);
		r = RLC_SEL(r, -1, k == 1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		bn_free(_t);
		dv_free(f);
		dv_free(g);
		dv_free(t);
	}
	return r;
}

static int jumpdivstep(dis_t m[4], dig_t *k, dis_t delta, dig_t x, dig_t y, int s) {
	dig_t c0, c1, yi, ai = 1, bi = 0, ci = 0, di = 1, t, u = 0;
	for (; s > 0; s--) {
		yi = y;
		c0 = ~(delta >> (RLC_DIG - 1));
		c1 = -(x & 1);
		c0 &= c1;

		t = x;
		x = (x + (((y ^ c0) - c0) & c1)) >> 1;
		/* Conditionally copy y = t. */
		t = (t ^ y) & c0;
		y ^= t;

		t = ai;
		ai += ((ci ^ c0) - c0) & c1;
		/* Conditionally copy ci = t. */
		t = (t ^ ci) & c0;
		ci ^= t;

		t = bi;
		bi += ((di ^ c0) - c0) & c1;
		/* Conditionally copy di = t. */
		t = (t ^ di) & c0;
		di ^= t;

		ci += ci;
		di += di;
		/* delta = RLC_SEL(delta + 1, -delta, c0) */
		delta = (delta ^ c0) + 1;

		u += ((yi & y) ^ (y >> (dig_t)1)) & 2;
		u += (u & (dig_t)1) ^ (ci >> (dig_t)(RLC_DIG - 1));
		u %= 4;
	}
	m[0] = ai;
	m[1] = bi;
	m[2] = ci;
	m[3] = di;
	*k = u;
	return delta;
}

static dig_t bn_rsh2_low(dig_t *c, const dig_t *a, int size, int bits) {
	dig_t r, carry, shift, mask;

	/* Prepare the bit mask. */
	shift = (RLC_DIG - bits) % RLC_DIG;
	mask = RLC_MASK(bits);
	carry = a[size - 1] & mask;
	c[size - 1] = (dis_t)a[size - 1] >> bits;
	for (int i = size - 2; i >= 0; i--) {
		r = a[i] & mask;
		c[i] = (a[i] >> bits) | (carry << shift);
		carry = r;
	}
	return carry;
}

static void bn_mul2_low(dig_t *c, const dig_t *a, int sa, dis_t digit) {
	int i, sign, sd = digit >> (RLC_DIG - 1);
	dig_t _c, c0, c1;
	dbl_t r;

	sa = -sa;
	sign = sa ^ sd;
	digit = (digit ^ sd) - sd;

	r = (dbl_t)((a[0] ^ sa) - sa) * digit;
	_c = ((dig_t)r) ^ sign;
	c[0] = _c - sign;

	c0 = ((dbl_t)r >> RLC_DIG);
	c1 = (c[0] < _c);
	for (i = 1; i < RLC_FP_DIGS; i++) {
		r = (a[i] ^ sa) * (dbl_t)digit + c0;
		_c = (dig_t)r ^ sign;
		c[i] = _c + c1;
		c1 = (c[i] < _c);
		c0 = ((dbl_t)r >> RLC_DIG);
	}
	c[i] = (c0 ^ sign) + c1;
}

int fp_smb_jmpds(const fp_t a) {
	dis_t m[4];
	/* Compute number of iterations based on modulus size. */
	int r, i, d = 0, s = RLC_DIG - 2;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	int iterations = (45907 * FP_PRIME + 26313) / 19929;
	dv_t f, g, t, p, t0, t1, u0, u1, v0, v1, p01, p11;
	dig_t j, k = 0;

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

		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
		dv_zero(f, 2 * RLC_FP_DIGS);
		dv_zero(g, 2 * RLC_FP_DIGS);
		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_zero(p, 2 * RLC_FP_DIGS);
		dv_zero(u0, 2 * RLC_FP_DIGS);
		dv_zero(u1, 2 * RLC_FP_DIGS);
		dv_zero(v0, 2 * RLC_FP_DIGS);
		dv_zero(v1, 2 * RLC_FP_DIGS);

		dv_copy(g, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(f, t);
#else
		fp_copy(f, a);
#endif

		int loops = iterations / s;
		loops = (iterations % s == 0 ? loops - 1 : loops);

		j = 0;
		dig_t mask = RLC_MASK(s + 2);
		for (i = 0; i <= loops; i++) {
			d = jumpdivstep(m, &k, d, f[0] & mask, g[0] & mask, s);

			bn_mul2_low(t0, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[0]);
			bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[1]);
			bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

			bn_mul2_low(f, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[2]);
			bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[3]);
			bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

			/* Update f and g. */
			bn_rsh2_low(f, t0, RLC_FP_DIGS + 1, s);
			bn_rsh2_low(g, t1, RLC_FP_DIGS + 1, s);

			j = (j + k) % 4;
			j = (j + ((j & 1) ^ (g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1)))) % 4;
		}

		r = 0;
		j = (j + (j & 1)) % 4;

		t0[0] = 1;
		dv_zero(t0 + 1, RLC_FP_DIGS - 1);
		r = RLC_SEL(r, 1 - j, dv_cmp_const(g, t0, RLC_FP_DIGS) == RLC_EQ);
		for (i = 0; i < RLC_FP_DIGS; i++) {
			g[i] = ~g[i];
		}
		bn_add1_low(g, g, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_const(g, t0, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - j, fp_is_zero(g));
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

	return r;
}
