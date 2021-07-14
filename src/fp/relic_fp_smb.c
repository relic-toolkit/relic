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

void fp_smb_leg(fp_t c, const fp_t a) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* t = (b - 1)/2. */
		t->sign = RLC_POS;
		t->used = RLC_FP_DIGS;
		dv_copy(t->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(t, t, 1);
		bn_hlv(t, t);

		fp_exp(c, a, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

void fp_smb_kro(fp_t c, const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	int d = (49 * FP_PRIME + 80)/17;
#else
	int d = (49 * FP_PRIME + 57)/17;
#endif
	dig_t delta = 1, g0, d0, fs, gs, k, mask, s;
	bn_t _t;
	dv_t f, g, t;

	bn_null(_t);
	dv_null(f);
	dv_null(g);
	dv_null(t);

	if (fp_is_zero(a)) {
		fp_zero(c);
		return;
	}

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
			f[j] ^= -fs;
		}
		fp_add1_low(f, f, fs);

		fp_set_dig(c, 1);
		for (int j = 0; j < RLC_FP_DIGS; j++) {
			c[j] &= -(!fp_is_zero(f));
		}
		fp_neg(t, c);
		dv_copy_cond(c, t, RLC_FP_DIGS, k & 1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		bn_free(_t);
		dv_free(f);
		dv_free(g);
		dv_free(t);
	}
}

/*
# the fixpoint is when f = g (or g = 0, but this is an uninteresting corner case)
# we also compute u,v,q and r here, since we wish to extend this to a jumping version
def posdivsteps2k(n,k,delta,f,g):
    assert (g != 0) & (f & 1)
    u,v,q,r = 1,0,0,1
    # while (f != g):
    while n > 0:
        if delta > 0 and g&1: delta,f,g,u,v,q,r,k = -delta,g,f,q,r,u,v, (k ^^ (g >> 1) & (f >> 1)) & 1
        g0 = g&1
        k = (k ^^ (f >> 1) ^^ (f >> 2)) & 1
        delta,g,u,v,q,r = 1+delta,(g+g0*f)//2,2*u, 2*v, (q+g0*u),(r+g0*v)
        n,g = n-1,ZZ(g)
    M = MatrixSpace(ZZ,2)((u,v,q,r))
    return delta,f,g,M,k
	*/

static int jumpdivstep(dis_t m[4],  dig_t *k, dis_t delta, dig_t f, dig_t g) {
	dig_t t, u = 1, v = 0, q = 0, r = 1, c0, c1;

	//while (f != g) {
	for (int s = 62; s >= 0; s--) {
		/* First handle the else part: if delta < 0, compute -(f,u,v). */
		c0 = delta >> (RLC_DIG - 1);
		c1 = -(g & 1);
		c0 &= c1;

		t = (f ^ g) & c0;
		f ^= t;
		g ^= t;
		t = (u ^ q) & c0;
		u ^= t;
		q ^= t;
		t = (v ^ r) & c0;
		v ^= t;
		r ^= t;
		*k ^= ((g >> (dig_t)1) & (f >> (dig_t)1)) & c0;
		*k ^= ((f >> (dig_t)1) & (f >> (dig_t)2)) & 1;

		g += f & c1;
		q += u & c1;
		r += v & c1;
		/* Now handle the 'if' part, so c0 will be (delta < 0) && (g & 1)) */
		/* delta = RLC_SEL(delta, -delta, c0 & 1) - 2 (for half-divstep), thus
		 * delta = - delta - 2 or delta - 1 */
		delta = (delta ^ c0) - 1;
		g >>= 1;
		u += u;
		v += v;
	}
	m[0] = u;
	m[1] = v;
	m[2] = q;
	m[3] = r;
	//printf("%ld %ld %ld %ld\n", m[0], m[1], m[2], m[3]);
	return delta;
}

static void bn_muls_low(dig_t *c, const dig_t *a, dis_t digit, int size) {
	int sd = digit >> (RLC_DIG - 1);
	digit = (digit ^ sd) - sd;
	c[size] = bn_mul1_low(c, a, digit, size);
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

void fp_smb_jmpds(fp_t c, const fp_t a) {
	dis_t m[4];
	/* Compute number of iterations based on modulus size. */
	int i, j = 0, d = -1, s = RLC_DIG - 2;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	int iterations = (45907 * FP_PRIME + 26313) / 19929;
	dv_t f, g, t, p, t0, t1, u0, u1, v0, v1, p01, p11;
	dig_t k = 0;

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

		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		dv_copy(p + 1, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		d = jumpdivstep(m, &k, d, f[0], g[0]);

		bn_mul2_low(t0, f, RLC_POS, m[0]);
		bn_mul2_low(t1, g, RLC_POS, m[1]);
		bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

		bn_mul2_low(f, f, RLC_POS, m[2]);
		bn_mul2_low(t1, g, RLC_POS, m[3]);
		bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

		/* Update f and g. */
		bn_rsh2_low(f, t0, RLC_FP_DIGS + 1, s);
		bn_rsh2_low(g, t1, RLC_FP_DIGS + 1, s);

		/* Update column vector below. */
		v1[0] = RLC_SEL(m[1], -m[1], (dig_t)m[1] >> (RLC_DIG - 1));
		fp_negm_low(t, v1);
		dv_copy_cond(v1, t, RLC_FP_DIGS, (dig_t)m[1] >> (RLC_DIG - 1));
		u1[0] = RLC_SEL(m[3], -m[3], (dig_t)m[3] >> (RLC_DIG - 1));
		fp_negm_low(t, u1);
		dv_copy_cond(u1, t, RLC_FP_DIGS, (dig_t)m[3] >> (RLC_DIG - 1));

		dv_copy(p01, v1, 2 * RLC_FP_DIGS);
		dv_copy(p11, u1, 2 * RLC_FP_DIGS);

		iterations += iterations/4;
		int loops = iterations / (RLC_DIG - 2);
		loops = (iterations % (RLC_DIG - 2) == 0 ? loops - 1 : loops);

		for (i = 1; i < loops; i++) {
			d = jumpdivstep(m, &k, d, f[0], g[0]);

			bn_mul2_low(t0, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[0]);
			bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[1]);
			bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

			bn_mul2_low(f, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[2]);
			bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[3]);
			bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

			/* Update f and g. */
			bn_rsh2_low(f, t0, RLC_FP_DIGS + 1, s);
			bn_rsh2_low(g, t1, RLC_FP_DIGS + 1, s);

			p[j] = 0;
			dv_copy(p + j + 1, fp_prime_get(), RLC_FP_DIGS);

			/* Update column vector below. */
			bn_muls_low(v0, p01, m[0], RLC_FP_DIGS + j);
			fp_subd_low(t, p, v0);
			dv_copy_cond(v0, t, RLC_FP_DIGS + j + 1,
					(dig_t)m[0] >> (RLC_DIG - 1));

			bn_muls_low(v1, p11, m[1], RLC_FP_DIGS + j);
			fp_subd_low(t, p, v1);
			dv_copy_cond(v1, t, RLC_FP_DIGS + j + 1,
					(dig_t)m[1] >> (RLC_DIG - 1));

			bn_muls_low(u0, p01, m[2], RLC_FP_DIGS + j);
			fp_subd_low(t, p, u0);
			dv_copy_cond(u0, t, RLC_FP_DIGS + j + 1,
					(dig_t)m[2] >> (RLC_DIG - 1));

			bn_muls_low(u1, p11, m[3], RLC_FP_DIGS + j);
			fp_subd_low(t, p, u1);
			dv_copy_cond(u1, t, RLC_FP_DIGS + j + 1,
					(dig_t)m[3] >> (RLC_DIG - 1));

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
		}

		s = 2 * iterations - loops * (RLC_DIG - 2);
		d = jumpdivstep(m, &k, d, f[0] & RLC_MASK(s), g[0] & RLC_MASK(s));

		bn_mul2_low(t0, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[0]);
		bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[1]);
		bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);

		bn_mul2_low(f, f, f[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[2]);
		bn_mul2_low(t1, g, g[RLC_FP_DIGS - 1] >> (RLC_DIG - 1), m[3]);
		bn_addn_low(t1, t1, f, RLC_FP_DIGS + 1);

		/* Update f and g. */
		bn_rsh2_low(f, t0, RLC_FP_DIGS + 1, s);
		bn_rsh2_low(g, t1, RLC_FP_DIGS + 1, s);

		p[j] = 0;
		dv_copy(p + j + 1, fp_prime_get(), RLC_FP_DIGS);

		/* Update column vector below. */
		bn_muls_low(v0, p01, m[0], RLC_FP_DIGS + j);
		fp_subd_low(t, p, v0);
		dv_copy_cond(v0, t, RLC_FP_DIGS + j + 1,
				(dig_t)m[0] >> (RLC_DIG - 1));

		bn_muls_low(v1, p11, m[1], RLC_FP_DIGS + j);
		fp_subd_low(t, p, v1);
		dv_copy_cond(v1, t, RLC_FP_DIGS + j + 1,
				(dig_t)m[1] >> (RLC_DIG - 1));

		fp_addd_low(t, v0, v1);
		fp_rdcn_low(p01, t);

		fp_set_dig(c, 1);
		for (int j = 0; j < RLC_FP_DIGS; j++) {
			c[j] &= -(!fp_is_zero(p01));
		}
		fp_neg(t, c);
		dv_copy_cond(c, t, RLC_FP_DIGS, k & 1);
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
