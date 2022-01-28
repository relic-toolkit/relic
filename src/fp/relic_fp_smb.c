/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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

#if FP_SMB == BASIC || !defined(STRIP)

int fp_smb_basic(const fp_t a) {
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

#endif

#if FP_SMB == DIVST || !defined(STRIP)

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

		r = !(dv_cmp_const(f, t, RLC_FP_DIGS) == RLC_NE);
		r = RLC_SEL(r, -1, (r == 1 && k == 1));
		r = RLC_SEL(r, 1, (r == 1 && k == 0));
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

#endif

#if FP_SMB == BINAR || !defined(STRIP)

#include <stddef.h>

#define MSB(x) ((x) >> (RLC_DIG-1))

static inline dig_t is_zero(dig_t l)
{   return (~l & (l - 1)) >> (RLC_DIG - 1);   }

static dig_t lshift_2(dig_t hi, dig_t lo, size_t l)
{
    size_t r = RLC_DIG - l;
    dig_t mask = 0 - (is_zero(l)^1);
    return (hi << (l&(RLC_DIG-1))) | ((lo & mask) >> (r&(RLC_DIG-1)));
}

static void ab_approximation_n(dig_t a_[2], const dig_t a[],
                               dig_t b_[2], const dig_t b[])
{
    dig_t a_hi, a_lo, b_hi, b_lo, mask;
    size_t i;

    i = RLC_FP_DIGS-1;
    a_hi = a[i],    a_lo = a[i-1];
    b_hi = b[i],    b_lo = b[i-1];
    for (i--; --i;) {
        mask = 0 - is_zero(a_hi | b_hi);
        a_hi = ((a_lo ^ a_hi) & mask) ^ a_hi;
        b_hi = ((b_lo ^ b_hi) & mask) ^ b_hi;
        a_lo = ((a[i] ^ a_lo) & mask) ^ a_lo;
        b_lo = ((b[i] ^ b_lo) & mask) ^ b_lo;
    }
    i = RLC_DIG - util_bits_dig(a_hi | b_hi);
    /* |i| can be RLC_DIG if all a[2..]|b[2..] were zeros */

    a_[0] = a[0], a_[1] = lshift_2(a_hi, a_lo, i);
    b_[0] = b[0], b_[1] = lshift_2(b_hi, b_lo, i);
}

static dig_t cneg_n(dig_t ret[], const dig_t a[], dig_t neg, size_t n)
{
    dbl_t limbx = 0;
    dig_t carry;
    size_t i;

    for (carry=neg&1, i=0; i<n; i++) {
        limbx = (dbl_t)(a[i] ^ neg) + carry;
        ret[i] = (dig_t)limbx;
        carry = (dig_t)(limbx >> RLC_DIG);
    }

    return 0 - MSB((dig_t)limbx);
}

static dig_t smul_n_shift_n(dig_t ret[], const dig_t a[], dig_t *f_,
                                           const dig_t b[], dig_t *g_,
                                           size_t n)
{
    dig_t a_[n+1], b_[n+1], f, g, neg, carry, hi;
    size_t i;

    /* |a|*|f_| */
    f = *f_;
    neg = 0 - MSB(f);
    f = (f ^ neg) - neg;            /* ensure |f| is positive */
    (void)cneg_n(a_, a, neg, n);
    hi = bn_mul1_low(a_, a_, f, n);
    a_[n] = hi - (f & neg);

    /* |b|*|g_| */
    g = *g_;
    neg = 0 - MSB(g);
    g = (g ^ neg) - neg;            /* ensure |g| is positive */
    (void)cneg_n(b_, b, neg, n);
    hi = bn_mul1_low(b_, b_, g, n);
    b_[n] = hi - (g & neg);

    /* |a|*|f_| + |b|*|g_| */
    (void)bn_addn_low(a_, a_, b_, n+1);

    /* (|a|*|f_| + |b|*|g_|) >> k */
    for (carry=a_[0], i=0; i<n; i++) {
        hi = carry >> (RLC_DIG-2);
        carry = a_[i+1];
        ret[i] = hi | (carry << 2);
    }

    /* ensure result is non-negative, fix up |f_| and |g_| accordingly */
    neg = 0 - MSB(carry);
    *f_ = (*f_ ^ neg) - neg;
    *g_ = (*g_ ^ neg) - neg;
    (void)cneg_n(ret, ret, neg, n);

    return neg;
}

/*
 * Copy of inner_loop_n above, but with |L| updates.
 */
static dig_t legendre_loop_n(dig_t L, dig_t m[4], const dig_t a_[2],
                              const dig_t b_[2], size_t n)
{
    dbl_t limbx;
    dig_t f0 = 1, g0 = 0, f1 = 0, g1 = 1;
    dig_t a_lo, a_hi, b_lo, b_hi, t_lo, t_hi, odd, borrow, xorm;

    a_lo = a_[0], a_hi = a_[1];
    b_lo = b_[0], b_hi = b_[1];

    while(n--) {
        odd = 0 - (a_lo&1);

        /* a_ -= b_ if a_ is odd */
        t_lo = a_lo, t_hi = a_hi;
        limbx = a_lo - (dbl_t)(b_lo & odd);
        a_lo = (dig_t)limbx;
        borrow = (dig_t)(limbx >> RLC_DIG) & 1;
        limbx = a_hi - ((dbl_t)(b_hi & odd) + borrow);
        a_hi = (dig_t)limbx;
        borrow = (dig_t)(limbx >> RLC_DIG);

        L += ((t_lo & b_lo) >> 1) & borrow;

        /* negate a_-b_ if it borrowed */
        a_lo ^= borrow;
        a_hi ^= borrow;
        limbx = a_lo + (dbl_t)(borrow & 1);
        a_lo = (dig_t)limbx;
        a_hi += (dig_t)(limbx >> RLC_DIG) & 1;

        /* b_=a_ if a_-b_ borrowed */
        b_lo = ((t_lo ^ b_lo) & borrow) ^ b_lo;
        b_hi = ((t_hi ^ b_hi) & borrow) ^ b_hi;

        /* exchange f0 and f1 if a_-b_ borrowed */
        xorm = (f0 ^ f1) & borrow;
        f0 ^= xorm;
        f1 ^= xorm;

        /* exchange g0 and g1 if a_-b_ borrowed */
        xorm = (g0 ^ g1) & borrow;
        g0 ^= xorm;
        g1 ^= xorm;

        /* subtract if a_ was odd */
        f0 -= f1 & odd;
        g0 -= g1 & odd;

        f1 <<= 1;
        g1 <<= 1;
        a_lo >>= 1; a_lo |= a_hi << (RLC_DIG-1);
        a_hi >>= 1;

        L += (b_lo + 2) >> 2;
    }

	m[0] = f0;
	m[1] = g0;
	m[2] = f1;
	m[3] = g1;

    return L;
}

int fp_smb_binar(const fp_t a) {
	dv_t x, y, t;
    dig_t a_[2], b_[2], neg, L = 0, m[4];
	bn_t _t;

	if (fp_is_zero(a)) {
		return 0;
	}

	bn_null(_t);
	dv_null(x);
	dv_null(y);
	dv_null(t);

	RLC_TRY {
		bn_new(_t);
		dv_new(x);
		dv_new(y);
		dv_new(t);

		fp_prime_back(_t, a);
		dv_zero(x, RLC_FP_DIGS);
		dv_copy(x, _t->dp, _t->used);
		dv_copy(y, fp_prime_get(), RLC_FP_DIGS);

		for (size_t i = 0; i < (2 * RLC_FP_DIGS * RLC_DIG)/(RLC_DIG - 2); i++) {
	        ab_approximation_n(a_, x, b_, y);
	        L = legendre_loop_n(L, m, a_, b_, RLC_DIG-2);
	        neg = smul_n_shift_n(t, x, &m[0], y, &m[1], RLC_FP_DIGS);
	        (void)smul_n_shift_n(y, x, &m[2], y, &m[3], RLC_FP_DIGS);
	        dv_copy(x, t, RLC_FP_DIGS);
	        L += (y[0] >> 1) & neg;
	    }

	    L = legendre_loop_n(L, m, x, y, (2*RLC_FP_DIGS*RLC_DIG)%(RLC_DIG-2));

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		bn_free(_t);
		dv_free(x);
		dv_free(y);
		dv_free(t);
	}

	return (L & 1 ? -1 : 1);
}

#endif

#if FP_SMB == JMPDS || !defined(STRIP)

dis_t jumpdivstep(dis_t m[4], dig_t *k, dis_t delta, dis_t x, dis_t y, int s) {
	dig_t t0, t1, t2, c0, c1, yi, ai = 1, bi = 0, ci = 0, di = 1, u = 0;
	for (s = RLC_DIG - 2; s > 0; s--) {
		yi = y;

		c0 = ~(delta >> (RLC_DIG - 1));
		c1 = -(x & 1);
		c0 &= c1;

		t0 = (delta < 0 ? y : -y);
		t1 = (delta < 0 ? ci : -ci);
		t2 = (delta < 0 ? di : -di);
		x += t0 & c1;
		ai += t1 & c1;
		bi += t2 & c1;

		/* delta = RLC_SEL(delta + 1, -delta, c0) */
		y = y + (x & c0);
		ci = ci + (ai & c0);
		di = di + (bi & c0);
		x >>= 1;
		ci <<= 1;
		di <<= 1;
		delta = (delta ^ c0) + 1;

		u += ((yi & y) ^ (y >> 1)) & 2;
		u += (u & 1) ^ RLC_SIGN(ci);
	}
	m[0] = ai;
	m[1] = bi;
	m[2] = ci;
	m[3] = di;
	*k = u;
	return delta;
}

static inline dig_t _bn_muls_low(dig_t *c, const dig_t *a, dig_t sa, dis_t digit, int size) {
	dig_t r, _c, c0, c1, sign, sd = digit >> (RLC_DIG - 1);

	sa = -sa;
	sign = sa ^ sd;
	digit = (digit ^ sd) - sd;

	RLC_MUL_DIG(r, _c, a[0], (dig_t)digit);
	_c ^= sign;
	c[0] = _c - sign;
	c1 = (c[0] < _c);
	c0 = r;
	for (int i = 1; i < size; i++) {
		RLC_MUL_DIG(r, _c, a[i], (dig_t)digit);
		_c += c0;
		c0 = r + (_c < c0);
		_c ^= sign;
		c[i] = _c + c1;
		c1 = (c[i] < _c);
	}
	return (c0 ^ sign) + c1;
}

int fp_smb_jmpds(const fp_t a) {
	dis_t m[4], d = 0;
	int r, i, s = RLC_DIG - 2;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	int loops, iterations = (45907 * FP_PRIME + 26313) / 19929;
	dv_t f, g, t, p, t0, t1, u0, u1, p01, p11;
	dig_t j, k, mask = RLC_MASK(s + 2);

	dv_null(f);
	dv_null(g);
	dv_null(t);
	dv_null(p);
	dv_null(t0);
	dv_null(t1);
	dv_null(u0);
	dv_null(u1);
	dv_null(p01);
	dv_null(p11);

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

		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
		dv_zero(f, 2 * RLC_FP_DIGS);
		dv_zero(g, 2 * RLC_FP_DIGS);
		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_zero(p, 2 * RLC_FP_DIGS);
		dv_zero(u0, 2 * RLC_FP_DIGS);
		dv_zero(u1, 2 * RLC_FP_DIGS);

		dv_copy(g, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(f, t);
#else
		fp_copy(f, a);
#endif

		loops = iterations / s;
		loops = (iterations % s == 0 ? loops - 1 : loops);

		j = k = 0;
		for (i = 0; i <= loops; i++) {
			int precision = RLC_FP_DIGS;
			d = jumpdivstep(m, &k, d, f[0] & mask, g[0] & mask, s);

			cneg_n(u0, f, -RLC_SIGN(f[precision]), precision);
			cneg_n(u1, g, -RLC_SIGN(g[precision]), precision);

			t0[precision] = _bn_muls_low(t0, u0, RLC_SIGN(f[precision]), m[0], precision);
			t1[precision] = _bn_muls_low(t1, u1, RLC_SIGN(g[precision]), m[1], precision);
			bn_addn_low(t0, t0, t1, precision + 1);

			f[precision] = _bn_muls_low(f, u0, RLC_SIGN(f[precision]), m[2], precision);
			t1[precision] = _bn_muls_low(t1, u1, RLC_SIGN(g[precision]), m[3], precision);
			bn_addn_low(t1, t1, f, precision + 1);

			/* Update f and g. */
			bn_rshs_low(f, t0, precision + 1, s);
			bn_rshs_low(g, t1, precision + 1, s);

			j = (j + k) % 4;
			j = (j + ((j & 1) ^ (RLC_SIGN(g[precision])))) % 4;
		}

		r = 0;
		j = (j + (j & 1)) % 4;

		fp_zero(t0);
		t0[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_const(g, t0, RLC_FP_DIGS) == RLC_EQ);
		cneg_n(g, g, -1, RLC_FP_DIGS);
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
		dv_free(p01);
		dv_free(p11);
	}

	return r;
}

#endif

#if FP_SMB == LOWER || !defined(STRIP)

int fp_smb_lower(const fp_t a) {
	return fp_smbm_low(a);
}

#endif
