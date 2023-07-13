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
/* Private definitions                                                        */
/*============================================================================*/

#if FP_SMB == JMPDS || !defined(STRIP)

/**
 * Conditionally negate a digit vector using two's complement representation.
 *
 * @param[out] c 		- the result.
 * @param[in] a 		- the digit vector to conditionally negate.
 * @param[in] sa 		- the sign of the digit vector.
 * @param[in] n			- the number of digits to conditionally negate.
 */
static void bn_negs_low(dig_t c[], const dig_t a[], dig_t sa, size_t n) {
    dig_t carry = sa & 1;

	sa = -sa;
    for (int i = 0; i < n; i++) {
        c[i] = (a[i] ^ sa) + carry;
		carry = (c[i] < carry);
    }
}

static dis_t jumpdivstep(dis_t m[4], dig_t *k, dis_t delta,
		dis_t x, dis_t y, int s) {
	dig_t t0, t1, t2, c0, c1, yi, ai = 1, bi = 0, ci = 0, di = 1, u = 0;

	/* Unrolling twice makes it faster. */
	for (s -= 2; s >= 0; s -= 2) {
		yi = y;

		c0 = ~(delta >> (RLC_DIG - 1));
		c1 = -(x & 1);
		c0 &= c1;

		t0 = RLC_SEL(-y, y, delta < 0);
		t1 = RLC_SEL(-ci, ci, delta < 0);
		t2 = RLC_SEL(-di, di, delta < 0);
		x  += t0 & c1;
		ai += t1 & c1;
		bi += t2 & c1;

		/* delta = RLC_SEL(delta + 1, -delta, c0) */
		y  += x  & c0;
		ci += ai & c0;
		di += bi & c0;

		x  >>= 1;
		ci <<= 1;
		di <<= 1;
		delta = (delta ^ c0) + 1;

		u += ((yi & y) ^ (y >> 1)) & 2;
		u += (u & 1) ^ RLC_SIGN(ci);

		yi = y;

		c0 = ~(delta >> (RLC_DIG - 1));
		c1 = -(x & 1);
		c0 &= c1;

		t0 = RLC_SEL(-y, y, delta < 0);
		t1 = RLC_SEL(-ci, ci, delta < 0);
		t2 = RLC_SEL(-di, di, delta < 0);
		x  += t0 & c1;
		ai += t1 & c1;
		bi += t2 & c1;

		/* delta = RLC_SEL(delta + 1, -delta, c0) */
		y  += x  & c0;
		ci += ai & c0;
		di += bi & c0;

		x  >>= 1;
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

#endif

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

#if FP_SMB == BINAR || !defined(STRIP)

static inline dig_t is_zero(dig_t l) {
    l = ~l & (l - 1);
    return (l >> (RLC_DIG - 1));
}

static dig_t lshift_2(dig_t hi, dig_t lo, size_t l) {
    size_t r = RLC_DIG - l;
    dig_t mask = 0 - (is_zero(l)^1);
    return (hi << (l&(RLC_DIG-1))) | ((lo & mask) >> (r&(RLC_DIG-1)));
}

static void ab_approximation_n(dig_t a_[2], const dig_t a[],
        dig_t b_[2], const dig_t b[]) {
    dig_t a_hi, a_lo, b_hi, b_lo, mask;
    size_t i;

    i = RLC_FP_DIGS-1;
    a_hi = a[i],    a_lo = a[i-1];
    b_hi = b[i],    b_lo = b[i-1];
    for (int j = i - 1; j >= 0; j--) {
        mask = 0 - is_zero(a_hi | b_hi);
        a_hi = ((a_lo ^ a_hi) & mask) ^ a_hi;
        b_hi = ((b_lo ^ b_hi) & mask) ^ b_hi;
        a_lo = ((a[j] ^ a_lo) & mask) ^ a_lo;
        b_lo = ((b[j] ^ b_lo) & mask) ^ b_lo;
    }
    i = RLC_DIG - util_bits_dig(a_hi | b_hi);
    /* |i| can be RLC_DIG if all a[2..]|b[2..] were zeros */

    a_[0] = a[0], a_[1] = lshift_2(a_hi, a_lo, i);
    b_[0] = b[0], b_[1] = lshift_2(b_hi, b_lo, i);
}

static dig_t smul_n_shift_n(dig_t ret[], const dig_t a[], dig_t *f_,
        const dig_t b[], dig_t *g_) {
    dig_t a_[RLC_FP_DIGS+1], b_[RLC_FP_DIGS+1], f, g, neg, carry, hi;
    size_t i;

    /* |a|*|f_| */
    f = *f_;
    neg = 0 - RLC_SIGN(f);
    f = (f ^ neg) - neg;            /* ensure |f| is positive */
    bn_negs_low(a_, a, -neg, RLC_FP_DIGS);
    hi = fp_mul1_low(a_, a_, f);
    a_[RLC_FP_DIGS] = hi - (f & neg);

    /* |b|*|g_| */
    g = *g_;
    neg = 0 - RLC_SIGN(g);
    g = (g ^ neg) - neg;            /* ensure |g| is positive */
    bn_negs_low(b_, b, -neg, RLC_FP_DIGS);
    hi = fp_mul1_low(b_, b_, g);
    b_[RLC_FP_DIGS] = hi - (g & neg);

    /* |a|*|f_| + |b|*|g_| */
    (void)bn_addn_low(a_, a_, b_, RLC_FP_DIGS+1);

    /* (|a|*|f_| + |b|*|g_|) >> k */
    for (carry=a_[0], i=0; i<RLC_FP_DIGS; i++) {
        hi = carry >> (RLC_DIG-2);
        carry = a_[i+1];
        ret[i] = hi | (carry << 2);
    }

    /* ensure result is non-negative, fix up |f_| and |g_| accordingly */
    neg = 0 - RLC_SIGN(carry);
    *f_ = (*f_ ^ neg) - neg;
    *g_ = (*g_ ^ neg) - neg;
    bn_negs_low(ret, ret, -neg, RLC_FP_DIGS);

    return neg;
}

/*
 * Copy of inner_loop_n above, but with |L| updates.
 */
static dig_t legendre_loop_n(dig_t l, dig_t m[4], const dig_t a_[2],
		const dig_t b_[2], size_t n) {
    dig_t limbx, f0 = 1, g0 = 0, f1 = 0, g1 = 1;
    dig_t a_lo, a_hi, b_lo, b_hi, t_lo, t_hi, odd, borrow, xorm;

    a_lo = a_[0], a_hi = a_[1];
    b_lo = b_[0], b_hi = b_[1];

   while(n--) {
        odd = 0 - (a_lo&1);

        /* a_ -= b_ if a_ is odd */
        t_lo = a_lo, t_hi = a_hi;

        borrow = 0;
        limbx = a_lo - (b_lo & odd);
        borrow = (a_lo < limbx);
        a_lo = limbx;

        limbx = a_hi - (b_hi & odd);
        xorm = limbx - borrow;
        borrow = -((a_hi < limbx) || (borrow && !limbx));
        a_hi = xorm;

        l += ((t_lo & b_lo) >> 1) & borrow;

        /* negate a_-b_ if it borrowed */
        a_lo ^= borrow;
        a_hi ^= borrow;
        limbx = a_lo + (borrow & 1);
        a_hi += (a_lo < limbx);
        a_lo = limbx;

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

        l += (b_lo + 2) >> 2;
    }

	m[0] = f0;
	m[1] = g0;
	m[2] = f1;
	m[3] = g1;

    return l;
}

int fp_smb_binar(const fp_t a) {
	const size_t s = RLC_DIG - 2;
    dv_t x, y, t;
    dig_t a_[2], b_[2], neg, l = 0, m[4];
	bn_t _t;
	int iterations = 2 * RLC_FP_DIGS * RLC_DIG;

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

		for (size_t i = 0; i < iterations/s; i++) {
	        ab_approximation_n(a_, x, b_, y);
	        l = legendre_loop_n(l, m, a_, b_, s);
	        neg = smul_n_shift_n(t, x, &m[0], y, &m[1]);
	        (void)smul_n_shift_n(y, x, &m[2], y, &m[3]);
	        fp_copy(x, t);
	        l += (y[0] >> 1) & neg;
	    }

	    l = legendre_loop_n(l, m, x, y, iterations % s);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		bn_free(_t);
		dv_free(x);
		dv_free(y);
		dv_free(t);
	}

	return (l & 1 ? -1 : 1);
}

#endif

#if FP_SMB == DIVST || !defined(STRIP)

int fp_smb_divst(const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	int r = 0, d = (49 * FP_PRIME + 80)/17;
#else
	int r = 0, d = (49 * FP_PRIME + 57)/17;
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

#if FP_SMB == JMPDS || !defined(STRIP)

int fp_smb_jmpds(const fp_t a) {
	const int s = RLC_DIG - 2;
	dis_t m[4], d = 0;
	int i, r = 0;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	int iterations = (45907 * FP_PRIME + 26313) / 19929;
	dv_t f, g, t0, t1, u0, u1;
	dig_t sf, sg, j, k;

	dv_null(f);
	dv_null(g);
	dv_null(t0);
	dv_null(t1);
	dv_null(u0);
	dv_null(u1);

	RLC_TRY {
		dv_new(f);
		dv_new(g);
		dv_new(t0);
		dv_new(t1);
		dv_new(u0);
		dv_new(u1);

		dv_zero(f, RLC_FP_DIGS + 1);
		dv_copy(g, fp_prime_get(), RLC_FP_DIGS);
		dv_zero(t0 + RLC_FP_DIGS, RLC_FP_DIGS);
		g[RLC_FP_DIGS] = 0;

#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t0, a);
		fp_rdcn_low(f, t0);
#else
		fp_copy(f, a);
#endif

		for (i = j = k = 0; i < iterations; i += s) {
			int precision = RLC_FP_DIGS;
			d = jumpdivstep(m, &k, d, f[0], g[0], s);

			sf = RLC_SIGN(f[precision]);
			sg = RLC_SIGN(g[precision]);
			bn_negs_low(u0, f, sf, precision);
			bn_negs_low(u1, g, sg, precision);

			t0[precision] = bn_muls_low(t0, u0, sf, m[0], precision);
			t1[precision] = bn_muls_low(t1, u1, sg, m[1], precision);
			bn_addn_low(t0, t0, t1, precision + 1);
			bn_rshs_low(f, t0, precision + 1, s);

			t0[precision] = bn_muls_low(t0, u0, sf, m[2], precision);
			t1[precision] = bn_muls_low(t1, u1, sg, m[3], precision);
			bn_addn_low(t1, t1, t0, precision + 1);
			bn_rshs_low(g, t1, precision + 1, s);

			j = (j + k) % 4;
			j = (j + ((j & 1) ^ (RLC_SIGN(g[precision])))) % 4;
		}

		r = 0;
		j = (j + (j & 1)) % 4;

		fp_zero(t0);
		t0[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_const(g, t0, RLC_FP_DIGS) == RLC_EQ);
		bn_negs_low(g, g, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_const(g, t0, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - j, fp_is_zero(g));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free(f);
		dv_free(g);
		dv_free(t0);
		dv_free(t1);
		dv_free(u0);
		dv_free(u1);
	}

	return r;
}

#endif

#if FP_SMB == LOWER || !defined(STRIP)

int fp_smb_lower(const fp_t a) {
	return fp_smbm_low(a);
}

#endif
