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

#if FP_SMB == BINAR || !defined(STRIP)
/**
 * Approach heavily inpired in the blst implementation of the algorithm.
 */
static dig_t porninstep(dis_t m[4],const dig_t f[2], const dig_t g[2], 
		dig_t k, size_t s) {
	dig_t limbx, ai = 1, bi = 0, ci = 0, di = 1;
	dig_t g_lo = g[0], g_hi = g[1], f_lo = f[0], f_hi = f[1];
	dig_t t_lo, t_hi, odd, borrow, xorm;

	/* Unrolling twice gives some small speedup. */
	for (size_t i = 0; i < s; i+=2) {
		odd = 0 - (g_lo & 1);

		/* g_ -= f_ if g_ is odd */
		t_lo = g_lo, t_hi = g_hi;

		borrow = 0;
		limbx = g_lo - (f_lo & odd);
		borrow = (g_lo < limbx);
		g_lo = limbx;

		limbx = g_hi - (f_hi & odd);
		xorm = limbx - borrow;
		borrow = -((g_hi < limbx) || (borrow && !limbx));
		g_hi = xorm;

		k += ((t_lo & f_lo) >> 1) & borrow;

		/* negate g_-f_ if it borrowed */
		g_lo ^= borrow;
		g_hi ^= borrow;
		limbx = g_lo + (borrow & 1);
		g_hi += (g_lo < limbx);
		g_lo = limbx;

		/* f_=g_ if g_-f_ borrowed */
		f_lo = ((t_lo ^ f_lo) & borrow) ^ f_lo;
		f_hi = ((t_hi ^ f_hi) & borrow) ^ f_hi;

		/* exchange ai and ci if g_-f_ borrowed */
		xorm = (ai ^ ci) & borrow;
		ai ^= xorm;
		ci ^= xorm;

		/* exchange bi and di if g_-f_ borrowed */
		xorm = (bi ^ di) & borrow;
		bi ^= xorm;
		di ^= xorm;

		/* subtract if g_ was odd */
		ai -= ci & odd;
		bi -= di & odd;

		ci <<= 1;
		di <<= 1;
		g_lo >>= 1;
		g_lo |= g_hi << (RLC_DIG - 1);
		g_hi >>= 1;

		k += (f_lo + 2) >> 2;

		odd = 0 - (g_lo & 1);

		/* g_ -= f_ if g_ is odd */
		t_lo = g_lo, t_hi = g_hi;

		borrow = 0;
		limbx = g_lo - (f_lo & odd);
		borrow = (g_lo < limbx);
		g_lo = limbx;

		limbx = g_hi - (f_hi & odd);
		xorm = limbx - borrow;
		borrow = -((g_hi < limbx) || (borrow && !limbx));
		g_hi = xorm;

		k += ((t_lo & f_lo) >> 1) & borrow;

		/* negate g_-f_ if it borrowed */
		g_lo ^= borrow;
		g_hi ^= borrow;
		limbx = g_lo + (borrow & 1);
		g_hi += (g_lo < limbx);
		g_lo = limbx;

		/* f_=g_ if g_-f_ borrowed */
		f_lo = ((t_lo ^ f_lo) & borrow) ^ f_lo;
		f_hi = ((t_hi ^ f_hi) & borrow) ^ f_hi;

		/* exchange ai and ci if g_-f_ borrowed */
		xorm = (ai ^ ci) & borrow;
		ai ^= xorm;
		ci ^= xorm;

		/* exchange bi and di if g_-f_ borrowed */
		xorm = (bi ^ di) & borrow;
		bi ^= xorm;
		di ^= xorm;

		/* subtract if g_ was odd */
		ai -= ci & odd;
		bi -= di & odd;

		ci <<= 1;
		di <<= 1;
		g_lo >>= 1;
		g_lo |= g_hi << (RLC_DIG - 1);
		g_hi >>= 1;

		k += (f_lo + 2) >> 2;
	}

	m[0] = ai;
	m[1] = bi;
	m[2] = ci;
	m[3] = di;

	return k;
}

#endif

#if FP_SMB == JMPDS || !defined(STRIP)

static dis_t jumpdivstep(dis_t m[4], dig_t *k, dis_t delta, dis_t y, dis_t x, 
		int s) {
	dig_t t0, t1, t2, c0, c1, yi, ai = 1, bi = 0, ci = 0, di = 1, u = 0;

	/* Unrolling twice makes it faster. */
	for (s -= 2; s >= 0; s -= 2) {
		yi = y;

		c0 = delta >> (RLC_DIG - 1);
		c1 = -(x & 1);
		c0 &= c1;

		t0 = (y ^ c0) - c0;
		t1 = (ci ^ c0) - c0;
		t2 = (di ^ c0) - c0;
		x  += t0 & c1;
		ai += t1 & c1;
		bi += t2 & c1;

		/* delta = RLC_SEL(2 + delta, 2 - delta, c0) */
		y  += x  & c0;
		ci += ai & c0;
		di += bi & c0;

		x  >>= 1;
		ci <<= 1;
		di <<= 1;
		delta = (delta ^ c0) - 1;

		u += ((yi & y) ^ (y >> 1)) & 2;
		u += (u & 1) ^ RLC_SIGN(ci);

		yi = y;

		c0 = delta >> (RLC_DIG - 1);
		c1 = -(x & 1);
		c0 &= c1;

		t0 = (y ^ c0) - c0;
		t1 = (ci ^ c0) - c0;
		t2 = (di ^ c0) - c0;
		x  += t0 & c1;
		ai += t1 & c1;
		bi += t2 & c1;

		/* delta = RLC_SEL(2 + delta, 2 - delta, c0) */
		y  += x  & c0;
		ci += ai & c0;
		di += bi & c0;

		x  >>= 1;
		ci <<= 1;
		di <<= 1;
		delta = (delta ^ c0) - 1;

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

#define RLC_LSH(H, L, I)													\
		(H << I) | (L & -(I != 0)) >> ((RLC_DIG - I) & (RLC_DIG - 1))

int fp_smb_binar(const fp_t a) {
	const size_t s = RLC_DIG - 2;
	dv_t f, g, t, t0, t1;
	dig_t g_[2], f_[2], neg, l, g_hi, g_lo, f_hi, f_lo, mask, k = 0;
	dis_t m[4];
	int iterations = 2 * RLC_FP_DIGS * RLC_DIG;

	if (fp_is_zero(a)) {
		return 0;
	}

	dv_null(f);
	dv_null(g);
	dv_null(t);
	dv_null(t0);
	dv_null(t1);

	RLC_TRY {
		dv_new(f);
		dv_new(g);
		dv_new(t);
		dv_new(t0);
		dv_new(t1);

		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif

		for (size_t len, i = 0; i < iterations / s; i++) {
			f_hi = f[RLC_FP_DIGS - 1], f_lo = f[RLC_FP_DIGS - 2];
			g_hi = g[RLC_FP_DIGS - 1], g_lo = g[RLC_FP_DIGS - 2];
			for (int j = RLC_FP_DIGS - 2; j >= 0; j--) {
				l = (f_hi | g_hi);
				l = ~l & (l - 1);
				mask = -(l >> (RLC_DIG - 1));
				f_hi = ((f_lo ^ f_hi) & mask) ^ f_hi;
				g_hi = ((g_lo ^ g_hi) & mask) ^ g_hi;
				f_lo = ((f[j] ^ f_lo) & mask) ^ f_lo;
				g_lo = ((g[j] ^ g_lo) & mask) ^ g_lo;
			}
			len = RLC_DIG - util_bits_dig(f_hi | g_hi);
			f_[0] = f[0], f_[1] = RLC_LSH(f_hi, f_lo, len);
			g_[0] = g[0], g_[1] = RLC_LSH(g_hi, g_lo, len);

			k = porninstep(m, f_, g_, k, s);

			t0[RLC_FP_DIGS] = bn_muls_low(t0, g, RLC_POS, m[0], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_muls_low(t1, f, RLC_POS, m[1], RLC_FP_DIGS);
			bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);
			neg = RLC_SIGN(t0[RLC_FP_DIGS]);
			bn_rshb_low(t, t0, RLC_FP_DIGS + 1, (RLC_DIG - 2));
			bn_negs_low(t, t, neg, RLC_FP_DIGS);

			t0[RLC_FP_DIGS] = bn_muls_low(t0, g, RLC_POS, m[2], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_muls_low(t1, f, RLC_POS, m[3], RLC_FP_DIGS);
			bn_addn_low(t1, t1, t0, RLC_FP_DIGS + 1);
			bn_rshb_low(f, t1, RLC_FP_DIGS + 1, (RLC_DIG - 2));
			bn_negs_low(f, f, RLC_SIGN(t1[RLC_FP_DIGS]), RLC_FP_DIGS);

			fp_copy(g, t);
			k += (f[0] >> 1) & neg;
		}

		k = porninstep(m, g, f, k, iterations % s);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT)
	} RLC_FINALLY {
		dv_free(f);
		dv_free(g);
		dv_free(t);
		dv_free(t0);
		dv_free(t1);
	}

	return (k & 1 ? -1 : 1);
}

#endif

#if FP_SMB == DIVST || !defined(STRIP)

int fp_smb_divst(const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	const int d = (49 * FP_PRIME + 80) / 17;
#else
	const int d = (49 * FP_PRIME + 57) / 17;
#endif
	dig_t delta = 1, g0, d0, fs, gs, k, mask, s;
	bn_t _t;
	dv_t f, g, t;
	int r = 0;

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
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		dv_zero(t, 2 * RLC_FP_DIGS);
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		r = dv_cmp(g, f, RLC_FP_DIGS);
		fp_subn_low(t, g, f);
		fp_copy_sec(g, t, r != RLC_LT);

		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			d0 = g[0] & ((int)delta > 0);
			/* Conditionally negate delta if d0 is set. */
			delta = (delta ^ -d0) + d0;
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

			k ^= (((g[0] & f[0]) >> (dig_t)1) ^ (fs & gs)) & d0;
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

		k = (2*k) % 4;
		fp_zero(t);
		t[0] = 1;
		bn_negs_low(f, f, fs, RLC_FP_DIGS);
		
		r = RLC_SEL(r, 1 - k, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_negs_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - k, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - k, fp_is_zero(f));
		r = RLC_SEL(r, 0, fp_is_zero(a));
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
	dis_t m[4], d = -1;
	/* Iterations taken directly from https://github.com/sipa/safegcd-bounds */
	const int iterations = (45907 * FP_PRIME + 26313) / 19929;
	int loops, precision, i, r = 0, s = RLC_DIG - 2;
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

		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		f[RLC_FP_DIGS] = 0;
		dv_zero(g, RLC_FP_DIGS + 1);
		dv_zero(t0 + RLC_FP_DIGS, RLC_FP_DIGS);

#if FP_RDC == MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t0, a);
		fp_rdcn_low(g, t0);
#else
		fp_copy(g, a);
#endif
		precision = RLC_FP_DIGS;
		loops = iterations / s;
		loops = (iterations % s == 0 ? loops - 1 : loops);

		for (i = j = k = 0; i < loops; i++) {
			d = jumpdivstep(m, &k, d, f[0], g[0], s);

			sf = RLC_SIGN(f[precision]);
			sg = RLC_SIGN(g[precision]);
			bn_negs_low(u0, f, sf, precision);
			bn_negs_low(u1, g, sg, precision);
			
			t0[precision] = bn_muls_low(t0, u0, sf, m[3], precision);
			t1[precision] = bn_muls_low(t1, u1, sg, m[2], precision);
			bn_addn_low(t0, t0, t1, precision + 1);
			bn_rshs_low(f, t0, precision + 1, s);

			t0[precision] = bn_muls_low(t0, u0, sf, m[1], precision);
			t1[precision] = bn_muls_low(t1, u1, sg, m[0], precision);
			bn_addn_low(t1, t1, t0, precision + 1);
			bn_rshs_low(g, t1, precision + 1, s);

			j = (j + k) % 4;
			j = (j + ((j & 1) ^ (RLC_SIGN(f[precision])))) % 4;
		}

		s = iterations - loops * s;
		d = jumpdivstep(m, &k, d, f[0], g[0], s);

		sf = RLC_SIGN(f[precision]);
		sg = RLC_SIGN(g[precision]);
		bn_negs_low(u0, f, sf, precision);
		bn_negs_low(u1, g, sg, precision);

		t0[precision] = bn_muls_low(t0, u0, sf, m[3], precision);
		t1[precision] = bn_muls_low(t1, u1, sg, m[2], precision);
		bn_addn_low(t0, t0, t1, precision + 1);
		bn_rshs_low(f, t0, precision + 1, s);

		j = (j + k) % 4;
		j = (j + ((j & 1) ^ (RLC_SIGN(f[precision])))) % 4;
		j = (j + (j & 1)) % 4;

		fp_zero(t0);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t0, RLC_FP_DIGS) == RLC_EQ);
		t0[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t0, RLC_FP_DIGS) == RLC_EQ);
		bn_negs_low(t0, t0, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t0, RLC_FP_DIGS) == RLC_EQ);
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
