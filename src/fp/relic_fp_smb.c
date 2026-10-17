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

/**
 * Number of division steps for any modulus p < 2^FP_PRIME, from the bound for
 * half-delta divsteps in https://github.com/sipa/safegcd-bounds.
 */
#define JMPDS_ITERS	((3787 * FP_PRIME + 2166) / 1644)

/**
 * Number of division steps in each jump, done in two halves so that each row
 * of the transition matrix of a half fits in a digit.
 */
#define JMPDS_STEPS			(RLC_DIG - 4)

/**
 * Performs s <= JMPDS_STEPS half-delta division steps on the lowest digits of
 * f and g, and returns the transition matrix m = (u, v; q, r) scaled by 2^s,
 * with the rows packed in single digits within each half. The count k tracks
 * the Jacobi symbol: modulo 4, the sign changes of v plus two for each flip.
 *
 * @param[out] m			- the transition matrix.
 * @param[out] k			- the count of sign changes and flips.
 * @param[in] zeta			- the current value of zeta.
 * @param[in] f				- the lowest digit of f, which must be odd.
 * @param[in] g				- the lowest digit of g.
 * @param[in] s				- the number of steps.
 * @return the updated value of zeta.
 */
#if RLC_WSIZE == 8
static int smb_steps(dis_t m[4], dig_t *k, int zeta, dig_t f, dig_t g,
		int s) {
#else
static dis_t smb_steps(dis_t m[4], dig_t *k, dis_t zeta, dig_t f, dig_t g,
		int s) {
#endif
	const int h = RLC_DIG / 2;
	dig_t uv, qr, c0, c1, fi, w, c, n = 0;
	dis_t u, v, q, r, t0, t1;

	m[0] = m[3] = 1;
	m[1] = m[2] = 0;
	for (int l, half = 0; half < 2; half++) {
		l = (half == 0 ? s / 2 : s - s / 2);
		uv = 1;
		qr = (dig_t)1 << h;
		c = 0;
		for (int j = 0; j < l; j++) {
			fi = f;
			/* c0 is all ones if zeta < 0, c1 if g is odd. */
			c0 = zeta >> (8 * sizeof(zeta) - 1);
			c1 = -(g & 1);
			/* Add (f, u, v) to (g, q, r) if g is odd, negated if zeta < 0. */
			g += ((f ^ c0) - c0) & c1;
			qr += ((uv ^ c0) - c0) & c1;
			/* Swap if zeta < 0 and g is odd, then update zeta. */
			c0 &= c1;
			zeta = (zeta ^ (dis_t)c0) - 1;
			/* When swapping, (f, u, v) becomes the old (g, q, r). */
			f += g & c0;
			uv += qr & c0;
			/* Halve g by doubling (u, v) instead, keeping integer entries. */
			g >>= 1;
			uv += uv;
			/* Flip for the rotation and the halving, from f mod 8. */
			c += ((fi & f) ^ (f >> 1)) & 2;
			/* Count the sign changes of v, the high half of uv. */
			w = uv - (dig_t)((dis_t)(uv << h) >> h);
			c += (c & 1) ^ (w >> (RLC_DIG - 1));
		}
		/* Unpack the signed entries and accumulate the matrix product. */
		u = (dis_t)(uv << h) >> h;
		v = (dis_t)(uv - u) >> h;
		q = (dis_t)(qr << h) >> h;
		r = (dis_t)(qr - q) >> h;
		t0 = u * m[0] + v * m[2];
		t1 = u * m[1] + v * m[3];
		m[2] = q * m[0] + r * m[2];
		m[3] = q * m[1] + r * m[3];
		m[0] = t0;
		m[1] = t1;
		/* Correct the count with the sign of v in the product. */
		n += c;
		n += (n & 1) ^ RLC_SIGN(m[1]);
	}
	*k = n & 3;
	return zeta;
}

/**
 * Adds a * b to the signed double digit (c1, c0); sb is the sign mask of b.
 */
static inline void smb_mac(dig_t *c1, dig_t *c0, dis_t a, dig_t b,
		dig_t sb) {
	dig_t h, l;
#ifdef RLC_CONF_NODBL
	RLC_MUL_DIG(h, l, (dig_t)a, b);
#else
	/* Multiply once to get both halves. */
	dbl_t t = (dbl_t)(dig_t)a * b;
	h = (dig_t)(t >> RLC_DIG);
	l = (dig_t)t;
#endif
	/* Correct the unsigned high half for the signs of a and b. */
	h -= (b & -RLC_SIGN(a)) + ((dig_t)a & sb);
	*c0 += l;
	*c1 += h + (*c0 < l);
}

/**
 * Applies the transition matrix m = (u, v; q, r) of s division steps to
 * (f, g), computing (u * f + v * g, q * f + r * g) / 2^s in a single pass,
 * where the division is exact. Both values have RLC_FP_DIGS + 1 signed digits.
 *
 * @param[in,out] f			- the first entry of the column vector.
 * @param[in,out] g			- the second entry of the column vector.
 * @param[in] m				- the transition matrix.
 * @param[in] s				- the number of division steps.
 */
static void smb_apply(dig_t *f, dig_t *g, const dis_t m[4], int s) {
	const dis_t u = m[0], v = m[1], q = m[2], r = m[3];
	dig_t f1 = 0, f0 = 0, g1 = 0, g0 = 0, fs = 0, gs = 0, fi, gi;
	size_t i;

	for (i = 0; i < RLC_FP_DIGS; i++) {
		fi = f[i];
		gi = g[i];
		smb_mac(&f1, &f0, u, fi, 0);
		smb_mac(&f1, &f0, v, gi, 0);
		smb_mac(&g1, &g0, q, fi, 0);
		smb_mac(&g1, &g0, r, gi, 0);
		/* Store the previous digits shifted right by s bits. */
		if (i > 0) {
			f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
			g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
		}
		/* Keep the current digits and shift the accumulators by a digit. */
		fs = f0;
		gs = g0;
		f0 = f1;
		g0 = g1;
		f1 = -RLC_SIGN(f1);
		g1 = -RLC_SIGN(g1);
	}
	/* Only the top digits are signed. */
	fi = f[i];
	gi = g[i];
	smb_mac(&f1, &f0, u, fi, -RLC_SIGN(fi));
	smb_mac(&f1, &f0, v, gi, -RLC_SIGN(gi));
	smb_mac(&g1, &g0, q, fi, -RLC_SIGN(fi));
	smb_mac(&g1, &g0, r, gi, -RLC_SIGN(gi));
	f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
	g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
	f[i] = (dis_t)f0 >> s;
	g[i] = (dis_t)g0 >> s;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

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
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return r;
}

/* Shifts the double digit H:L left by I bits, for 0 <= I <= RLC_DIG, keeping
 * the high digit. Shifting by RLC_DIG is undefined in C, but H is zero then. */
#define RLC_LSH(H, L, I)													\
		(H << (I & (RLC_DIG - 1))) |										\
		(L & -(I != 0)) >> ((RLC_DIG - I) & (RLC_DIG - 1))

int fp_smb_binar(const fp_t a) {
	const size_t s = RLC_DIG - 2;
	dv_t f, g, t, t0, t1;
	dig_t g_[2], f_[2], neg, l, g_hi, g_lo, f_hi, f_lo, mask, k = 0;
	dis_t m[4];
	int iterations = 2 * RLC_FP_DIGS * RLC_DIG;

	if (fp_is_zero(a)) {
		return 0;
	}

	dv_null_all(f, g, t, t0, t1);

	RLC_TRY {
		dv_new_all(f, g, t, t0, t1);

		dv_zero(t, 2 * RLC_FP_DIGS);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
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

			t0[RLC_FP_DIGS] = bn_smul_low(t0, g, RLC_POS, m[0], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_smul_low(t1, f, RLC_POS, m[1], RLC_FP_DIGS);
			bn_addn_low(t0, t0, t1, RLC_FP_DIGS + 1);
			neg = RLC_SIGN(t0[RLC_FP_DIGS]);
			bn_rshb_low(t, t0, RLC_FP_DIGS + 1, (RLC_DIG - 2));
			bn_sneg_low(t, t, neg, RLC_FP_DIGS);

			t0[RLC_FP_DIGS] = bn_smul_low(t0, g, RLC_POS, m[2], RLC_FP_DIGS);
			t1[RLC_FP_DIGS] = bn_smul_low(t1, f, RLC_POS, m[3], RLC_FP_DIGS);
			bn_addn_low(t1, t1, t0, RLC_FP_DIGS + 1);
			bn_rshb_low(f, t1, RLC_FP_DIGS + 1, (RLC_DIG - 2));
			bn_sneg_low(f, f, RLC_SIGN(t1[RLC_FP_DIGS]), RLC_FP_DIGS);

			fp_copy(g, t);
			k += (f[0] >> 1) & neg;
		}

		k = porninstep(m, g, f, k, iterations % s);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv_free_all(f, g, t, t0, t1);
	}

	return (k & 1 ? -1 : 1);
}

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
	dv_null_all(f, g, t);

	RLC_TRY {
		bn_new(_t);
		dv_new_all(f, g, t);

#if RLC_WSIZE == 8
		bn_set_dig(_t, d >> 8);
		bn_lsh(_t, _t, 8);
		bn_add_dig(_t, _t, d & 0xFF);
#else
		bn_set_dig(_t, d);
#endif

		k = 0;
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		dv_zero(t, 2 * RLC_FP_DIGS);
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		r = dv_cmp_sec(g, f, RLC_FP_DIGS);
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
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
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
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
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
		bn_sneg_low(f, f, fs, RLC_FP_DIGS);
		
		r = RLC_SEL(r, 1 - k, dv_equ_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_sneg_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - k, dv_equ_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - k, fp_is_zero(f));
		r = RLC_SEL(r, 0, fp_is_zero(a));
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(_t);
		dv_free_all(f, g, t);
	}
	return r;
}

int fp_smb_jmpds(const fp_t a) {
	dis_t m[4];
	dv_t f, g, t;
	dig_t j = 0, k;
	int r = 0, s;
#if RLC_WSIZE == 8
	int zeta = -1;
#else
	dis_t zeta = -1;
#endif

	dv_null_all(f, g, t);

	RLC_TRY {
		dv_new_all(f, g, t);

		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
		f[RLC_FP_DIGS] = 0;
		dv_zero(g, RLC_FP_DIGS + 1);
		dv_zero(t + RLC_FP_DIGS, RLC_FP_DIGS);

#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif

		/* The number of steps only depends on the prime size. */
		for (int i = 0; i < JMPDS_ITERS; i += s) {
			s = RLC_MIN(JMPDS_STEPS, JMPDS_ITERS - i);
			zeta = smb_steps(m, &k, zeta, f[0], g[0], s);
			smb_apply(f, g, m, s);
			/* Count the sign changes of f, whose parity is its sign. */
			j = (j + k) % 4;
			j = (j + ((j & 1) ^ RLC_SIGN(f[RLC_FP_DIGS]))) % 4;
		}
		/* Each flip of the symbol added two to the count. */
		j = (j + (j & 1)) % 4;

		fp_zero(t);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		t[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_sneg_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_sec(f, t, RLC_FP_DIGS) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(f, g, t);
	}

	return r;
}

#if FP_SMB == FP_LOWER

int fp_smb_lower(const fp_t a) {
	return fp_smbm_low(a);
}

#endif
