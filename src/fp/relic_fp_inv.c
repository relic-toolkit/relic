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
/* Private definitions                                                        */
/*============================================================================*/

/*
 * Number of division steps for any modulus p < 2^FP_PRIME, from the bound for
 * half-delta divsteps in https://github.com/sipa/safegcd-bounds.
 */
#define JMPDS_ITERS	((3787 * FP_PRIME + 2166) / 1644)

/*
 * Number of division steps in each jump, done in two halves so that each row
 * of the transition matrix of a half fits in a digit.
 */
#define JMPDS_STEPS			(RLC_DIG - 4)

/*
 * Number of steps in each round of the optimized binary GCD (Pornin, "Optimized
 * Binary GCD for Modular Inversion", https://eprint.iacr.org/2020/972), on
 * approximations of a digit that keep k - 1 low bits and k + 1 high bits for
 * k = RLC_DIG / 2.
 */
#define BINAR_STEPS			(RLC_DIG / 2 - 1)

/*
 * Number of rounds of the optimized binary GCD, as 2 * len(p) - 1 steps
 * suffice for any modulus p < 2^FP_PRIME.
 */
#define BINAR_ITERS			RLC_CEIL(2 * FP_PRIME - 1, BINAR_STEPS)

/**
 * Performs s <= JMPDS_STEPS half-delta division steps (Bernstein and Yang,
 * TCHES 2019) on the lowest digits of f and g, with zeta = -(delta + 1/2) as in
 * libsecp256k1, and returns the transition matrix m = (u, v; q, r) scaled by
 * 2^s. The rows are packed in single digits within each half.
 *
 * @param[out] m			- the transition matrix.
 * @param[in] zeta			- the current value of zeta.
 * @param[in] f				- the lowest digit of f, which must be odd.
 * @param[in] g				- the lowest digit of g.
 * @param[in] s				- the number of steps.
 * @return the updated value of zeta.
 */
#if RLC_WSIZE == 8
static int inv_steps(dis_t m[4], int zeta, dig_t f, dig_t g, int s) {
#else
static dis_t inv_steps(dis_t m[4], dis_t zeta, dig_t f, dig_t g, int s) {
#endif
	const int h = RLC_DIG / 2;
	dig_t uv, qr, c0, c1;
	dis_t u, v, q, r, t0, t1;

	m[0] = m[3] = 1;
	m[1] = m[2] = 0;
	for (int k, half = 0; half < 2; half++) {
		k = (half == 0 ? s / 2 : s - s / 2);
		uv = 1;
		qr = (dig_t)1 << h;
		for (int j = 0; j < k; j++) {
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
	}
	return zeta;
}

/**
 * Adds a * b to the signed double digit (c1, c0); sb is the sign mask of b.
 */
static inline void inv_mac(dig_t *c1, dig_t *c0, dis_t a, dig_t b,
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
 * Applies the transition matrix of s division steps to (f, g) and to (d, e),
 * with f = d * a and g = e * a mod p, dividing by 2^s exactly by adding the
 * right multiples of p to d and e, as in update_de of libsecp256k1. All values
 * have RLC_FP_DIGS + 1 signed digits, and d, e stay in (-2p, p).
 *
 * @param[in,out] f			- the first entry of the column vector.
 * @param[in,out] g			- the second entry of the column vector.
 * @param[in,out] d			- the coefficient of f.
 * @param[in,out] e			- the coefficient of g.
 * @param[in] m				- the transition matrix.
 * @param[in] s				- the number of division steps.
 */
static void inv_apply(dig_t *f, dig_t *g, dig_t *d, dig_t *e,
		const dis_t m[4], int s) {
	const dis_t u = m[0], v = m[1], q = m[2], r = m[3];
	const dig_t *p = fp_prime_get(), rdc = *fp_prime_get_rdc();
	const dig_t sd = -RLC_SIGN(d[RLC_FP_DIGS]), se = -RLC_SIGN(e[RLC_FP_DIGS]);
	dig_t f1 = 0, f0 = 0, g1 = 0, g0 = 0, d1 = 0, d0 = 0, e1 = 0, e0 = 0;
	dig_t fs = 0, gs = 0, ds = 0, es = 0, fi, gi, di, ei, cd, ce;
	dis_t md, me;
	size_t i;

	/* Choose md and me to clear the low s bits of the sums. */
	md = (u & sd) + (v & se);
	me = (q & sd) + (r & se);
	cd = RLC_MUL_LOW((dig_t)u, d[0]) + RLC_MUL_LOW((dig_t)v, e[0]);
	ce = RLC_MUL_LOW((dig_t)q, d[0]) + RLC_MUL_LOW((dig_t)r, e[0]);
	md -= (md - RLC_MUL_LOW(cd, rdc)) & RLC_MASK(s);
	me -= (me - RLC_MUL_LOW(ce, rdc)) & RLC_MASK(s);

	for (i = 0; i < RLC_FP_DIGS; i++) {
		fi = f[i];
		gi = g[i];
		di = d[i];
		ei = e[i];
		inv_mac(&f1, &f0, u, fi, 0);
		inv_mac(&f1, &f0, v, gi, 0);
		inv_mac(&g1, &g0, q, fi, 0);
		inv_mac(&g1, &g0, r, gi, 0);
		inv_mac(&d1, &d0, u, di, 0);
		inv_mac(&d1, &d0, v, ei, 0);
		inv_mac(&d1, &d0, md, p[i], 0);
		inv_mac(&e1, &e0, q, di, 0);
		inv_mac(&e1, &e0, r, ei, 0);
		inv_mac(&e1, &e0, me, p[i], 0);
		/* Store the previous digits shifted right by s bits. */
		if (i > 0) {
			f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
			g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
			d[i - 1] = (ds >> s) | (d0 << (RLC_DIG - s));
			e[i - 1] = (es >> s) | (e0 << (RLC_DIG - s));
		}
		/* Keep the current digits and shift the accumulators by a digit. */
		fs = f0;
		gs = g0;
		ds = d0;
		es = e0;
		f0 = f1;
		g0 = g1;
		d0 = d1;
		e0 = e1;
		f1 = -RLC_SIGN(f1);
		g1 = -RLC_SIGN(g1);
		d1 = -RLC_SIGN(d1);
		e1 = -RLC_SIGN(e1);
	}
	/* Only the top digits are signed, and p has none. */
	fi = f[i];
	gi = g[i];
	di = d[i];
	ei = e[i];
	inv_mac(&f1, &f0, u, fi, -RLC_SIGN(fi));
	inv_mac(&f1, &f0, v, gi, -RLC_SIGN(gi));
	inv_mac(&g1, &g0, q, fi, -RLC_SIGN(fi));
	inv_mac(&g1, &g0, r, gi, -RLC_SIGN(gi));
	inv_mac(&d1, &d0, u, di, -RLC_SIGN(di));
	inv_mac(&d1, &d0, v, ei, -RLC_SIGN(ei));
	inv_mac(&e1, &e0, q, di, -RLC_SIGN(di));
	inv_mac(&e1, &e0, r, ei, -RLC_SIGN(ei));
	f[i - 1] = (fs >> s) | (f0 << (RLC_DIG - s));
	g[i - 1] = (gs >> s) | (g0 << (RLC_DIG - s));
	d[i - 1] = (ds >> s) | (d0 << (RLC_DIG - s));
	e[i - 1] = (es >> s) | (e0 << (RLC_DIG - s));
	f[i] = (dis_t)f0 >> s;
	g[i] = (dis_t)g0 >> s;
	d[i] = (dis_t)d0 >> s;
	e[i] = (dis_t)e0 >> s;
}

/**
 * Computes approximations of two nonnegative integers below 2^(RLC_DIG *
 * RLC_FP_DIGS) in a digit each, in constant time: their k - 1 low bits, and
 * their k + 1 bits below the top bit of the larger one, or the integers
 * themselves if they fit in a digit.
 *
 * @param[out] x			- the approximation of the first integer.
 * @param[out] y			- the approximation of the second integer.
 * @param[in] a				- the first integer.
 * @param[in] b				- the second integer.
 */
static void binar_approx(dig_t *x, dig_t *y, const dig_t *a, const dig_t *b) {
	const int k = RLC_DIG / 2;
	dig_t ah = 0, al = 0, bh = 0, bl = 0, c, w;
	int n;

	/* Select the top digit nonzero in either integer, and the one below. */
	for (size_t i = 1; i < RLC_FP_DIGS; i++) {
		w = a[i] | b[i];
		c = 0 - (dig_t)((dig_t)(w | (0 - w)) >> (RLC_DIG - 1));
		ah = (a[i] & c) | (ah & ~c);
		al = (a[i - 1] & c) | (al & ~c);
		bh = (b[i] & c) | (bh & ~c);
		bl = (b[i - 1] & c) | (bl & ~c);
	}
	w = ah | bh;
	c = 0 - (dig_t)((dig_t)(w | (0 - w)) >> (RLC_DIG - 1));
	/* Align the top bit of the larger one, never shifting by RLC_DIG. */
	n = arch_lzcnt(w | (~c & 1));
	ah = (ah << n) | ((al >> 1) >> (RLC_DIG - 1 - n));
	bh = (bh << n) | ((bl >> 1) >> (RLC_DIG - 1 - n));
	ah = (a[0] & RLC_MASK(k - 1)) | ((ah >> (RLC_DIG - k - 1)) << (k - 1));
	bh = (b[0] & RLC_MASK(k - 1)) | ((bh >> (RLC_DIG - k - 1)) << (k - 1));
	*x = (ah & c) | (a[0] & ~c);
	*y = (bh & c) | (b[0] & ~c);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

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

void fp_inv_binar(fp_t c, const fp_t a) {
	const dig_t *p = fp_prime_get();
	dig_t mask, carry, x, y, t0, t1, v[RLC_FP_DIGS];
	dis_t m[4];
	dv_t f, g, d, e, t;

#if FP_RDC == FP_RENUS
	/* Elements in RNS have no digits, so take those of the value in [0, p),
	 * which are also the cheapest to test for zero. */
	fp_rns_get(v, a);
	if (dv_is_zero_sec(v, RLC_FP_DIGS)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
#else
	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	dv_copy(v, a, RLC_FP_DIGS);
#endif

	dv_null_all(f, g, d, e, t);

	RLC_TRY {
		dv_new_all(f, g, d, e, t);

		/* Start from (f, g) = (a, p) and (d, e) = (1, 0), with f = d * a and
		 * g = e * a modulo p, both nonnegative. */
		dv_copy(f, v, RLC_FP_DIGS);
		dv_copy(g, p, RLC_FP_DIGS);
		dv_zero(d, RLC_FP_DIGS + 1);
		dv_zero(e, RLC_FP_DIGS + 1);
		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
		d[0] = 1;

		/* The number of steps only depends on the prime size. */
		for (int i = 0; i < BINAR_ITERS; i++) {
			binar_approx(&x, &y, f, g);
			m[0] = m[3] = 1;
			m[1] = m[2] = 0;
			for (int j = 0; j < BINAR_STEPS; j++) {
				/* t0 is all ones if x is odd, t1 if also x < y. */
				t0 = 0 - (x & 1);
				t1 = (0 - (dig_t)(x < y)) & t0;
				/* Swap if x is odd and x < y, then subtract y if x is odd. */
				carry = t1 & (x ^ y);
				x ^= carry;
				y ^= carry;
				carry = t1 & (dig_t)(m[0] ^ m[2]);
				m[0] ^= (dis_t)carry;
				m[2] ^= (dis_t)carry;
				carry = t1 & (dig_t)(m[1] ^ m[3]);
				m[1] ^= (dis_t)carry;
				m[3] ^= (dis_t)carry;
				x = (x - (y & t0)) >> 1;
				m[0] -= m[2] & (dis_t)t0;
				m[1] -= m[3] & (dis_t)t0;
				/* Halve x by doubling the second row instead. */
				m[2] += m[2];
				m[3] += m[3];
			}
			/* Apply the steps to (f, g) and (d, e), dividing by 2^s. */
			inv_apply(f, g, d, e, m, BINAR_STEPS);
			/* Keep f and g nonnegative, negating d and e along, and bring d
			 * and e back from (-2p, 2p) to (-2p, p). */
			for (int k = 0; k < 2; k++) {
				dig_t *w = (k == 0 ? f : g), *z = (k == 0 ? d : e);

				mask = 0 - RLC_SIGN(w[RLC_FP_DIGS]);
				carry = mask & 1;
				for (size_t j = 0; j <= RLC_FP_DIGS; j++) {
					w[j] = (w[j] ^ mask) + carry;
					carry = (w[j] < carry);
				}
				carry = mask & 1;
				for (size_t j = 0; j <= RLC_FP_DIGS; j++) {
					z[j] = (z[j] ^ mask) + carry;
					carry = (z[j] < carry);
				}
				carry = bn_subn_low(t, z, p, RLC_FP_DIGS);
				t[RLC_FP_DIGS] = z[RLC_FP_DIGS] - carry;
				dv_copy_sec(z, t, RLC_FP_DIGS + 1,
						RLC_SIGN(t[RLC_FP_DIGS]) ^ 1);
			}
		}

		/* Now g = 1, so 1/a = e; bring it from (-2p, p) to [0, p). */
		for (int k = 0; k < 2; k++) {
			mask = 0 - RLC_SIGN(e[RLC_FP_DIGS]);
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
				t[j] = p[j] & mask;
			}
			e[RLC_FP_DIGS] += bn_addn_low(e, e, t, RLC_FP_DIGS);
		}
#if FP_RDC == FP_MONTY
		/* Multiply 1/(x * R) by R^3 and reduce to get R/x for the input x. */
		fp_mul(c, e, core_get()->inv);
#elif FP_RDC == FP_RENUS
		fp_rns_set(c, e);
#else
		fp_copy(c, e);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(f, g, d, e, t);
	}
}

void fp_inv_monty(fp_t c, const fp_t a) {
	bn_t _a, _p, u, v, x1, x2;
	const dig_t *p = NULL;
	dig_t carry;
	size_t i;
	int k;
#if FP_RDC == FP_MONTY
#if RLC_ALLOC == RLC_AUTO
	const dig_t *conv = (const dig_t *)fp_prime_get_conv();
#else
	const fp_t conv = (fp_t)fp_prime_get_conv();
#endif
#endif

	bn_null_all(_a, _p, u, v, x1, x2);

	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		bn_new_all(_a, _p, u, v, x1, x2);

		p = fp_prime_get();

		/* u = a, v = p, x1 = 1, x2 = 0, k = 0. */
		k = 0;
		bn_set_dig(x1, 1);
		bn_zero(x2);

#if FP_RDC != FP_MONTY
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

		/* If k < Wt then x1 = x1 * R mod p. */
		if (k <= (int)(RLC_FP_DIGS * RLC_DIG)) {
			k = k + RLC_FP_DIGS * RLC_DIG;
#if FP_RDC == FP_MONTY
			/* Multiply by R^2 * R^{-1}. */
			fp_mul(x1->dp, x1->dp, conv);
#else
			fp_mul(x1->dp, x1->dp, core_get()->one);
#endif
		}

#if FP_RDC == FP_MONTY
		/* x1 = x1 * R^2 * R^{-1} mod p. */
		fp_mul(x1->dp, x1->dp, conv);
#endif
		/* c = x1 * 2^(2Wt - k) * R^{-1} mod p. */
		fp_copy(c, x1->dp);
		dv_zero(x1->dp, RLC_FP_DIGS);
		bn_set_2b(x1, 2 * RLC_FP_DIGS * RLC_DIG - k);
		fp_mul(c, c, x1->dp);

#if FP_RDC != FP_MONTY
		/*
		 * If we do not use Montgomery reduction, convert back.
		 */
		bn_read_raw(_a, c, RLC_FP_DIGS);
		bn_mod_monty_back(_a, _a, _p);

		fp_zero(c);
		dv_copy(c, _a->dp, _a->used);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(_a, _p, u, v, x1, x2);
	}
}

void fp_inv_exgcd(fp_t c, const fp_t a) {
	bn_t u, v, g1, g2, p, q, r;

	bn_null_all(u, v, g1, g2, p, q, r);

	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		bn_new_all(u, v, g1, g2, p, q, r);

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
		bn_free_all(u, v, g1, g2, p, q, r);
	}
}

void fp_inv_divst(fp_t c, const fp_t a) {
	/* Compute number of iterations based on modulus size. */
#if FP_PRIME < 46
	const int d = (49 * FP_PRIME + 80) / 17;
#else
	const int d = (49 * FP_PRIME + 57) / 17;
#endif
	int g0, d0;
	dig_t fs, gs, delta = 1;
	bn_t _t;
	fp_t f, g, u, v, r;
	dv_t t;

	bn_null(_t);
	dv_null(t);
	fp_null_all(f, g, u, v, r);

	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		bn_new(_t);
		dv_new(t);
		fp_new_all(f, g, u, v, r);

		fp_zero(v);
		fp_set_dig(r, 1);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
		/* Convert a from Montgomery form. */
		dv_zero(t, 2 * RLC_FP_DIGS);
		fp_copy(t, a);
		fp_rdcn_low(g, t);
#else
		fp_copy(g, a);
#endif
		fs = gs = RLC_POS;

		for (int i = 0; i < d; i++) {
			g0 = g[0] & 1;
			d0 = delta >> (RLC_DIG - 1);
			d0 = g0 & ~d0;
			/* Conditionally negate delta if d0 is set. */
			delta = (delta ^ -d0) + d0;
			/* Conditionally swap based on d0. */
			dv_swap_sec(r, v, RLC_FP_DIGS, d0);
			fp_negm_low(t, r);
			dv_swap_sec(f, g, RLC_FP_DIGS, d0);
			dv_copy_sec(r, t, RLC_FP_DIGS, d0);
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
				g[j] = RLC_SEL(g[j], ~g[j], d0);
			}
			fp_add1_low(g, g, d0);
			t[0] = (fs ^ gs) & (-d0);
			fs ^= t[0];
			gs ^= t[0] ^ d0;

			delta++;
			g0 = g[0] & 1;
			for (size_t j = 0; j < RLC_FP_DIGS; j++) {
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
		fp_copy_sec(v, t, fs);

		dv_copy(t, fp_prime_get(), RLC_FP_DIGS);
		fp_add_dig(t, t, 1);
		fp_hlv(t, t);
#if RLC_WSIZE == 8
		bn_set_dig(_t, d >> 8);
		bn_lsh(_t, _t, 8);
		bn_add_dig(_t, _t, d & 0xFF);
#else
		bn_set_dig(_t, d);
#endif
		fp_exp(t, t, _t);

		fp_mul(c, v, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(_t);
		dv_free(t);
		fp_free_all(f, g, u, v, r);
	}
}

void fp_inv_jmpds(fp_t c, const fp_t a) {
	const dig_t *p = fp_prime_get();
	dig_t mask, carry, v[RLC_FP_DIGS];
	dis_t m[4];
	dv_t f, g, d, e, t;
	int s;
#if RLC_WSIZE == 8
	int zeta = -1;
#else
	dis_t zeta = -1;
#endif

#if FP_RDC == FP_RENUS
	/* Elements in RNS have no digits, so take those of the value in [0, p),
	 * which are also the cheapest to test for zero. */
	fp_rns_get(v, a);
	if (dv_is_zero_sec(v, RLC_FP_DIGS)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
#else
	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	dv_copy(v, a, RLC_FP_DIGS);
#endif

	dv_null_all(f, g, d, e, t);

	RLC_TRY {
		dv_new_all(f, g, d, e, t);

		/* Start from (f, g) = (p, a) and (d, e) = (0, 1). */
		dv_copy(f, p, RLC_FP_DIGS);
		dv_copy(g, v, RLC_FP_DIGS);
		dv_zero(d, RLC_FP_DIGS + 1);
		dv_zero(e, RLC_FP_DIGS + 1);
		f[RLC_FP_DIGS] = g[RLC_FP_DIGS] = 0;
		e[0] = 1;

		/* The number of steps only depends on the prime size. */
		for (int i = 0; i < JMPDS_ITERS; i += s) {
			s = RLC_MIN(JMPDS_STEPS, JMPDS_ITERS - i);
			zeta = inv_steps(m, zeta, f[0], g[0], s);
			inv_apply(f, g, d, e, m, s);
		}

		/* Now f = 1 or -1, so 1/a = d * f; bring it from (-2p, p) to [0, p). */
		mask = -RLC_SIGN(d[RLC_FP_DIGS]);
		for (size_t j = 0; j < RLC_FP_DIGS; j++) {
			t[j] = p[j] & mask;
		}
		d[RLC_FP_DIGS] += bn_addn_low(d, d, t, RLC_FP_DIGS);
		mask = -RLC_SIGN(f[RLC_FP_DIGS]);
		carry = mask & 1;
		for (size_t j = 0; j <= RLC_FP_DIGS; j++) {
			d[j] = (d[j] ^ mask) + carry;
			carry = (d[j] < carry);
		}
		mask = -RLC_SIGN(d[RLC_FP_DIGS]);
		for (size_t j = 0; j < RLC_FP_DIGS; j++) {
			t[j] = p[j] & mask;
		}
		bn_addn_low(d, d, t, RLC_FP_DIGS);
#if FP_RDC == FP_MONTY
		/* Multiply 1/(x * R) by R^3 and reduce to get R/x for the input x. */
		fp_mul(c, d, core_get()->inv);
#elif FP_RDC == FP_RENUS
		fp_rns_set(c, d);
#else
		fp_copy(c, d);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(f, g, d, e, t);
	}
}

#if FP_INV == FP_LOWER

void fp_inv_lower(fp_t c, const fp_t a) {
	if (fp_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	fp_invm_low(c, a);
}

#endif

void fp_inv_sim(fp_t *c, const fp_t *a, int n) {
	int i;
	fp_t u, *t;

	if (n <= 0) {
		return;
	}

	t = RLC_ALLOCA(fp_t, n);
	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	fp_null(u);
	for (i = 0; i < n; i++) {
		fp_null(t[i]);
	}

	RLC_TRY {
		for (i = 0; i < n; i++) {
			fp_new(t[i]);
		}
		fp_new(u);

		fp_copy(t[0], a[0]);
		fp_copy(c[0], a[0]);

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
