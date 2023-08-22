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

static dis_t jumpdivstep(dis_t m[4], dig_t *k, dis_t delta, dis_t y, dis_t x, 
		int s) {
	dig_t d0, t0, t1, t2, c0, c1, yi, ai = 1, bi = 0, ci = 0, di = 1, u = 0;

	/* Unrolling twice makes it faster. */
	for (s -= 2; s >= 0; s -= 2) {
		yi = y;

		d0 = (delta >= 0);
		c1 = -(x & 1);
		c0 = (-d0) & c1;

		t0 = (y ^ -d0) + d0;
		t1 = (ci ^ -d0) + d0;
		t2 = (di ^ -d0) + d0;
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

		d0 = (delta >= 0);
		c1 = -(x & 1);
		c0 = (-d0) & c1;

		t0 = (y ^ -d0) + d0;
		t1 = (ci ^ -d0) + d0;
		t2 = (di ^ -d0) + d0;
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
		fp_prime_back(_t, a);
		dv_zero(g, RLC_FP_DIGS);
		dv_copy(g, _t->dp, _t->used);
		dv_copy(f, fp_prime_get(), RLC_FP_DIGS);
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
		for (int j = 0; j < RLC_FP_DIGS; j++) {
			f[j] ^= -fs;
		}
		fp_add1_low(f, f, fs);

		r = RLC_SEL(r, 1 - k, dv_cmp_const(f, t, RLC_FP_DIGS) == RLC_EQ);
		bn_negs_low(t, t, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - k, dv_cmp_const(f, t, RLC_FP_DIGS) == RLC_EQ);
		r = RLC_SEL(r, 1 - k, fp_is_zero(f));
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
	dis_t m[4], d = 0;
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
		r = RLC_SEL(r, 1 - j, dv_cmp_const(f, t0, RLC_FP_DIGS) == RLC_EQ);
		t0[0] = 1;
		r = RLC_SEL(r, 1 - j, dv_cmp_const(f, t0, RLC_FP_DIGS) == RLC_EQ);
		bn_negs_low(t0, t0, 1, RLC_FP_DIGS);
		r = RLC_SEL(r, 1 - j, dv_cmp_const(f, t0, RLC_FP_DIGS) == RLC_EQ);
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
