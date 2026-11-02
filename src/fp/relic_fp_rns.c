/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of prime field arithmetic in a Residue Number System.
 *
 * An element is represented by its residues modulo the RLC_FP_RNS moduli of
 * each of two bases B and B', all primes of the form 2^RLC_RNS_BITS - c. Each
 * residue is kept in Montgomery form x_i * R mod m_i, with R = 2^RLC_RNS_DIG,
 * so that products of residues are Montgomery products. In B', an element x is
 * moreover stored as x / M, as in Langowski, He and Devadas (VROOM, USENIX
 * Security 2025): a product then carries 1 / M^2, so that the division by M of
 * Montgomery reduction comes for free, and the constants around the base
 * extensions are folded into their tables.
 *
 * Multiplication is Montgomery multiplication in RNS, with M = prod(B) as the
 * Montgomery constant: the quotient is computed in B and extended to B'
 * approximately, and the result is computed in B' and extended back to B
 * exactly, as in Kawamura et al. (EUROCRYPT 2000). B must exceed the sums of
 * products to reduce divided by p, below 2^30 * p^2, and B' the reduced result,
 * below (RLC_FP_RNS + 1)p in absolute value, as the first extension skips its
 * correction. The residue-wise operations, the base extensions
 * and the reduction are at the lower level, so that backends can vectorize
 * them.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*
 * An unreduced product of elements must fit in a temporary vector.
 */
RLC_STATIC_ASSERT(RLC_FP_DLEN <= RLC_DV_DIGS, rns_dv);

/**
 * Tests if the i-th residue of an element pads its base.
 */
#define RNS_PAD(I)		((I) % RLC_FP_RNSO >= RLC_FP_RNS)

/**
 * Multiplies two plain residues modulo the i-th modulus, for precomputation.
 *
 * @param[in] a				- the first residue.
 * @param[in] b				- the second residue.
 * @param[in] i				- the index of the modulus.
 * @return the product.
 */
static dig_t fp_rns_mulp(dig_t a, dig_t b, size_t i) {
	ctx_t *ctx = core_get();
	dig_t m = ctx->rns.m[i], u = ctx->rns.u[i];

	return fp_rns_mul(fp_rns_mul(a, b, m, u), ctx->rns.r2[i], m, u);
}

/**
 * Computes an integer modulo the i-th modulus.
 */
static dig_t fp_rns_bn(const bn_t a, size_t i) {
	dig_t d;

	bn_mod_dig(&d, a, core_get()->rns.m[i]);
	return d;
}

/**
 * Computes the inverse of a residue modulo the i-th modulus.
 */
static dig_t fp_rns_inv(dig_t a, size_t i) {
	bn_t t, u;
	dig_t r = 0;

	bn_null_all(t, u);

	RLC_TRY {
		bn_new_all(t, u);
		bn_set_dig(t, a);
		bn_set_dig(u, core_get()->rns.m[i]);
		bn_mod_inv(t, t, u);
		r = t->dp[0];
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(t, u);
	}
	return r;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rns_pre(void) {
	ctx_t *ctx = core_get();
	bn_t m, mb, t, u;
	dig_t c = 1, d, r2, r3;
	size_t k = 0, l = 0, n = RLC_FP_RNS, o = RLC_FP_RNSO, j0;

	bn_null_all(m, mb, t, u);

	RLC_TRY {
		bn_new_all(m, mb, t, u);

		/* The residues that pad each base are zero in all tables. */
		dv_zero(ctx->rns.m, 2 * o);
		dv_zero(ctx->rns.u, 2 * o);
		dv_zero(ctx->rns.iv, 2 * o);
		dv_zero(ctx->rns.r2, 2 * o);
		dv_zero(ctx->rns.e, 2 * o);
		dv_zero(ctx->rns.ib, 2 * o);
		dv_zero(ctx->rns.nq, o);
		dv_zero(ctx->rns.u1, o);
		dv_zero(ctx->rns.u2, o);
		dv_zero(ctx->rns.t1[0], n * o);
		dv_zero(ctx->rns.t2[0], n * o);
		dv_zero(ctx->rns.kp[0], 5 * 2 * o);
		dv_zero(ctx->rns.pw[0], 2 * o * RLC_FP_DIGS);

		/* Pick the largest primes 2^RLC_RNS_BITS - c coprime to p, with c
		 * below the square root of R: first for B, then for B'. */
		while (k < n || l < n) {
			if (c >= ((dig_t)1 << (RLC_RNS_DIG / 2))) {
				RLC_THROW(ERR_NO_VALID);
				break;
			}
			d = ((dig_t)1 << RLC_RNS_BITS) - c;
			bn_set_dig(t, d);
			bn_mod_dig(&r2, &(ctx->prime), d);
			if (r2 != 0 && bn_is_prime(t)) {
				if (k < n) {
					ctx->rns.m[k++] = d;
				} else {
					ctx->rns.m[o + l++] = d;
				}
			}
			c += 2;
		}

		/* -m^{-1} mod R by Newton iteration, and R^2 mod m. */
		for (size_t i = 0; i < 2 * o; i++) {
			dig_t x = ctx->rns.m[i];
			if (RNS_PAD(i)) {
				continue;
			}
			for (int j = 0; j < 6; j++) {
				x *= 2 - ctx->rns.m[i] * x;
			}
			ctx->rns.u[i] = (0 - x) & RLC_RNS_MASK;
			ctx->rns.iv[i] = x & RLC_RNS_MASK;
			bn_set_2b(t, 2 * RLC_RNS_DIG);
			ctx->rns.r2[i] = fp_rns_bn(t, i);
		}

		/* M and M' as integers. */
		bn_set_dig(m, 1);
		bn_set_dig(mb, 1);
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(m, m, ctx->rns.m[i]);
			ctx->rns.e[i] = ctx->rns.r2[i];
		}
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(mb, mb, ctx->rns.m[o + i]);
		}
		/* Elements are multiplied by R^2 in B and by R^2 / M in B' to be
		 * stored, and the tables of the first extension carry 1 / M^2. */
		for (size_t i = 0; i < n; i++) {
			d = fp_rns_inv(fp_rns_bn(m, o + i), o + i);
			ctx->rns.e[o + i] = fp_rns_mulp(ctx->rns.r2[o + i], d, o + i);
			ctx->rns.mi[i] = RLC_RNS_SCL(d, o + i);
		}

		/* B must exceed 2^(RLC_FP_RNS_ROOM + 2) * p, and B' 2^11 * p. */
		if (bn_bits(m) < bn_bits(&(ctx->prime)) + RLC_FP_RNS_ROOM + 2 + 1 ||
				bn_bits(mb) < bn_bits(&(ctx->prime)) + 11 + 2) {
			RLC_THROW(ERR_NO_VALID);
		}

		for (size_t i = 0; i < n; i++) {
			/* (M/m_i)^{-1} mod m_i, and (M/m_i) * R^3 mod m'_j. */
			bn_div_dig(t, m, ctx->rns.m[i]);
			for (size_t j = 0; j < n; j++) {
				r3 = fp_rns_mulp(ctx->rns.r2[o + j], RLC_RNS_SCL(1, o + j),
						o + j);
				/* Times p / M^2, to give q * p as a product in B'. */
				d = fp_rns_mulp(fp_rns_bn(t, o + j),
						fp_rns_bn(&(ctx->prime), o + j), o + j);
				d = fp_rns_mulp(d, fp_rns_inv(fp_rns_bn(m, o + j), o + j),
						o + j);
				d = fp_rns_mulp(d, fp_rns_inv(fp_rns_bn(m, o + j), o + j),
						o + j);
				ctx->rns.t1[i][j] = fp_rns_mulp(d, r3, o + j);
			}
			ctx->rns.ib[i] = fp_rns_inv(fp_rns_bn(t, i), i);
			/* -p^{-1} (M/m_i)^{-1} mod m_i, to get xi_i of q directly. */
			d = fp_rns_inv(fp_rns_bn(&(ctx->prime), i), i);
			ctx->rns.nq[i] = fp_rns_mulp(ctx->rns.m[i] - d, ctx->rns.ib[i], i);
			/* -M' * R^3 mod m_i. */
			r3 = fp_rns_mulp(ctx->rns.r2[i], RLC_RNS_SCL(1, i), i);
			ctx->rns.u2[i] = fp_rns_mulp(
					RLC_RNS_SUB(0, fp_rns_bn(mb, i), ctx->rns.m[i]), r3, i);
		}

		for (size_t i = 0; i < n; i++) {
			j0 = o + i;

			/* (M'/m'_i)^{-1} mod m'_i, and (M'/m'_i) * R^3 mod m_j. */
			bn_div_dig(t, mb, ctx->rns.m[j0]);
			for (size_t j = 0; j < n; j++) {
				r3 = fp_rns_mulp(ctx->rns.r2[j], RLC_RNS_SCL(1, j), j);
				ctx->rns.t2[i][j] = fp_rns_mulp(fp_rns_bn(t, j), r3, j);
			}
			/* Times M, as elements are divided by M in B'. */
			ctx->rns.ib[j0] = fp_rns_mulp(fp_rns_inv(fp_rns_bn(t, j0), j0),
					fp_rns_bn(m, j0), j0);

			/* -M * p / M^2 * R^3 mod m'_i. */
			r3 = fp_rns_mulp(ctx->rns.r2[j0], RLC_RNS_SCL(1, j0), j0);
			d = fp_rns_mulp(fp_rns_bn(&(ctx->prime), j0),
					fp_rns_inv(fp_rns_bn(m, j0), j0), j0);
			ctx->rns.u1[i] = fp_rns_mulp(RLC_RNS_SUB(0, d, ctx->rns.m[j0]), r3,
					j0);
		}

#if RLC_ARITH == RLC_AVX512
		/* The vectorized extensions reduce their sums with one Montgomery
		 * reduction instead of two, so their tables carry one factor R less. */
		for (size_t i = 0; i < n; i++) {
			const dig_t *m = ctx->rns.m, *u = ctx->rns.u;

			for (size_t j = 0; j < n; j++) {
				ctx->rns.t1[i][j] =
						fp_rns_mul(ctx->rns.t1[i][j], 1, m[o + j], u[o + j]);
				ctx->rns.t2[i][j] = fp_rns_mul(ctx->rns.t2[i][j], 1, m[j], u[j]);
			}
			ctx->rns.u1[i] = fp_rns_mul(ctx->rns.u1[i], 1, m[o + i], u[o + i]);
			ctx->rns.u2[i] = fp_rns_mul(ctx->rns.u2[i], 1, m[i], u[i]);
		}
#endif

		/* Constants in Montgomery form: M, M^2, M/2 and M/3 modulo p. */
		bn_mod(t, m, &(ctx->prime));
		fp_rns_conv(ctx->one, t);
		bn_sqr(u, t);
		bn_mod(u, u, &(ctx->prime));
		fp_rns_conv(ctx->conv, u);
		bn_add_dig(u, &(ctx->prime), 1);
		bn_hlv(u, u);
		bn_mul(u, u, t);
		bn_mod(u, u, &(ctx->prime));
		fp_rns_conv(ctx->rns.half, u);
		bn_set_dig(u, 3);
		bn_mod_inv(u, u, &(ctx->prime));
		bn_mul(u, u, t);
		bn_mod(u, u, &(ctx->prime));
		fp_rns_conv(ctx->rns.third, u);

		/* The multiples kp for -2 <= k <= 2, in both bases. */
		for (int j = 0; j < 5; j++) {
			bn_mul_dig(t, &(ctx->prime), (dig_t)(j < 2 ? 2 - j : j - 2));
			for (size_t i = 0; i < 2 * o; i++) {
				if (RNS_PAD(i)) {
					continue;
				}
				d = RLC_RNS_CONV(fp_rns_bn(t, i), i);
				ctx->rns.kp[j][i] =
						(j < 2 ? RLC_RNS_SUB(0, d, ctx->rns.m[i]) : d);
			}
		}

		/* The low digits of M/m_i, -M and 3p for the conversion to positional
		 * form, and the residues of 2^(RLC_DIG * k) for the way back. */
		bn_set_2b(u, RLC_DIG * (RLC_FP_DIGS + 1));
		bn_mod_2b(t, m, RLC_DIG * (RLC_FP_DIGS + 1));
		bn_sub(t, u, t);
		for (size_t k = 0; k <= RLC_FP_DIGS; k++) {
			ctx->rns.mm[k] = (k < t->used ? t->dp[k] : 0);
		}
		bn_mul_dig(t, &(ctx->prime), 3);
		for (size_t k = 0; k <= RLC_FP_DIGS; k++) {
			ctx->rns.p3[k] = (k < t->used ? t->dp[k] : 0);
		}
		for (size_t i = 0; i < n; i++) {
			bn_div_dig(t, m, ctx->rns.m[i]);
			bn_mod_2b(t, t, RLC_DIG * (RLC_FP_DIGS + 1));
			for (size_t k = 0; k <= RLC_FP_DIGS; k++) {
				ctx->rns.mp[i][k] = (k < t->used ? t->dp[k] : 0);
			}
		}
		for (size_t k = 0; k < RLC_FP_DIGS; k++) {
			bn_set_2b(t, RLC_DIG * k);
			for (size_t i = 0; i < 2 * o; i++) {
				if (RNS_PAD(i)) {
					continue;
				}
				ctx->rns.pw[i][k] = fp_rns_mulp(fp_rns_bn(t, i), ctx->rns.e[i],
						i);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, mb, t, u);
	}
}

void fp_rns_conv(dig_t *c, const bn_t a) {
	for (size_t i = 0; i < RLC_FP_LEN; i++) {
		if (RNS_PAD(i)) {
			c[i] = 0;
			continue;
		}
		c[i] = RLC_RNS_CONV(fp_rns_bn(a, i), i);
		if (bn_sign(a) == RLC_NEG) {
			c[i] = RLC_RNS_SUB(0, c[i], core_get()->rns.m[i]);
		}
	}
}

void fp_rns_back(bn_t c, const dig_t *a) {
	ctx_t *ctx = core_get();
	bn_t m, t;

	bn_null_all(m, t);

	RLC_TRY {
		bn_new_all(m, t);

		/* CRT in B: c = sum xi_i * (M/m_i) mod M. */
		bn_set_dig(m, 1);
		for (size_t i = 0; i < RLC_FP_RNS; i++) {
			bn_mul_dig(m, m, ctx->rns.m[i]);
		}
		bn_zero(c);
		for (size_t i = 0; i < RLC_FP_RNS; i++) {
			bn_div_dig(t, m, ctx->rns.m[i]);
			bn_mul_dig(t, t, fp_rns_mul(a[i], ctx->rns.ib[i], ctx->rns.m[i],
					ctx->rns.u[i]));
			bn_add(c, c, t);
		}
		bn_mod(c, c, m);
		/* Values above M/2 represent negative integers. */
		bn_hlv(t, m);
		if (bn_cmp(c, t) == RLC_GT) {
			bn_sub(c, c, m);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, t);
	}
}

void fp_rns_rdc(dig_t *c, const dig_t *a) {
	/* The reduction in RNS does not write to its input. */
	fp_rdcn_low(c, (dig_t *)a);
}

/*============================================================================*/

void fp_rns_val(bn_t c, const dig_t *a) {
	rlc_align dig_t t[RLC_FP_LEN];

	fp_rns_wide(t, a);
	fp_rns_rdc(t, t);
	fp_rns_back(c, t);
	bn_mod(c, c, &(core_get()->prime));
	if (bn_sign(c) == RLC_NEG) {
		bn_add(c, c, &(core_get()->prime));
	}
}

void fp_rns_get(dig_t *c, const dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, l = RLC_FP_DIGS + 1;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u, *p = fp_prime_get();
	rlc_align dig_t r[RLC_FP_LEN];
	dig_t xi[RLC_FP_RNS], s[RLC_FP_DIGS + 1];
	dig_t t[RLC_FP_DIGS + 1], a1, b;

	/* r = a / M is the value of a, with -p < r < (RLC_FP_RNS + 1)p. */
	fp_rns_wide(r, a);
	fp_rns_rdc(r, r);
	/* r = sum xi_i (M/m_i) - alpha M, where alpha rounds sum xi_i / m_i, as
	 * r / M is tiny. */
	for (size_t i = 0; i < n; i++) {
		xi[i] = fp_rns_mul(r[i], ctx->rns.ib[i], m[i], u[i]);
	}
	a1 = fp_rns_alpha(xi, n, 1);
	/* The low digits of r + 3p are enough to recover it, as it is positive. */
	dv_copy(s, ctx->rns.p3, l);
	bn_mula_low(s, ctx->rns.mm, a1, l);
	for (size_t i = 0; i < n; i++) {
		bn_mula_low(s, ctx->rns.mp[i], xi[i], l);
	}
	/* Now 0 < s < (RLC_FP_RNS + 4)p, so subtract p up to RLC_FP_RNS + 3
	 * times. */
	for (size_t k = 0; k < RLC_FP_RNS + 3; k++) {
		b = bn_subn_low(t, s, p, l - 1);
		t[l - 1] = s[l - 1] - b;
		b = (s[l - 1] < b);
		dv_copy_sec(s, t, l, b ^ 1);
	}
	dv_copy(c, s, RLC_FP_DIGS);
}

void fp_rns_set(dig_t *c, const dig_t *a) {
	ctx_t *ctx = core_get();
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u;
	rlc_align dig_t t[RLC_FP_LEN];

	/* The residues of sum a_k 2^(RLC_DIG * k), stored as elements. */
	for (size_t i = 0; i < RLC_FP_LEN; i++) {
		t[i] = 0;
		if (RNS_PAD(i)) {
			continue;
		}
		for (size_t k = 0; k < RLC_FP_DIGS; k++) {
			t[i] = RLC_RNS_ADD(t[i],
					fp_rns_mul(a[k], ctx->rns.pw[i][k], m[i], u[i]), m[i]);
		}
	}
	/* Times M^2 / M for Montgomery form. */
	fp_mulm_low(c, t, ctx->conv);
}

int fp_rns_is_zero(const dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u;
	dig_t q[RLC_FP_RNS], r[RLC_FP_RNS], d, z = 0;

	/* The first half of the reduction gives r = a / M in B', with |r| < 3p,
	 * so a is zero modulo p if and only if r is one of -2p, -p, 0, p or 2p,
	 * which B' tells apart without extending r back to B. */
	for (size_t i = 0; i < n; i++) {
		q[i] = fp_rns_mul(a[i], ctx->rns.nq[i], m[i], u[i]);
	}
	fp_rnsx_low(r, q, 1, 0);
	for (size_t i = 0; i < n; i++) {
		r[i] = RLC_RNS_ADD(
				fp_rns_mul(a[o + i], ctx->rns.mi[i], m[o + i], u[o + i]),
				r[i], m[o + i]);
	}
	for (int k = 0; k < 5; k++) {
		d = 0;
		for (size_t i = 0; i < n; i++) {
			d |= r[i] ^ ctx->rns.kp[k][o + i];
		}
		z |= (d == 0);
	}
	return (int)z;
}

#endif /* FP_RDC == FP_RENUS */
