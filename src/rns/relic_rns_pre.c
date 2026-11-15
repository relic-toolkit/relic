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
 * Implementation of the precomputation of a Residue Number System.
 *
 * Multiplication is Montgomery multiplication in RNS, with M = prod(B) as the
 * Montgomery constant: the quotient is computed in B and extended to B'
 * approximately, and the result is computed in B' and extended back to B
 * exactly, as in Kawamura et al. (EUROCRYPT 2000). In B', a value x is stored
 * as x / M, as in Langowski, He and Devadas (VROOM, USENIX Security 2025): a
 * product then carries 1 / M^2, so that the division by M of Montgomery
 * reduction comes for free, and the constants around the base extensions are
 * folded into their tables.
 *
 * @ingroup rns
 */

#include "relic_core.h"
#include "relic_rns_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Tests if the i-th residue pads its base.
 */
#define RNS_PAD(C, I)	((I) % (C)->o >= (C)->n)

/**
 * Reduces a digit modulo the i-th modulus and converts it to Montgomery form,
 * as a multiplier of residues.
 */
#define RNS_SCL(C, D, I)													\
	rns_mul(RLC_RNS_MOD(D, (C)->m[I]), (C)->r2[I], (C)->m[I], (C)->u[I])

/**
 * Multiplies two plain residues modulo the i-th modulus.
 *
 * @param[in] c				- the context.
 * @param[in] a				- the first residue.
 * @param[in] b				- the second residue.
 * @param[in] i				- the index of the modulus.
 * @return the product.
 */
static dig_t rns_mulp(const rns_st *c, dig_t a, dig_t b, size_t i) {
	return rns_mul(rns_mul(a, b, c->m[i], c->u[i]), c->r2[i], c->m[i],
			c->u[i]);
}

/**
 * Computes an integer modulo the i-th modulus.
 *
 * @param[in] c				- the context.
 * @param[in] a				- the integer.
 * @param[in] i				- the index of the modulus.
 * @return the residue.
 */
static dig_t rns_res(const rns_st *c, const bn_t a, size_t i) {
	dig_t d;

	bn_mod_dig(&d, a, c->m[i]);
	return d;
}

/**
 * Computes the inverse of a residue modulo the i-th modulus.
 *
 * @param[in] c				- the context.
 * @param[in] a				- the residue.
 * @param[in] i				- the index of the modulus.
 * @return the inverse.
 */
static dig_t rns_inv(const rns_st *c, dig_t a, size_t i) {
	bn_t t, u;
	dig_t r = 0;

	bn_null_all(t, u);

	RLC_TRY {
		bn_new_all(t, u);
		bn_set_dig(t, a);
		bn_set_dig(u, c->m[i]);
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

void rns_pre(rns_t c, const bn_t mod, int room) {
	bn_t m, mb, t;
	dig_t s = 1, d, r2, r3;
	const size_t n = c->n, o = c->o, l = c->d + 1;
	size_t k = 0, h = 0, j0;

	bn_null_all(m, mb, t);

	RLC_TRY {
		bn_new_all(m, mb, t);

		/* The residues that pad each base are zero in all tables. */
		dv_zero(c->m, 2 * o);
		dv_zero(c->u, 2 * o);
		dv_zero(c->iv, 2 * o);
		dv_zero(c->r2, 2 * o);
		dv_zero(c->e, 2 * o);
		dv_zero(c->ib, 2 * o);
		dv_zero(c->nq, o);
		dv_zero(c->nqv, o);
		dv_zero(c->ibv, o);
		dv_zero(c->u1, o);
		dv_zero(c->u2, o);
		dv_zero(c->t1, n * o);
		dv_zero(c->t2, n * o);
		dv_zero(c->kp, 5 * 2 * o);
		dv_zero(c->pw, c->w * 2 * o);

		/* Pick the largest primes 2^RLC_RNS_BITS - s coprime to the modulus,
		 * with s below the square root of R: first for B, then for B'. */
		while (k < n || h < n) {
			if (s >= ((dig_t)1 << (RLC_RNS_DIG / 2))) {
				RLC_THROW(ERR_NO_VALID);
				break;
			}
			d = ((dig_t)1 << RLC_RNS_BITS) - s;
			bn_set_dig(t, d);
			bn_mod_dig(&r2, mod, d);
			if (r2 != 0 && bn_is_prime(t)) {
				if (k < n) {
					c->m[k++] = d;
				} else {
					c->m[o + h++] = d;
				}
			}
			s += 2;
		}

		/* -m^{-1} mod R by Newton iteration, and R^2 mod m. */
		for (size_t i = 0; i < 2 * o; i++) {
			dig_t x = c->m[i];
			if (RNS_PAD(c, i)) {
				continue;
			}
			for (int j = 0; j < 6; j++) {
				x *= 2 - c->m[i] * x;
			}
			c->u[i] = (0 - x) & RLC_RNS_MASK;
			c->iv[i] = x & RLC_RNS_MASK;
			bn_set_2b(t, 2 * RLC_RNS_DIG);
			c->r2[i] = rns_res(c, t, i);
		}

		/* M and M' as integers. */
		bn_set_dig(m, 1);
		bn_set_dig(mb, 1);
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(m, m, c->m[i]);
			c->e[i] = c->r2[i];
		}
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(mb, mb, c->m[o + i]);
		}
		/* Values are multiplied by R^2 in B and by R^2 / M in B' to be stored,
		 * and the tables of the first extension carry 1 / M^2. */
		for (size_t i = 0; i < n; i++) {
			d = rns_inv(c, rns_res(c, m, o + i), o + i);
			c->e[o + i] = rns_mulp(c, c->r2[o + i], d, o + i);
			c->mi[i] = RNS_SCL(c, d, o + i);
		}

		/* B must exceed 2^(room + 2) * N, and B' 2^11 * N. */
		if (bn_bits(m) < bn_bits(mod) + room + 2 + 1 ||
				bn_bits(mb) < bn_bits(mod) + 11 + 2) {
			RLC_THROW(ERR_NO_VALID);
		}

		for (size_t i = 0; i < n; i++) {
			/* (M/m_i)^{-1} mod m_i, and (M/m_i) * R^3 mod m'_j. */
			bn_div_dig(t, m, c->m[i]);
			for (size_t j = 0; j < n; j++) {
				r3 = rns_mulp(c, c->r2[o + j], RNS_SCL(c, 1, o + j), o + j);
				/* Times N / M^2, to give q * N as a product in B'. */
				d = rns_mulp(c, rns_res(c, t, o + j), rns_res(c, mod, o + j),
						o + j);
				d = rns_mulp(c, d, rns_inv(c, rns_res(c, m, o + j), o + j),
						o + j);
				d = rns_mulp(c, d, rns_inv(c, rns_res(c, m, o + j), o + j),
						o + j);
				c->t1[i * o + j] = rns_mulp(c, d, r3, o + j);
			}
			c->ib[i] = rns_inv(c, rns_res(c, t, i), i);
			/* -N^{-1} (M/m_i)^{-1} mod m_i, to get xi_i of q directly. */
			d = rns_inv(c, rns_res(c, mod, i), i);
			c->nq[i] = rns_mulp(c, c->m[i] - d, c->ib[i], i);
			/* -M' * R^3 mod m_i. */
			r3 = rns_mulp(c, c->r2[i], RNS_SCL(c, 1, i), i);
			c->u2[i] = rns_mulp(c, RLC_RNS_SUB(0, rns_res(c, mb, i), c->m[i]),
					r3, i);
		}

		for (size_t i = 0; i < n; i++) {
			j0 = o + i;

			/* (M'/m'_i)^{-1} mod m'_i, and (M'/m'_i) * R^3 mod m_j. */
			bn_div_dig(t, mb, c->m[j0]);
			for (size_t j = 0; j < n; j++) {
				r3 = rns_mulp(c, c->r2[j], RNS_SCL(c, 1, j), j);
				c->t2[i * o + j] = rns_mulp(c, rns_res(c, t, j), r3, j);
			}
			/* Times M, as values are divided by M in B'. */
			c->ib[j0] = rns_mulp(c, rns_inv(c, rns_res(c, t, j0), j0),
					rns_res(c, m, j0), j0);

			/* -M * N / M^2 * R^3 mod m'_i. */
			r3 = rns_mulp(c, c->r2[j0], RNS_SCL(c, 1, j0), j0);
			d = rns_mulp(c, rns_res(c, mod, j0),
					rns_inv(c, rns_res(c, m, j0), j0), j0);
			c->u1[i] = rns_mulp(c, RLC_RNS_SUB(0, d, c->m[j0]), r3, j0);
		}

#if RLC_ARITH == RLC_AVX512
		/* The vectorized extensions reduce their sums with one Montgomery
		 * reduction instead of two, so their tables carry one factor R less. */
		for (size_t i = 0; i < n; i++) {
			for (size_t j = 0; j < n; j++) {
				c->t1[i * o + j] =
						rns_mul(c->t1[i * o + j], 1, c->m[o + j], c->u[o + j]);
				c->t2[i * o + j] =
						rns_mul(c->t2[i * o + j], 1, c->m[j], c->u[j]);
			}
			c->u1[i] = rns_mul(c->u1[i], 1, c->m[o + i], c->u[o + i]);
			c->u2[i] = rns_mul(c->u2[i], 1, c->m[i], c->u[i]);
			/* The quotients of the Montgomery reductions of products by nq and
			 * ib are their other factors times these values mod R. */
			c->nqv[i] = (c->nq[i] * c->iv[i]) & RLC_RNS_MASK;
			c->ibv[i] = (c->ib[o + i] * c->iv[o + i]) & RLC_RNS_MASK;
		}
#endif

		/* The multiples kN for -2 <= k <= 2, in both bases. */
		for (size_t j = 0; j < 5; j++) {
			bn_mul_dig(t, mod, (dig_t)(j < 2 ? 2 - j : j - 2));
			for (size_t i = 0; i < 2 * o; i++) {
				if (RNS_PAD(c, i)) {
					continue;
				}
				d = rns_mul(rns_res(c, t, i), c->e[i], c->m[i], c->u[i]);
				c->kp[j * 2 * o + i] = (j < 2 ? RLC_RNS_SUB(0, d, c->m[i]) : d);
			}
		}

		/* The low digits of M/m_i, -M and 3N for the conversion to positional
		 * form, and the residues of 2^(RLC_RNS_DIG * k) for the way back. */
		bn_set_2b(mb, RLC_DIG * l);
		bn_mod_2b(t, m, RLC_DIG * l);
		bn_sub(t, mb, t);
		for (size_t j = 0; j < l; j++) {
			c->mm[j] = (j < t->used ? t->dp[j] : 0);
		}
		bn_mul_dig(t, mod, 3);
		for (size_t j = 0; j < l; j++) {
			c->p3[j] = (j < t->used ? t->dp[j] : 0);
		}
		for (size_t i = 0; i < n; i++) {
			bn_div_dig(t, m, c->m[i]);
			bn_mod_2b(t, t, RLC_DIG * l);
			for (size_t j = 0; j < l; j++) {
				c->mp[i * l + j] = (j < t->used ? t->dp[j] : 0);
			}
		}
		for (size_t j = 0; j < c->w; j++) {
			bn_set_2b(t, RLC_RNS_DIG * j);
			for (size_t i = 0; i < 2 * o; i++) {
				if (RNS_PAD(c, i)) {
					continue;
				}
				c->pw[j * 2 * o + i] =
						rns_mulp(c, rns_res(c, t, i), c->e[i], i);
			}
		}

		/* The digits of N, and M and M^2 modulo N in storage form. */
		for (size_t j = 0; j < c->d; j++) {
			c->p[j] = (j < mod->used ? mod->dp[j] : 0);
		}
		bn_mod(t, m, mod);
		rns_conv(c->one, t, c);
		bn_sqr(t, t);
		bn_mod(t, t, mod);
		rns_conv(c->cv, t, c);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, mb, t);
	}
}
