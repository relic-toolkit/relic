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
 * Computes the inverse of a nonzero residue modulo the i-th modulus, as its
 * power to m - 2 in Montgomery form. The modulus is public, so the time may
 * depend on it.
 *
 * @param[in] c				- the context, with the moduli and R^2 mod m.
 * @param[in] a				- the residue.
 * @param[in] i				- the index of the modulus.
 * @return the inverse.
 */
static dig_t rns_inv(const rns_st *c, dig_t a, size_t i) {
	const dig_t m = c->m[i], u = c->u[i];
	dig_t b = rns_mul(a, c->r2[i], m, u), r = rns_mul(1, c->r2[i], m, u);

	for (dig_t e = m - 2; e > 0; e >>= 1) {
		if (e & 1) {
			r = rns_mul(r, b, m, u);
		}
		b = rns_mul(b, b, m, u);
	}
	return rns_mul(r, 1, m, u);
}

#ifndef RLC_CONF_NODBL
/**
 * Computes a * b mod m for digits below m.
 */
static dig_t rns_mod_mul(dig_t a, dig_t b, dig_t m) {
	return (dig_t)(((dbl_t)a * b) % m);
}

/**
 * Tests if a digit is prime, deterministically: small primes are checked by
 * trial division, and Miller-Rabin with these bases is exact for all inputs
 * below 2^64 (Jaeschke, Sinclair) or 2^32 (Jaeschke).
 *
 * @param[in] p				- the odd digit to test, above the small primes.
 * @return 1 if the digit is prime, 0 otherwise.
 */
static int rns_is_prime(dig_t p) {
	static const dig_t small[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
#if RLC_DIG == 64
	static const dig_t base[] = { 2, 325, 9375, 28178, 450775, 9780504,
		1795265022 };
#else
	static const dig_t base[] = { 2, 7, 61 };
#endif
	dig_t d = p - 1, x, y;
	int r = 0;

	for (size_t k = 0; k < sizeof(small) / sizeof(small[0]); k++) {
		if (p % small[k] == 0) {
			return 0;
		}
	}
	while ((d & 1) == 0) {
		d >>= 1;
		r++;
	}
	for (size_t k = 0; k < sizeof(base) / sizeof(base[0]); k++) {
		dig_t a = base[k] % p;
		if (a == 0) {
			continue;
		}
		/* x = a^d mod p by square-and-multiply. */
		x = 1;
		y = a;
		for (dig_t e = d; e > 0; e >>= 1) {
			if (e & 1) {
				x = rns_mod_mul(x, y, p);
			}
			y = rns_mod_mul(y, y, p);
		}
		if (x == 1 || x == p - 1) {
			continue;
		}
		for (int j = 1; j < r && x != p - 1; j++) {
			x = rns_mod_mul(x, x, p);
		}
		if (x != p - 1) {
			return 0;
		}
	}
	return 1;
}
#endif

/**
 * Precomputes the base of a context: the moduli and the tables that do not
 * depend on the modulus N. Three tables of a base differ from those of a
 * context, which computes its own from them: t1 holds the residues of M/m_i
 * before the column factors of N are applied, u1 holds M^{-2} R^3 mod m'_j and
 * nq holds M^{-1} R^3 mod m'_j.
 *
 * @param[out] b			- the base, sized as the context.
 * @param[in] mod			- a modulus the moduli must not divide, or NULL.
 */
static void rns_pre_base(rns_t b, const bn_t mod) {
	bn_t m, mb, t;
	dig_t s = 1, d, r3, f2[RLC_RNS_MAX];
	const size_t n = b->n, o = b->o, l = b->d + 1;
	size_t k = 0, h = 0, j0;

	bn_null_all(m, mb, t);

	RLC_TRY {
		bn_new_all(m, mb, t);

		/* The residues that pad each base are zero in all tables. */
		dv_zero(b->m, 2 * o);
		dv_zero(b->u, 2 * o);
		dv_zero(b->iv, 2 * o);
		dv_zero(b->r2, 2 * o);
		dv_zero(b->e, 2 * o);
		dv_zero(b->ib, 2 * o);
		dv_zero(b->nq, o);
		dv_zero(b->nqv, o);
		dv_zero(b->ibv, o);
		dv_zero(b->u1, o);
		dv_zero(b->u2, o);
		dv_zero(b->t1, n * o);
		dv_zero(b->t2, n * o);
		dv_zero(b->kp, 5 * 2 * o);
		dv_zero(b->pw, b->w * 2 * o);

		/* Pick the largest primes 2^bits - s, coprime to the modulus if
		 * given, with s below the square root of R: first for B, then for
		 * B'. */
		while (k < n || h < n) {
			if (s >= ((dig_t)1 << (RLC_RNS_DIG / 2))) {
				RLC_THROW(ERR_NO_VALID);
				break;
			}
			d = ((dig_t)1 << b->bits) - s;
			s += 2;
			if (mod != NULL) {
				bn_mod_dig(&r3, mod, d);
				if (r3 == 0) {
					continue;
				}
			}
#ifndef RLC_CONF_NODBL
			if (rns_is_prime(d)) {
#else
			bn_set_dig(t, d);
			if (bn_is_prime(t)) {
#endif
				if (k < n) {
					b->m[k++] = d;
				} else {
					b->m[o + h++] = d;
				}
			}
		}

		/* -m^{-1} mod R by Newton iteration, and R^2 mod m. */
		for (size_t i = 0; i < 2 * o; i++) {
			dig_t x = b->m[i];
			if (RLC_RNS_PAD(b, i)) {
				continue;
			}
			for (int j = 0; j < 6; j++) {
				x *= 2 - b->m[i] * x;
			}
			b->u[i] = (0 - x) & RLC_RNS_MASK;
			b->iv[i] = x & RLC_RNS_MASK;
			bn_set_2b(t, 2 * RLC_RNS_DIG);
			b->r2[i] = rns_res(b, t, i);
		}

		/* M and M' as integers. */
		bn_set_dig(m, 1);
		bn_set_dig(mb, 1);
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(m, m, b->m[i]);
			b->e[i] = b->r2[i];
		}
		for (size_t i = 0; i < n; i++) {
			bn_mul_dig(mb, mb, b->m[o + i]);
		}
		/* Values are multiplied by R^2 in B and by R^2 / M in B' to be stored,
		 * and the tables of the first extension carry 1 / M^2. With R^3, the
		 * column factors M^{-2} R^3 and M^{-1} R^3 mod m'_j, and R^3 mod m_j
		 * for the second extension. */
		for (size_t j = 0; j < n; j++) {
			d = rns_inv(b, rns_res(b, m, o + j), o + j);
			b->e[o + j] = rns_mulp(b, b->r2[o + j], d, o + j);
			b->mi[j] = RNS_SCL(b, d, o + j);
			r3 = rns_mulp(b, b->r2[o + j], RNS_SCL(b, 1, o + j), o + j);
			b->nq[j] = rns_mulp(b, d, r3, o + j);
			b->u1[j] = rns_mulp(b, b->nq[j], d, o + j);
			f2[j] = rns_mulp(b, b->r2[j], RNS_SCL(b, 1, j), j);
		}

		for (size_t i = 0; i < n; i++) {
			/* (M/m_i)^{-1} mod m_i, and M/m_i mod m'_j. */
			bn_div_dig(t, m, b->m[i]);
			for (size_t j = 0; j < n; j++) {
				b->t1[i * o + j] = rns_res(b, t, o + j);
			}
			b->ib[i] = rns_inv(b, rns_res(b, t, i), i);
			/* -M' * R^3 mod m_i. */
			r3 = rns_mulp(b, b->r2[i], RNS_SCL(b, 1, i), i);
			b->u2[i] = rns_mulp(b, RLC_RNS_SUB(0, rns_res(b, mb, i), b->m[i]),
					r3, i);
		}

		for (size_t i = 0; i < n; i++) {
			j0 = o + i;
			/* (M'/m'_i)^{-1} mod m'_i, and (M'/m'_i) * R^3 mod m_j. */
			bn_div_dig(t, mb, b->m[j0]);
			for (size_t j = 0; j < n; j++) {
				b->t2[i * o + j] = rns_mulp(b, rns_res(b, t, j), f2[j], j);
			}
			/* Times M, as values are divided by M in B'. */
			b->ib[j0] = rns_mulp(b, rns_inv(b, rns_res(b, t, j0), j0),
					rns_res(b, m, j0), j0);
		}

#if RLC_ARITH == RLC_AVX512
		/* The vectorized extensions reduce their sums with one Montgomery
		 * reduction instead of two, so their tables carry one factor R less. */
		for (size_t i = 0; i < n; i++) {
			for (size_t j = 0; j < n; j++) {
				b->t2[i * o + j] =
						rns_mul(b->t2[i * o + j], 1, b->m[j], b->u[j]);
			}
			b->u2[i] = rns_mul(b->u2[i], 1, b->m[i], b->u[i]);
			/* The quotients of the Montgomery reductions of products by ib are
			 * their other factors times these values mod R. */
			b->ibv[i] = (b->ib[o + i] * b->iv[o + i]) & RLC_RNS_MASK;
		}
#endif

		/* The low digits of M/m_i and -M for the conversion to positional
		 * form, and the residues of 2^(RLC_RNS_DIG * k) for the way back. */
		bn_set_2b(mb, RLC_DIG * l);
		bn_mod_2b(t, m, RLC_DIG * l);
		bn_sub(t, mb, t);
		for (size_t j = 0; j < l; j++) {
			b->mm[j] = (j < t->used ? t->dp[j] : 0);
		}
		for (size_t i = 0; i < n; i++) {
			bn_div_dig(t, m, b->m[i]);
			bn_mod_2b(t, t, RLC_DIG * l);
			for (size_t j = 0; j < l; j++) {
				b->mp[i * l + j] = (j < t->used ? t->dp[j] : 0);
			}
		}
		for (size_t j = 0; j < b->w; j++) {
			bn_set_2b(t, RLC_RNS_DIG * j);
			for (size_t i = 0; i < 2 * o; i++) {
				if (RLC_RNS_PAD(b, i)) {
					continue;
				}
				b->pw[j * 2 * o + i] =
						rns_mulp(b, rns_res(b, t, i), b->e[i], i);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, mb, t);
	}
}

/**
 * Returns the base for contexts of the given sizes from the library context,
 * precomputing it in place of the older one if it is missing.
 *
 * @param[in] n				- the number of moduli in each base.
 * @param[in] d				- the number of digits of the moduli N.
 * @param[in] bits			- the size in bits of the moduli.
 * @return the base, or NULL if there is no memory for it.
 */
static const rns_st *rns_base(size_t n, size_t d, size_t bits) {
	ctx_t *ctx = core_get();
	rns_st *b;

	for (int k = 0; k < 2; k++) {
		b = &(ctx->rns_base[k]);
		if (b->mem != NULL && b->n == n && b->d == d && b->bits == bits) {
			return b;
		}
	}
	b = &(ctx->rns_base[ctx->rns_bnext]);
	ctx->rns_bnext ^= 1;
	rns_free(b);
	rns_new(b, n, d);
	if (b->mem != NULL) {
		b->bits = bits;
		rns_pre_base(b, NULL);
	}
	return (b->mem != NULL ? b : NULL);
}

/**
 * Precomputes the tables of a context that depend on the modulus N, from a
 * base of the same sizes, which may be the context itself.
 *
 * @param[out] c			- the context.
 * @param[in] b				- the base.
 * @param[in] mod			- the modulus.
 * @param[in] room			- the room for sums of products, in bits.
 * @return 1 if the moduli of the base are coprime to N, 0 otherwise.
 */
static int rns_pre_mod(rns_t c, const rns_st *b, const bn_t mod, int room) {
	bn_t m, t;
	dig_t d, f1[RLC_RNS_MAX], g1[RLC_RNS_MAX], g2[RLC_RNS_MAX];
	dig_t rn[2 * RLC_RNS_MAX];
	const size_t n = c->n, o = c->o, l = c->d + 1;
	int result = 1;

	bn_null_all(m, t);

	RLC_TRY {
		bn_new_all(m, t);

		/* The residues of N, which must all be nonzero. */
		for (size_t i = 0; i < 2 * o; i++) {
			rn[i] = (RLC_RNS_PAD(b, i) ? 0 : rns_res(b, mod, i));
			if (!RLC_RNS_PAD(b, i) && rn[i] == 0) {
				result = 0;
			}
		}
		if (result) {
			/* The column factors, read before the tables are overwritten. */
			for (size_t j = 0; j < n; j++) {
				g1[j] = b->u1[j];
				g2[j] = b->nq[j];
			}
			if (b != c) {
				dv_copy(c->m, b->m, 2 * o);
				dv_copy(c->u, b->u, 2 * o);
				dv_copy(c->iv, b->iv, 2 * o);
				dv_copy(c->r2, b->r2, 2 * o);
				dv_copy(c->e, b->e, 2 * o);
				dv_copy(c->ib, b->ib, 2 * o);
				dv_copy(c->mi, b->mi, n);
				dv_copy(c->ibv, b->ibv, o);
				dv_copy(c->u2, b->u2, o);
				dv_copy(c->t1, b->t1, n * o);
				dv_copy(c->t2, b->t2, n * o);
				dv_copy(c->mm, b->mm, l);
				dv_copy(c->mp, b->mp, n * l);
				dv_copy(c->pw, b->pw, c->w * 2 * o);
				dv_zero(c->nq, o);
				dv_zero(c->nqv, o);
				dv_zero(c->u1, o);
			}

			/* B must exceed 2^(room + 2) * N, and B' 2^11 * N. */
			bn_set_dig(m, 1);
			bn_set_dig(t, 1);
			for (size_t i = 0; i < n; i++) {
				bn_mul_dig(m, m, c->m[i]);
				bn_mul_dig(t, t, c->m[o + i]);
			}
			if (bn_bits(m) < bn_bits(mod) + room + 2 + 1 ||
					bn_bits(t) < bn_bits(mod) + 11 + 2) {
				RLC_THROW(ERR_NO_VALID);
			}

			for (size_t j = 0; j < n; j++) {
				/* N / M^2 * R^3 mod m'_j, the column factor of the first
				 * extension, and -M * N / M^2 * R^3 mod m'_j. */
				f1[j] = rns_mulp(c, rn[o + j], g1[j], o + j);
				d = rns_mulp(c, rn[o + j], g2[j], o + j);
				c->u1[j] = RLC_RNS_SUB(0, d, c->m[o + j]);
			}
			for (size_t i = 0; i < n; i++) {
				/* (M/m_i) * N / M^2 * R^3 mod m'_j, to give q * N as a
				 * product in B'. */
				for (size_t j = 0; j < n; j++) {
					c->t1[i * o + j] =
							rns_mulp(c, c->t1[i * o + j], f1[j], o + j);
				}
				/* -N^{-1} (M/m_i)^{-1} mod m_i, to get xi_i of q directly. */
				d = rns_inv(c, rn[i], i);
				c->nq[i] = rns_mulp(c, c->m[i] - d, c->ib[i], i);
			}

#if RLC_ARITH == RLC_AVX512
			/* One factor R less, as for the base, and the quotients of the
			 * reductions of products by nq. */
			for (size_t i = 0; i < n; i++) {
				for (size_t j = 0; j < n; j++) {
					c->t1[i * o + j] = rns_mul(c->t1[i * o + j], 1,
							c->m[o + j], c->u[o + j]);
				}
				c->u1[i] = rns_mul(c->u1[i], 1, c->m[o + i], c->u[o + i]);
				c->nqv[i] = (c->nq[i] * c->iv[i]) & RLC_RNS_MASK;
			}
#endif

			/* The multiples kN for -2 <= k <= 2, in both bases. */
			for (size_t j = 0; j < 5; j++) {
				dig_t k = (dig_t)(j < 2 ? 2 - j : j - 2);
				for (size_t i = 0; i < 2 * o; i++) {
					if (RLC_RNS_PAD(c, i)) {
						c->kp[j * 2 * o + i] = 0;
						continue;
					}
					d = rns_mul(rns_mulp(c, rn[i], k, i), c->e[i], c->m[i],
							c->u[i]);
					c->kp[j * 2 * o + i] =
							(j < 2 ? RLC_RNS_SUB(0, d, c->m[i]) : d);
				}
			}

			/* The low digits of 3N, the digits of N, and M and M^2 modulo N
			 * in storage form. */
			bn_mul_dig(t, mod, 3);
			for (size_t j = 0; j < l; j++) {
				c->p3[j] = (j < t->used ? t->dp[j] : 0);
			}
			for (size_t j = 0; j < c->d; j++) {
				c->p[j] = (j < mod->used ? mod->dp[j] : 0);
			}
			bn_mod(t, m, mod);
			rns_conv(c->one, t, c);
			bn_sqr(t, t);
			bn_mod(t, t, mod);
			rns_conv(c->cv, t, c);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(m, t);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_pre(rns_t c, const bn_t mod, int room) {
	const rns_st *b = rns_base(c->n, c->d, c->bits);

	/* A modulus divisible by a modulus of the shared base, which is rare, gets
	 * a base of its own. */
	if (b == NULL || !rns_pre_mod(c, b, mod, room)) {
		rns_pre_base(c, mod);
		rns_pre_mod(c, c, mod, room);
	}
}
