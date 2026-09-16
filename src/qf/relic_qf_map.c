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
 * Implementation of the hashing to class group.
 *
 * @ingroup qf
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_md.h"
#include "relic_qf.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** Below this bound an integer is drawn and factored directly. */
#define QF_MAP_SMALL	((dig_t)1 << 20)

/** The constant in the RF(K, L) approximation, per the paper's advice. */
#define QF_MAP_RF		(0.6)

/** Number of tries to draw a prime power factor. */
#define QF_MAP_TRIES	(1 << 10)

/**
 * Draws a prime power factor, biased as the paper's genFactorWithBias.
 *
 * Rejection is on nu <= delta_N(q) * 2 * log2(q), with delta_N(q) the paper's
 * (log p / log N) * RF(N/2q, N/q) / N and RF approximated linearly, and the
 * candidate is required to be a prime power whose base leaves the discriminant
 * a residue, so that a form of that norm exists at all.
 */
static int qf_map_factor(bn_t q, bn_t p, size_t *e, xof_t *g, const bn_t n,
		const bn_t dsc) {
	bn_t t;
	size_t j, tries, bits = bn_bits(n);
	double nu, del, lq, lp, ln;
	int result = 0;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		ln = (double)bits;
		for (tries = 0; tries < QF_MAP_TRIES; tries++) {
			/* q = 2^j + r with r below 2^j, so q lands in [2^j, 2^(j+1)) */
			j = 1 + md_xof_int(g, bits);
			bn_set_dig(q, 1);
			bn_lsh(q, q, j);
			md_xof_bits(t, j, g);
			bn_add(q, q, t);
			if (bn_cmp(q, n) == RLC_GT || bn_cmp_dig(q, 2) == RLC_LT) {
				continue;
			}
			nu = md_xof_double(g);
			/* recognize q as a prime or a prime square, giving its base and
			 * exponent, so that a form of that norm exists at all */
			if (bn_is_prime(q)) {
				bn_copy(p, q);
				*e = 1;
			} else {
				bn_copy(t, q);
				bn_srt(p, t);
				bn_sqr(t, p);
				if (bn_cmp(t, q) != RLC_EQ || !bn_is_prime(p)) {
					continue;
				}
				*e = 2;
			}
			/* the Jacobi symbol needs an odd modulus, and 2 cannot be lifted
			 * through Hensel's method below anyway, so it is never usable */
			if (bn_cmp_dig(p, 2) == RLC_EQ) {
				continue;
			}
			bn_mod(t, dsc, p);
			if (bn_smb_jac(t, p) != 1) {
				continue;
			}
			/*
			 * delta_N(q) * 2 * log2(q) with RF(N/2q, N/q) taken as
			 * c * N / (2q), which cancels the division by N.
			 */
			lq = (double)bn_bits(q);
			lp = (double)bn_bits(p);
			del = (lp / ln) * QF_MAP_RF / 2.0;
			if (nu <= del * 2.0 * lq / lq) {
				result = 1;
				break;
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return result;
}

/**
 * Draws an integer below n together with its factorization, biased towards
 * integers with many prime factors. This is the paper's BachWithBias.
 *
 * @param[out] a			- the resulting integer.
 * @param[out] p			- the distinct prime factors.
 * @param[out] e			- their exponents.
 * @param[out] np			- the number of distinct prime factors.
 * @param[in] cap			- the capacity of the factor arrays.
 * @param[in] g				- the digest stream.
 * @param[in] n				- the upper bound.
 * @param[in] dsc			- the discriminant.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int qf_map_bach(bn_t a, bn_t *p, size_t *e, size_t *np, size_t cap,
		xof_t *g, const bn_t n, const bn_t dsc) {
	bn_t q, pp, z, t;
	size_t ee, i, k, rounds;
	double mu;
	int result = RLC_ERR;

	bn_null(q);
	bn_null(pp);
	bn_null(z);
	bn_null(t);

	RLC_TRY {
		bn_new(q);
		bn_new(pp);
		bn_new(z);
		bn_new(t);

		if (bn_cmp_dig(n, QF_MAP_SMALL) != RLC_GT) {
			/*
			 * Small enough to draw and factor directly. The bias is applied by
			 * rejecting candidates for which no form exists, which is what
			 * R(D, x) being zero means.
			 */
			dig_t v, d, m;
			for (rounds = 0; rounds < 4096; rounds++) {
				bn_get_dig(&m, n);
				v = m / 2 + 1 + (dig_t)md_xof_int(g, m / 2);
				*np = 0;
				bn_set_dig(a, v);
				for (d = 2; (dig_t)d * d <= v && *np < cap; d++) {
					if (v % d == 0) {
						size_t c = 0;
						while (v % d == 0) {
							v /= d;
							c++;
						}
						bn_set_dig(p[*np], d);
						e[*np] = c;
						(*np)++;
					}
				}
				if (v > 1 && *np < cap) {
					bn_set_dig(p[*np], v);
					e[*np] = 1;
					(*np)++;
				}
				/* every factor must leave the discriminant a residue; 2 is
				 * never usable, as bn_smb_jac needs an odd modulus and 2
				 * cannot be lifted through Hensel's method below anyway */
				k = 1;
				for (i = 0; i < *np; i++) {
					if (bn_cmp_dig(p[i], 2) == RLC_EQ) {
						k = 0;
						break;
					}
					bn_mod(q, dsc, p[i]);
					if (bn_smb_jac(q, p[i]) != 1) {
						k = 0;
						break;
					}
				}
				if (k) {
					result = RLC_OK;
					break;
				}
			}
		} else {
			for (rounds = 0; rounds < 64; rounds++) {
				if (!qf_map_factor(q, pp, &ee, g, n, dsc)) {
					break;
				}
				bn_div(t, n, q);				/* N' = N / q */
				if (qf_map_bach(a, p, e, np, cap, g, t, dsc) != RLC_OK) {
					continue;
				}
				bn_copy(z, a);
				bn_mul(a, q, z);				/* y = q * z */
				mu = md_xof_double(g);
				/*
				 * The bias: R(D, q) is two for every accepted prime power, since
				 * the discriminant is a residue modulo its base, so the adjustment
				 * is a halving whenever the two parts are coprime.
				 */
				bn_gcd(t, q, z);
				if (bn_cmp_dig(t, 1) == RLC_EQ) {
					mu /= 2.0;
				}
				if (mu * (double)bn_bits(a) <= (double)(bn_bits(n) - 1)) {
					/* merge the drawn factor into the factorization */
					for (i = 0; i < *np; i++) {
						if (bn_cmp(p[i], pp) == RLC_EQ) {
							e[i] += ee;
							break;
						}
					}
					if (i == *np) {
						if (*np >= cap) {
							continue;
						}
						bn_copy(p[*np], pp);
						e[*np] = ee;
						(*np)++;
					}
					result = RLC_OK;
					break;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(pp);
		bn_free(z);
		bn_free(t);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_map(qf_t r, const uint8_t *msg, size_t len, const bn_t dsc) {
	bn_t p, b, t;
	dig_t s3;
	uint32_t k = 0;
	/*
	 * A prime of about half the discriminant's bit length is on the same
	 * scale as a reduced form's norm, which is what keeps the hash close to
	 * uniform over the class group; see the discussion of bit length choices
	 * in the paper below.
	 */
	size_t bits = bn_bits(dsc) / 2;

	bn_null(p);
	bn_null(b);
	bn_null(t);

	/* Implement Alg. 5 in "How (not) to hash into class groups of imaginary
	 * quadratic fields? by Seres, Burcsi and Kutas:
	 * https://eprint.iacr.org/2024/034 */

	RLC_TRY {
		bn_new(p);
		bn_new(b);
		bn_new(t);
 
		while (1) {
			if (bn_map_prime(p, &k, msg, len, bits, k) != RLC_OK) {
				RLC_THROW(ERR_NO_VALID);
			}
			k++;
 
			/* a form of this norm exists only when the discriminant splits */
			bn_mod(t, dsc, p);
			if (bn_smb_jac(t, p) != 1) {
				continue;
			}
			if (!bn_srt_mod(b, t, p)) {
				continue;
			}
			/*
			 * Both roots give a form, so one is chosen by a rule depending only
			 * on the prime, which keeps the function deterministic.
			 */
			bn_mod_dig(&s3, p, 3);
			if (s3 == 2) {
				bn_sub(b, p, b);
			}
			/* the parity of b must match that of the discriminant, so that the
			 * root lifts from modulo p to modulo four p */
			if (bn_is_even(b) != bn_is_even(dsc)) {
				bn_sub(b, p, b);
			}
			qf_set_dsc(r, p, b, dsc);
			if (qf_has_dsc(r, dsc)) {
				qf_rdc(r, r);
				break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(b);
		bn_free(t);
	}
}

void qf_map_bqf(qf_t r, const uint8_t *msg, size_t len, const bn_t dsc) {
	xof_t g;
	bn_t n, a, b, t, u, m, mi, hm, ht, hv;
	bn_t p[32];
	size_t e[32], np, i, k, sel, rounds;

	bn_null(n);
	bn_null(a);
	bn_null(b);
	bn_null(t);
	bn_null(u);
	bn_null(m);
	bn_null(mi);
	bn_null(hm);
	bn_null(ht);
	bn_null(hv);

	/* Implement Alg. 6 in "How (not) to hash into class groups of imaginary
	 * quadratic fields? by Seres, Burcsi and Kutas:
	 * https://eprint.iacr.org/2024/034 */

	RLC_TRY {
		bn_new(n);
		bn_new(a);
		bn_new(b);
		bn_new(t);
		bn_new(u);
		bn_new(m);
		bn_new(mi);
		bn_new(hm);
		bn_new(ht);
		bn_new(hv);
		for (i = 0; i < 32; i++) {
			bn_null(p[i]);
			bn_new(p[i]);
		}

		{
			/* seed the XOF from a domain separation tag, the discriminant and
			 * the message, all absorbed as a single input */
			uint8_t *buf;
			size_t bl = 0, dl = bn_size_bin(dsc);

			buf = RLC_ALLOCA(uint8_t, 1 + dl + len);
			if (buf == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			buf[bl++] = 0x03;
			bn_write_bin(buf + bl, dl, dsc);
			bl += dl;
			if (len > 0) {
				memcpy(buf + bl, msg, len);
				bl += len;
			}
			md_xof_init(&g, buf, bl);
			RLC_FREE(buf);
		}

		/* the first coefficient must not exceed the root of a third of |D| */
		bn_abs(n, dsc);
		bn_div_dig(n, n, 3);
		bn_srt(n, n);

		for (rounds = 0; rounds < 256; rounds++) {
			if (qf_map_bach(a, p, e, &np, 32, &g, n, dsc) != RLC_OK) {
				continue;
			}
			if (bn_is_zero(a) || np == 0) {
				continue;
			}
			/*
			 * There are two square roots modulo each prime power, so two to the
			 * number of factors in total. Rather than form them all and index
			 * the list, the sign of each is taken from a bit of a mod that
			 * count, which selects the same element far more cheaply.
			 */
			sel = 0;
			bn_set_dig(t, (dig_t)np);
			bn_mod(u, a, t);
			bn_get_dig((dig_t *)&sel, u);

			bn_set_dig(b, 0);
			bn_set_dig(m, 1);
			for (i = 0; i < np; i++) {
				bn_copy(t, p[i]);
				for (k = 1; k < e[i]; k++) {
					bn_mul(t, t, p[i]);
				}
				/* u <- sqrt(dsc) mod p[i]^e[i], lifted from mod p[i] by Hensel */
				bn_mod(ht, dsc, p[i]);
				bn_srt_mod(u, ht, p[i]);
				bn_copy(hm, p[i]);
				for (k = 1; k < e[i]; k++) {
					/* u <- u - (u^2 - dsc) / (2u) modulo the next power */
					bn_mul(hm, hm, p[i]);
					bn_sqr(ht, u);
					bn_sub(ht, ht, dsc);
					bn_mod(ht, ht, hm);
					bn_dbl(hv, u);
					bn_mod_inv(hv, hv, hm);
					bn_mul(ht, ht, hv);
					bn_mod(ht, ht, hm);
					bn_sub(u, u, ht);
					bn_mod(u, u, hm);
				}
				if ((sel >> i) & 1) {
					bn_sub(u, t, u);
				}
				/* combine with what is already accumulated, by the remainder
				 * theorem: b <- b + m * ((u - b) / m mod t) */
				bn_sub(u, u, b);
				bn_mod(u, u, t);
				bn_mod_inv(mi, m, t);
				bn_mul(u, u, mi);
				bn_mod(u, u, t);
				bn_mul_add(b, u, m);
				bn_mul(m, m, t);
				bn_mod(b, b, m);
			}
			/* the parity of b must match that of the discriminant */
			if (bn_is_even(b) != bn_is_even(dsc)) {
				bn_sub(b, m, b);
			}
			qf_set_dsc(r, a, b, dsc);
			if (!qf_has_dsc(r, dsc)) {
				continue;
			}
			/* discard what is not already reduced, as the paper does */
			qf_rdc(r, r);
			if (qf_has_dsc(r, dsc)) {
				break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(a);
		bn_free(b);
		bn_free(t);
		bn_free(u);
		bn_free(m);
		bn_free(mi);
		bn_free(hm);
		bn_free(ht);
		bn_free(hv);
		for (i = 0; i < 32; i++) {
			bn_free(p[i]);
		}
	}
}