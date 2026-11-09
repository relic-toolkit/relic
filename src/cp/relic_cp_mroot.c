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
 * Implementation of the MinRoot sequential function.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Checks that a modulus admits cube roots by exponentiation, that is, it is
 * odd, larger than 3 and congruent to 2 modulo 3. Primality is not checked.
 *
 * @param[in] p				- the modulus.
 * @return 1 if the modulus is valid, 0 otherwise.
 */
static int mroot_mod(const bn_t p) {
	dig_t r;

	if (bn_sign(p) == RLC_NEG || bn_is_even(p) || bn_cmp_dig(p, 3) != RLC_GT) {
		return 0;
	}
	bn_mod_dig(&r, p, 3);
	return (r == 2);
}

/**
 * Checks that a pair of integers lies in [0, p).
 *
 * @param[in] a				- the first integer.
 * @param[in] b				- the second integer.
 * @param[in] p				- the modulus.
 * @return 1 if both integers are reduced, 0 otherwise.
 */
static int mroot_in(const bn_t a, const bn_t b, const bn_t p) {
	return bn_sign(a) != RLC_NEG && bn_sign(b) != RLC_NEG &&
			bn_cmp(a, p) == RLC_LT && bn_cmp(b, p) == RLC_LT;
}

/**
 * Assigns the number of rounds modulo p to a multiple precision integer.
 *
 * @param[out] a			- the result.
 * @param[in] t				- the number of rounds.
 * @param[in] p				- the modulus.
 */
static void mroot_set(bn_t a, size_t t, const bn_t p) {
	uint8_t buf[sizeof(size_t)];

	for (size_t j = 0; j < sizeof(size_t); j++) {
		buf[j] = (uint8_t)(t >> (8 * (sizeof(size_t) - 1 - j)));
	}
	bn_read_bin(a, buf, sizeof(size_t));
	bn_mod_basic(a, a, p);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_mroot_gen(bn_t p, size_t bits) {
	int result = RLC_OK;

	if (bits < 8) {
		return RLC_ERR;
	}

	/* A safe prime p = 2p' + 1 with p' > 3 is 2 modulo 3, as p' is. */
	do {
		result = bn_gen_prime_chain(p, NULL, bits, 2);
	} while (result == RLC_OK && !mroot_mod(p));

	return result;
}

int cp_mroot_fwd(bn_t x, bn_t y, const bn_t a, const bn_t b, size_t t,
		const bn_t p) {
	bn_t e, i, s, u, v;
	int result = RLC_OK;

	if (!mroot_mod(p) || !mroot_in(a, b, p)) {
		return RLC_ERR;
	}

	bn_null_all(e, i, s, u, v);

	RLC_TRY {
		bn_new_all(e, i, s, u, v);

		/* e = (2p - 1) / 3 = 3^(-1) mod (p - 1). */
		bn_dbl(e, p);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 3);

		bn_copy(u, a);
		bn_copy(v, b);
		bn_zero(i);
		for (size_t r = 0; r < t; r++) {
			/* i = r + 1 mod p, kept reduced for small moduli. */
			bn_add_dig(i, i, 1);
			if (bn_cmp(i, p) == RLC_EQ) {
				bn_zero(i);
			}
			/* (u, v) = ((u + v)^e, u + i). */
			bn_add(s, u, v);
			if (bn_cmp(s, p) != RLC_LT) {
				bn_sub(s, s, p);
			}
			bn_add(v, u, i);
			if (bn_cmp(v, p) != RLC_LT) {
				bn_sub(v, v, p);
			}
			bn_mxp(u, s, e, p);
		}
		bn_copy(x, u);
		bn_copy(y, v);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(e, i, s, u, v);
	}

	return result;
}

int cp_mroot_bwd(bn_t x, bn_t y, const bn_t a, const bn_t b, size_t t,
		const bn_t p) {
	bn_t c, i, k, m, u, v;
	int result = RLC_OK;

	if (!mroot_mod(p) || !mroot_in(a, b, p)) {
		return RLC_ERR;
	}

	bn_null_all(c, i, k, m, u, v);

	RLC_TRY {
		bn_new_all(c, i, k, m, u, v);

		/* Keep the state in the representation of the configured reduction,
		 * with i = t and k = 1 as well, so that they can be subtracted. */
		bn_mod_pre(m, p);
		bn_copy(u, a);
		bn_copy(v, b);
		mroot_set(i, t, p);
		bn_set_dig(k, 1);
#if BN_MOD == BN_MONTY
		bn_mod_monty_conv(u, u, p);
		bn_mod_monty_conv(v, v, p);
		bn_mod_monty_conv(i, i, p);
		bn_mod_monty_conv(k, k, p);
#endif

		for (size_t r = 0; r < t; r++) {
			/* c = u^3. */
			bn_sqr(c, u);
			bn_mod(c, c, p, m);
			bn_mul(c, c, u);
			bn_mod(c, c, p, m);
			/* (u, v) = (v - i, u^3 - v + i). */
			bn_sub(u, v, i);
			if (bn_sign(u) == RLC_NEG) {
				bn_add(u, u, p);
			}
			bn_sub(v, c, u);
			if (bn_sign(v) == RLC_NEG) {
				bn_add(v, v, p);
			}
			bn_sub(i, i, k);
			if (bn_sign(i) == RLC_NEG) {
				bn_add(i, i, p);
			}
		}

#if BN_MOD == BN_MONTY
		bn_mod_monty_back(u, u, p);
		bn_mod_monty_back(v, v, p);
#endif
		bn_copy(x, u);
		bn_copy(y, v);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(c, i, k, m, u, v);
	}

	return result;
}
