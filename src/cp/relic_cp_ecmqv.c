/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2011 RELIC Authors
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
 * Implementation of the ECMQV protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_ecmqv_gen(bn_t d, ec_t q) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ec_curve_get_ord(n);
		bn_rand_mod(d, n);
		ec_mul_gen(q, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_ecmqv_key(uint8_t *key, size_t key_len, const bn_t d1, const bn_t d2,
		const ec_t q2u, const ec_t q1v, const ec_t q2v) {
	ec_t p;
	bn_t x, n, s;
	int l, result = RLC_OK;
	uint8_t _x[RLC_FC_BYTES];

	/* The peer's keys must be valid points of prime order, or invalid-curve
	 * and small-subgroup points could leak the private keys. */
	if (!ec_is_valid(q1v) || !ec_is_valid(q2v)) {
		return RLC_ERR;
	}

	ec_null(p);
	bn_null(x);
	bn_null(n);
	bn_null(s);

	RLC_TRY {
		ec_new(p);
		bn_new(x);
		bn_new(n);
		bn_new(s);

		ec_curve_get_ord(n);
		l = bn_bits(n);
		l = (l % 2) ? (l + 1) / 2 : l / 2;

		/* Read x-coordinates of normalized points only. */
		ec_norm(p, q2u);
		ec_get_x(x, p);
		bn_mod_2b(x, x, l);

		bn_set_bit(x, l, 1);

		bn_mul(s, x, d1);
		bn_mod(s, s, n);
		bn_add(s, s, d2);
		bn_mod(s, s, n);

		ec_norm(p, q2v);
		ec_get_x(x, p);
		bn_mod_2b(x, x, l);

		bn_set_bit(x, l, 1);

		/* Combine the public keys first, so that only the multiplication
		 * by the secret s needs to take constant time. */
		ec_mul(p, q1v, x);
		ec_add(p, p, q2v);
		ec_norm(p, p);
		ec_mul_sec(p, p, s);
		ec_norm(p, p);
		if (ec_is_infty(p)) {
			result = RLC_ERR;
		} else {
			ec_get_x(x, p);
			l = bn_size_bin(x);
			bn_write_bin(_x, l, x);
			md_kdf(key, key_len, _x, l);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		ec_free(p);
		bn_free(x);
		bn_free(n);
		bn_free(s);
	}
	return result;
}
