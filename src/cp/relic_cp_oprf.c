/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the oblivious pseudorandom function protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_oprf_ask(ec_t b, bn_t x, const ec_t a) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	if (ec_is_infty(a)) {
		return RLC_ERR;
	}

	RLC_TRY {
		bn_new(n);

		ec_curve_get_ord(n);
		do {
			bn_rand_mod(x, n);
		} while (bn_is_zero(x));
		ec_mul(b, a, x);
		bn_mod_inv(x, x, n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_oprf_ans(ec_t c, const bn_t alpha, const ec_t b) {
	if (bn_is_zero(alpha) || ec_is_infty(b)) {
		return RLC_ERR;
	}

	ec_mul(c, b, alpha);
	return RLC_OK;
}

int cp_oprf_res(ec_t r, const bn_t x, const ec_t c) {
	if (bn_is_zero(x) || ec_is_infty(c)) {
		return RLC_ERR;
	}

	ec_mul(r, c, x);
	return RLC_OK;
}
