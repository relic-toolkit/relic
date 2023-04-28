/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of point multiplication of a prime elliptic curve by the
 * curve cofactor.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep_mul_cof(ep_t r, const ep_t p) {
	ep_t v;
	bn_t k;

	bn_null(k);
	ep_null(v);

	RLC_TRY {
		bn_new(k);
		ep_new(v);

		switch (ep_curve_is_pairf()) {
#if defined(EP_ENDOM) && !defined(STRIP)
			case EP_BN:
				/* h = 1 */
				break;
			case EP_B12:
			case EP_B24:
				/* Multiply by (1-x) to get the correct group, as proven in
				 * Piellard. https://eprint.iacr.org/2022/352.pdf */
				fp_prime_get_par(k);
				bn_neg(k, k);
				bn_add_dig(k, k, 1);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(r, p, k->dp[0]);
				} else {
					ep_mul_basic(r, p, k);
				}
				break;
			case EP_K18:
				/* Compute 343*(P + [u+3]psi(P)). */
				fp_prime_get_par(k);
				bn_add_dig(k, k, 3);
				ep_psi(v, p);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(v, v, k->dp[0]);
				} else {
					ep_mul_basic(v, v, k);
				}
				ep_add(v, v, p);
				ep_norm(r, v);
				ep_mul_dig(r, r, 49);
				ep_mul_dig(r, r, 7);
				break;
#endif
			default:
				/* multiply by cofactor to get the correct group. */
				ep_curve_get_cof(k);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(r, p, k->dp[0]);
				} else {
					ep_mul_basic(r, p, k);
				}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
		ep_free(v);
	}
}
