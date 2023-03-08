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
 * Implementation of point multiplication of a prime elliptic curve over a
 * quadratic extension by the curve cofactor.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep3_mul_cof_k18(ep3_t r, const ep3_t p) {
	ep3_t tx1, tx2, tx3, t0, t1, t2, t3, t4, t5;
	bn_t x;

	ep3_null(tx1);
	ep3_null(tx2);
	ep3_null(tx3);
	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	ep3_null(t5);
	bn_null(x);

	RLC_TRY {
		ep3_new(tx1);
		ep3_new(tx2);
		ep3_new(tx3);
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		ep3_new(t5);
		bn_new(x);

		fp_prime_get_par(x);

		ep3_mul_basic(tx1, p, x);
		ep3_mul_basic(tx2, tx1, x);
		ep3_mul_basic(tx3, tx2, x);

		ep3_frb(t1, tx1, 2);
		ep3_frb(t2, t1, 3);
		ep3_add(t2, t2, tx1);
		ep3_frb(t3, t1, 1);
		ep3_neg(t1, t1);

		ep3_frb(t4, tx2, 1);
		ep3_add(t3, t3, t4);
		ep3_frb(t4, t4, 1);
		ep3_sub(t3, t3, t4);

		ep3_frb(t4, p, 4);
		ep3_neg(t4, t4);

		ep3_frb(t5, p, 1);
		ep3_frb(tx1, t5, 2);
		ep3_add(t5, t5, tx1);
		ep3_frb(tx1, tx2, 4);
		ep3_sub(t5, t5, tx1);
		ep3_frb(tx2, tx1, 1);
		ep3_add(t5, t5, tx2);
		ep3_frb(tx3, tx3, 1);
		ep3_add(t5, t5, tx3);

		ep3_add(t1, t1, p);
		ep3_dbl(t0, p);
		ep3_add(t0, t0, t2);
		ep3_add(t0, t0, t1);
		ep3_add(t3, t3, t1);
		ep3_add(t4, t4, t0);
		ep3_add(t3, t3, t0);
		ep3_add(t4, t4, t3);
		ep3_add(t3, t3, t5);
		ep3_dbl(t4, t4);
		ep3_add(r, t4, t3);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(tx1);
		ep3_free(tx2);
		ep3_free(tx3);
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		ep3_free(t5);
		bn_free(x);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep3_mul_cof(ep3_t r, const ep3_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		switch (ep_curve_is_pairf()) {
			case EP_K18:
				ep3_mul_cof_k18(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep3_curve_get_cof(k);
				if (bn_bits(k) < RLC_DIG) {
					ep3_mul_dig(r, p, k->dp[0]);
				} else {
					ep3_mul_big(r, p, k);
				}
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
