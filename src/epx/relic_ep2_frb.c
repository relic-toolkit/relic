/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of frobenius action on prime elliptic curves over
 * quadratic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep2_frb(ep2_t r, const ep2_t p, int i) {
	if (ep2_curve_opt_a() == RLC_ZERO) {
		ctx_t *ctx = core_get();

		ep2_copy(r, p);
		for (; i > 0; i--) {
			fp2_frb(r->x, r->x, 1);
			fp2_frb(r->y, r->y, 1);
			fp2_frb(r->z, r->z, 1);
			fp2_mul(r->x, r->x, ctx->ep2_frb[0]);
			fp2_mul(r->y, r->y, ctx->ep2_frb[1]);
		}
	} else {
		bn_t t;

		bn_null(t);

		RLC_TRY {
			bn_new(t);
			
			/* Can we do faster than this? */
			fp_prime_get_par(t);
			for (; i > 0; i--) {
				ep2_mul_basic(r, p, t);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_NO_MEMORY);
		} RLC_FINALLY {
			bn_free(t);
		}
	}
}
