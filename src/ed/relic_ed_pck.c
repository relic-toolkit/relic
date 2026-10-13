/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2017 RELIC Authors
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
 * Implementation of point compression on Edwards elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ed_pck(ed_t r, const ed_t p) {
	bn_t x;
	int b;

	bn_null(x);

	RLC_TRY {
		bn_new(x);

		/* Take the parity of x itself, out of the internal representation. */
		fp_prime_back(x, p->x);
		b = bn_get_bit(x, 0);
		fp_copy(r->y, p->y);
		fp_zero(r->x);
		fp_set_bit(r->x, 0, b);
		fp_set_dig(r->z, 1);
		r->coord = BASIC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
	}
}

int ed_upk(ed_t r, const ed_t p) {
	int result = 1;
	fp_t t, u;
	bn_t x;

	fp_null_all(t, u);
	bn_null(x);

	RLC_TRY {
		fp_new_all(t, u);
		bn_new(x);

		fp_copy(r->y, p->y);

		/* x = +/- sqrt((y^2 - 1) / (dy^2 - a)). */
		fp_sqr(t, p->y);
		fp_sub_dig(u, t, 1);
		fp_mul(t, t, core_get()->ed_d);
		fp_sub(t, t, core_get()->ed_a);
		fp_inv(t, t);
		fp_mul(u, u, t);
		result = fp_srt(u, u);

		/* Choose the root whose parity matches the compressed bit. */
		fp_prime_back(x, u);
		if (bn_get_bit(x, 0) != fp_get_bit(p->x, 0)) {
			fp_neg(u, u);
		}
		fp_copy(r->x, u);

#if ED_ADD == EXTND
		fp_mul(r->t, r->x, r->y);
#endif
		fp_set_dig(r->z, 1);
		r->coord = BASIC;
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free_all(t, u);
		bn_free(x);
	}
	return result;
}
