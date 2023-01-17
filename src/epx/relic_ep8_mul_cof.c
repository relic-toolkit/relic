/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of point multiplication of a prime elliptic curve over an
 * octic extension by the curve cofactor.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep8_mul_cof(ep8_t r, const ep8_t p) {
	bn_t z;
	ep8_t t0, t1, t2, t3, t4, t5, t6, t7;

	ep8_null(t0);
	ep8_null(t1);
	ep8_null(t2);
	ep8_null(t3);
	ep8_null(t4);
	ep8_null(t5);
	ep8_null(t6);
	ep8_null(t7);
	bn_null(z);

	RLC_TRY {
		bn_new(z);
		ep8_new(t0);
		ep8_new(t1);
		ep8_new(t2);
		ep8_new(t3);

		fp_prime_get_par(z);

		ep8_mul_basic(t0, p, z);
		ep8_mul_basic(t1, t0, z);
		ep8_mul_basic(t2, t1, z);
		ep8_mul_basic(t3, t2, z);
		ep8_mul_basic(t4, t3, z);
		ep8_mul_basic(t5, t4, z);
		ep8_mul_basic(t6, t5, z);
		ep8_mul_basic(t7, t6, z);

		ep8_sub(t7, t7, t6);
		ep8_sub(t7, t7, p);

		ep8_sub(t6, t6, t5);
		ep8_frb(t6, t6, 1);

		ep8_sub(t5, t5, t4);
		ep8_frb(t5, t5, 2);

		ep8_sub(t4, t4, t3);
		ep8_frb(t4, t4, 3);

		ep8_sub(t3, t3, t2);
		ep8_frb(t3, t3, 4);

		ep8_sub(t2, t2, t1);
		ep8_frb(t2, t2, 5);

		ep8_sub(t1, t1, t0);
		ep8_frb(t1, t1, 6);

		ep8_sub(t0, t0, p);
		ep8_frb(t0, t0, 7);

		ep8_dbl(r, p);
		ep8_frb(r, r, 8);
		ep8_add(r, r, t0);
		ep8_add(r, r, t1);
		ep8_add(r, r, t2);
		ep8_add(r, r, t3);
		ep8_add(r, r, t4);
		ep8_add(r, r, t5);
		ep8_add(r, r, t6);
		ep8_add(r, r, t7);

		ep8_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t0);
		ep8_free(t1);
		ep8_free(t2);
		ep8_free(t3);
		ep8_free(t4);
		ep8_free(t5);
		ep8_free(t6);
		ep8_free(t7);
		bn_free(z);
	}
}
