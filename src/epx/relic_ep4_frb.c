/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of frobenius action on prime elliptic curves over a quartic
 * extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep4_frb(ep4_t r, const ep4_t p, int i) {
	if (ep4_curve_is_twist()) {
		ep4_copy(r, p);
		for (; i > 0; i--) {
			fp4_frb(r->x, r->x, 1);
			fp4_frb(r->y, r->y, 1);
			fp4_frb(r->z, r->z, 1);
			fp4_mul_frb(r->x, r->x, 1, 2);
			fp4_mul_frb(r->y, r->y, 1, 3);
		}
	} else {
		ep4_copy(r, p);
		for (; i > 0; i--) {
			fp4_frb(r->x, r->x, 2);
			fp4_frb(r->y, r->y, 2);
			fp4_frb(r->z, r->z, 2);
			fp2_mul(r->x[0], r->x[0], core_get()->fp4_p1);
			fp2_mul(r->x[1], r->x[1], core_get()->fp4_p1);
			fp2_mul_art(r->y[0], r->y[0]);
			fp2_mul_art(r->y[1], r->y[1]);
		}
	}
}