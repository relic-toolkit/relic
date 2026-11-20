/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the low-level multiple precision integer modular reduction
 * functions.
 *
 * @ingroup bn
 */

#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_dv.h"
#include "relic_util.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_modn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *m, size_t sm,
		dig_t u) {
	/* The double width of the modulus, which with dynamic allocation may
	 * exceed the precision. */
	dig_t *t = RLC_ALLOCA(dig_t, 2 * sm), r;

	dv_copy(t, a, sa);
	dv_zero(t + sa, 2 * sm - sa);
	/* Row by row, cancel the lowest digit with a multiple of m, keeping the
	 * carry of the row in the digit that it cancels, which no later row
	 * touches, so that fewer values stay live than in a column-wise pass. */
	for (size_t i = 0; i < sm; i++) {
		r = RLC_MLO_DIG(t[i], u);
		t[i] = bn_mula_low(t + i, m, r, sm);
	}
	/* Add the carries to the high half, at the columns where they belong. */
	if (bn_addn_low(c, t + sm, t, sm)) {
		bn_subn_low(c, c, m, sm);
	}
	RLC_FREE(t);
}
