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
 * Implementation of the low-level binary field bit shifting functions.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_fb.h"
#include "relic_util.h"
#include "relic_fb_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fb_lsh1_low(dig_t *c, const dig_t *a) {
	return mpn_lshift((mp_ptr)c, (mp_srcptr)a, RLC_FB_DIGS, 1);
}

dig_t fb_lshb_low(dig_t *c, const dig_t *a, uint_t bits) {
	return mpn_lshift((mp_ptr)c, (mp_srcptr)a, RLC_FB_DIGS, bits);
}

dig_t fb_rsh1_low(dig_t *c, const dig_t *a) {
	return mpn_rshift((mp_ptr)c, (mp_srcptr)a, RLC_FB_DIGS, 1);
}

dig_t fb_rshb_low(dig_t *c, const dig_t *a, uint_t bits) {
	return mpn_rshift((mp_ptr)c, (mp_srcptr)a, RLC_FB_DIGS, bits);
}

dig_t fb_lsha_low(dig_t *c, const dig_t *a, uint_t bits, size_t size) {
	int i, j;
	dig_t b1, b2;

	j = RLC_DIG - bits;
	b1 = a[0];
	c[0] ^= (b1 << bits);
	if (size == RLC_FB_DIGS) {
		for (i = 1; i < RLC_FB_DIGS; i++) {
			b2 = a[i];
			c[i] ^= ((b2 << bits) | (b1 >> j));
			b1 = b2;
		}
	} else {
		for (i = 1; i < size; i++) {
			b2 = a[i];
			c[i] ^= ((b2 << bits) | (b1 >> j));
			b1 = b2;
		}
	}
	return (b1 >> j);
}
