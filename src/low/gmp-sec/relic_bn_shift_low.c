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
 * Implementation of the low-level multiple precision bit shifting functions.
 *
 * @ingroup bn
 */

#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "relic_dv.h"
#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t bn_lsh1_low(dig_t *c, const dig_t *a, size_t size) {
	return mpn_lshift((mp_ptr)c, (mp_srcptr)a, size, 1);
}

dig_t bn_lshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits) {
	dig_t carry, *t = (dig_t *)RLC_ALLOCA(dig_t, size);
	carry = mpn_lshift((mp_ptr)t, (mp_srcptr)a, size, bits);
	dv_copy(c, a, size);
	dv_copy_sec(c, t, size, bits > 0);
	RLC_FREE(t);
	return RLC_SEL(0, carry, bits > 0);
}

dig_t bn_rsh1_low(dig_t *c, const dig_t *a, size_t size) {
	return mpn_rshift((mp_ptr)c, (mp_srcptr)a, size, 1);
}

dig_t bn_rshb_low(dig_t *c, const dig_t *a, size_t size, uint_t bits) {
	dig_t carry, *t = (dig_t *)RLC_ALLOCA(dig_t, size);
	carry = mpn_rshift((mp_ptr)t, (mp_srcptr)a, size, bits);
	dv_copy(c, a, size);
	dv_copy_sec(c, t, size, bits > 0);
	RLC_FREE(t);
	return RLC_SEL(0, carry, bits > 0);
}

dig_t bn_rshs_low(dig_t *c, const dig_t *a, size_t size, uint_t bits) {
	dig_t r, carry, shift, mask;

	/* Prepare the bit mask. */
	shift = (RLC_DIG - bits) % RLC_DIG;
	mask = RLC_MASK(bits);
	r = a[size - 1] & mask;
	c[size - 1] = (dis_t)a[size - 1] >> bits;
	carry = mpn_rshift((mp_ptr)c, (mp_srcptr)a, size - 1, bits);
	c[size - 2] |= (r << shift);
	return carry;
}
