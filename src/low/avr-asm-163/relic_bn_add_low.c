/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2011 RELIC Authors
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
 * Implementation of the low-level multiple precision addition functions.
 *
 * @ingroup bn
 */

#include "relic_bn.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t bn_sneg_low(dig_t *c, const dig_t *a, dig_t sa, size_t size) {
	dig_t carry = sa & 1;

	sa = -sa;
	for (size_t i = 0; i < size; i++) {
		c[i] = (a[i] ^ sa) + carry;
		carry = (c[i] < carry);
	}
	return carry;
}
