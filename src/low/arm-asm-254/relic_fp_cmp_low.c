/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the low-level prime field comparison functions.
 *
 * @version $Id: relic_fp_cmp_low.c 1108 2012-03-11 21:45:01Z dfaranha $
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_cmp1_low(dig_t a, dig_t b) {
	if (a > b)
		return CMP_GT;
	if (a < b)
		return CMP_LT;
	return CMP_EQ;
}

/*
int fp_cmpn_low(dig_t *a, dig_t *b) {
	int i, r;

	a += (FP_DIGS - 1);
	b += (FP_DIGS - 1);

	r = CMP_EQ;
	for (i = 0; i < FP_DIGS; i++, --a, --b) {
		if (*a != *b && r == CMP_EQ) {
			r = (*a > *b ? CMP_GT : CMP_LT);
		}
	}
	return r;
}
*/
