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
 * Implementation of the multiple precision integer arithmetic multiplication
 * functions.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t bn_mula_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
	dig_t t[size + 1], scratch[mpn_sec_mul_itch(size, 1)];
	mpn_sec_mul(t, a, size, &digit, 1, scratch);
	return t[size] + mpn_add_n(c, c, t, size);
}

dig_t bn_mul1_low(dig_t *c, const dig_t *a, dig_t digit, int size) {
	dig_t t[size + 1], scratch[mpn_sec_mul_itch(size, 1)];
	mpn_sec_mul(t, a, size, &digit, 1, scratch);
	mpn_copyd(c, t, size);
	return t[size];
}

void bn_muln_low(dig_t *c, const dig_t *a, const dig_t *b, int size) {
	dig_t scratch[mpn_sec_mul_itch(size, size)];
	mpn_sec_mul(c, a, size, b, size, scratch);
}

void bn_muld_low(dig_t *c, const dig_t *a, int sa, const dig_t *b, int sb,
		int low, int high) {
	(void)low;
	(void)high;
	dig_t scratch[mpn_sec_mul_itch(sa, sb)];
	mpn_sec_mul(c, a, sa, b, sb, scratch);
}
