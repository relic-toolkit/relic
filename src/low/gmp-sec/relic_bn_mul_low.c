/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2015 RELIC Authors
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
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t bn_mula_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
	dig_t u[size + 1], *t = RLC_ALLOCA(dig_t, mpn_sec_mul_itch(size, 1));
	mpn_sec_mul((mp_ptr)u, (mp_srcptr)a, size, (mp_srcptr)&digit, 1, (mp_ptr)t);
	return u[size] + mpn_add_n((mp_ptr)c, (mp_srcptr)c, (mp_srcptr)u, size);
}

dig_t bn_mul1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
	dig_t u[size + 1], *t = RLC_ALLOCA(dig_t, mpn_sec_mul_itch(size, 1));
	mpn_sec_mul((mp_ptr)u, (mp_srcptr)a, size, (mp_srcptr)&digit, 1, (mp_ptr)t);
	mpn_copyd((mp_ptr)c, (mp_srcptr)u, size);
	return u[size];
}

dig_t bn_muls_low(dig_t *c, const dig_t *a, dig_t sa, dis_t digit, size_t size) {
	dig_t carry, sign, sd = digit >> (RLC_DIG - 1);

	sa = -sa;
	sign = sa ^ sd;
	digit = (digit ^ sd) - sd;

	carry = bn_mul1_low(c, a, (dig_t)digit, size);
	for (size_t i = 0; i < size; i++) {
		c[i] = c[i] ^ sign;
	}
	return (carry ^ sign) + bn_add1_low(c, c, -sign, size);
}

void bn_muln_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
	dig_t *t = RLC_ALLOCA(dig_t, mpn_sec_mul_itch(size, size));
	mpn_sec_mul((mp_ptr)c, (mp_srcptr)a, size, (mp_srcptr)b, size, (mp_ptr)t);
	RLC_FREE(t);
}

void bn_muld_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb,
		uint_t low, uint_t high) {
	(void)low;
	(void)high;
	dig_t *t = RLC_ALLOCA(dig_t, mpn_sec_mul_itch(sa, sb));
	mpn_sec_mul((mp_ptr)c, (mp_srcptr)a, sa, (mp_srcptr)b, sb, (mp_ptr)t);
	RLC_FREE(t);
}
