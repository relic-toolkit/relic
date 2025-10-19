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
 * Implementation of the low-level multiple precision addition and subtraction
 * functions.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_dv.h"
#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_core.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t bn_add1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
	dig_t *t = (dig_t *)RLC_ALLOCA(dig_t, mpn_sec_add_1_itch(size));
	dig_t r = mpn_sec_add_1((mp_ptr)c, (mp_srcptr)a, size, digit, (mp_ptr)t);
	RLC_FREE(t);
	return r;
}

dig_t bn_addn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
	return mpn_add_n((mp_ptr)c, (mp_srcptr)a, (mp_srcptr)b, size);
}

dig_t bn_sub1_low(dig_t *c, const dig_t *a, dig_t digit, size_t size) {
	dig_t *t = (dig_t *)RLC_ALLOCA(dig_t, mpn_sec_sub_1_itch(size));
	dig_t r = mpn_sec_sub_1((mp_ptr)c, (mp_srcptr)a, size, digit, (mp_ptr)t);
	RLC_FREE(t);
	return r;
}

dig_t bn_subn_low(dig_t *c, const dig_t *a, const dig_t *b, size_t size) {
	return mpn_sub_n((mp_ptr)c, (mp_srcptr)a, (mp_srcptr)b, size);
}

dig_t bn_negs_low(dig_t *c, const dig_t *a, dig_t sa, size_t size) {
	dig_t carry, *t = (dig_t *)RLC_ALLOCA(dig_t, size);
	mpn_com((mp_ptr)t, (mp_srcptr)a, size);
	carry = bn_add1_low(t, t, sa, size);
	dv_copy(c, a, size);
	dv_copy_sec(c, t, size, sa);
	RLC_FREE(t);
	return carry;
}