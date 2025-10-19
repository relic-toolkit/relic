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
 * Implementation of the low-level multiple precision integer modular reduction
 * functions.
 *
 * @ingroup bn
 */

#include <gmp.h>
#include <string.h>

#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_util.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_modn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *m, size_t sm,
		dig_t u) {
	dig_t *s = RLC_ALLOCA(dig_t, mpn_sec_mul_itch(sm, 1));
	dig_t r, *tc = c, t[sm + 1];

	mpn_copyd((mp_ptr)c, (mp_srcptr)a, sa);
	for (int i = 0; i < sm; i++, tc++) {
		r = (dig_t)(*tc * u);
		mpn_sec_mul((mp_ptr)t, (mp_srcptr)m, sm, (mp_srcptr)&r, 1, (mp_ptr)s);
		*tc = t[sm] + mpn_add_n((mp_ptr)tc, (mp_srcptr)tc, (mp_srcptr)t, sm);
	}
	mpn_cnd_sub_n(mpn_add_n((mp_ptr)c, (mp_srcptr)c, (mp_srcptr)tc, sm),
		(mp_ptr)c, (mp_srcptr)c, (mp_srcptr)m, sm);
	RLC_FREE(s);
}
