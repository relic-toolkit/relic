/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * or <https://www.apache.org/licenses/>
 */

/**
 * @file
 *
 * Implementation of low-level modular exponentiation.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_dv.h"
#include "relic_util.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mxpn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb,
		const dig_t *m, size_t sm, dig_t u) {
	mp_bitcnt_t enb = (mp_bitcnt_t)sb * RLC_DIG;
	dig_t *s = RLC_ALLOCA(dig_t, sm + 1);
	dig_t *t = RLC_ALLOCA(dig_t, mpn_sec_powm_itch(sm + 1, enb, sm));
	(void)u;

	/* GMP needs a positive base, so pass a + m, which is congruent to a. */
	dv_zero(s, sm);
	dv_copy(s, a, RLC_MIN(sa, sm));
	s[sm] = mpn_add_n((mp_ptr)s, (mp_srcptr)s, (mp_srcptr)m, sm);

	mpn_sec_powm((mp_ptr)c, (mp_srcptr)s, sm + 1, (mp_srcptr)b, enb,
		(mp_srcptr)m, sm, (mp_ptr)t);
	RLC_FREE(t);
	RLC_FREE(s);
}
