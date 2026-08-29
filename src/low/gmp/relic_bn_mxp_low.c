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
#include "relic_util.h"
#include "relic_alloc.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

mp_size_t __gmpn_binvert_itch (mp_size_t);

/*
 * The routine mpz_powm reduces with is not part of the public interface and is
 * not declared in gmp.h, though it is exported. It is declared here.
 */
extern void __gmpn_powm(mp_limb_t *rp, const mp_limb_t *bp, mp_size_t bn,
		const mp_limb_t *ep, mp_size_t en, const mp_limb_t *mp, mp_size_t n,
		mp_limb_t *tp);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

size_t bn_mxpn_itch_low(size_t sm) {
	/*
	 * Room for the window table at the largest window the routine uses, plus
	 * the accumulator, the double width product and the reduction.
	 */
	return (sm << 5) + 8 * sm + 32;
}

void bn_mxpn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb,
		const dig_t *m, size_t sm, dig_t u) {
	dig_t *t = RLC_ALLOCA(dig_t, RLC_MAX(__gmpn_binvert_itch(sm), 2 * sm));
	(void)u;

	__gmpn_powm((mp_limb_t *)c, (const mp_limb_t *)a, (mp_size_t)sa,
			(const mp_limb_t *)b, (mp_size_t)sb, (const mp_limb_t *)m,
			(mp_size_t)sm, (mp_limb_t *)t);
	RLC_FREE(t);
}