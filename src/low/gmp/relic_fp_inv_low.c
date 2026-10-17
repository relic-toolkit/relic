/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of the low-level inversion functions.
 *
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_invm_low(dig_t *c, const dig_t *a) {
	mp_size_t cn;
	rlc_align dig_t s[RLC_FP_DIGS], t[2 * RLC_FP_DIGS], u[RLC_FP_DIGS + 1];
	/* RLC_GMP needs one more limb than the modulus for the cofactor. */
	rlc_align dig_t w[RLC_FP_DIGS + 1];

#if FP_RDC == MONTY
	dv_zero(t + RLC_FP_DIGS, RLC_FP_DIGS);
	dv_copy(t, a, RLC_FP_DIGS);
	fp_rdcn_low(u, t);
#else
	fp_copy(u, a);
#endif

	dv_copy(s, fp_prime_get(), RLC_FP_DIGS);

	mpn_gcdext(t, w, &cn, u, RLC_FP_DIGS, s, RLC_FP_DIGS);
	if (cn < 0) {
		dv_zero(w - cn, RLC_FP_DIGS + cn);
		mpn_sub_n(c, fp_prime_get(), w, RLC_FP_DIGS);
	} else {
		dv_zero(w + cn, RLC_FP_DIGS - cn);
		dv_copy(c, w, RLC_FP_DIGS);
	}

#if FP_RDC == MONTY
	dv_zero(t, RLC_FP_DIGS);
	dv_copy(t + RLC_FP_DIGS, c, RLC_FP_DIGS);
	mpn_tdiv_qr(u, c, 0, t, 2 * RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);
#endif
}
