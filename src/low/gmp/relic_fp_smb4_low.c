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
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level quartic residue symbol.
 *
 * @ingroup fp
 */

#include "relic_bn.h"
#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb4_low(const dig_t *a) {
	bn_st e;
	dig_t t[RLC_FP_DIGS], u[RLC_FP_DIGS];
	int r = -1, q = (fp_prime_get_mod8() % 4 == 3);

	/* By Euler's criterion, a^((p - 1)/4) = z^k, and 0 for zero, or
	 * a^((p - 1)/2) = (-1)^(k/2) for p = 3 mod 4. */
	bn_make(&e, RLC_FP_DIGS);
	e.used = RLC_FP_DIGS;
	dv_copy(e.dp, fp_prime_get(), RLC_FP_DIGS);
	bn_rsh(&e, &e, 2 - q);
#if RLC_AUTO == RLC_ALLOC
	fp_exp(t, a, &e);
#else
	fp_exp(t, (const fp_t)a, &e);
#endif
	/* The k of the only one of 1, z, -1 and -z that is equal to the power,
	 * from dv_equ_sec(), which is 0 if equal and RLC_NE = 2 otherwise, on
	 * the reduced values, as some backends keep elements below a multiple of
	 * p. */
	fp_norm(t, t);
	fp_set_dig(u, 1);
	fp_norm(u, u);
	r += 1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1);
	fp_neg(u, u);
	fp_norm(u, u);
	r += 3 * (1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1));
	if (!q) {
		dv_copy(u, fp_prime_get_qrt(), RLC_FP_DIGS);
		fp_norm(u, u);
		r += 2 * (1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1));
		fp_neg(u, u);
		fp_norm(u, u);
		r += 4 * (1 - (dv_equ_sec(t, u, RLC_FP_DIGS) >> 1));
	}

	bn_clean(&e);

	return r;
}
