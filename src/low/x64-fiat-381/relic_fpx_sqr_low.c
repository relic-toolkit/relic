/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of the low-level extension field squaring functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

#define FP2_ASM

/* Fp3 and Fp12 are the portable versions. */
#include "../easy/relic_fpx_sqr_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#include "bls12_381_q2_64.c"

void fp2_sqrn_low(dv2_t c, const fp2_t a) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

	/* t0 = (a0 + a1). */
#ifdef RLC_FP_ROOM
	/* if we have room for carries, we can avoid reductions here. */
	fp_addn_low(t0, a[0], a[1]);
#else
	fp_addm_low(t0, a[0], a[1]);
#endif
	/* t1 = (a0 - a1). */
	fp_subm_low(t1, a[0], a[1]);

#ifdef FP_QNRES

#ifdef RLC_FP_ROOM
	fp_dbln_low(t2, a[0]);
#else
	fp_dblm_low(t2, a[0]);
#endif
	/* c1 = 2 * a0 * a1. */
	fp_muln_low(c[1], t2, a[1]);
	/* c_0 = a_0^2 + a_1^2 * u^2. */
	fp_muln_low(c[0], t0, t1);

#else /* !FP_QNRES */

	if (fp_prime_get_qnr() == -1) {
		/* t2 = 2 * a0. */
		fp_dbl(t2, a[0]);
		/* c1 = 2 * a0 * a1. */
		fp_muln_low(c[1], t2, a[1]);
		/* c0 = a0^2 + a_1^2 * u^2. */
		fp_muln_low(c[0], t0, t1);
	} else {
		/* t1 = a0 + a1 * u^2, with u^2 < 0. */
		fp_mul_dig(t2, a[1], -fp_prime_get_qnr());
		fp_subm_low(t1, a[0], t2);
		/* c1 = a0 * a1. */
		fp_muln_low(c[1], a[0], a[1]);
		/* c0 = a0^2 + b_0^2 * u^2. */
		fp_muln_low(c[0], t0, t1);

		/* c0 += (|u^2| - 1) * a0 * a1. */
		fp2_mul1_low(t2, c[1], -fp_prime_get_qnr() - 1);
		fp_addc_low(c[0], c[0], t2);
#ifdef RLC_FP_ROOM
		/* c1 = 2 * a0 * a1. */
		fp_addd_low(c[1], c[1], c[1]);
#else
		/* c1 = 2 * a0 * a1. */
		fp_addc_low(c[1], c[1], c[1]);
#endif
	}
#endif
	/* c = c0 + c1 * u. */
}

void fp2_sqrm_low(fp2_t c, const fp2_t a) {
	fiat_bls12_381_q2_squareFp2(c[0], c[1], a[0], a[1]);
}
