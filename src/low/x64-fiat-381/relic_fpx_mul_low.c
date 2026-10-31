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
 * Implementation of the low-level extension field multiplication functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

#define FP2_ASM

/* Fp3, Fp12 and the multiplication by a digit are the portable versions. */
#include "../easy/relic_fpx_mul_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#include "bls12_381_q2_64.c"

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

	/* Karatsuba algorithm. */

	/* t0 = a_0 + a_1, t1 = b_0 + b_1. */
#ifdef RLC_FP_ROOM
	fp_addn_low(t0, a[0], a[1]);
	fp_addn_low(t1, b[0], b[1]);
#else
	fp_addm_low(t0, a[0], a[1]);
	fp_addm_low(t1, b[0], b[1]);
#endif
	/* c_0 = a_0 * b_0, c_1 = a_1 * b_1. */
	fp_muln_low(c[0], a[0], b[0]);
	fp_muln_low(c[1], a[1], b[1]);
	/* t2 = (a_0 + a_1) * (b_0 + b_1). */
	fp_muln_low(t2, t0, t1);

	/* t0 = (a_0 * b_0) + (a_1 * b_1). */
#ifdef RLC_FP_ROOM
	fp_addd_low(t0, c[0], c[1]);
#else
	fp_addc_low(t0, c[0], c[1]);
#endif

	/* c_0 = (a_0 * b_0) + u^2 * (a_1 * b_1), with u^2 < 0. */
#ifndef FP_QNRES
	if (fp_prime_get_qnr() != -1) {
		/* t1 = |u^2| * (a_1 * b_1). */
		fp2_mul1_low(t1, c[1], -fp_prime_get_qnr());
		fp_subc_low(c[0], c[0], t1);
	} else {
		fp_subc_low(c[0], c[0], c[1]);
	}
#else
	fp_subc_low(c[0], c[0], c[1]);
#endif

	/* c_1 = t2 - t0. */
#ifdef RLC_FP_ROOM
	fp_subd_low(c[1], t2, t0);
#else
	fp_subc_low(c[1], t2, t0);
#endif
}

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	fiat_bls12_381_q2_mulFp2(c[0], c[1], a[0], a[1], b[0], b[1]);
}
