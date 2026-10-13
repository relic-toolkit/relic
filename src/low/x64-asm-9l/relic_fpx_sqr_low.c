/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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

/*
 * The assembly reads both coordinates from one contiguous vector, which only
 * automatic allocation guarantees.
 */
#if defined(FP_QNRES) && ALLOC == AUTO
#define FP2_ASM
#endif

/* Fp3, and Fp2 when it is not in assembly, are the portable versions. */
#include "../easy/relic_fpx_sqr_low.c"

#ifdef FP2_ASM

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_sqrn_c0(fp_t c, const fp2_t a);
void fp2_sqrn_c1(fp_t c, const fp2_t a);

void fp2_sqrn_low(dv2_t c, const fp2_t a) {
	fp2_sqrn_c0(c[0], a);
	fp2_sqrn_c1(c[1], a);
}

void fp2_sqrm_c0(fp_t c, const fp2_t a);
void fp2_sqrm_c1(fp_t c, const fp2_t a);

void fp2_sqrm_low(fp2_t c, const fp2_t a) {
	rlc_align dig_t t[RLC_FP_DIGS];

	fp2_sqrm_c0(t, a);
	fp2_sqrm_c1(c[1], a);
	fp_copy(c[0], t);
}

#endif
