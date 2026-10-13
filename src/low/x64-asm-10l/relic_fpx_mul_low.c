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
 * Implementation of the low-level extension field multiplication functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
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
#include "../easy/relic_fpx_mul_low.c"

#ifdef FP2_ASM

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_muln_c0(dv_t c, const fp2_t a, const fp2_t b);
void fp2_muln_c1(dv_t c, const fp2_t a, const fp2_t b);

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS];

    fp2_muln_c0(t0, a, b);
    fp2_muln_c1(t1, a, b);
    dv_copy(c[0], t0, 2 * RLC_FP_DIGS);
    dv_copy(c[1], t1, 2 * RLC_FP_DIGS);
}

/*
 * The real part is accumulated as a signed value of RLC_FP_DIGS digits, so
 * results in (-p, 2p) must fit in (-2^639, 2^639), which needs 2p < 2^639.
 */
void fp2_mulm_c0(dv_t c, const fp2_t a, const fp2_t b);
void fp2_mulm_c1(dv_t c, const fp2_t a, const fp2_t b);

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
    rlc_align dig_t t0[RLC_FP_DIGS];

    fp2_mulm_c0(t0, a, b);
    fp2_mulm_c1(c[1], a, b);
    fp_copy(c[0], t0);
}

#endif
