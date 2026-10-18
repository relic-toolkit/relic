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
 * automatic allocation guarantees. It has u^2 = -1 with FP_QNRES, and u^2 = -5
 * for the 544-bit prime otherwise.
 */
#if (defined(FP_QNRES) || FP_PRIME == 544) && RLC_ALLOC == RLC_AUTO
#define FP2_ASM
#endif

/* Fp3, and Fp2 when it is not in assembly, are the portable versions. */
#include "../easy/relic_fpx_mul_low.c"

#ifdef FP2_ASM

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/* The assembly finds c[1] of a dv2_t at RLC_DV_STRIDE bytes from c[0]. */
typedef char rlc_dv_stride_check[sizeof(dv_t) == RLC_DV_STRIDE ? 1 : -1];

#endif
