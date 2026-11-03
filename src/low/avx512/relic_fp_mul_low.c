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
 * Implementation of the low-level prime field multiplication in a Residue
 * Number System with AVX-512 IFMA.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

#define FP_RNS_VEC

/* The functions that are not residue-wise are the portable versions. */
#include "../rns/relic_fp_mul_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_muln_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vmul(RNS_V(a), RNS_V(b), _vm, _vi));
}

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	rlc_align dig_t t[RLC_FP_LEN];
	dig_t *const cs[1] = { c };
	const dig_t *const ts[1] = { t };

	/* The reduction is inlined, so the products need not leave registers. */
	fp_muln_low(t, a, b);
	rns_vrdc(cs, ts, 1);
}

#endif /* FP_RDC == FP_RENUS */
