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
 * Implementation of the low-level prime field modular reduction in a Residue
 * Number System.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m) {
	(void)c;
	(void)a;
	(void)m;
	/* There is no special-form reduction for elements in RNS. */
	RLC_THROW(ERR_NO_VALID);
}

/* Defining FP_RNS_VEC leaves out the residue-wise functions, so that a backend
 * can replace them with vectorized ones. */
#ifndef FP_RNS_VEC

void fp_rnsx_low(dig_t *r, const dig_t *xi, int b, int exact, const rns_st *c) {
	rns_extm_imp(r, xi, b, exact, c, RLC_FP_RNS, RLC_FP_RNSO);
}

void fp_rdcn_low(dig_t *c, dig_t *a) {
	dig_t q[RLC_FP_RNS], r[RLC_FP_RNS];

	rns_rdcn_imp(c, a, core_get()->prime_rns, RLC_FP_RNS, RLC_FP_RNSO, q, r,
			fp_rnsx_low);
}

void fp_rdcv_low(dig_t *const c[], dig_t *const a[], int n) {
	for (int i = 0; i < n; i++) {
		fp_rdcn_low(c[i], a[i]);
	}
}

#endif /* !FP_RNS_VEC */

#endif /* FP_RDC == FP_RENUS */
