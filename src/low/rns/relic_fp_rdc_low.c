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

void fp_rdcn_low(dig_t *c, dig_t *a) {
	ctx_t *ctx = core_get();
	const size_t n = RLC_FP_RNS, o = RLC_FP_RNSO;
	const dig_t *m = ctx->rns.m, *u = ctx->rns.u;
	dig_t q[RLC_FP_RNS], r[RLC_FP_RNS];

	/* xi_i of q = a * (-p^{-1}) mod M, in B, as plain residues. */
	for (size_t i = 0; i < n; i++) {
		q[i] = fp_rns_mul(a[i], ctx->rns.nq[i], m[i], u[i]);
	}
	/* q * p for q, or q + M, as a product in B'. */
	fp_rnsx_low(r, q, 1, 0);
	/* c = (a + q * p) / M in B', as a product carries 1 / M^2 there and an
	 * element 1 / M; and its xi_j for the exact extension. */
	for (size_t j = 0; j < n; j++) {
		c[o + j] = RLC_RNS_ADD(a[o + j], r[j], m[o + j]);
		q[j] = fp_rns_mul(c[o + j], ctx->rns.ib[o + j], m[o + j], u[o + j]);
	}
	/* c in B, exactly, since c < 3p is far below M'/2. */
	fp_rnsx_low(c, q, 0, 1);
}

#endif /* !FP_RNS_VEC */

#endif /* FP_RDC == FP_RENUS */
