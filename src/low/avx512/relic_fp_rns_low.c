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
 * Implementation of the low-level prime field base extensions in a Residue
 * Number System with AVX-512 IFMA.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rnsi_low(dig_t *c, const dig_t *a) {
	ctx_t *ctx = core_get();
	const __m512i z = _mm512_setzero_si512();
	/* Each digit times a weight at most m has its top bits below m, so the
	 * sum of all is at most (RLC_FP_RNS_DIGS + 1) * m once reduced. */
	const int s = rns_halvings(4 * (RLC_FP_RNS_DIGS + 1));
	__m512i w[RLC_FP_RNS_DIGS];

	for (size_t k = 0; k < RLC_FP_RNS_DIGS; k++) {
		size_t j = k * RLC_RNS_DIG / RLC_DIG, b = k * RLC_RNS_DIG % RLC_DIG;
		dig_t x = a[j] >> b;

		if (b + RLC_RNS_DIG > RLC_DIG && j + 1 < RLC_FP_DIGS) {
			x |= a[j + 1] << (RLC_DIG - b);
		}
		w[k] = _mm512_set1_epi64(x & RLC_RNS_MASK);
	}
	for (size_t i = 0; i < RNS_NE; i++) {
		__m512i l = z, h = z, m = rns_load(ctx->rns.m, i);

		for (size_t k = 0; k < RLC_FP_RNS_DIGS; k++) {
			__m512i y = rns_load(ctx->rns.pw[k], i);
			l = _mm512_madd52lo_epu64(l, w[k], y);
			h = _mm512_madd52hi_epu64(h, w[k], y);
		}
		rns_store(c, i, rns_vpeel(rns_vmon(l, h, m, rns_load(ctx->rns.iv, i)),
				m, s));
	}
}

void fp_rnsx_low(dig_t *r, const dig_t *xi, int b, int exact) {
	const size_t n = RLC_FP_RNS;
	__m512i x[1][RNS_NB], v[1][RNS_NB];
	size_t l;

	/* Only as many residues as each base has are read and written. */
	for (size_t k = 0; k < RNS_NB; k++) {
		l = (n > 8 * k ? n - 8 * k : 0);
		x[0][k] = _mm512_maskz_loadu_epi64(l >= 8 ? 0xFF :
				(__mmask8)((1 << l) - 1), xi + 8 * k);
	}
	if (b) {
		rns_vext(v, x, 1, 1, exact, 1);
	} else {
		rns_vext(v, x, 1, 0, exact, 1);
	}
	for (size_t k = 0; 8 * k < n; k++) {
		l = n - 8 * k;
		_mm512_mask_storeu_epi64(r + 8 * k, l >= 8 ? 0xFF :
				(__mmask8)((1 << l) - 1), v[0][k]);
	}
}

#endif /* FP_RDC == FP_RENUS */
