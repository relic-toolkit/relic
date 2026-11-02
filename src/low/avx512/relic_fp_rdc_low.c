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
 * Implementation of the low-level prime field modular reduction and base
 * extensions in a Residue Number System with AVX-512 IFMA.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

#define FP_RNS_VEC

/* The functions that are not residue-wise are the portable versions. */
#include "../rns/relic_fp_rdc_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

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

void fp_rdcn_low(dig_t *c, dig_t *a) {
	dig_t *const cs[1] = { c };
	const dig_t *const as[1] = { a };

	rns_vrdc(cs, as, 1);
}

/**
 * Reduces a batch of k values, for 1 <= k <= RNS_K, with the batch size known
 * at compile time in each case. The sizes above 4 are capped only to keep
 * unused code in bounds when RNS_K is 4.
 */
static void rns_vrdck(dig_t *const c[], const dig_t *const a[], int k) {
	switch (k) {
		case 1:
			rns_vrdc(c, a, 1);
			break;
		case 2:
			rns_vrdc(c, a, 2);
			break;
		case 3:
			rns_vrdc(c, a, 3);
			break;
		case 4:
			rns_vrdc(c, a, 4);
			break;
		case 5:
			rns_vrdc(c, a, RLC_MIN(5, RNS_K));
			break;
		case 6:
			rns_vrdc(c, a, RLC_MIN(6, RNS_K));
			break;
		case 7:
			rns_vrdc(c, a, RLC_MIN(7, RNS_K));
			break;
		case 8:
			rns_vrdc(c, a, RLC_MIN(8, RNS_K));
			break;
	}
}

void fp_rdcv_low(dig_t *const c[], dig_t *const a[], int n) {
	const dig_t *const *b = (const dig_t *const *)a;
	int i = 0;

	for (; n - i > RNS_K + 3; i += RNS_K) {
		rns_vrdc(c + i, b + i, RNS_K);
	}
	/* A few values beyond a full batch go in two batches of about half, as
	 * small batches cost more per value. */
	if (n - i > RNS_K) {
		rns_vrdck(c + i, b + i, (n - i) / 2);
		i += (n - i) / 2;
	}
	if (n - i > 0) {
		rns_vrdck(c + i, b + i, n - i);
	}
}

#endif /* FP_RDC == FP_RENUS */
