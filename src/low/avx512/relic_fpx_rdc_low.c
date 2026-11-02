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
 * Implementation of the low-level extension field modular reduction in a
 * Residue Number System with AVX-512 IFMA, reducing the components together.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fp_rns_avx.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** Number of extension field elements whose components are gathered at once. */
#define RNS_SIM		8

#if RLC_ALLOC == RLC_AUTO

/**
 * Reduces K values that lie at fixed strides, as rns_vrdc() does: the pointers
 * are computed from the strides, so they need no arrays in memory once the
 * reduction is inlined.
 *
 * @param[out] c			- the first result.
 * @param[in] s				- the stride of the results, in digits.
 * @param[in] a				- the first value to reduce.
 * @param[in] t				- the stride of the values, in digits.
 * @param[in] K				- the number of values, up to RNS_K.
 */
rlc_inline void rns_vrdcs(dig_t *c, size_t s, const dig_t *a, size_t t,
		const int K) {
	dig_t *u[RNS_K];
	const dig_t *w[RNS_K];

	for (int j = 0; j < K; j++) {
		u[j] = c + j * s;
		w[j] = a + j * t;
	}
	rns_vrdc(u, w, K);
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_rdcn_low(fp2_t c, dv2_t a) {
	dig_t *const cs[2] = { c[0], c[1] };
	const dig_t *const as[2] = { a[0], a[1] };

	rns_vrdc(cs, as, 2);
}

void fp3_rdcn_low(fp3_t c, dv3_t a) {
	dig_t *const cs[2] = { c[0], c[1] }, *const cs1[1] = { c[2] };
	const dig_t *const as[2] = { a[0], a[1] }, *const as1[1] = { a[2] };

	rns_vrdc(cs, as, 2);
	rns_vrdc(cs1, as1, 1);
}

void fp2_rdcv_low(fp2_t *c, dv2_t *a, int n) {
	dig_t *cs[2 * RNS_SIM];
	dig_t *as[2 * RNS_SIM];

#if RLC_ALLOC == RLC_AUTO
	/* The coefficients of an element of Fp^12 are contiguous, so they are
	 * reduced from strides, in two batches of 6 when they fit, which are
	 * faster than 8 and 4. */
	if (n == 6) {
		const size_t s = sizeof(fp_t) / sizeof(dig_t);
		const size_t t = sizeof(dv_t) / sizeof(dig_t);
		dig_t *x = c[0][0];
		const dig_t *y = a[0][0];

		if (RNS_K >= 6) {
			rns_vrdcs(x, s, y, t, RLC_MIN(6, RNS_K));
			rns_vrdcs(x + 6 * s, s, y + 6 * t, t, RLC_MIN(6, RNS_K));
		} else {
			rns_vrdcs(x, s, y, t, 4);
			rns_vrdcs(x + 4 * s, s, y + 4 * t, t, 4);
			rns_vrdcs(x + 8 * s, s, y + 8 * t, t, 4);
		}
		return;
	}
#endif

	for (int i = 0; i < n; i += RNS_SIM) {
		int m = RLC_MIN(RNS_SIM, n - i);
		for (int j = 0; j < m; j++) {
			cs[2 * j] = c[i + j][0];
			cs[2 * j + 1] = c[i + j][1];
			as[2 * j] = a[i + j][0];
			as[2 * j + 1] = a[i + j][1];
		}
		fp_rdcv_low(cs, as, 2 * m);
	}
}

void fp3_rdcv_low(fp3_t *c, dv3_t *a, int n) {
	dig_t *cs[3 * RNS_SIM];
	dig_t *as[3 * RNS_SIM];

	for (int i = 0; i < n; i += RNS_SIM) {
		int m = RLC_MIN(RNS_SIM, n - i);
		for (int j = 0; j < m; j++) {
			for (int k = 0; k < 3; k++) {
				cs[3 * j + k] = c[i + j][k];
				as[3 * j + k] = a[i + j][k];
			}
		}
		fp_rdcv_low(cs, as, 3 * m);
	}
}
