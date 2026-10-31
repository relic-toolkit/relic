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

/**
 * Reduces n prime field values, in batches of up to RNS_K.
 *
 * @param[out] c			- the results.
 * @param[in] a				- the values to reduce.
 * @param[in] n				- the number of values.
 */
static void rns_vrdc_all(dig_t *const c[], const dig_t *const a[], int n) {
	int i = 0;

	for (; i + RNS_K <= n; i += RNS_K) {
		rns_vrdc(c + i, a + i, RNS_K);
	}
	/* RNS_K is at least 4, so a remainder needs at most three batches. */
	if (i + 4 <= n) {
		rns_vrdc(c + i, a + i, 4);
		i += 4;
	}
	if (i + 2 <= n) {
		rns_vrdc(c + i, a + i, 2);
		i += 2;
	}
	if (i < n) {
		rns_vrdc(c + i, a + i, 1);
	}
}

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
	const dig_t *as[2 * RNS_SIM];

	for (int i = 0; i < n; i += RNS_SIM) {
		int m = RLC_MIN(RNS_SIM, n - i);
		for (int j = 0; j < m; j++) {
			cs[2 * j] = c[i + j][0];
			cs[2 * j + 1] = c[i + j][1];
			as[2 * j] = a[i + j][0];
			as[2 * j + 1] = a[i + j][1];
		}
		rns_vrdc_all(cs, as, 2 * m);
	}
}

void fp3_rdcv_low(fp3_t *c, dv3_t *a, int n) {
	dig_t *cs[3 * RNS_SIM];
	const dig_t *as[3 * RNS_SIM];

	for (int i = 0; i < n; i += RNS_SIM) {
		int m = RLC_MIN(RNS_SIM, n - i);
		for (int j = 0; j < m; j++) {
			for (int k = 0; k < 3; k++) {
				cs[3 * j + k] = c[i + j][k];
				as[3 * j + k] = a[i + j][k];
			}
		}
		rns_vrdc_all(cs, as, 3 * m);
	}
}
