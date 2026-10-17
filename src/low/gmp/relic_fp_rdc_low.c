/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the low-level prime field modular reduction functions.
 *
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_core.h"
#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m) {
	rlc_align dig_t q[2 * RLC_FP_DIGS], r[2 * RLC_FP_DIGS];
	rlc_align dig_t t[2 * RLC_FP_DIGS + 1];
	const int *sform;
	int len, i, j, b, d, k, bi, di, ti;

	/* Write m = 2^n - s, with the sparse terms of m in sform. */
	sform = fp_prime_get_sps(&len);
	RLC_RIP(b, d, sform[len - 1]);
	/* The quotient q = floor(r/2^n) has at most k digits. */
	k = 2 * RLC_FP_DIGS - d;

	/* Fold q into r mod 2^n since 2^n = s mod m. */
	mpn_copyi(r, a, 2 * RLC_FP_DIGS);
	bn_rshb_low(q, r + d, k, b);
	while (!mpn_zero_p(q, k)) {
		r[d] &= RLC_MASK(b);
		mpn_zero(r + d + 1, k - 1);
		/* The partial sums may wrap around, but r + q * s does not. */
		for (i = 0; i < len - 1; i++) {
			/* The first term is the constant +1 or -1, so its power is 0. */
			j = (i == 0 ? 0 : (sform[i] < 0 ? -sform[i] : sform[i]));
			RLC_RIP(bi, di, j);
			/* Add or subtract q * 2^j as t = q * 2^bi at digit di. */
			t[k] = bn_lshb_low(t, q, k, bi);
			ti = RLC_MIN(k + 1, (int)(2 * RLC_FP_DIGS) - di);
			if (sform[i] < 0) {
				mpn_add(r + di, r + di, 2 * RLC_FP_DIGS - di, t, ti);
			} else {
				mpn_sub(r + di, r + di, 2 * RLC_FP_DIGS - di, t, ti);
			}
		}
		bn_rshb_low(q, r + d, k, b);
	}
	/* Now r < 2^n < 2m. */
	if (mpn_cmp(r, m, RLC_FP_DIGS) >= 0) {
		mpn_sub_n(r, r, m, RLC_FP_DIGS);
	}
	mpn_copyi(c, r, RLC_FP_DIGS);
}

void fp_rdcn_low(dig_t *c, dig_t *a) {
	dig_t r, u = *(fp_prime_get_rdc());
	const dig_t *m = fp_prime_get();

	for (size_t i = 0; i < RLC_FP_DIGS; i++, a++) {
		r = (dig_t)(*a * u);
#if FP_PRIME == 3072
		/* The low half of p is 1, so add r and carry into the rest of a. */
		mpn_add_1(a, a, 2 * RLC_FP_DIGS - i, r);
		*a = mpn_addmul_1(a + RLC_FP_DIGS/2, m + RLC_FP_DIGS/2, RLC_FP_DIGS/2, r);
#else
		*a = mpn_addmul_1(a, m, RLC_FP_DIGS, r);
#endif
	}
	fp_addm_low(c, a, a - RLC_FP_DIGS);
}
