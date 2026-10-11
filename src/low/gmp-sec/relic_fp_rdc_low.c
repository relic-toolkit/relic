/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
	rlc_align dig_t q[2 * RLC_FP_DIGS], r[2 * RLC_FP_DIGS], t[2 * RLC_FP_DIGS];
	const int *sform;
	int len, i, j, b, d, e, k, l, n, bi, di;
	dig_t borrow;

	/* Write m = 2^n - s, with the sparse terms of m in sform. */
	sform = fp_prime_get_sps(&len);
	n = sform[len - 1];
	RLC_RIP(b, d, n);
	/* The largest power of 2 in s, so that s < 2^(e + 1). */
	e = (len > 2 ? (sform[len - 2] < 0 ? -sform[len - 2] : sform[len - 2]) : 0);

	/* Count the folds from the public bounds only. A fold takes r from l to
	 * max(n, l - n + e + 1) + 1 bits; once l <= n + 1, two more folds bring r
	 * below 2^n, since s < 2^(n - 1). */
	for (k = 2, l = 2 * RLC_FP_DIGS * RLC_DIG; l > n + 1 && e + 2 < n; k++) {
		l = RLC_MAX(n, l - n + e + 1) + 1;
	}

	/* Fold q = floor(r/2^n) into r mod 2^n since 2^n = s mod m. */
	mpn_copyi((mp_ptr)r, (mp_srcptr)a, 2 * RLC_FP_DIGS);
	for (; k > 0; k--) {
		dv_rshd(q, r, 2 * RLC_FP_DIGS, d);
		bn_rshb_low(q, q, 2 * RLC_FP_DIGS, b);
		r[d] &= RLC_MASK(b);
		mpn_zero((mp_ptr)r + d + 1, 2 * RLC_FP_DIGS - d - 1);
		/* The partial sums may wrap around, but r + q * s does not. */
		for (i = 0; i < len - 1; i++) {
			/* The first term is the constant +1 or -1, so its power is 0. */
			j = (i == 0 ? 0 : (sform[i] < 0 ? -sform[i] : sform[i]));
			RLC_RIP(bi, di, j);
			dv_lshd(t, q, 2 * RLC_FP_DIGS, di);
			bn_lshb_low(t, t, 2 * RLC_FP_DIGS, bi);
			if (sform[i] < 0) {
				mpn_add_n((mp_ptr)r, (mp_srcptr)r, (mp_srcptr)t, 2 * RLC_FP_DIGS);
			} else {
				mpn_sub_n((mp_ptr)r, (mp_srcptr)r, (mp_srcptr)t, 2 * RLC_FP_DIGS);
			}
		}
	}
	/* Now r < 2^n < 2m, so subtract m in constant time if r >= m. */
	borrow = mpn_sub_n((mp_ptr)t, (mp_srcptr)r, (mp_srcptr)m, RLC_FP_DIGS);
	dv_copy_sec(r, t, RLC_FP_DIGS, borrow ^ 1);
	mpn_copyi((mp_ptr)c, (mp_srcptr)r, RLC_FP_DIGS);
}

void fp_rdcn_low(dig_t *c, dig_t *a) {
	dig_t r, u = *(fp_prime_get_rdc());
	const dig_t *m = fp_prime_get();

	for (int i = 0; i < RLC_FP_DIGS; i++, a++) {
		r = (dig_t)(*a * u);
#if FP_PRIME == 3072
		*a = mpn_add_1((mp_ptr)a, (mp_srcptr)a, RLC_FP_DIGS, r);
		*a = mpn_addmul_1((mp_ptr)a + RLC_FP_DIGS/2,
			(mp_srcptr)m + RLC_FP_DIGS/2, RLC_FP_DIGS/2, r);
#else
		*a = mpn_addmul_1((mp_ptr)a, (mp_srcptr)m, RLC_FP_DIGS, r);
#endif
	}
	fp_addm_low(c, a, a - RLC_FP_DIGS);
}
