/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of square root in a nonic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Computes the norm of a nonic extension field element down to the prime
 * field.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the nonic extension field element.
 */
static void fp9_norm(fp_t c, const fp9_t a) {
	fp9_t t, u;
	fp3_t v, w;

	fp9_null(t);
	fp9_null(u);
	fp3_null(v);
	fp3_null(w);

	RLC_TRY {
		fp9_new(t);
		fp9_new(u);
		fp3_new(v);
		fp3_new(w);

		/* The norm down to Fp^3 is a * a^(p^3) * a^(p^6). */
		fp9_frb(u, a, 3);
		fp9_mul(t, a, u);
		fp9_frb(u, a, 6);
		fp9_mul(t, t, u);
		/* The norm down to Fp is then v * v^p * v^(p^2). */
		fp3_frb(w, t[0], 1);
		fp3_mul(v, t[0], w);
		fp3_frb(w, w, 1);
		fp3_mul(v, v, w);
		fp_copy(c, v[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp9_free(t);
		fp9_free(u);
		fp3_free(v);
		fp3_free(w);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp9_is_sqr(const fp9_t a) {
	fp_t n;
	int r = 0;

	fp_null(n);

	RLC_TRY {
		fp_new(n);
		/* For odd degree, a is a square if and only if its norm is. */
		fp9_norm(n, a);
		r = fp_is_sqr(n);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(n);
	}

	return r;
}

int fp9_srt(fp9_t c, const fp9_t a) {
	int r = 0;
	fp_t n;
	fp9_t t0, t1, t2;
	bn_t e;

	fp_null(n);
	fp9_null(t0);
	fp9_null(t1);
	fp9_null(t2);
	bn_null(e);

	if (fp9_is_zero(a)) {
		fp9_zero(c);
		return 1;
	}

	RLC_TRY {
		fp_new(n);
		fp9_new(t0);
		fp9_new(t1);
		fp9_new(t2);
		bn_new(e);

		/* Let S = 1 + p + ... + p^8, so that a^S is the norm N(a). Then
		 * a^((S + 1)/2) / sqrt(N(a)) squares to a^(S + 1)/a^S = a, where
		 * (S + 1)/2 = 1 + sum_{i = 1}^{4} p^(2i - 1) * (p + 1)/2. */
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_trim(e);
		bn_add_dig(e, e, 1);
		bn_hlv(e, e);
		fp9_exp(t1, a, e);
		fp9_copy(t0, a);
		for (int i = 1; i < 9; i += 2) {
			fp9_frb(t2, t1, i);
			fp9_mul(t0, t0, t2);
		}

		fp9_norm(n, a);
		if (fp_srt(n, n)) {
			fp_inv(n, n);
			for (int i = 0; i < 3; i++) {
				for (int j = 0; j < 3; j++) {
					fp_mul(t0[i][j], t0[i][j], n);
				}
			}
		}

		/* Test the candidate, since the norm may not have a square root. */
		fp9_sqr(t1, t0);
		r = (fp9_cmp(t1, a) == RLC_EQ ? 1 : 0);
		fp9_zero(c);
		fp9_copy_sec(c, t0, r);
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(n);
		fp9_free(t0);
		fp9_free(t1);
		fp9_free(t2);
		bn_free(e);
	}

	return r;
}
