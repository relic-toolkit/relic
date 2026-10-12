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
 * Implementation of the prime field modular reduction functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rdc_basic(fp_t c, dv_t a) {
	dv_t t0, t1, t2, t3;

	dv_null_all(t0, t1, t2, t3);

	RLC_TRY {
		dv_new_all(t0, t1, t2, t3);

		dv_copy(t2, a, 2 * RLC_FP_DIGS);
		dv_copy(t3, fp_prime_get(), RLC_FP_DIGS);
		bn_divn_low(t0, t1, t2, 2 * RLC_FP_DIGS, t3, RLC_FP_DIGS);
		fp_copy(c, t1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv_free_all(t0, t1, t2, t3);
	}
}

void fp_rdc_monty_basic(fp_t c, dv_t a) {
	size_t i;
	dig_t r, u0;

	u0 = *(fp_prime_get_rdc());

	for (i = 0; i < RLC_FP_DIGS; i++, a++) {
		r = (dig_t)(*a * u0);
		*a = fp_mula_low(a, fp_prime_get(), r);
	}
	fp_addm_low(c, a, a - RLC_FP_DIGS);
}

void fp_rdc_monty_comba(fp_t c, dv_t a) {
	fp_rdcn_low(c, a);
}

void fp_rdc_quick(fp_t c, dv_t a) {
	const int *sform;
	int len, i, n;
	bn_t q, r, t;

	bn_null_all(q, r, t);

	RLC_TRY {
		bn_new_all(q, r, t);

		/* Write p = 2^n - s, with the sparse terms of p in sform. */
		sform = fp_prime_get_sps(&len);
		n = sform[len - 1];

		/* Fold q = floor(r/2^n) into r mod 2^n since 2^n = s mod p. */
		bn_read_raw(r, a, 2 * RLC_FP_DIGS);
		bn_rsh(q, r, n);
		while (!bn_is_zero(q)) {
			bn_mod_2b(r, r, n);
			for (i = 0; i < len - 1; i++) {
				/* The first term is the constant +1 or -1, so its power is 0. */
				bn_lsh(t, q, i == 0 ? 0 : (sform[i] < 0 ? -sform[i] : sform[i]));
				if (sform[i] < 0) {
					bn_add(r, r, t);
				} else {
					bn_sub(r, r, t);
				}
			}
			bn_rsh(q, r, n);
		}
		fp_zero(c);
		dv_copy(c, r->dp, r->used);
		fp_norm(c, c);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(q, r, t);
	}
}

#if FP_RDC == LOWER

void fp_rdc_lower(fp_t c, dv_t a) {
	fp_rdcs_low(c, a, fp_prime_get());
}

#endif
