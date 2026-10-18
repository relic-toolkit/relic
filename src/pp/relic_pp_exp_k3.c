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
 * Implementation of the final exponentiation for pairings over supersingular
 * curves over Fp^4 with embedding degree 3.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k3(fp12_t c, fp12_t a) {
	fp12_t t0, t1, t2;
	bn_t d, e, n;
	const int *b;
	int l;

	fp12_null(t0);
	fp12_null(t1);
	fp12_null(t2);
	bn_null(d);
	bn_null(e);
	bn_null(n);

	RLC_TRY {
		fp12_new(t0);
		fp12_new(t1);
		fp12_new(t2);
		bn_new(d);
		bn_new(e);
		bn_new(n);

		/* The prime is p = d + e * r, and the hard part of the exponent is
		 * e * (p^2 + d^2 - 1) * (p + d) + 1. */
		fp_prime_get_par(d);
		b = fp_prime_get_par_sps(&l);
		ep4_curve_get_ord(n);
		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_sub(e, e, d);
		bn_div(e, e, n);

		/* First, compute m = f^(p^6 - 1)(p^2 + 1). */
		fp12_conv_cyc(t0, a);

		/* t1 = m^e. */
		fp12_exp_cyc(t1, t0, e);
		/* t1 = t1^(p^2 + d^2 - 1). */
		fp12_exp_cyc_sps(t2, t1, b, l, RLC_POS);
		fp12_exp_cyc_sps(t2, t2, b, l, RLC_POS);
		fp12_frb(c, t1, 2);
		fp12_mul(t2, t2, c);
		fp12_inv_cyc(t1, t1);
		fp12_mul(t1, t2, t1);
		/* t1 = t1^(p + d). */
		fp12_exp_cyc_sps(t2, t1, b, l, RLC_POS);
		fp12_frb(t1, t1, 1);
		fp12_mul(t1, t1, t2);
		/* c = t1 * m. */
		fp12_mul(c, t1, t0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t0);
		fp12_free(t1);
		fp12_free(t2);
		bn_free(d);
		bn_free(e);
		bn_free(n);
	}
}
