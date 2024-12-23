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
 * Implementation of the final exponentiation for curves of embedding degree 24.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k24(fp24_t c, fp24_t a) {
	fp24_t t0, t1, t2;
	const int *b;
	bn_t x;
	int l;

	bn_null(x);
	fp24_null(t0);
	fp24_null(t1);
	fp24_null(t2);

	RLC_TRY {
		bn_new(x);
		fp24_new(t0);
		fp24_new(t1);
		fp24_new(t2);

		/*
		 * Final exponentiation following Hayashida, Hayasaka and Teruya:
		 * Efficient Final Exponentiation via Cyclotomic Structure for Pairings
		 * over Families of Elliptic Curves: https://eprint.iacr.org/2020/875
		 */
		fp_prime_get_par(x);
		b = fp_prime_get_par_sps(&l);
		/* First, compute m^(p^12 - 1)(p^4 + 1). */
		fp24_conv_cyc(c, a);

		/* t0 = f^(x-1)^2. */
		if (bn_sign(x) == RLC_NEG && b[0] == 0 && b[1] == -1) {
			fp24_exp_cyc_sps(t0, c, b+2, l-2, RLC_POS);
			fp24_exp_cyc_sps(t0, t0, b+2, l-2, RLC_POS);
		} else {
			fp24_exp_cyc_sps(t1, c, b, l, bn_sign(x));
			fp24_inv_cyc(t0, c);
			fp24_mul(t1, t1, t0);
			fp24_exp_cyc_sps(t0, t1, b, l, bn_sign(x));
			fp24_inv_cyc(t1, t1);
			fp24_mul(t0, t0, t1);
		}

		/* t1 = t0^(x + p). */
		fp24_exp_cyc_sps(t1, t0, b, l, bn_sign(x));
		fp24_frb(t0, t0, 1);
		fp24_mul(t1, t1, t0);

		/* t0 = t1^(x^2 + p^2). */
		fp24_exp_cyc_sps(t0, t1, b, l, RLC_POS);
		fp24_exp_cyc_sps(t0, t0, b, l, RLC_POS);
		fp24_frb(t1, t1, 2);
		fp24_mul(t0, t0, t1);

		/* t1 = t0^(x^4 + p^4 - 1). */
		fp24_exp_cyc_sps(t1, t0, b, l, RLC_POS);
		fp24_exp_cyc_sps(t1, t1, b, l, RLC_POS);
		fp24_exp_cyc_sps(t1, t1, b, l, RLC_POS);
		fp24_exp_cyc_sps(t1, t1, b, l, RLC_POS);
		fp24_inv_cyc(t2, t0);
		fp24_frb(t0, t0, 4);
		fp24_mul(t1, t1, t0);
		fp24_mul(t1, t1, t2);

		/* c = c^3. */
		fp24_sqr_cyc(t0, c);
		fp24_mul(c, c, t0);
		fp24_mul(c, c, t1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp24_free(t0);
		fp24_free(t1);
		fp24_free(t2);
	}
}
