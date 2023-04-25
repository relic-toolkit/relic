/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of the final exponentiation for curves of embedding degree 18.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k18(fp18_t c, fp18_t a) {
	fp18_t t0, t1, t2, t3, t4, t5;
	const int *b;
	bn_t x;
	int l;

	bn_null(x);
	fp18_null(t0);
	fp18_null(t1);
	fp18_null(t2);
	fp18_null(t3);
	fp18_null(t4);
	fp18_null(t5);

	RLC_TRY {
		bn_new(x);
		fp18_new(t0);
		fp18_new(t1);
		fp18_new(t2);
		fp18_new(t3);
		fp18_new(t4);
		fp18_new(t5);

		/*
		 * Final exponentiation following Cai, Hu and Zhao:
		 * Faster Final Exponentiation on the KSS18 Curve
		 */
		fp_prime_get_par(x);
		b = fp_prime_get_par_sps(&l);
		/* First, compute m^(p^9 - 1)(p^3 + 1). */
		fp18_conv_cyc(c, a);

		/* t0 = f^x, t1 = f^2, t4 = f * t1 = f^3. */
		fp18_exp_cyc_sps(t0, c, b, l, bn_sign(x));
		fp18_sqr_cyc(t1, c);
		fp18_mul(t4, c, t1);
		/* t2 = f^5, t1 = f^7. */
		fp18_mul(t2, t1, t4);
		fp18_mul(t1, t1, t2);
		/* t0 = f^(x + 5), t2 = f^(x^2 + 5x), c = f^l_6. */
		fp18_mul(t0, t0, t2);
		fp18_exp_cyc_sps(t2, t0, b, l, bn_sign(x));
		fp18_mul(c, t1, t2);

		/* t0 = f^7l_6, t1 = f^14l_6, t3 = f^xl_6 */
		fp18_sqr_cyc(t5, c);
		fp18_sqr_cyc(t0, t5);
		fp18_mul(t0, t0, c);
		fp18_mul(t0, t0, t5);
		fp18_sqr_cyc(t1, t0);
		fp18_exp_cyc_sps(t3, c, b, l, bn_sign(x));
		/* c = f^x^2l_6 + 3 = f^l_5. */
		fp18_exp_cyc_sps(c, t3, b, l, bn_sign(x));
		fp18_mul(c, c, t4);
		/* t2 = f^xl_5, t4 = f^-xl_5, t5 = f^(-xl_5 - 14l_6). */
		fp18_exp_cyc_sps(t2, c, b, l, bn_sign(x));
		fp18_inv_cyc(t4, t2);
		fp18_inv_cyc(t1, t1);
		fp18_mul(t5, t1, t4);
		/* t1 = f^(-3xl_5 - 49l_6) = f^l_4. */
		fp18_sqr_cyc(t1, t5);
		fp18_mul(t1, t1, t5);
		fp18_inv_cyc(t0, t0);
		fp18_mul(t1, t1, t0);

		/* t2 = f^x^2l_5, t0 = f^-l_4, t1 = f^-(-2l_4 - xl_5)p = f^l_1p. */
		fp18_exp_cyc_sps(t2, t2, b, l, bn_sign(x));
		fp18_inv_cyc(t0, t1);
		fp18_sqr_cyc(t1, t0);
		fp18_mul(t1, t1, t4);
		fp18_inv_cyc(t1, t1);
		fp18_frb(t1, t1, 1);
		/* t4 = (fl_5p * f^l_4)p^4 * f^l_1p. */
		fp18_frb(t4, c, 1);
		fp18_inv_cyc(t0, t0);
		fp18_mul(t4, t4, t0);
		fp18_frb(t4, t4, 4);
		fp18_mul(t4, t4, t1);
		/* t3 = f^7xl_6, t1 = f^14xl_6, t0 = f^(35xl_6 + 2x^2l_5) = f^l_3. */
		fp18_sqr_cyc(t5, t3);
		fp18_sqr_cyc(t1, t5);
		fp18_mul(t3, t1, t3);
		fp18_mul(t3, t3, t5);
		fp18_sqr_cyc(t1, t3);
		fp18_mul(t0, t1, t2);
		fp18_sqr_cyc(t0, t0);
		fp18_mul(t0, t0, t3);

		/* t3 = f^21xl_6, t1 = f^x^2l_5 + 21xl_6 = f^l_0. */
		fp18_mul(t3, t1, t3);
		fp18_mul(t1, t2, t3);
		/* t4 = (fl_5p * f^l_4)p^4 * f^l_1p * f^l_0. */
		fp18_mul(t4, t1, t4);
		/* t1 = f^(2l_5 - xl_0) = f^l_2. */
		fp18_exp_cyc_sps(t1, t1, b, l, bn_sign(x));
		fp18_inv_cyc(t1, t1);
		fp18_sqr_cyc(t2, c);
		fp18_mul(t1, t1, t2);
		/* t0 = (f^l_3p * f^l_2)p^2. */
		fp18_frb(t0, t0, 1);
		fp18_mul(t0, t0, t1);
		fp18_frb(t0, t0, 2);
		/* c = (fl_5p * f^l_4)p^4 * f^l_1p * f^l_0 * (f^l_3p * f^l_2)p^2. */
		fp18_mul(c, t4, t0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp18_free(t0);
		fp18_free(t1);
		fp18_free(t2);
		fp18_free(t3);
		fp18_free(t4);
		fp18_free(t5);
	}
}
