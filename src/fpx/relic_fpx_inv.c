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
 * Implementation of inversion in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_inv(fp2_t c, const fp2_t a) {
	fp_t t0, t1;

	fp_null_all(t0, t1);

	RLC_TRY {
		fp_new_all(t0, t1);

		/* t0 = a_0^2, t1 = a_1^2. */
		fp_sqr(t0, a[0]);
		fp_sqr(t1, a[1]);

		/* t1 = 1/(a_0^2 + a_1^2). */
#ifndef FP_QNRES
		if (fp_prime_get_qnr() != -1) {
			if (fp_prime_get_qnr() == -2) {
				fp_dbl(t1, t1);
				fp_add(t0, t0, t1);
			} else {
				if (fp_prime_get_qnr() < 0) {
					fp_mul_dig(t1, t1, -fp_prime_get_qnr());
					fp_add(t0, t0, t1);
				} else {
					fp_mul_dig(t1, t1, fp_prime_get_qnr());
					fp_sub(t0, t0, t1);
				}
			}
		} else {
			fp_add(t0, t0, t1);
		}
#else
		fp_add(t0, t0, t1);
#endif

		fp_inv(t1, t0);

		/* c_0 = a_0/(a_0^2 + a_1^2). */
		fp_mul(c[0], a[0], t1);
		/* c_1 = - a_1/(a_0^2 + a_1^2). */
		fp_mul(c[1], a[1], t1);
		fp_neg(c[1], c[1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free_all(t0, t1);
	}
}

void fp2_inv_cyc(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_neg(c[1], a[1]);
}

TMPL_FPX_INV_SIM(fp2);

void fp3_inv(fp3_t c, const fp3_t a) {
	fp_t v0;
	fp_t v1;
	fp_t v2;
	fp_t t0;

	fp_null_all(v0, v1, v2, t0);

	RLC_TRY {
		fp_new_all(v0, v1, v2, t0);

		/* v0 = a_0^2 - B * a_1 * a_2. */
		fp_sqr(t0, a[0]);
		fp_mul(v0, a[1], a[2]);
		fp_copy(v2, v0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(v2, v2, v0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(v2, v2, v0);
		}
		fp_sub(v0, t0, v2);

		/* v1 = B * a_2^2 - a_0 * a_1. */
		fp_sqr(t0, a[2]);
		fp_copy(v2, t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(v2, v2, t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(v2, v2, t0);
		}
		fp_mul(v1, a[0], a[1]);
		fp_sub(v1, v2, v1);

		/* v2 = a_1^2 - a_0 * a_2. */
		fp_sqr(t0, a[1]);
		fp_mul(v2, a[0], a[2]);
		fp_sub(v2, t0, v2);

		fp_mul(t0, a[1], v2);
		fp_copy(c[1], t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[1], c[1], t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[1], c[1], t0);
		}

		fp_mul(c[0], a[0], v0);

		fp_mul(t0, a[2], v1);
		fp_copy(c[2], t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[2], c[2], t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[2], c[2], t0);
		}

		fp_add(t0, c[0], c[1]);
		fp_add(t0, t0, c[2]);
		fp_inv(t0, t0);

		fp_mul(c[0], v0, t0);
		fp_mul(c[1], v1, t0);
		fp_mul(c[2], v2, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free_all(v0, v1, v2, t0);
	}
}

TMPL_FPX_INV_SIM(fp3);

TMPL_FPX_INV_CYC_QUAD(fp4, fp2);

TMPL_FPX_INV_QUAD(fp4, fp2, fp2_mul_nor);

TMPL_FPX_INV_SIM(fp4);

TMPL_FPX_INV_CUBIC(fp6, fp2, fp2_mul_nor);

TMPL_FPX_INV_CYC_QUAD(fp8, fp4);

TMPL_FPX_INV_QUAD(fp8, fp4, fp4_mul_art);

TMPL_FPX_INV_SIM(fp8);

TMPL_FPX_INV_CUBIC(fp9, fp3, fp3_mul_nor);

TMPL_FPX_INV_SIM(fp9);

TMPL_FPX_INV_QUAD(fp12, fp6, fp6_mul_art);

TMPL_FPX_INV_CYC_QUAD(fp12, fp6);

TMPL_FPX_INV_CYC_QUAD(fp16, fp8);

TMPL_FPX_INV_QUAD(fp16, fp8, fp8_mul_art);

TMPL_FPX_INV_SIM(fp16);

TMPL_FPX_INV_QUAD(fp18, fp9, fp9_mul_art);

TMPL_FPX_INV_CYC_QUAD(fp18, fp9);

TMPL_FPX_INV_CUBIC(fp24, fp8, fp8_mul_art);

TMPL_FPX_INV_CYC_CUBIC(fp24, fp8);

TMPL_FPX_INV_QUAD(fp48, fp24, fp24_mul_art);

TMPL_FPX_INV_CYC_QUAD(fp48, fp24);

TMPL_FPX_INV_CUBIC(fp54, fp18, fp18_mul_art);

TMPL_FPX_INV_CYC_CUBIC(fp54, fp18);
