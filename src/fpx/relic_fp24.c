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
 * Implementation of arithmetic in the extension of degree 24 of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_cyc_tmpl.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_sqr_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp24, fp8, 3);

TMPL_FPX_BIN_CQ(fp24, fp8, fp4, 24);

TMPL_FPX_CMP(fp24, fp8, 3);

TMPL_FPX_ADD(fp24, fp8, 3);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_CUBIC(fp24, fp8, fp8_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_mul_unr);

TMPL_FPX_MUL_LAZYR(fp24, dv24, fp2, dv2, 12);

#endif

TMPL_FPX_MUL_ART_CUBIC(fp24, fp8, fp8_mul_art);

void fp24_mul_dxs(fp24_t c, const fp24_t a, const fp24_t b) {
	fp8_t t0, t1, t2, t3, t4;

	fp8_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		fp8_new_all(t0, t1, t2, t3, t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp8_mul(t0, a[0], b[0]);
		fp8_add(t3, a[1], a[2]);
		fp8_add(t4, a[0], a[1]);

		if (fp8_is_zero(b[2])) {
			/* t1 = a_1 * b_1. */
			fp8_mul(t1, a[1], b[1]);
			/* b_2 = 0. */

			fp8_mul(t3, t3, b[1]);
			fp8_sub(t3, t3, t1);
			fp8_mul_art(t3, t3);
			fp8_add(t3, t3, t0);

			fp8_add(t2, b[0], b[1]);
			fp8_mul(t4, t4, t2);
			fp8_sub(t4, t4, t0);
			fp8_sub(c[1], t4, t1);

			fp8_add(t4, a[0], a[2]);
			fp8_mul(c[2], t4, b[0]);
			fp8_sub(c[2], c[2], t0);
			fp8_add(c[2], c[2], t1);
		} else {
			/* b_1 = 0. */
			/* t2 = a_2 * b_2. */
			fp8_mul(t1, a[2], b[2]);

			fp8_mul(t3, t3, b[2]);
			fp8_sub(t3, t3, t1);
			fp8_mul_art(t3, t3);
			fp8_add(t3, t3, t0);

			fp8_mul(t4, t4, b[0]);
			fp8_sub(t4, t4, t0);
			fp8_mul_art(t2, t1);
			fp8_add(c[1], t4, t2);

			fp8_add(t4, a[0], a[2]);
			fp8_add(t2, b[0], b[2]);
			fp8_mul(c[2], t4, t2);
			fp8_sub(c[2], c[2], t0);
			fp8_sub(c[2], c[2], t1);
		}
		
		fp8_copy(c[0], t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1, t2, t3, t4);
	}
}

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_CUBIC(fp24, fp8, fp8_mul_art, 8);

TMPL_SQR_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_SQR_PCK_CQ(fp24, fp4, fp4_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr, fp8_mul_unr, 8);

TMPL_FPX_SQR_LAZYR(fp24, dv24, fp2, dv2, 12);

TMPL_SQR_PCK_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr, fp4_mul_art);

TMPL_SQR_CYC_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr);

#endif

TMPL_FPX_INV_CUBIC(fp24, fp8, fp8_mul_art);

TMPL_FPX_INV_CYC_CUBIC(fp24, fp8);

TMPL_FPX_EXP_CYC(fp24);

TMPL_FPX_EXP_DIG(fp24);

void fp24_frb(fp24_t c, const fp24_t a, int i) {
	/* Cost of 20 multiplication in Fp^2 per Frobenius. */
	fp24_copy(c, a);
	for (; i % 24 > 0; i--) {
		fp8_frb(c[0], c[0], 1);
		fp8_frb(c[1], c[1], 1);
		fp8_frb(c[2], c[2], 1);
		for (int j = 0; j < 2; j++) {
			for (int l = 0; l < 2; l++) {
				fp2_mul_frb(c[1][j][l], c[1][j][l], 2, 3);
				fp2_mul_frb(c[2][j][l], c[2][j][l], 1, 1);
			}
			if ((fp_prime_get_mod8() % 4) == 3) {
				fp4_mul_art(c[1][j], c[1][j]);
			}
		}
	}
}

TMPL_FPX_CONV_CYC(fp24, 4);

TMPL_FPX_TEST_CYC(fp24, 4);

TMPL_FPX_BACK_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_FPX_BACK_CYC_SIM_CQ(fp24, fp4, fp4_mul_art);

TMPL_EXP_CYC(fp24);

TMPL_EXP_CYC_SIM(fp24, fp24_sqr_cyc);

TMPL_EXP_CYC_SPS(fp24);

TMPL_FPX_PCK_CQ(fp24, fp4);

TMPL_FPX_UPK_CQ(fp24, fp4);
