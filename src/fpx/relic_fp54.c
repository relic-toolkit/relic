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
 * Implementation of arithmetic in the extension of degree 54 of a prime field.
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

TMPL_FPX_UTIL(fp54, fp18, 3);

TMPL_FPX_BIN_CQ(fp54, fp18, fp9, 54);

TMPL_FPX_CMP(fp54, fp18, 3);

TMPL_FPX_ADD(fp54, fp18, 3);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_CUBIC(fp54, fp18, fp18_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_CUBIC(fp54, fp18, dv54, dv18, fp3, dv3, 6, 2,
		fp18_mul_unr);

TMPL_FPX_MUL_LAZYR(fp54, dv54, fp3, dv3, 18);

#endif

void fp54_mul_dxs(fp54_t c, const fp54_t a, const fp54_t b) {
	fp18_t t0, t1, t2, t3, t4;

	fp18_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		fp18_new_all(t0, t1, t2, t3, t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
#if EP_ADD == BASIC
		fp18_mul_dxs(t0, a[0], b[0]);
#else
		fp18_mul(t0, a[0], b[0]);
#endif
		/* t2 = a_2 * b_2. */
		fp9_mul(t2[0], a[2][0], b[2][0]);
		fp9_mul(t2[1], a[2][1], b[2][0]);

		fp18_add(t3, a[1], a[2]);
		fp9_mul(t3[0], t3[0], b[2][0]);
		fp9_mul(t3[1], t3[1], b[2][0]);
		fp18_sub(t3, t3, t2);
		fp18_mul_art(t3, t3);
		fp18_add(t3, t3, t0);

		fp18_add(t4, a[0], a[1]);
#if EP_ADD == BASIC
		fp18_mul_dxs(t4, t4, b[0]);
#else
		fp18_mul(t4, t4, b[0]);
#endif
		fp18_sub(t4, t4, t0);
		fp18_mul_art(t1, t2);
		fp18_add(c[1], t4, t1);

		fp18_add(t4, a[0], a[2]);
		fp9_add(t1[0], b[0][0], b[2][0]);
		fp9_copy(t1[1], b[0][1]);
#if EP_ADD == BASIC
		fp18_mul_dxs(c[2], t4, t1);
#else
		fp18_mul(c[2], t4, t1);
#endif
		fp18_sub(c[2], c[2], t0);
		fp18_sub(c[2], c[2], t2);

		fp18_copy(c[0], t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free_all(t0, t1, t2, t3, t4);
	}
}

TMPL_FPX_MUL_ART_CUBIC(fp54, fp18, fp18_mul_art);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_CUBIC(fp54, fp18, fp18_mul_art, 18);

TMPL_SQR_CYC_CQ(fp54, fp9, fp9_mul_art);

TMPL_SQR_PCK_CQ(fp54, fp9, fp9_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_CUBIC(fp54, fp18, dv54, dv18, fp3, dv3, 6, 2,
		fp18_sqr_unr, fp18_mul_unr, 18);

TMPL_FPX_SQR_LAZYR(fp54, dv54, fp3, dv3, 18);

TMPL_SQR_PCK_LAZYR_CQ(fp54, fp9, dv9, fp3, dv3, 3, 1, fp9_sqr_unr, fp9_mul_art);

TMPL_SQR_CYC_LAZYR_CQ(fp54, fp9, dv9, fp3, dv3, 3, 1, fp9_sqr_unr);

#endif

TMPL_FPX_INV_CUBIC(fp54, fp18, fp18_mul_art);

TMPL_FPX_INV_CYC_CUBIC(fp54, fp18);

TMPL_FPX_EXP_CYC(fp54);

TMPL_FPX_EXP_DIG(fp54);

void fp54_frb(fp54_t c, const fp54_t a, int i) {
	/* Since w^18 = u, w^(p - 1) = u^((p - p mod 18)/18) * t^((p mod 18 - 1)/6)
	 * and w^(2(p - 1)) = u^((p - p mod 9)/9) * t^((p mod 9 - 1)/3). */
	int k1 = (fp_prime_get_mod18() - 1) / 6;
	int k2 = (fp_prime_get_mod18() % 9 - 1) / 3;

	/* Cost of 12 sparse multiplications in Fp^3 per Frobenius. */
	fp54_copy(c, a);
	for (; i % 54 > 0; i--) {
		fp18_frb(c[0], c[0], 1);
		fp18_frb(c[1], c[1], 1);
		fp18_frb(c[2], c[2], 1);
		for (int j = 0; j < 2; j++) {
			for (int l = 0; l < 3; l++) {
				fp3_mul_frb(c[1][j][l], c[1][j][l], 2, 2);
				fp3_mul_frb(c[2][j][l], c[2][j][l], 2, 1);
			}
			for (int l = 0; l < k1; l++) {
				fp9_mul_art(c[1][j], c[1][j]);
			}
			for (int l = 0; l < k2; l++) {
				fp9_mul_art(c[2][j], c[2][j]);
			}
		}
	}
}

TMPL_FPX_CONV_CYC(fp54, 9);

TMPL_FPX_TEST_CYC(fp54, 9);

TMPL_FPX_BACK_CYC_CQ(fp54, fp9, fp9_mul_art);

TMPL_FPX_BACK_CYC_SIM_CQ(fp54, fp9, fp9_mul_art);

TMPL_EXP_CYC(fp54);

TMPL_EXP_CYC_SPS(fp54);

TMPL_FPX_PCK_CQ(fp54, fp9);

TMPL_FPX_UPK_CQ(fp54, fp9);
