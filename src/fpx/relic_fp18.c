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
 * Implementation of arithmetic in the octdecic extension of a prime field.
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
/* Private definitions                                                        */
/*============================================================================*/

#if FPX_RDC == LAZYR || !defined(STRIP)

inline static void fp9_mul_dxs_unr_lazyr(dv9_t c, const fp9_t a, const fp9_t b) {
	dv3_t u0, u1, u2, u3;
	fp3_t t0, t1;

	dv3_null_all(u0, u1, u2, u3);
	fp3_null_all(t0, t1);

	RLC_TRY {
		dv3_new_all(u0, u1, u2, u3);
		fp3_new_all(t0, t1);

		fp3_muln_low(u0, a[0], b[0]);
		fp3_muln_low(u1, a[1], b[1]);
		fp3_addm_low(t0, a[0], a[1]);
		fp3_addm_low(t1, b[0], b[1]);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1 */
		fp3_muln_low(u2, t0, t1);
		fp3_subc_low(u2, u2, u0);
		fp3_subc_low(c[1], u2, u1);

		/* c_0 = a_0b_0 + E a_2b_1 */
		fp3_muln_low(u2, a[2], b[1]);
		fp3_nord_low(c[0], u2);
		fp3_addc_low(c[0], u0, c[0]);

		/* c_2 = a_0b_2 + a_1b_1 */
		fp3_muln_low(u2, a[2], b[0]);
		fp3_addc_low(c[2], u1, u2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free_all(u0, u1, u2, u3);
		fp3_free_all(t0, t1);
	}
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp18, fp9, 2);

TMPL_FPX_BIN_QC(fp18, fp9, fp3, 18);

TMPL_FPX_CMP(fp18, fp9, 2);

TMPL_FPX_ADD(fp18, fp9, 2);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp18, fp9, fp9_mul_art);

void fp18_mul_dxs_basic(fp18_t c, const fp18_t a, const fp18_t b) {
	fp9_t t0, t1, t2;

	fp9_null_all(t0, t1, t2);

	RLC_TRY {
		fp9_new_all(t0, t1, t2);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp9_mul_dxs(t0, a[0], b[0]);
#if EP_ADD == BASIC
		/* t1 = a_1 * b_1. */
		fp_mul(t2[0][0], a[1][2][0], b[1][1][0]);
		fp_mul(t2[0][1], a[1][2][1], b[1][1][0]);
		fp3_mul_nor(t1[0], t2[0]);
		fp_mul(t1[1][0], a[1][0][0], b[1][1][0]);
		fp_mul(t1[1][1], a[1][0][1], b[1][1][0]);
		fp_mul(t1[2][0], a[1][1][0], b[1][1][0]);
		fp_mul(t1[2][1], a[1][1][1], b[1][1][0]);
		/* t2 = b_0 + b_1. */
		fp3_copy(t2[0], b[0][0]);
		fp_add(t2[1][0], b[0][1][0], b[1][1][0]);
		fp_copy(t2[1][1], b[0][1][1]);
#elif EP_ADD == PROJC || EP_ADD == JACOB
		/* t1 = a_1 * b_1. */
		fp3_mul(t2[0], a[1][2], b[1][1]);
		fp3_mul_nor(t1[0], t2[0]);
		fp3_mul(t1[1], a[1][0], b[1][1]);
		fp3_mul(t1[2], a[1][1], b[1][1]);
		/* t2 = b_0 + b_1. */
		fp3_copy(t2[0], b[0][0]);
		fp3_add(t2[1], b[0][1], b[1][1]);
#endif
		/* c_1 = a_0 + a_1. */
		fp9_add(c[1], a[0], a[1]);

		/* c_1 = (a_0 + a_1) * (b_0 + b_1) - a_0 * b_0 - a_1 * b_1. */
		fp9_mul_dxs(c[1], c[1], t2);
		fp9_sub(c[1], c[1], t0);
		fp9_sub(c[1], c[1], t1);

		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp9_mul_art(t1, t1);
		fp9_add(c[0], t0, t1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp9_free_all(t0, t1, t2);
	}
}

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_QUAD(fp18, fp9, dv18, dv9, fp3, dv3, 3, 1,
		fp9_mul_unr);

TMPL_FPX_MUL_LAZYR(fp18, dv18, fp3, dv3, 6);

void fp18_mul_dxs_lazyr(fp18_t c, const fp18_t a, const fp18_t b) {
	fp9_t t0;
	dv9_t u0, u1, u2;

	fp9_null(t0);
	dv9_null_all(u0, u1, u2);

	RLC_TRY {
		fp9_new(t0);
		dv9_new_all(u0, u1, u2);

		if (ep3_curve_is_twist() == RLC_EP_DTYPE) {
#if EP_ADD == BASIC
			/* t0 = a_0 * b_0. */
			fp_muln_low(u0[0][0], a[0][0][0], b[0][0][0]);
			fp_muln_low(u0[0][1], a[0][0][1], b[0][0][0]);
			fp_muln_low(u0[1][0], a[0][1][0], b[0][0][0]);
			fp_muln_low(u0[1][1], a[0][1][1], b[0][0][0]);
			fp_muln_low(u0[2][0], a[0][2][0], b[0][0][0]);
			fp_muln_low(u0[2][1], a[0][2][1], b[0][0][0]);
			/* t2 = b_0 + b_1. */
			fp_add(t0[0][0], b[0][0][0], b[1][0][0]);
			fp_copy(t0[0][1], b[1][0][1]);
			fp3_copy(t0[1], b[1][1]);
#elif EP_ADD == PROJC || EP_ADD == JACOB
			/* t0 = a_0 * b_0. */
			fp3_muln_low(u0[0], a[0][0], b[0][0]);
			fp3_muln_low(u0[1], a[0][1], b[0][0]);
			fp3_muln_low(u0[2], a[0][2], b[0][0]);

			/* t2 = b_0 + b_1. */
			fp3_add(t0[0], b[0][0], b[1][0]);
			fp3_copy(t0[1], b[1][1]);
#endif
			/* t1 = a_1 * b_1. */
			fp9_mul_dxs_unr_lazyr(u1, a[1], b[1]);
		} else {
			/* t0 = a_0 * b_0. */
			fp9_mul_dxs_unr_lazyr(u0, a[0], b[0]);
#if EP_ADD == BASIC
			/* t0 = a_1 * b_1. */
			fp_muln_low(u1[1][0], a[1][2][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][2][1], b[1][1][0]);
			fp_muln_low(u1[1][2], a[1][2][2], b[1][1][0]);
			fp3_nord_low(u1[0], u1[1]);
			fp_muln_low(u1[1][0], a[1][0][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][0][1], b[1][1][0]);
			fp_muln_low(u1[1][2], a[1][0][2], b[1][1][0]);
			fp_muln_low(u1[2][0], a[1][1][0], b[1][1][0]);
			fp_muln_low(u1[2][1], a[1][1][1], b[1][1][0]);
			fp_muln_low(u1[2][2], a[1][1][2], b[1][1][0]);
			/* t2 = b_0 + b_1. */
			fp3_copy(t0[0], b[0][0]);
			fp_add(t0[1][0], b[0][1][0], b[1][1][0]);
			fp_copy(t0[1][1], b[0][1][1]);
			fp_copy(t0[1][2], b[0][1][2]);
#elif EP_ADD == PROJC || EP_ADD == JACOB
			/* t1 = a_1 * b_1. */
			fp3_muln_low(u1[1], a[1][2], b[1][1]);
			fp3_nord_low(u1[0], u1[1]);
			fp3_muln_low(u1[1], a[1][0], b[1][1]);
			fp3_muln_low(u1[2], a[1][1], b[1][1]);
			/* t2 = b_0 + b_1. */
			fp3_copy(t0[0], b[0][0]);
			fp3_add(t0[1], b[0][1], b[1][1]);
#endif
		}
		/* c_1 = a_0 + a_1. */
		fp9_add(c[1], a[0], a[1]);
		/* c_1 = (a_0 + a_1) * (b_0 + b_1) */
		fp9_mul_dxs_unr_lazyr(u2, c[1], t0);
		for (int i = 0; i < 3; i++) {
			fp3_subc_low(u2[i], u2[i], u0[i]);
			fp3_subc_low(u2[i], u2[i], u1[i]);
		}
		fp3_rdcn_low(c[1][0], u2[0]);
		fp3_rdcn_low(c[1][1], u2[1]);
		fp3_rdcn_low(c[1][2], u2[2]);

		fp3_nord_low(u2[0], u1[2]);
		fp3_addc_low(u0[0], u0[0], u2[0]);
		fp3_addc_low(u0[1], u0[1], u1[0]);
		fp3_addc_low(u0[2], u0[2], u1[1]);
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp3_rdcn_low(c[0][0], u0[0]);
		fp3_rdcn_low(c[0][1], u0[1]);
		fp3_rdcn_low(c[0][2], u0[2]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp9_free(t0);
		dv9_free_all(u0, u1, u2);
	}
}

#endif

TMPL_FPX_MUL_ART_QUAD(fp18, fp9, fp9_mul_art);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp18, fp9, fp9_mul_art);

TMPL_SQR_CYC_QC(fp18, fp3, fp3_mul_nor);

TMPL_SQR_PCK_QC(fp18, fp3, fp3_mul_nor);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_QUAD(fp18, fp9, dv18, dv9, fp3, dv3, 3, 1,
		fp9_sqr_unr);

TMPL_FPX_SQR_LAZYR(fp18, dv18, fp3, dv3, 6);

TMPL_SQR_PCK_LAZYR_QC(fp18, fp3, dv3, fp3, dv3, 1, 1, fp3_sqrn_low,
		fp3_mul_nor);

TMPL_SQR_CYC_LAZYR_QC(fp18, fp3, dv3, fp3, dv3, 1, 1, fp3_sqrn_low);

#endif

TMPL_FPX_INV_QUAD(fp18, fp9, fp9_mul_art);

TMPL_FPX_INV_CYC_QUAD(fp18, fp9);

TMPL_FPX_EXP_CYC(fp18);

TMPL_FPX_EXP_DIG(fp18);

void fp18_frb(fp18_t c, const fp18_t a, int i) {
	/* Cost of five multiplication in Fp^3 per Frobenius. */
	fp18_copy(c, a);
	for (; i % 18 > 0; i--) {
		fp9_frb(c[0], c[0], 1);
		fp3_frb(c[1][0], c[1][0], 1);
		fp3_frb(c[1][1], c[1][1], 1);
		fp3_frb(c[1][2], c[1][2], 1);
		fp3_mul_frb(c[1][0], c[1][0], 1, 1);
		fp3_mul_frb(c[1][1], c[1][1], 1, 3);
		fp3_mul_frb(c[1][2], c[1][2], 1, 5);
	}
}

TMPL_FPX_CONV_CYC(fp18, 3);

TMPL_FPX_TEST_CYC(fp18, 3);

TMPL_FPX_BACK_CYC_QC(fp18, fp3, fp3_mul_nor);

TMPL_FPX_BACK_CYC_SIM_QC(fp18, fp3, fp3_mul_nor);

TMPL_EXP_CYC(fp18);

TMPL_EXP_CYC_SIM(fp18, fp18_sqr_cyc);

TMPL_EXP_CYC_SPS(fp18);

TMPL_FPX_PCK_QC(fp18, fp3);

TMPL_FPX_UPK_QC(fp18, fp3);
