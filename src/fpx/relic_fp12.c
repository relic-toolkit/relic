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
 * Implementation of arithmetic in the dodecic extension of a prime field.
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

inline static void fp6_mul_dxs_unr_lazyr(dv6_t c, const fp6_t a, const fp6_t b) {
	dv2_t u0, u1, u2, u3;
	fp2_t t0, t1;

	dv2_null_all(u0, u1, u2, u3);
	fp2_null_all(t0, t1);

	RLC_TRY {
		dv2_new_all(u0, u1, u2, u3);
		fp2_new_all(t0, t1);

		fp2_muln_low(u0, a[0], b[0]);
		fp2_muln_low(u1, a[1], b[1]);
		fp2_addm_low(t0, a[0], a[1]);
		fp2_addm_low(t1, b[0], b[1]);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1 */
		fp2_muln_low(u2, t0, t1);
		fp2_subc_low(u2, u2, u0);
		fp2_subc_low(c[1], u2, u1);

		/* c_0 = a_0b_0 + E a_2b_1 */
		fp2_muln_low(u2, a[2], b[1]);
		fp2_nord_low(c[0], u2);
		fp2_addc_low(c[0], u0, c[0]);

		/* c_2 = a_0b_2 + a_1b_1 */
		fp2_muln_low(u2, a[2], b[0]);
		fp2_addc_low(c[2], u1, u2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free_all(u0, u1, u2, u3);
		fp2_free_all(t0, t1);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_BASE(fp12, fp6, 2);

TMPL_FPX_BIN_QC(fp12, fp6, fp2, 12);

TMPL_FPX_MUL_QUAD(fp12, fp6, fp6_mul_art);

void fp12_mul_dxs_basic(fp12_t c, const fp12_t a, const fp12_t b) {
	fp6_t t0, t1, t2;

	fp6_null_all(t0, t1, t2);

	RLC_TRY {
		fp6_new_all(t0, t1, t2);

		if (ep2_curve_is_twist() == RLC_EP_DTYPE) {
#if EP_ADD == EP_BASIC
			/* t0 = a_0 * b_0 */
			fp_mul(t0[0][0], a[0][0][0], b[0][0][0]);
			fp_mul(t0[0][1], a[0][0][1], b[0][0][0]);
			fp_mul(t0[1][0], a[0][1][0], b[0][0][0]);
			fp_mul(t0[1][1], a[0][1][1], b[0][0][0]);
			fp_mul(t0[2][0], a[0][2][0], b[0][0][0]);
			fp_mul(t0[2][1], a[0][2][1], b[0][0][0]);
			/* t2 = b_0 + b_1. */
			fp_add(t2[0][0], b[0][0][0], b[1][0][0]);
			fp_copy(t2[0][1], b[1][0][1]);
			fp2_copy(t2[1], b[1][1]);
#elif EP_ADD == EP_PROJC || EP_ADD == EP_JACOB
			/* t0 = a_0 * b_0 */
			fp2_mul(t0[0], a[0][0], b[0][0]);
			fp2_mul(t0[1], a[0][1], b[0][0]);
			fp2_mul(t0[2], a[0][2], b[0][0]);
			/* t2 = b_0 + b_1. */
			fp2_add(t2[0], b[0][0], b[1][0]);
			fp2_copy(t2[1], b[1][1]);
#endif
			/* t1 = a_1 * b_1. */
			fp6_mul_dxs(t1, a[1], b[1]);
		} else {
			/* t0 = a_0 * b_0. */
			fp6_mul_dxs(t0, a[0], b[0]);
#if EP_ADD == EP_BASIC
			/* t1 = a_1 * b_1. */
			fp_mul(t2[0][0], a[1][2][0], b[1][1][0]);
			fp_mul(t2[0][1], a[1][2][1], b[1][1][0]);
			fp2_mul_nor(t1[0], t2[0]);
			fp_mul(t1[1][0], a[1][0][0], b[1][1][0]);
			fp_mul(t1[1][1], a[1][0][1], b[1][1][0]);
			fp_mul(t1[2][0], a[1][1][0], b[1][1][0]);
			fp_mul(t1[2][1], a[1][1][1], b[1][1][0]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t2[0], b[0][0]);
			fp_add(t2[1][0], b[0][1][0], b[1][1][0]);
			fp_copy(t2[1][1], b[0][1][1]);
#elif EP_ADD == EP_PROJC || EP_ADD == EP_JACOB
			/* t1 = a_1 * b_1. */
			fp2_mul(t2[0], a[1][2], b[1][1]);
			fp2_mul_nor(t1[0], t2[0]);
			fp2_mul(t1[1], a[1][0], b[1][1]);
			fp2_mul(t1[2], a[1][1], b[1][1]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t2[0], b[0][0]);
			fp2_add(t2[1], b[0][1], b[1][1]);
#endif
		}
		/* c_1 = a_0 + a_1. */
		fp6_add(c[1], a[0], a[1]);
		/* c_1 = (a_0 + a_1) * (b_0 + b_1) - a_0 * b_0 - a_1 * b_1. */
		fp6_mul_dxs(c[1], c[1], t2);
		fp6_sub(c[1], c[1], t0);
		fp6_sub(c[1], c[1], t1);
		/* c_0 = a_0 * b_0 + v * a_1 * b_1. */
		fp6_mul_art(t1, t1);
		fp6_add(c[0], t0, t1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp6_free_all(t0, t1, t2);
	}
}

TMPL_FPX_MUL_UNR_QUAD(fp12, fp6, dv12, dv6, fp2, dv2, 3, 1, fp6_mul_unr);

TMPL_FPX_MUL_LAZYR(fp12, dv12, fp2, dv2, 6);

void fp12_mul_dxs_lazyr(fp12_t c, const fp12_t a, const fp12_t b) {
	fp6_t t0;
	dv6_t u0, u1, u2;

	fp6_null(t0);
	dv6_null_all(u0, u1, u2);

	RLC_TRY {
		fp6_new(t0);
		dv6_new_all(u0, u1, u2);

		if (ep2_curve_is_twist() == RLC_EP_DTYPE) {
#if EP_ADD == EP_BASIC
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
			fp2_copy(t0[1], b[1][1]);
#elif EP_ADD == EP_PROJC || EP_ADD == EP_JACOB
			/* t0 = a_0 * b_0. */
			fp2_muln_low(u0[0], a[0][0], b[0][0]);
			fp2_muln_low(u0[1], a[0][1], b[0][0]);
			fp2_muln_low(u0[2], a[0][2], b[0][0]);
			
			/* t2 = b_0 + b_1. */
			fp2_add(t0[0], b[0][0], b[1][0]);
			fp2_copy(t0[1], b[1][1]);
#endif
			/* t1 = a_1 * b_1. */
			fp6_mul_dxs_unr_lazyr(u1, a[1], b[1]);
		} else {
			/* t0 = a_0 * b_0. */
			fp6_mul_dxs_unr_lazyr(u0, a[0], b[0]);
#if EP_ADD == EP_BASIC
			/* t0 = a_0 * b_0. */
			fp_muln_low(u1[1][0], a[1][2][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][2][1], b[1][1][0]);
			fp2_nord_low(u1[0], u1[1]);
			fp_muln_low(u1[1][0], a[1][0][0], b[1][1][0]);
			fp_muln_low(u1[1][1], a[1][0][1], b[1][1][0]);
			fp_muln_low(u1[2][0], a[1][1][0], b[1][1][0]);
			fp_muln_low(u1[2][1], a[1][1][1], b[1][1][0]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t0[0], b[0][0]);
			fp_add(t0[1][0], b[0][1][0], b[1][1][0]);
			fp_copy(t0[1][1], b[0][1][1]);
#elif EP_ADD == EP_PROJC || EP_ADD == EP_JACOB
			/* t1 = a_1 * b_1. */
			fp2_muln_low(u1[1], a[1][2], b[1][1]);
			fp2_nord_low(u1[0], u1[1]);
			fp2_muln_low(u1[1], a[1][0], b[1][1]);
			fp2_muln_low(u1[2], a[1][1], b[1][1]);
			/* t2 = b_0 + b_1. */
			fp2_copy(t0[0], b[0][0]);
			fp2_add(t0[1], b[0][1], b[1][1]);
#endif
		}
		/* c_1 = a_0 + a_1. */
		fp6_add(c[1], a[0], a[1]);
		/* c_1 = (a_0 + a_1) * (b_0 + b_1) */
		fp6_mul_dxs_unr_lazyr(u2, c[1], t0);
		for (int i = 0; i < 3; i++) {
			fp2_subc_low(u2[i], u2[i], u0[i]);
			fp2_subc_low(u2[i], u2[i], u1[i]);
		}
		fp2_rdcn_low(c[1][0], u2[0]);
		fp2_rdcn_low(c[1][1], u2[1]);
		fp2_rdcn_low(c[1][2], u2[2]);

		fp2_nord_low(u2[0], u1[2]);
		fp2_addc_low(u0[0], u0[0], u2[0]);
		fp2_addc_low(u0[1], u0[1], u1[0]);
		fp2_addc_low(u0[2], u0[2], u1[1]);
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_rdcn_low(c[0][0], u0[0]);
		fp2_rdcn_low(c[0][1], u0[1]);
		fp2_rdcn_low(c[0][2], u0[2]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp6_free(t0);
		dv6_free_all(u0, u1, u2);
	}
}

TMPL_FPX_MUL_ART_QUAD(fp12, fp6, fp6_mul_art);

TMPL_FPX_SQR_QUAD(fp12, fp6, fp6_mul_art);

TMPL_SQR_CYC_QC(fp12, fp2, fp2_mul_nor);

TMPL_SQR_PCK_QC(fp12, fp2, fp2_mul_nor);

void fp12_sqr_unr(dv12_t c, const fp12_t a) {
	fp4_t t0, t1;
	dv4_t u0, u1, u2, u3, u4;

	fp4_null_all(t0, t1);
	dv4_null_all(u0, u1, u2, u3, u4);

	RLC_TRY {
		fp4_new_all(t0, t1);
		dv4_new_all(u0, u1, u2, u3, u4);

		/* a0 = (a00, a11). */
		/* a1 = (a10, a02). */
		/* a2 = (a01, a12). */

		/* (t0,t1) = a0^2 */
		fp2_copy(t0[0], a[0][0]);
		fp2_copy(t0[1], a[1][1]);
		fp4_sqr_unr(u0, t0);

		/* (t2,t3) = 2 * a1 * a2 */
		fp2_copy(t0[0], a[1][0]);
		fp2_copy(t0[1], a[0][2]);
		fp2_copy(t1[0], a[0][1]);
		fp2_copy(t1[1], a[1][2]);
		fp4_mul_unr(u1, t0, t1);
		fp2_addc_low(u1[0], u1[0], u1[0]);
		fp2_addc_low(u1[1], u1[1], u1[1]);

		/* (t4,t5) = a2^2. */
		fp4_sqr_unr(u2, t1);

		/* c2 = a0 + a2. */
		fp2_addm_low(t1[0], a[0][0], a[0][1]);
		fp2_addm_low(t1[1], a[1][1], a[1][2]);

		/* (t6,t7) = (a0 + a2 + a1)^2. */
		fp2_addm_low(t0[0], t1[0], a[1][0]);
		fp2_addm_low(t0[1], t1[1], a[0][2]);
		fp4_sqr_unr(u3, t0);

		/* c2 = (a0 + a2 - a1)^2. */
		fp2_subm_low(t0[0], t1[0], a[1][0]);
		fp2_subm_low(t0[1], t1[1], a[0][2]);
		fp4_sqr_unr(u4, t0);

		/* c2 = (c2 + (t6,t7))/2. */
#ifdef RLC_FP_ROOM
		fp2_addd_low(u4[0], u4[0], u3[0]);
		fp2_addd_low(u4[1], u4[1], u3[1]);
#else
		fp2_addc_low(u4[0], u4[0], u3[0]);
		fp2_addc_low(u4[1], u4[1], u3[1]);
#endif
		fp_hlvd_low(u4[0][0], u4[0][0]);
		fp_hlvd_low(u4[0][1], u4[0][1]);
		fp_hlvd_low(u4[1][0], u4[1][0]);
		fp_hlvd_low(u4[1][1], u4[1][1]);

		/* (t6,t7) = (t6,t7) - c2 - (t2,t3). */
		fp2_subc_low(u3[0], u3[0], u4[0]);
		fp2_subc_low(u3[1], u3[1], u4[1]);
		fp2_subc_low(u3[0], u3[0], u1[0]);
		fp2_subc_low(u3[1], u3[1], u1[1]);

		/* c2 = c2 - (t0,t1) - (t4,t5). */
		fp2_subc_low(u4[0], u4[0], u0[0]);
		fp2_subc_low(u4[1], u4[1], u0[1]);
		fp2_subc_low(c[0][1], u4[0], u2[0]);
		fp2_subc_low(c[1][2], u4[1], u2[1]);

		/* c1 = (t6,t7) + (t4,t5) * E. */
		fp2_nord_low(u4[1], u2[1]);
		fp2_addc_low(c[1][0], u3[0], u4[1]);
		fp2_addc_low(c[0][2], u3[1], u2[0]);

		/* c0 = (t0,t1) + (t2,t3) * E. */
		fp2_nord_low(u4[1], u1[1]);
		fp2_addc_low(c[0][0], u0[0], u4[1]);
		fp2_addc_low(c[1][1], u0[1], u1[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free_all(t0, t1);
		dv4_free_all(u0, u1, u2, u3, u4);
	}
}

TMPL_FPX_SQR_LAZYR(fp12, dv12, fp2, dv2, 6);

TMPL_SQR_PCK_LAZYR_QC(fp12, fp2, dv2, fp2, dv2, 1, 1, fp2_sqrn_low,
		fp2_norm_low);

TMPL_SQR_CYC_LAZYR_QC(fp12, fp2, dv2, fp2, dv2, 1, 1, fp2_sqrn_low);

TMPL_FPX_CUB_CYC_LAZYR_QC(fp12, fp2, dv2, fp2, dv2, 1, 1, fp2_muln_low,
		fp2_sqrn_low);

TMPL_FPX_CYC(fp12, fp6, fp2, fp2_mul_nor, QC);

void fp12_frb(fp12_t c, const fp12_t a, int i) {
	ctx_t *ctx = core_get();
	int e;

	fp12_copy(c, a);
	i = i % 12;
	if (i % 2 == 1) {
		/* Cost of five multiplications in Fp^2 for an odd power. */
		fp6_frb(c[0], c[0], 1);
		fp2_frb(c[1][0], c[1][0], 1);
		fp2_frb(c[1][1], c[1][1], 1);
		fp2_frb(c[1][2], c[1][2], 1);
		fp2_mul_frb(c[1][0], c[1][0], 1, 1);
		fp2_mul_frb(c[1][1], c[1][1], 1, 3);
		fp2_mul_frb(c[1][2], c[1][2], 1, 5);
	}
	/* The power p^(2m) maps the coefficient of w^j to its product by z^(mj),
	 * for the sixth root of unity z in Fp, with z^3 = -1. */
	for (int j = 1; j < 6 && i > 1; j++) {
		e = ((i / 2) * j) % 6;
		if (e % 3 != 0) {
			fp2_mul_fp(c[j % 2][j / 2], c[j % 2][j / 2],
					ctx->fp2_p0[e % 3 - 1]);
		}
		if (e >= 3) {
			fp2_neg(c[j % 2][j / 2], c[j % 2][j / 2]);
		}
	}
}
