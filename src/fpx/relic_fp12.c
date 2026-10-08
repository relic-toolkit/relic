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

#if FPX_RDC == LAZYR || !defined(STRIP)

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

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp12, fp6, 2);

TMPL_FPX_BIN_QC(fp12, fp6, fp2, 12);

TMPL_FPX_CMP(fp12, fp6, 2);

TMPL_FPX_ADD(fp12, fp6, 2);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp12, fp6, fp6_mul_art);

void fp12_mul_dxs_basic(fp12_t c, const fp12_t a, const fp12_t b) {
	fp6_t t0, t1, t2;

	fp6_null_all(t0, t1, t2);

	RLC_TRY {
		fp6_new_all(t0, t1, t2);

		if (ep2_curve_is_twist() == RLC_EP_DTYPE) {
#if EP_ADD == BASIC
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
#elif EP_ADD == PROJC || EP_ADD == JACOB
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
#if EP_ADD == BASIC
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
#elif EP_ADD == PROJC || EP_ADD == JACOB
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

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_QUAD(fp12, fp6, dv12, dv6, fp2, dv2, 3, 1,
		fp6_mul_unr);

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
			fp2_copy(t0[1], b[1][1]);
#elif EP_ADD == PROJC || EP_ADD == JACOB
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
#if EP_ADD == BASIC
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
#elif EP_ADD == PROJC || EP_ADD == JACOB
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

#endif

TMPL_FPX_MUL_ART_QUAD(fp12, fp6, fp6_mul_art);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp12, fp6, fp6_mul_art);

TMPL_SQR_CYC_QC(fp12, fp2, fp2_mul_nor);

TMPL_SQR_PCK_QC(fp12, fp2, fp2_mul_nor);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

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

#endif

TMPL_FPX_INV_QUAD(fp12, fp6, fp6_mul_art);

TMPL_FPX_INV_CYC_QUAD(fp12, fp6);

TMPL_FPX_EXP_CYC(fp12);

TMPL_FPX_EXP_DIG(fp12);

void fp12_frb(fp12_t c, const fp12_t a, int i) {
	/* Cost of five multiplication in Fp^2 per Frobenius. */
	fp12_copy(c, a);
	for (; i % 12 > 0; i--) {
		fp6_frb(c[0], c[0], 1);
		fp2_frb(c[1][0], c[1][0], 1);
		fp2_frb(c[1][1], c[1][1], 1);
		fp2_frb(c[1][2], c[1][2], 1);
		fp2_mul_frb(c[1][0], c[1][0], 1, 1);
		fp2_mul_frb(c[1][1], c[1][1], 1, 3);
		fp2_mul_frb(c[1][2], c[1][2], 1, 5);
	}
}

TMPL_FPX_CONV_CYC(fp12, 2);

TMPL_FPX_TEST_CYC(fp12, 2);

TMPL_FPX_BACK_CYC_QC(fp12, fp2, fp2_mul_nor);

TMPL_FPX_BACK_CYC_SIM_QC(fp12, fp2, fp2_mul_nor);

TMPL_EXP_CYC(fp12);

TMPL_EXP_CYC_SIM(fp12, fp12_sqr_cyc);

TMPL_EXP_CYC_SPS(fp12);

TMPL_FPX_PCK_QC(fp12, fp2);

TMPL_FPX_UPK_QC(fp12, fp2);

void fp12_pck_max(fp12_t c, const fp12_t a) {
	fp12_copy(c, a);
	if (fp12_cmp_dig(a, 1) == RLC_EQ) {
		/* The torus has no representative for unity, so use zero since it
		 * otherwise decompresses to -1, which is not in the subgroup. */
		fp12_zero(c);
	} else if (fp12_test_cyc(c)) {
		/* Use torus-based compression from Section 4.1 in
		 * "On Compressible Pairings and Their Computation" by Naehrig et al.
		 */
		fp2_add_dig(c[0][0], a[0][0], 1);
		fp6_inv(c[1], a[1]);
		fp6_mul(c[0], c[0], c[1]);
		fp6_zero(c[1]);
	}
}

int fp12_upk_max(fp12_t c, const fp12_t a) {
	if (fp12_is_zero(a)) {
		fp12_set_dig(c, 1);
		return 1;
	}
	if (fp6_is_zero(a[1])) {
		fp12_t t;

		fp12_null(t);

		RLC_TRY {
			fp12_new(t);
			/* Formula for decompression for the odd q case from Section 2 in
			 * "Compression in finite fields and torus-based cryptography" by
			 * Rubin-Silverberg.
			 */
			fp6_copy(t[0], a[0]);
			fp6_zero(t[1]);
			fp_set_dig(t[1][0][0], 1);
			fp_neg(t[1][0][0], t[1][0][0]);
			fp12_inv(t, t);
			fp6_copy(c[0], a[0]);
			fp6_set_dig(c[1], 1);
			fp12_mul(c, c, t);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			fp12_free(t);
		}
		if (fp12_test_cyc(c)) {
			return 1;
		} else {
			return 0;
		}
	} else {
		fp12_copy(c, a);
		return 1;
	}
}
