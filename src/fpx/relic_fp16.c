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
 * Implementation of arithmetic in the sextadecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_cyc_tmpl.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp16, fp8, 2);

TMPL_FPX_BIN_T2(fp16, fp8, 16);

TMPL_FPX_CMP(fp16, fp8, 2);

TMPL_FPX_ADD(fp16, fp8, 2);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp16, fp8, fp8_mul_art);

void fp16_mul_dxs_basic(fp16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1, t4;

	fp8_null_all(t0, t1, t4);

	RLC_TRY {
		fp8_new_all(t0, t1, t4);

		/* Karatsuba algorithm. */

		if (fp4_is_zero(b[1][0])) {
			/* t0 = a_0 * b_0. */
			fp8_mul(t0, a[0], b[0]);

			/* t1 = a_1 * b_1. */
			fp4_mul(t1[0], a[1][1], b[1][1]);
			fp4_add(t1[1], a[1][0], a[1][1]);
			fp4_mul(t1[1], t1[1], b[1][1]);
			fp4_sub(t1[1], t1[1], t1[0]);
			fp4_mul_art(t1[0], t1[0]);
		} else {
#if EP_ADD == BASIC
			/* t0 = a_0 * b_0. */
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					for (int k = 0; k < 2; k++) {
						fp_mul(t0[i][j][k], a[0][i][j][k], b[0][0][0][0]);
					}
				}
			}
#else
			/* t0 = a_0 * b_0. */
			for (int i = 0; i < 2; i++) {
				fp4_mul(t0[i], a[0][i], b[0][0]);
			}
#endif
			/* t1 = a_1 * b_1. */
			fp8_mul(t1, a[1], b[1]);
		}
		/* t4 = b_0 + b_1. */
		fp8_add(t4, b[0], b[1]);

		/* c_1 = a_0 + a_1. */
		fp8_add(c[1], a[0], a[1]);

		/* c_1 = (a_0 + a_1) * (b_0 + b_1) */
		fp8_mul(c[1], c[1], t4);
		fp8_sub(c[1], c[1], t0);
		fp8_sub(c[1], c[1], t1);

		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp8_mul_art(t4, t1);
		fp8_add(c[0], t0, t4);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1, t4);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_QUAD(fp16, fp8, dv16, dv8, fp2, dv2, 4, 2,
		fp8_mul_unr);

TMPL_FPX_MUL_LAZYR(fp16, dv16, fp2, dv2, 8);

void fp16_mul_dxs_lazyr(fp16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1;
	dv8_t u0, u1, u2, u3;
	dv16_t t;

	fp8_null_all(t0, t1);
	dv8_null_all(u0, u1, u2, u3);
	dv16_null(t);

	RLC_TRY {
		fp8_new_all(t0, t1);
		dv8_new_all(u0, u1, u2, u3);
		dv16_new(t);

		/* Karatsuba algorithm. */

		if (fp4_is_zero(b[1][0])) {
			/* u0 = a_0 * b_0. */
			fp8_mul_unr(u0, a[0], b[0]);

			/* u1 = a_1 * b_1. */
			fp4_mul_unr(u2[0], a[1][1], b[1][1]);
			fp4_add(t1[0], a[1][0], a[1][1]);
			fp4_mul_unr(u2[1], t1[0], b[1][1]);
			fp2_subc_low(u1[1][0], u2[1][0], u2[0][0]);
			fp2_subc_low(u1[1][1], u2[1][1], u2[0][1]);
			fp2_nord_low(u1[0][0], u2[0][1]);
			dv_copy(u1[0][1][0], u2[0][0][0], 2 * RLC_FP_DIGS);
			dv_copy(u1[0][1][1], u2[0][0][1], 2 * RLC_FP_DIGS);
		} else {
#if EP_ADD == BASIC
			/* u0 = a_0 * b_0. */
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					for (int k = 0; k < 2; k++) {
						fp_muln_low(u0[i][j][k], a[0][i][j][k], b[0][0][0][0]);
					}
				}
			}
#else
			/* u0 = a_0 * b_0. */
			for (int i = 0; i < 2; i++) {
				fp4_mul_unr(u0[i], a[0][i], b[0][0]);
			}
#endif
			/* u1 = a_1 * b_1. */
			fp8_mul_unr(u1, a[1], b[1]);
		}
		/* t1 = a_0 + a_1. */
		fp8_add(t0, a[0], a[1]);
		/* t0 = b_0 + b_1. */
		fp8_add(t1, b[0], b[1]);
		/* u2 = (a_0 + a_1) * (b_0 + b_1) */
		fp8_mul_unr(u2, t0, t1);

		/* c_1 = u2 - a_0b_0 - a_1b_1. */
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				fp2_subc_low(t[1][i][j], u2[i][j], u0[i][j]);
				fp2_subc_low(t[1][i][j], t[1][i][j], u1[i][j]);
			}
		}
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_nord_low(u2[0][0], u1[1][1]);
		dv_copy(u2[0][1][0], u1[1][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[0][1][1], u1[1][0][1], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][0][0], u1[0][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][0][1], u1[0][0][1], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][1][0], u1[0][1][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][1][1], u1[0][1][1], 2 * RLC_FP_DIGS);
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				fp2_addc_low(t[0][i][j], u0[i][j], u2[i][j]);
			}
		}
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				for (int k = 0; k < 2; k++) {
					fp2_rdcn_low(c[i][j][k], t[i][j][k]);
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1);
		dv8_free_all(u0, u1, u2, u3);
		dv16_free(t);
	}
}

#endif

TMPL_FPX_MUL_ART_QUAD(fp16, fp8, fp8_mul_art);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp16, fp8, fp8_mul_art);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_QUAD(fp16, fp8, dv16, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr);

TMPL_FPX_SQR_LAZYR(fp16, dv16, fp2, dv2, 8);

#endif

void fp16_sqr_cyc(fp16_t c, const fp16_t a) {
	fp8_t t0, t1, t2;

	fp8_null_all(t0, t1, t2);

	RLC_TRY {
		fp8_new_all(t0, t1, t2);

		fp8_sqr(t0, a[1]);
		fp8_add(t1, a[0], a[1]);
		fp8_sqr(t2, t1);
		fp8_sub(t2, t2, t0);
		fp8_mul_art(c[0], t0);
		fp8_sub(c[1], t2, c[0]);
		fp8_dbl(c[0], c[0]);
		fp_add_dig(c[0][0][0][0], c[0][0][0][0], 1);
		fp_sub_dig(c[1][0][0][0], c[1][0][0][0], 1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1, t2);
	}
}

TMPL_FPX_INV_CYC_QUAD(fp16, fp8);

TMPL_FPX_INV_QUAD(fp16, fp8, fp8_mul_art);

TMPL_FPX_INV_SIM(fp16);

TMPL_FPX_EXP_CYC(fp16);

TMPL_FPX_EXP_DIG(fp16);

void fp16_frb(fp16_t c, const fp16_t a, int i) {
	/* Cost of four multiplication in Fp^2 per Frobenius. */
	fp16_copy(c, a);
	for (; i % 8 > 0; i--) {
		fp8_frb(c[0], c[0], 1);
		fp8_frb(c[1], c[1], 1);
		fp2_mul_frb(c[1][0][0], c[1][0][0], 2, 2);
		fp2_mul_frb(c[1][0][1], c[1][0][1], 2, 2);
		fp2_mul_frb(c[1][1][0], c[1][1][0], 2, 2);
		fp2_mul_frb(c[1][1][1], c[1][1][1], 2, 2);
		if (fp_prime_get_mod8() % 4 != 1) {
			fp8_mul_art(c[1], c[1]);
		}
		if (fp_prime_get_mod8() == 5) {
			fp4_mul_art(c[1][0], c[1][0]);
			fp4_mul_art(c[1][1], c[1][1]);
		}
	}
}

TMPL_FPX_CONV_CYC_QUAD(fp16);

TMPL_FPX_TEST_CYC_QUAD(fp16);

TMPL_EXP_CYC_NAF(fp16, fp16_sqr_cyc);

TMPL_EXP_CYC_SIM(fp16, fp16_sqr_cyc);

TMPL_FPX_IS_SQR(fp16, 16);

TMPL_FPX_SRT_QUAD(fp16, fp8, fp8_mul_art, 8);
