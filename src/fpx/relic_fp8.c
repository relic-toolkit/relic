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
 * Implementation of arithmetic in the octic extension of a prime field.
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
/* Private definitions                                                        */
/*============================================================================*/

#if PP_EXT == LAZYR || !defined(STRIP)

static void fp4_mul_dxs_unr(dv4_t c, const fp4_t a, const fp4_t b) {
	fp2_t t0, t1;
	dv2_t u0, u1;

	fp2_null_all(t0, t1);
	dv2_null_all(u0, u1);

	RLC_TRY {
		fp2_new_all(t0, t1);
		dv2_new_all(u0, u1);

		fp2_muln_low(u1, a[1], b[1]);
		fp2_addm_low(t0, b[0], b[1]);
		fp2_addm_low(t1, a[0], a[1]);

		fp2_muln_low(c[1], t1, t0);
		fp2_subc_low(c[1], c[1], u1);
		fp2_nord_low(c[0], u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
		dv2_free_all(t1, u0, u1);
	}
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp8, fp4, 2);

TMPL_FPX_BIN_T2(fp8, fp4, 8);

TMPL_FPX_CMP(fp8, fp4, 2);

TMPL_FPX_ADD(fp8, fp4, 2);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp8, fp4, fp4_mul_art);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp8_mul_dxs(fp8_t c, const fp8_t a, const fp8_t b) {
	fp4_t t0, t1;
	dv4_t u0, u1, u2, u3;

	fp4_null_all(t0, t1);
	dv4_null_all(u0, u1, u2, u3);

	RLC_TRY {
		fp4_new_all(t0, t1);
		dv4_new_all(u0, u1, u2, u3);

		/* Karatsuba algorithm. */

		/* u0 = a_0 * b_0. */
		fp4_mul_unr(u0, a[0], b[0]);
		/* u1 = a_1 * b_1. */
		fp4_mul_dxs_unr(u1, a[1], b[1]);

		/* t1 = a_0 + a_1. */
		fp4_add(t0, a[0], a[1]);
		/* t0 = b_0 + b_1. */
		fp4_add(t1, b[0], b[1]);
		/* u2 = (a_0 + a_1) * (b_0 + b_1) */
		fp4_mul_unr(u2, t0, t1);
		/* c_1 = u2 - a_0b_0 - a_1b_1. */
		for (int i = 0; i < 2; i++) {
			fp2_addc_low(u3[i], u0[i], u1[i]);
			fp2_subc_low(u2[i], u2[i], u3[i]);
			fp2_rdcn_low(c[1][i], u2[i]);
		}
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_nord_low(u2[0], u1[1]);
		dv_copy(u2[1][0], u1[0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][1], u1[0][1], 2 * RLC_FP_DIGS);
		for (int i = 0; i < 2; i++) {
			fp2_addc_low(u2[i], u0[i], u2[i]);
			fp2_rdcn_low(c[0][i], u2[i]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t0);
		dv4_free_all(t1, u0, u1, u2, u3);
	}
}

TMPL_FPX_MUL_UNR_QUAD(fp8, fp4, dv8, dv4, fp2, dv2, 2, 1,
		fp4_mul_unr);

TMPL_FPX_MUL_LAZYR(fp8, dv8, fp2, dv2, 4);

#endif

TMPL_FPX_MUL_ART_QUAD(fp8, fp4, fp4_mul_art);

void fp8_mul_frb(fp8_t c, const fp8_t a, int i, int j) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp4_new(t);

		fp_copy(t[0], core_get()->fp8_p1[0]);
		fp_copy(t[1], core_get()->fp8_p1[1]);

	    if (i == 1) {
			fp8_copy(c, a);
			for (int k = 0; k < j; k++) {
	        	fp2_mul(c[0][0], c[0][0], t);
				fp2_mul(c[0][1], c[0][1], t);
				fp2_mul(c[1][0], c[1][0], t);
				fp2_mul(c[1][1], c[1][1], t);
				/* If constant in base field, then second component is zero. */
				if (core_get()->frb8 == 1) {
					fp8_mul_art(c, c);
				}
			}
	    } else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t);
	}
}

void fp8_mul_dig(fp8_t c, const fp8_t a, dig_t b) {
	fp4_mul_dig(c[0], a[0], b);
	fp4_mul_dig(c[1], a[1], b);
}

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp8, fp4, fp4_mul_art);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_QUAD(fp8, fp4, dv8, dv4, fp2, dv2, 2, 1,
		fp4_sqr_unr);

TMPL_FPX_SQR_LAZYR(fp8, dv8, fp2, dv2, 4);

#endif

void fp8_sqr_cyc(fp8_t c, const fp8_t a) {
	fp4_t t0, t1, t2;

	fp4_null_all(t0, t1, t2);

	RLC_TRY {
		fp4_new_all(t0, t1, t2);

		fp4_sqr(t0, a[1]);
		fp4_add(t1, a[0], a[1]);
		fp4_sqr(t2, t1);
		fp4_sub(t2, t2, t0);
		fp4_mul_art(c[0], t0);
		fp4_sub(c[1], t2, c[0]);
		fp4_dbl(c[0], c[0]);
		fp_add_dig(c[0][0][0], c[0][0][0], 1);
		fp_sub_dig(c[1][0][0], c[1][0][0], 1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free_all(t0, t1, t2);
	}
}

TMPL_FPX_INV_CYC_QUAD(fp8, fp4);

TMPL_FPX_INV_QUAD(fp8, fp4, fp4_mul_art);

TMPL_FPX_INV_SIM(fp8);

TMPL_FPX_EXP_CYC(fp8);

TMPL_FPX_EXP_DIG(fp8);

void fp8_frb(fp8_t c, const fp8_t a, int i) {
	/* Cost of four multiplication in Fp^2 per Frobenius. */
	fp8_copy(c, a);
	for (; i % 8 > 0; i--) {
		fp4_frb(c[0], c[0], 1);
		fp4_frb(c[1], c[1], 1);
		fp2_mul_frb(c[1][0], c[1][0], 2, 1);
		fp2_mul_frb(c[1][1], c[1][1], 2, 1);
		if (fp_prime_get_mod8() % 4 != 1) {
			fp4_mul_art(c[1], c[1]);
		}
	}
}

TMPL_FPX_CONV_CYC_QUAD(fp8);

TMPL_FPX_TEST_CYC_QUAD(fp8);

TMPL_EXP_CYC_NAF(fp8, fp8_sqr_cyc);

TMPL_EXP_CYC_SIM(fp8, fp8_sqr_cyc);

TMPL_FPX_IS_SQR(fp8, 8);

TMPL_FPX_SRT_QUAD(fp8, fp4, fp4_mul_art, 4);
