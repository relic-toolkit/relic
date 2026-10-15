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
 * Implementation of arithmetic in the extension of degree 48 of a prime field.
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

/**
 * Multiplies two 48-extension field elements without reduction with
 * Karatsuba, using Karatsuba or Toom-3 for the products in Fp^24.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first 48-extension field element.
 * @param[in] b				- the second 48-extension field element.
 * @param[in] toom			- the flag to use Toom-3 in Fp^24.
 */
static void fp48_mul_unr_imp(dv48_t c, const fp48_t a, const fp48_t b,
		int toom) {
	fp24_t t0, t1;
	dv24_t u0, u1, u2;

	fp24_null_all(t0, t1);
	dv24_null_all(u0, u1, u2);

	RLC_TRY {
		fp24_new_all(t0, t1);
		dv24_new_all(u0, u1, u2);

		/* Karatsuba algorithm over Karatsuba or Toom-3 products in Fp^24. */
		fp24_add(t0, a[0], a[1]);
		fp24_add(t1, b[0], b[1]);
		if (toom) {
			fp24_mul_toom_unr(u0, a[0], b[0]);
			fp24_mul_toom_unr(u1, a[1], b[1]);
			fp24_mul_toom_unr(u2, t0, t1);
		} else {
			fp24_mul_unr(u0, a[0], b[0]);
			fp24_mul_unr(u1, a[1], b[1]);
			fp24_mul_unr(u2, t0, t1);
		}
		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1. */
		TMPL_DV_SUBC(fp2, dv2, 12, c[1], u2, u0);
		TMPL_DV_SUBC(fp2, dv2, 12, c[1], c[1], u1);
		/* c_0 = u0 + w * u1, where w^3 = v generates Fp^8 over Fp^4. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][0], u0[0], u1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][1], u0[1], u1[0]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][2], u0[2], u1[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free_all(t0, t1);
		dv24_free_all(u0, u1, u2);
	}
}

/**
 * Multiplies a dense and a sparse 48-extension field element without
 * reduction, for a sparse element L + LX * w + LY * w * s, where w^3 = v,
 * s^2 = w and L, LX, LY are in Fp^8. With
 * t = a_1 * LY, a_1 * b_1 = w * t, so c_0 = a_0b_0 + w^2 * t and
 * c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - w * t, where the sparse products in
 * Fp^24 use Karatsuba or Toom-2.5.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the dense 48-extension field element.
 * @param[in] b				- the sparse 48-extension field element.
 * @param[in] toom			- the flag to use Toom-2.5 in Fp^24.
 */
static void fp48_mul_dxs_imp(dv48_t c, const fp48_t a, const fp48_t b,
		int toom) {
	fp24_t s0, s1;
	dv24_t t0, t1, u;

	fp24_null_all(s0, s1);
	dv24_null_all(t0, t1, u);

	RLC_TRY {
		fp24_new_all(s0, s1);
		dv24_new_all(t0, t1, u);

		fp24_add(s0, a[0], a[1]);
		fp8_copy(s1[0], b[0][0]);
		fp8_add(s1[1], b[0][1], b[1][1]);
		fp8_copy(s1[2], b[0][2]);
		if (toom) {
			fp24_mul_dxs_toom_unr(t0, a[0], b[0]);
			fp24_mul_dxs_toom_unr(u, s0, s1);
		} else {
			fp24_mul_dxs_unr(t0, a[0], b[0]);
			fp24_mul_dxs_unr(u, s0, s1);
		}
		fp8_mul_unr(t1[0], a[1][0], b[1][1]);
		fp8_mul_unr(t1[1], a[1][1], b[1][1]);
		fp8_mul_unr(t1[2], a[1][2], b[1][1]);
		/* c_1 = u - (t_0 + w * t), where w * t = v * t_2 + t_0 w + t_1 w^2. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][0], t0[0], t1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][1], t0[1], t1[0]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][2], t0[2], t1[1]);
		TMPL_DV_SUBC(fp2, dv2, 12, c[1], u, c[0]);
		/* c_0 = t_0 + w^2 * t, where
		 * w^2 * t = v * t_1 + v * t_2 w + t_0 w^2. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][0], t0[0], t1[1]);
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][1], t0[1], t1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][2], t0[2], t1[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free_all(s0, s1);
		dv24_free_all(t0, t1, u);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_BASE(fp48, fp24, 2);

TMPL_FPX_BIN_QC(fp48, fp24, fp8, 48);

TMPL_FPX_MUL_QUAD(fp48, fp24, fp24_mul_art);

void fp48_mul_unr(dv48_t c, const fp48_t a, const fp48_t b) {
	fp48_mul_unr_imp(c, a, b, 0);
}

TMPL_FPX_MUL_LAZYR(fp48, dv48, fp2, dv2, 24);

void fp48_mul_dxs_basic(fp48_t c, const fp48_t a, const fp48_t b) {
	fp24_t t0, t1, t2;

	fp24_null_all(t0, t1, t2);

	RLC_TRY {
		fp24_new_all(t0, t1, t2);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp24_mul_dxs(t0, a[0], b[0]);
		/* t1 = a_1 * b_1. */
#if EP_ADD == BASIC
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				for (int k = 0; k < 2; k++) {
					fp_mul(t1[0][i][j][k], a[1][0][i][j][k], b[1][1][0][0][0]);
					fp_mul(t1[1][i][j][k], a[1][1][i][j][k], b[1][1][0][0][0]);
					fp_mul(t1[2][i][j][k], a[1][2][i][j][k], b[1][1][0][0][0]);
				}
			}
		}
#else
		fp8_mul(t1[0], a[1][0], b[1][1]);
		fp8_mul(t1[1], a[1][1], b[1][1]);
		fp8_mul(t1[2], a[1][2], b[1][1]);
#endif
		fp24_mul_art(t1, t1);
		/* t2 = b_0 + b_1. */
		fp8_copy(t2[0], b[0][0]);
#if EP_ADD == BASIC
		fp8_copy(t2[1], b[0][1]);
		fp_add(t2[1][0][0][0], t2[1][0][0][0], b[1][1][0][0][0]);
#else
		fp8_add(t2[1], b[0][1], b[1][1]);
#endif
		fp8_copy(t2[2], b[0][2]);

		/* c_1 = a_0 + a_1. */
		fp24_add(c[1], a[0], a[1]);

		/* c_1 = (a_0 + a_1) * (b_0 + b_1) */
		fp24_mul_dxs(c[1], c[1], t2);
		fp24_sub(c[1], c[1], t0);
		fp24_sub(c[1], c[1], t1);

		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp24_mul_art(t1, t1);
		fp24_add(c[0], t0, t1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free_all(t0, t1, t2);
	}
}

void fp48_mul_dxs_lazyr(fp48_t c, const fp48_t a, const fp48_t b) {
	dv48_t t;

	dv48_null(t);

	RLC_TRY {
		dv48_new(t);
		fp48_mul_dxs_imp(t, a, b, 0);
		TMPL_DV_RDCN(fp2, dv2, 24, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv48_free(t);
	}
}

void fp48_mul_dxs_toom(fp48_t c, const fp48_t a, const fp48_t b) {
	dv48_t t;

	dv48_null(t);

	RLC_TRY {
		dv48_new(t);
		fp48_mul_dxs_imp(t, a, b, 1);
		TMPL_DV_RDCN(fp2, dv2, 24, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv48_free(t);
	}
}

void fp48_mul_toom(fp48_t c, const fp48_t a, const fp48_t b) {
	dv48_t t;

	dv48_null(t);

	RLC_TRY {
		dv48_new(t);
		fp48_mul_unr_imp(t, a, b, 1);
		TMPL_DV_RDCN(fp2, dv2, 24, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv48_free(t);
	}
}

TMPL_FPX_MUL_ART_QUAD(fp48, fp24, fp24_mul_art);

TMPL_FPX_SQR_QUAD(fp48, fp24, fp24_mul_art);

TMPL_SQR_CYC_QC(fp48, fp8, fp8_mul_art);

TMPL_SQR_PCK_QC(fp48, fp8, fp8_mul_art);

void fp48_sqr_unr(dv48_t c, const fp48_t a) {
	fp24_t t;
	dv24_t u0, u1;

	fp24_null(t);
	dv24_null_all(u0, u1);

	RLC_TRY {
		fp24_new(t);
		dv24_new_all(u0, u1);

		fp24_sqr_unr(u0, a[0]);
		fp24_sqr_unr(u1, a[1]);
		fp24_add(t, a[0], a[1]);
		/* c_0 = u0 + w * u1, where w^3 = v generates Fp^8 over Fp^4. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][0], u0[0], u1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][1], u0[1], u1[0]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][2], u0[2], u1[1]);
		/* c_1 = (a_0 + a_1)^2 - a_0^2 - a_1^2. */
		TMPL_DV_ADDC(fp2, dv2, 12, u1, u1, u0);
		fp24_sqr_unr(u0, t);
		TMPL_DV_SUBC(fp2, dv2, 12, c[1], u0, u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free(t);
		dv24_free_all(u0, u1);
	}
}

TMPL_FPX_SQR_LAZYR(fp48, dv48, fp2, dv2, 24);

TMPL_SQR_PCK_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr, fp8_mul_art);

TMPL_SQR_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr);

TMPL_FPX_CUB_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_mul_unr,
		fp8_sqr_unr);

TMPL_FPX_CYC(fp48, fp24, fp8, fp8_mul_art, QC);

void fp48_frb(fp48_t c, const fp48_t a, int i) {
	ctx_t *ctx = core_get();
	int e;

	fp48_copy(c, a);
	i = i % 48;
	/* Cost of 52 multiplication in Fp^2 per Frobenius. */
	for (; i % 16 > 0; i--) {
		fp24_frb(c[0], c[0], 1);
		fp24_frb(c[1], c[1], 1);
		for (int j = 0; j < 3; j++) {
			for (int k = 0; k < 2; k++) {
				for (int l = 0; l < 2; l++) {
					fp2_mul_frb(c[1][j][k][l], c[1][j][k][l], 2, 4);
				}
				if (fp_prime_get_mod8() == 3) {
					fp4_mul_art(c[1][j][k], c[1][j][k]);
				}
			}
			if ((fp_prime_get_mod8() % 4) == 3) {
				fp8_mul_art(c[1][j], c[1][j]);
			}
		}
	}
	/* The power p^16 fixes Fp^8 and maps the coefficient of s^j w^l to its
	 * product by rho^(j + 2l), for the cube root of unity rho = z^2 in Fp,
	 * where z^3 = -1, so that rho^2 = -z. */
	for (int j = 0; j < 2; j++) {
		for (int l = 0; l < 3; l++) {
			e = ((j + 2 * l) * (i / 16)) % 3;
			if (e > 0) {
				fp8_mul_fp(c[j][l], c[j][l], ctx->fp2_p0[2 - e]);
			}
			if (e == 2) {
				fp8_neg(c[j][l], c[j][l]);
			}
		}
	}
}

