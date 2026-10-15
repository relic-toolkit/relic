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

TMPL_FPX_BASE(fp24, fp8, 3);

TMPL_FPX_BIN_CQ(fp24, fp8, fp4, 24);

TMPL_FPX_MUL_CUBIC(fp24, fp8, fp8_mul_art);

TMPL_FPX_MUL_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2, fp8_mul_unr);

TMPL_FPX_MUL_LAZYR(fp24, dv24, fp2, dv2, 12);

TMPL_FPX_MUL_ART_CUBIC(fp24, fp8, fp8_mul_art);

void fp24_mul_dxs_basic(fp24_t c, const fp24_t a, const fp24_t b) {
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

void fp24_mul_dxs_unr(dv24_t c, const fp24_t a, const fp24_t b) {
	fp8_t t0, t1;
	dv8_t u0, u1, u2;

	fp8_null_all(t0, t1);
	dv8_null_all(u0, u1, u2);

	RLC_TRY {
		fp8_new_all(t0, t1);
		dv8_new_all(u0, u1, u2);

		/* Karatsuba algorithm without reduction. */
		fp8_mul_unr(u0, a[0], b[0]);
		if (fp8_is_zero(b[2])) {
			/* b_2 = 0: c_0 = a_0b_0 + v * a_2b_1, c_2 = a_1b_1 + a_2b_0 and
			 * c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1. */
			fp8_mul_unr(u1, a[1], b[1]);
			fp8_add(t0, a[0], a[1]);
			fp8_add(t1, b[0], b[1]);
			fp8_mul_unr(u2, t0, t1);
			TMPL_DV_SUBC(fp2, dv2, 4, c[1], u2, u0);
			TMPL_DV_SUBC(fp2, dv2, 4, c[1], c[1], u1);
			fp8_mul_unr(u2, a[2], b[1]);
			TMPL_DV_NADD(fp2, dv2, 4, 2, c[0], u0, u2);
			fp8_mul_unr(u2, a[2], b[0]);
			TMPL_DV_ADDC(fp2, dv2, 4, c[2], u1, u2);
		} else {
			/* b_1 = 0: c_0 = a_0b_0 + v * a_1b_2, c_1 = a_1b_0 + v * a_2b_2 and
			 * c_2 = (a_0 + a_2)(b_0 + b_2) - a_0b_0 - a_2b_2. */
			fp8_mul_unr(u1, a[2], b[2]);
			fp8_add(t0, a[1], a[2]);
			fp8_mul_unr(u2, t0, b[2]);
			TMPL_DV_SUBC(fp2, dv2, 4, u2, u2, u1);
			TMPL_DV_NADD(fp2, dv2, 4, 2, c[0], u0, u2);
			fp8_add(t0, a[0], a[1]);
			fp8_mul_unr(u2, t0, b[0]);
			TMPL_DV_SUBC(fp2, dv2, 4, u2, u2, u0);
			TMPL_DV_NADD(fp2, dv2, 4, 2, c[1], u2, u1);
			fp8_add(t0, a[0], a[2]);
			fp8_add(t1, b[0], b[2]);
			fp8_mul_unr(u2, t0, t1);
			TMPL_DV_SUBC(fp2, dv2, 4, c[2], u2, u0);
			TMPL_DV_SUBC(fp2, dv2, 4, c[2], c[2], u1);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1);
		dv8_free_all(u0, u1, u2);
	}
}

void fp24_mul_dxs_lazyr(fp24_t c, const fp24_t a, const fp24_t b) {
	dv24_t t;

	dv24_null(t);

	RLC_TRY {
		dv24_new(t);
		fp24_mul_dxs_unr(t, a, b);
		TMPL_DV_RDCN(fp2, dv2, 12, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv24_free(t);
	}
}

void fp24_mul_dxs_toom_unr(dv24_t c, const fp24_t a, const fp24_t b) {
	fp8_t e1, e2, f1, f2;
	dv8_t u1, u2, u3;

	if (!fp8_is_zero(b[2])) {
		fp24_mul_dxs_unr(c, a, b);
		return;
	}

	fp8_null_all(e1, e2, f1, f2);
	dv8_null_all(u1, u2, u3);

	RLC_TRY {
		fp8_new_all(e1, e2, f1, f2);
		dv8_new_all(u1, u2, u3);

		/* Toom-2.5 at 0, 1, -1 and infinity for b_2 = 0: with
		 * u_1 = a(1)b(1), u_2 = a(-1)b(-1) and u_3 = a_2b_1, the product has
		 * c_2 = (u_1 + u_2)/2 - a_0b_0, c_1 = (u_1 - u_2)/2 - u_3 and
		 * c_0 = a_0b_0 + v * u_3. */
		fp8_add(e2, a[0], a[2]);
		fp8_add(e1, e2, a[1]);
		fp8_sub(e2, e2, a[1]);
		fp8_add(f1, b[0], b[1]);
		fp8_sub(f2, b[0], b[1]);
		fp8_mul_unr(u1, e1, f1);
		fp8_mul_unr(u2, e2, f2);
		fp8_mul_unr(u3, a[2], b[1]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[2], u1, u2);
		TMPL_DV_SUBC(fp2, dv2, 4, c[1], u1, u2);
		for (int i = 0; i < 8; i++) {
			fp_hlvd_low(((dv_t *)c[2])[i], ((dv_t *)c[2])[i]);
			fp_hlvd_low(((dv_t *)c[1])[i], ((dv_t *)c[1])[i]);
		}
		fp8_mul_unr(u1, a[0], b[0]);
		TMPL_DV_SUBC(fp2, dv2, 4, c[2], c[2], u1);
		TMPL_DV_SUBC(fp2, dv2, 4, c[1], c[1], u3);
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0], u1, u3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(e1, e2, f1, f2);
		dv8_free_all(u1, u2, u3);
	}
}

void fp24_mul_dxs_toom(fp24_t c, const fp24_t a, const fp24_t b) {
	dv24_t t;

	dv24_null(t);

	RLC_TRY {
		dv24_new(t);
		fp24_mul_dxs_toom_unr(t, a, b);
		TMPL_DV_RDCN(fp2, dv2, 12, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv24_free(t);
	}
}

void fp24_mul_toom_unr(dv24_t c, const fp24_t a, const fp24_t b) {
	fp8_t t, e[3], f[3];
	dv8_t u0, u1, u2, u3, u4, s, d1, d3;
	dv_t x0, x1, y0, y1;

	if (fp_prime_get_qnr() != -1) {
		fp24_mul_unr(c, a, b);
		return;
	}

	fp8_null(t);
	dv8_null_all(u0, u1, u2, u3, u4, s, d1, d3);
	dv_null_all(x0, x1, y0, y1);
	for (int i = 0; i < 3; i++) {
		fp8_null(e[i]);
		fp8_null(f[i]);
	}

	RLC_TRY {
		fp8_new(t);
		dv8_new_all(u0, u1, u2, u3, u4, s, d1, d3);
		dv_new_all(x0, x1, y0, y1);
		for (int i = 0; i < 3; i++) {
			fp8_new(e[i]);
			fp8_new(f[i]);
		}

		/* Toom-3 at 0, 1, -1, i and infinity for i^2 = -1, with
		 * a(i) = a_0 - a_2 + i * a_1 computed in each Fp^2 part of Fp^8. */
		for (int k = 0; k < 2; k++) {
			const fp8_t *x = (k == 0 ? a : b);
			fp8_t *y = (k == 0 ? e : f);
			fp8_add(t, x[0], x[2]);
			fp8_add(y[0], t, x[1]);
			fp8_sub(y[1], t, x[1]);
			for (int j = 0; j < 4; j++) {
				fp_sub(y[2][j / 2][j % 2][0], x[0][j / 2][j % 2][0],
						x[2][j / 2][j % 2][0]);
				fp_sub(y[2][j / 2][j % 2][0], y[2][j / 2][j % 2][0],
						x[1][j / 2][j % 2][1]);
				fp_sub(y[2][j / 2][j % 2][1], x[0][j / 2][j % 2][1],
						x[2][j / 2][j % 2][1]);
				fp_add(y[2][j / 2][j % 2][1], y[2][j / 2][j % 2][1],
						x[1][j / 2][j % 2][0]);
			}
		}
		fp8_mul_unr(u0, a[0], b[0]);
		fp8_mul_unr(u1, e[0], f[0]);
		fp8_mul_unr(u2, e[1], f[1]);
		fp8_mul_unr(u3, e[2], f[2]);
		fp8_mul_unr(u4, a[2], b[2]);

		/* Interpolate in each Fp^2 part. With h_j = u_j/2 for j = 1, 2, 3,
		 * P_j = (1 + i) * h_j/2 for j = 1, 2 and T = u_0 + u_4 - h_3, the
		 * product has c_2 = h_1 + h_2 - u_0 - u_4,
		 * c_1 = (P1_1 - P2_0 - T_1) + (T_0 - P1_0 - P2_1) * i and
		 * c_3 = (P1_0 - P2_1 + T_1) + (P1_1 + P2_0 - T_0) * i. */
		for (int j = 0; j < 4; j++) {
			dv_t *v0 = u0[j / 2][j % 2], *v1 = u1[j / 2][j % 2];
			dv_t *v2 = u2[j / 2][j % 2], *v3 = u3[j / 2][j % 2];
			dv_t *v4 = u4[j / 2][j % 2], *w = s[j / 2][j % 2];
			dv_t *r1 = d1[j / 2][j % 2], *r2 = c[2][j / 2][j % 2];
			dv_t *r3 = d3[j / 2][j % 2];
			for (int l = 0; l < 2; l++) {
				fp_hlvd_low(v1[l], v1[l]);
				fp_hlvd_low(v2[l], v2[l]);
				fp_hlvd_low(v3[l], v3[l]);
				fp_addc_low(w[l], v0[l], v4[l]);
				fp_addc_low(r2[l], v1[l], v2[l]);
				fp_subc_low(r2[l], r2[l], w[l]);
				fp_subc_low(w[l], w[l], v3[l]);
			}
			fp_subc_low(x0, v1[0], v1[1]);
			fp_addc_low(x1, v1[0], v1[1]);
			fp_hlvd_low(x0, x0);
			fp_hlvd_low(x1, x1);
			fp_subc_low(y0, v2[0], v2[1]);
			fp_addc_low(y1, v2[0], v2[1]);
			fp_hlvd_low(y0, y0);
			fp_hlvd_low(y1, y1);
			fp_subc_low(r1[0], x1, y0);
			fp_subc_low(r1[0], r1[0], w[1]);
			fp_subc_low(r1[1], w[0], x0);
			fp_subc_low(r1[1], r1[1], y1);
			fp_subc_low(r3[0], x0, y1);
			fp_addc_low(r3[0], r3[0], w[1]);
			fp_addc_low(r3[1], x1, y0);
			fp_subc_low(r3[1], r3[1], w[0]);
		}
		/* Reduce modulo w^3 - v: c_0 + v * c_3, c_1 + v * c_4. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0], u0, d3);
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[1], d1, u4);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t);
		dv8_free_all(u0, u1, u2, u3, u4, s, d1, d3);
		dv_free_all(x0, x1, y0, y1);
		for (int i = 0; i < 3; i++) {
			fp8_free(e[i]);
			fp8_free(f[i]);
		}
	}
}

void fp24_mul_toom(fp24_t c, const fp24_t a, const fp24_t b) {
	dv24_t t;

	dv24_null(t);

	RLC_TRY {
		dv24_new(t);
		fp24_mul_toom_unr(t, a, b);
		TMPL_DV_RDCN(fp2, dv2, 12, c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv24_free(t);
	}
}

TMPL_FPX_SQR_CUBIC(fp24, fp8, fp8_mul_art, 8);

TMPL_SQR_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_SQR_PCK_CQ(fp24, fp4, fp4_mul_art);

TMPL_FPX_SQR_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr, fp8_mul_unr, 8);

TMPL_FPX_SQR_LAZYR(fp24, dv24, fp2, dv2, 12);

TMPL_SQR_PCK_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr, fp4_mul_art);

TMPL_SQR_CYC_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr);

TMPL_FPX_CUB_CYC_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_mul_unr,
		fp4_sqr_unr);

TMPL_FPX_CYC(fp24, fp8, fp4, fp4_mul_art, CQ);

void fp24_frb(fp24_t c, const fp24_t a, int i) {
	ctx_t *ctx = core_get();
	int e;

	fp24_copy(c, a);
	i = i % 24;
	/* Cost of 20 multiplication in Fp^2 per Frobenius. */
	for (; i % 8 > 0; i--) {
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
	/* The power p^8 fixes Fp^8 and maps w to rho * w, for the cube root of
	 * unity rho = z^2 in Fp, where z^3 = -1, so that rho^2 = -z. */
	for (int j = 1; j < 3; j++) {
		e = (j * (i / 8)) % 3;
		if (e > 0) {
			fp8_mul_fp(c[j], c[j], ctx->fp2_p0[2 - e]);
		}
		if (e == 2) {
			fp8_neg(c[j], c[j]);
		}
	}
}

