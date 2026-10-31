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
			/* Lines with their y-coefficient in the prime field are cheaper. */
			if (fp_is_zero(b[0][0][1])) {
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
			} else {
				/* t0 = a_0 * b_0 */
				fp2_mul(t0[0], a[0][0], b[0][0]);
				fp2_mul(t0[1], a[0][1], b[0][0]);
				fp2_mul(t0[2], a[0][2], b[0][0]);
				/* t2 = b_0 + b_1. */
				fp2_add(t2[0], b[0][0], b[1][0]);
				fp2_copy(t2[1], b[1][1]);
			}
			/* t1 = a_1 * b_1. */
			fp6_mul_dxs(t1, a[1], b[1]);
		} else {
			/* t0 = a_0 * b_0. */
			fp6_mul_dxs(t0, a[0], b[0]);
			/* Lines with their y-coefficient in the prime field are cheaper. */
			if (fp_is_zero(b[1][1][1])) {
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
			} else {
				/* t1 = a_1 * b_1. */
				fp2_mul(t2[0], a[1][2], b[1][1]);
				fp2_mul_nor(t1[0], t2[0]);
				fp2_mul(t1[1], a[1][0], b[1][1]);
				fp2_mul(t1[2], a[1][1], b[1][1]);
				/* t2 = b_0 + b_1. */
				fp2_copy(t2[0], b[0][0]);
				fp2_add(t2[1], b[0][1], b[1][1]);
			}
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

void fp12_mul_unr(dv12_t c, const fp12_t a, const fp12_t b) {
	fp12_muln_low(c, a, b);
}

TMPL_FPX_MUL_LAZYR(fp12, dv12, fp2, dv2, 6);

void fp12_mul_dxs_lazyr(fp12_t c, const fp12_t a, const fp12_t b) {
	dv12_t t;

	dv12_null(t);

	RLC_TRY {
		dv12_new(t);
		fp12_muld_low(t, a, b);
		fp2_rdcv_low((fp2_t *)c, (dv2_t *)t, 6);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv12_free(t);
	}
}

TMPL_FPX_MUL_ART_QUAD(fp12, fp6, fp6_mul_art);

TMPL_FPX_SQR_QUAD(fp12, fp6, fp6_mul_art);

TMPL_SQR_CYC_QC(fp12, fp2, fp2_mul_nor);

TMPL_SQR_PCK_QC(fp12, fp2, fp2_mul_nor);

void fp12_sqr_unr(dv12_t c, const fp12_t a) {
	fp12_sqrn_low(c, a);
}

TMPL_FPX_SQR_LAZYR(fp12, dv12, fp2, dv2, 6);

void fp12_sqr_pck_lazyr(fp12_t c, const fp12_t a) {
	dv12_t u;
	fp12_t t;
	fp2_t x;

	dv12_null(u);
	fp12_null(t);
	fp2_null(x);

	RLC_TRY {
		dv12_new(u);
		fp12_new(t);
		fp2_new(x);

		fp12_sqrc_low(u, a, 1);
		/* Move the term of c_12 next to the others, to reduce them at once. */
		dv_copy(u[1][1][0], u[1][2][0], RLC_FP_DLEN);
		dv_copy(u[1][1][1], u[1][2][1], RLC_FP_DLEN);
		fp2_rdcv_low(&t[0][1], &u[0][1], 4);
		/* c_0j = 3 * t_0j - 2 * a_0j, c_1j = 3 * t_1j + 2 * a_1j. */
		for (int j = 1; j < 3; j++) {
			fp2_sub(x, t[0][j], a[0][j]);
			fp2_dbl(x, x);
			fp2_add(c[0][j], t[0][j], x);
		}
		fp2_add(x, t[1][0], a[1][0]);
		fp2_dbl(x, x);
		fp2_add(c[1][0], t[1][0], x);
		fp2_add(x, t[1][1], a[1][2]);
		fp2_dbl(x, x);
		fp2_add(c[1][2], t[1][1], x);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv12_free(u);
		fp12_free(t);
		fp2_free(x);
	}
}

void fp12_sqr_cyc_lazyr(fp12_t c, const fp12_t a) {
	dv12_t u;
	fp12_t t;
	fp2_t x;

	dv12_null(u);
	fp12_null(t);
	fp2_null(x);

	RLC_TRY {
		dv12_new(u);
		fp12_new(t);
		fp2_new(x);

		fp12_sqrc_low(u, a, 0);
		fp2_rdcv_low((fp2_t *)t, (dv2_t *)u, 6);
		/* c_0j = 3 * t_0j - 2 * a_0j, c_1j = 3 * t_1j + 2 * a_1j. */
		for (int j = 0; j < 3; j++) {
			fp2_sub(x, t[0][j], a[0][j]);
			fp2_dbl(x, x);
			fp2_add(c[0][j], t[0][j], x);
			fp2_add(x, t[1][j], a[1][j]);
			fp2_dbl(x, x);
			fp2_add(c[1][j], t[1][j], x);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv12_free(u);
		fp12_free(t);
		fp2_free(x);
	}
}

TMPL_FPX_CUB_CYC_LAZYR_QC(fp12, fp2, dv2, fp2, dv2, 1, 1, fp2_muln_low,
		fp2_sqrn_low);

TMPL_FPX_CYC(fp12, fp6, fp2, fp2_mul_nor, QC);

void fp12_frb(fp12_t c, const fp12_t a, int i) {
	ctx_t *ctx = core_get();
	int e, m3 = fp_prime_get_mod18() % 3;
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

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
			if (m3 == 2) {
				/* For p = 2 mod 3, the Frobenius swaps w and w^5. */
				fp2_copy(t, c[1][0]);
				fp2_copy(c[1][0], c[1][2]);
				fp2_copy(c[1][2], t);
			}
		}
		/* The power p^(2m) maps the coefficient of w^j to its product by
		 * z^(mj), for a sixth root of unity z with z^3 = -1, which lies in
		 * Fp if p = 1 mod 3 and in Fp^2 otherwise. */
		for (int j = 1; j < 6 && i > 1; j++) {
			e = ((i / 2) * j) % 6;
			if (e % 3 != 0) {
				if (m3 == 1) {
					fp2_mul_fp(c[j % 2][j / 2], c[j % 2][j / 2],
							ctx->fp2_p0[e % 3 - 1]);
				} else {
					fp_copy(t[0], ctx->fp2_pz[e % 3 - 1][0]);
					fp_copy(t[1], ctx->fp2_pz[e % 3 - 1][1]);
					fp2_mul(c[j % 2][j / 2], c[j % 2][j / 2], t);
				}
			}
			if (e >= 3) {
				fp2_neg(c[j % 2][j / 2], c[j % 2][j / 2]);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}
