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

#if FP_RDC == FP_RENUS && FPX_RDC == FPX_LAZYR
/* Cyclotomic squarings in Fp^24 reduce their whole results, and cost less than
 * compressed squarings with the decompression. */
#define FP24_CYC_PCK		0
#else
#define FP24_CYC_PCK		1
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_BASE(fp24, fp8, 3);

TMPL_FPX_BIN_CQ(fp24, fp8, fp4, 24);

TMPL_FPX_MUL_CUBIC(fp24, fp8, fp8_mul_art);

void fp24_mul_unr(dv24_t c, const fp24_t a, const fp24_t b) {
	fp24_muln_low(c, a, b);
}

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
	fp24_muld_low(c, a, b);
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

TMPL_FPX_SQR_CUBIC(fp24, fp8, fp8_mul_art, 8);

TMPL_SQR_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_SQR_PCK_CQ(fp24, fp4, fp4_mul_art);

void fp24_sqr_unr(dv24_t c, const fp24_t a) {
	fp24_sqrn_low(c, a);
}

TMPL_FPX_SQR_LAZYR(fp24, dv24, fp2, dv2, 12);

TMPL_SQR_PCK_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr);

#if FP_RDC == FP_RENUS

void fp24_sqr_cyc_lazyr(fp24_t c, const fp24_t a) {
	dv24_t u;

	dv24_null(u);

	RLC_TRY {
		dv24_new(u);
		/* The terms are already combined into the square. */
		fp24_sqrc_low(u, a);
		fp2_rdcv_low((fp2_t *)c, (dv2_t *)u, 12);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv24_free(u);
	}
}

#else

TMPL_SQR_CYC_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr);

#endif

TMPL_FPX_CYC(fp24, fp8, fp4, dv4, fp4_mul_art, CQ, FP24_CYC_PCK);

void fp24_frb(fp24_t c, const fp24_t a, int i) {
	ctx_t *ctx = core_get();
	int e, m3 = fp_prime_get_mod18() % 3;
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp24_copy(c, a);
		i = i % 24;
		/* Cost of 20 multiplication in Fp^2 per Frobenius, up to a multiple
		 * of 4 in the power. */
		for (; i % 4 > 0; i--) {
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
		/* The power p^(4m) fixes Fp^4 and maps w^e, for w^12 the non-residue
		 * of Fp^2, to its product by z^(me), for the sixth root of unity z
		 * with z^3 = -1 of the even powers in Fp^12: w^(e(p^4 - 1)) is
		 * z^(e(p^2 + 1) / 2) and (p^2 + 1) / 2 = 1 mod 6. The coefficient of
		 * w^j * s^k in Fp^4, with s = w^3, takes e = j + 3k. */
		for (int j = 0; j < 3 && i > 0; j++) {
			for (int k = 0; k < 2; k++) {
				e = ((i / 4) * (j + 3 * k)) % 6;
				for (int l = 0; l < 2 && e % 3 != 0; l++) {
					if (m3 == 1) {
						fp2_mul_fp(c[j][k][l], c[j][k][l],
								ctx->fp2_p0[e % 3 - 1]);
					} else {
						fp_copy(t[0], ctx->fp2_pz[e % 3 - 1][0]);
						fp_copy(t[1], ctx->fp2_pz[e % 3 - 1][1]);
						fp2_mul(c[j][k][l], c[j][k][l], t);
					}
				}
				if (e >= 3) {
					fp4_neg(c[j][k], c[j][k]);
				}
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

