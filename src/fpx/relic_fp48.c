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

#if FP_RDC == FP_RENUS && FPX_RDC == FPX_LAZYR
/* Cyclotomic squarings in Fp^48 reduce their whole results, and cost less than
 * compressed squarings with the decompression. */
#define FP48_CYC_PCK		0
#else
#define FP48_CYC_PCK		1
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_BASE(fp48, fp24, 2);

TMPL_FPX_BIN_QC(fp48, fp24, fp8, 48);

TMPL_FPX_MUL_QUAD(fp48, fp24, fp24_mul_art);

void fp48_mul_unr(dv48_t c, const fp48_t a, const fp48_t b) {
	fp24_t t0, t1;
	dv24_t u0, u1, u2;

	fp24_null_all(t0, t1);
	dv24_null_all(u0, u1, u2);

	RLC_TRY {
		fp24_new_all(t0, t1);
		dv24_new_all(u0, u1, u2);

		/* Karatsuba algorithm. */
		fp24_mul_unr(u0, a[0], b[0]);
		fp24_mul_unr(u1, a[1], b[1]);
		fp24_add(t0, a[0], a[1]);
		fp24_add(t1, b[0], b[1]);
		fp24_mul_unr(u2, t0, t1);
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

TMPL_FPX_MUL_LAZYR(fp48, dv48, fp2, dv2, 24);

void fp48_mul_dxs_basic(fp48_t c, const fp48_t a, const fp48_t b) {
	fp24_t t0, t1, t2;

	fp24_null_all(t0, t1, t2);

	RLC_TRY {
		fp24_new_all(t0, t1, t2);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp24_mul_dxs(t0, a[0], b[0]);
		/* Lines with their y-coefficient in the prime field are cheaper. */
		fp8_copy(t2[0], b[1][1]);
		fp_zero(t2[0][0][0][0]);
		if (fp8_is_zero(t2[0])) {
			/* t1 = a_1 * b_1. */
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					for (int k = 0; k < 2; k++) {
						fp_mul(t1[0][i][j][k], a[1][0][i][j][k],
							b[1][1][0][0][0]);
						fp_mul(t1[1][i][j][k], a[1][1][i][j][k],
							b[1][1][0][0][0]);
						fp_mul(t1[2][i][j][k], a[1][2][i][j][k],
							b[1][1][0][0][0]);
					}
				}
			}
			/* t2 = b_0 + b_1. */
			fp8_copy(t2[1], b[0][1]);
			fp_add(t2[1][0][0][0], t2[1][0][0][0], b[1][1][0][0][0]);
		} else {
			/* t1 = a_1 * b_1. */
			fp8_mul(t1[0], a[1][0], b[1][1]);
			fp8_mul(t1[1], a[1][1], b[1][1]);
			fp8_mul(t1[2], a[1][2], b[1][1]);
			/* t2 = b_0 + b_1. */
			fp8_add(t2[1], b[0][1], b[1][1]);
		}
		fp24_mul_art(t1, t1);
		fp8_copy(t2[0], b[0][0]);
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
	fp24_t s0, s1;
	dv24_t t0, t1, u;
	dv48_t r;
	int z = 1;

	fp24_null_all(s0, s1);
	dv24_null_all(t0, t1, u);
	dv48_null(r);

	RLC_TRY {
		fp24_new_all(s0, s1);
		dv24_new_all(t0, t1, u);
		dv48_new(r);

		/* For the sparse element L + LX * w + LY * w * s produced by the line
		 * functions, where w^3 = v, s^2 = w and L, LX, LY are in Fp^8, let
		 * t = a_1 * LY. Then a_1 * b_1 = w * t, c_0 = a_0b_0 + w^2 * t and
		 * c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - w * t. */
		fp24_add(s0, a[0], a[1]);
		/* Lines with LY in the prime field are cheaper. They leave the other
		 * coordinates with zero digits, which is faster to test than zero. */
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				for (int k = 0; k < 2; k++) {
					if (i + j + k > 0) {
						z &= dv_is_zero(b[1][1][i][j][k], RLC_FP_LEN);
					}
				}
			}
		}
		if (z) {
			for (int i = 0; i < 3; i++) {
				for (int j = 0; j < 2; j++) {
					for (int k = 0; k < 2; k++) {
						fp_muln_low(t1[i][j][k][0], a[1][i][j][k][0],
							b[1][1][0][0][0]);
						fp_muln_low(t1[i][j][k][1], a[1][i][j][k][1],
							b[1][1][0][0][0]);
					}
				}
			}
		} else {
			fp8_mul_unr(t1[0], a[1][0], b[1][1]);
			fp8_mul_unr(t1[1], a[1][1], b[1][1]);
			fp8_mul_unr(t1[2], a[1][2], b[1][1]);
		}
		fp8_copy(s1[0], b[0][0]);
		fp8_add(s1[1], b[0][1], b[1][1]);
		fp8_copy(s1[2], b[0][2]);
		fp24_mul_dxs_unr(t0, a[0], b[0]);
		fp24_mul_dxs_unr(u, s0, s1);
		/* c_1 = u - (t_0 + w * t), where w * t = v * t_2 + t_0 w + t_1 w^2. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, r[0][0], t0[0], t1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, r[0][1], t0[1], t1[0]);
		TMPL_DV_ADDC(fp2, dv2, 4, r[0][2], t0[2], t1[1]);
		TMPL_DV_SUBC(fp2, dv2, 12, r[1], u, r[0]);
		/* c_0 = t_0 + w^2 * t, where w^2 * t = v * t_1 + v * t_2 w + t_0 w^2. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, r[0][0], t0[0], t1[1]);
		TMPL_DV_NADD(fp2, dv2, 4, 2, r[0][1], t0[1], t1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, r[0][2], t0[2], t1[0]);
		TMPL_DV_RDCN(fp2, dv2, 24, c, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free_all(s0, s1);
		dv24_free_all(t0, t1, u);
		dv48_free(r);
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

TMPL_SQR_PCK_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr);

#if FP_RDC == FP_RENUS

void fp48_sqr_cyc_lazyr(fp48_t c, const fp48_t a) {
	dv48_t u;

	dv48_null(u);

	RLC_TRY {
		dv48_new(u);
		/* The terms are already combined into the square. */
		fp48_sqrc_low(u, a);
		fp2_rdcv_low((fp2_t *)c, (dv2_t *)u, 24);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv48_free(u);
	}
}

#else

TMPL_SQR_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr);

#endif

TMPL_FPX_CUB_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_mul_unr,
		fp8_sqr_unr);

TMPL_FPX_CYC(fp48, fp24, fp8, dv8, fp8_mul_art, QC, FP48_CYC_PCK);

void fp48_frb(fp48_t c, const fp48_t a, int i) {
	ctx_t *ctx = core_get();
	int e, m3 = fp_prime_get_mod18() % 3;
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp48_copy(c, a);
		i = i % 48;
		/* Cost of 52 multiplication in Fp^2 per Frobenius, up to a multiple
		 * of 8 in the power. */
		for (; i % 8 > 0; i--) {
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
		/* The power p^(8m) fixes Fp^8 and maps t^e, for t^24 the non-residue
		 * of Fp^2, to its product by z^(me), for the sixth root of unity z
		 * with z^3 = -1 of the even powers in Fp^12: t^(e(p^8 - 1)) is
		 * z^(e(p^2 + 1)(p^4 + 1) / 4) and (p^2 + 1)(p^4 + 1) / 4 = 1 mod 6.
		 * The coefficient of t^j * w^k in Fp^8, with w = t^2, takes
		 * e = j + 2k. */
		for (int j = 0; j < 2 && i > 0; j++) {
			for (int k = 0; k < 3; k++) {
				e = ((i / 8) * (j + 2 * k)) % 6;
				for (int l = 0; l < 4 && e % 3 != 0; l++) {
					if (m3 == 1) {
						fp2_mul_fp(c[j][k][l / 2][l % 2],
								c[j][k][l / 2][l % 2], ctx->fp2_p0[e % 3 - 1]);
					} else {
						fp_copy(t[0], ctx->fp2_pz[e % 3 - 1][0]);
						fp_copy(t[1], ctx->fp2_pz[e % 3 - 1][1]);
						fp2_mul(c[j][k][l / 2][l % 2], c[j][k][l / 2][l % 2],
								t);
					}
				}
				if (e >= 3) {
					fp8_neg(c[j][k], c[j][k]);
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

