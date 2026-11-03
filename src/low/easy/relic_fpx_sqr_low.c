/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of the low-level extension field squaring functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/* Defining FP2_ASM leaves out the Fp2 functions, so they can be replaced. */
#ifndef FP2_ASM

void fp2_sqrn_low(dv2_t c, const fp2_t a) {
	rlc_align dig_t t0[RLC_FP_DLEN], t1[RLC_FP_DLEN], t2[RLC_FP_DLEN];

	/* t0 = (a0 + a1). */
#ifdef RLC_FP_ROOM
	/* if we have room for carries, we can avoid reductions here. */
	fp_addn_low(t0, a[0], a[1]);
#else
	fp_addm_low(t0, a[0], a[1]);
#endif
	/* t1 = (a0 - a1). */
	fp_subm_low(t1, a[0], a[1]);

#ifdef FP_QNRES

#ifdef RLC_FP_ROOM
	fp_dbln_low(t2, a[0]);
#else
	fp_dblm_low(t2, a[0]);
#endif
	/* c1 = 2 * a0 * a1. */
	fp_muln_low(c[1], t2, a[1]);
	/* c_0 = a_0^2 + a_1^2 * u^2. */
	fp_muln_low(c[0], t0, t1);

#else /* !FP_QNRES */

	if (fp_prime_get_qnr() == -1) {
		/* t2 = 2 * a0. */
		fp_dbl(t2, a[0]);
		/* c1 = 2 * a0 * a1. */
		fp_muln_low(c[1], t2, a[1]);
		/* c0 = a0^2 + a_1^2 * u^2. */
		fp_muln_low(c[0], t0, t1);
	} else {
		/* t1 = a0 + a1 * u^2, with u^2 < 0. */
		fp_mul_dig(t2, a[1], -fp_prime_get_qnr());
		fp_subm_low(t1, a[0], t2);
		/* c1 = a0 * a1. */
		fp_muln_low(c[1], a[0], a[1]);
		/* c0 = a0^2 + b_0^2 * u^2. */
		fp_muln_low(c[0], t0, t1);

		/* c0 += (|u^2| - 1) * a0 * a1. */
		fp2_mul1_low(t2, c[1], -fp_prime_get_qnr() - 1);
		fp_addc_low(c[0], c[0], t2);
#ifdef RLC_FP_ROOM
		/* c1 = 2 * a0 * a1. */
		fp_addd_low(c[1], c[1], c[1]);
#else
		/* c1 = 2 * a0 * a1. */
		fp_addc_low(c[1], c[1], c[1]);
#endif
	}
#endif
	/* c = c0 + c1 * u. */
}

void fp2_sqrm_low(fp2_t c, const fp2_t a) {
	rlc_align dv2_t t;

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);
		fp2_sqrn_low(t, a);
		fp2_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(t);
	}
}

#endif

/* Defining FP3_ASM leaves out the Fp3 functions, so they can be replaced. */
#ifndef FP3_ASM

void fp3_sqrn_low(dv3_t c, const fp3_t a) {
	rlc_align dig_t t0[RLC_FP_DLEN], t1[RLC_FP_DLEN], t2[RLC_FP_DLEN];
	rlc_align dig_t t3[RLC_FP_DLEN], t4[RLC_FP_DLEN];

	/* t0 = a_0^2. */
	fp_sqrn_low(t0, a[0]);

	/* t1 = 2 * a_1 * a_2. */
#ifdef RLC_FP_ROOM
	fp_dbln_low(t2, a[1]);
#else
	fp_dblm_low(t2, a[1]);
#endif

	fp_muln_low(t1, t2, a[2]);

	/* t3 = (a_0 + a_2 + a_1)^2, t4 = (a_0 + a_2 - a_1)^2. */
#ifdef RLC_FP_ROOM
	fp_addn_low(t3, a[0], a[2]);
	fp_addn_low(t4, t3, a[1]);
#else
	fp_addm_low(t3, a[0], a[2]);
	fp_addm_low(t4, t3, a[1]);
#endif
	fp_subm_low(t2, t3, a[1]);
	fp_sqrn_low(t3, t4);
	fp_sqrn_low(t4, t2);

	/* t2 = a_2^2. */
	fp_sqrn_low(t2, a[2]);

	/* t4 = (t4 + t3)/2. */
#ifdef RLC_FP_ROOM
	fp_addd_low(t4, t4, t3);
#else
	fp_addc_low(t4, t4, t3);
#endif
	fp_hlvd_low(t4, t4);

	/* t3 = t3 - t4 - t1. */
	fp_subc_low(t3, t3, t4);
	fp_subc_low(t3, t3, t1);

	/* c_2 = t4 - t0 - t2. */
	fp_subc_low(c[2], t4, t0);
	fp_subc_low(c[2], c[2], t2);

	/* c_0 = t0 + t1 * B. */
	fp_addc_low(c[0], t0, t1);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[0], c[0], t1);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[0], c[0], t1);
	}

	/* c_1 = t3 + t2 * B. */
	fp_addc_low(c[1], t3, t2);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[1], c[1], t2);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[1], c[1], t2);
	}
}

void fp3_sqrm_low(fp3_t c, const fp3_t a) {
	rlc_align dv3_t t;

	dv3_null(t);

	RLC_TRY {
		dv3_new(t);
		fp3_sqrn_low(t, a);
		fp3_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free(t);
	}
}

#endif

/* Defining FP8_ASM leaves out the Fp8 functions, so they can be replaced. */
#ifndef FP8_ASM

TMPL_FPX_SQR_UNR_QUAD(fp8_sqrn_low, fp8, fp4, dv8, dv4, fp2, dv2, 2, 1,
		fp4_sqr_unr);

#endif

/* Defining FP16_ASM leaves out the Fp16 functions, so they can be replaced. */
#ifndef FP16_ASM

TMPL_FPX_SQR_UNR_QUAD(fp16_sqrn_low, fp16, fp8, dv16, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr);

#endif

/* Defining FP24_ASM leaves out the Fp24 functions, so they can be replaced. */
#ifndef FP24_ASM

TMPL_FPX_SQR_UNR_CUBIC(fp24_sqrn_low, fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr, fp8_mul_unr, 8);

#endif

/* Defining FP12_ASM leaves out the Fp12 functions, so they can be replaced. */
#ifndef FP12_ASM

void fp12_sqrn_low(dv12_t c, const fp12_t a) {
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

void fp12_sqrc_low(dv12_t c, const fp12_t a, int pck) {
	fp4_t t;
	dv4_t u;

	fp4_null(t);
	dv4_null(u);

	RLC_TRY {
		fp4_new(t);
		dv4_new(u);

		if (!pck) {
			/* (a_00 + a_11 * w)^2, where c_00 and c_11 come from. */
			fp2_copy(t[0], a[0][0]);
			fp2_copy(t[1], a[1][1]);
			fp4_sqr_unr(u, t);
			for (int j = 0; j < 2; j++) {
				dv_copy(c[0][0][j], u[0][j], RLC_FP_DLEN);
				dv_copy(c[1][1][j], u[1][j], RLC_FP_DLEN);
			}
		}
		/* (a_01 + a_12 * w)^2, where c_02 and c_10 come from. */
		fp2_copy(t[0], a[0][1]);
		fp2_copy(t[1], a[1][2]);
		fp4_sqr_unr(u, t);
		fp2_nord_low(u[1], u[1]);
		for (int j = 0; j < 2; j++) {
			dv_copy(c[0][2][j], u[0][j], RLC_FP_DLEN);
			dv_copy(c[1][0][j], u[1][j], RLC_FP_DLEN);
		}
		/* (a_10 + a_02 * w)^2, where c_01 and c_12 come from. */
		fp2_copy(t[0], a[1][0]);
		fp2_copy(t[1], a[0][2]);
		fp4_sqr_unr(u, t);
		for (int j = 0; j < 2; j++) {
			dv_copy(c[0][1][j], u[0][j], RLC_FP_DLEN);
			dv_copy(c[1][2][j], u[1][j], RLC_FP_DLEN);
		}
#if FP_RDC == FP_RENUS
		/* c_0j = 3 * t_0j - 2 * a_0j and c_1j = 3 * t_1j + 2 * a_1j, with
		 * 2 * a as a product, so that the square needs one reduction. */
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 3; j++) {
				if (pck && i == j) {
					continue;
				}
				fp_add(t[0][0], core_get()->one, core_get()->one);
				if (i == 0) {
					fp_neg(t[0][0], t[0][0]);
				}
				for (int l = 0; l < 2; l++) {
					rlc_align dig_t w[RLC_FP_DLEN];

					fp_addc_low(w, c[i][j][l], c[i][j][l]);
					fp_addc_low(c[i][j][l], c[i][j][l], w);
					fp_muln_low(w, a[i][j][l], t[0][0]);
					fp_addc_low(c[i][j][l], c[i][j][l], w);
				}
			}
		}
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t);
		dv4_free(u);
	}
}

#endif
