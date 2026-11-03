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
 * Implementation of the low-level extension field multiplication functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifndef FP12_ASM

/**
 * Multiplies an element of Fp6 by a sparse one, with its last component zero,
 * without reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the dense element.
 * @param[in] b				- the sparse element.
 */
static void fp6_mul_dxs_unr_lazyr(dv6_t c, const fp6_t a, const fp6_t b) {
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

void fp2_mul1_low(dig_t *c, const dig_t *a, dig_t digit) {
	int k = 0;

	if (digit <= 1) {
		if (digit == 0) {
			dv_zero(c, RLC_FP_DLEN);
		} else {
			dv_copy(c, a, RLC_FP_DLEN);
		}
		return;
	}
	/* The top bit of the digit, which is small. */
	for (dig_t r = digit; r > 1; r >>= 1) {
		k++;
	}
	fp_addc_low(c, a, a);
	while (k-- > 0) {
		if ((digit >> k) & 1) {
			fp_addc_low(c, c, a);
		}
		if (k > 0) {
			fp_addc_low(c, c, c);
		}
	}
}

/* Defining FP2_ASM leaves out the Fp2 functions, so they can be replaced. */
#ifndef FP2_ASM

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dig_t t0[RLC_FP_DLEN], t1[RLC_FP_DLEN], t2[RLC_FP_DLEN];

	/* Karatsuba algorithm. */

	/* t0 = a_0 + a_1, t1 = b_0 + b_1. */
#ifdef RLC_FP_ROOM
	fp_addn_low(t0, a[0], a[1]);
	fp_addn_low(t1, b[0], b[1]);
#else
	fp_addm_low(t0, a[0], a[1]);
	fp_addm_low(t1, b[0], b[1]);
#endif
	/* c_0 = a_0 * b_0, c_1 = a_1 * b_1. */
	fp_muln_low(c[0], a[0], b[0]);
	fp_muln_low(c[1], a[1], b[1]);
	/* t2 = (a_0 + a_1) * (b_0 + b_1). */
	fp_muln_low(t2, t0, t1);

	/* t0 = (a_0 * b_0) + (a_1 * b_1). */
#ifdef RLC_FP_ROOM
	fp_addd_low(t0, c[0], c[1]);
#else
	fp_addc_low(t0, c[0], c[1]);
#endif

	/* c_0 = (a_0 * b_0) + u^2 * (a_1 * b_1), with u^2 < 0. */
#ifndef FP_QNRES
	if (fp_prime_get_qnr() != -1) {
		/* t1 = |u^2| * (a_1 * b_1). */
		fp2_mul1_low(t1, c[1], -fp_prime_get_qnr());
		fp_subc_low(c[0], c[0], t1);
	} else {
		fp_subc_low(c[0], c[0], c[1]);
	}
#else
	fp_subc_low(c[0], c[0], c[1]);
#endif

	/* c_1 = t2 - t0. */
#ifdef RLC_FP_ROOM
	fp_subd_low(c[1], t2, t0);
#else
	fp_subc_low(c[1], t2, t0);
#endif
}

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dv2_t t;

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);
		fp2_muln_low(t, a, b);
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

void fp3_muln_low(dv3_t c, const fp3_t a, const fp3_t b) {
	rlc_align dig_t t0[RLC_FP_DLEN], t1[RLC_FP_DLEN], t2[RLC_FP_DLEN];
	rlc_align dig_t t3[RLC_FP_DLEN], t4[RLC_FP_DLEN], t5[RLC_FP_DLEN];
	rlc_align dig_t t6[RLC_FP_DLEN];

	/* Karatsuba algorithm. */

	/* t0 = a_0 * b_0, t1 = a_1 * b_1, t2 = a_2 * b_2. */
	fp_muln_low(t0, a[0], b[0]);
	fp_muln_low(t1, a[1], b[1]);
	fp_muln_low(t2, a[2], b[2]);

	/* t3 = (a_1 + a_2) * (b_1 + b_2). */
#ifdef RLC_FP_ROOM
	fp_addn_low(t3, a[1], a[2]);
	fp_addn_low(t4, b[1], b[2]);
#else
	fp_addm_low(t3, a[1], a[2]);
	fp_addm_low(t4, b[1], b[2]);
#endif
	fp_muln_low(t5, t3, t4);
#ifdef RLC_FP_ROOM
	fp_addc_low(t6, t1, t2);
#else
	fp_addc_low(t6, t1, t2);
#endif
	fp_subc_low(t4, t5, t6);
	fp_addc_low(c[0], t0, t4);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[0], c[0], t4);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[0], c[0], t4);
	}

#ifdef RLC_FP_ROOM
	fp_addn_low(t4, a[0], a[1]);
	fp_addn_low(t5, b[0], b[1]);
#else
	fp_addm_low(t4, a[0], a[1]);
	fp_addm_low(t5, b[0], b[1]);
#endif
	fp_muln_low(t6, t4, t5);
#ifdef RLC_FP_ROOM
	fp_addc_low(t4, t0, t1);
#else
	fp_addc_low(t4, t0, t1);
#endif
	fp_subc_low(t4, t6, t4);
	fp_addc_low(c[1], t4, t2);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[1], c[1], t2);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[1], c[1], t2);
	}

#ifdef RLC_FP_ROOM
	fp_addn_low(t5, a[0], a[2]);
	fp_addn_low(t6, b[0], b[2]);
#else
	fp_addm_low(t5, a[0], a[2]);
	fp_addm_low(t6, b[0], b[2]);
#endif
	fp_muln_low(t4, t5, t6);
#ifdef RLC_FP_ROOM
	fp_addc_low(t6, t0, t2);
#else
	fp_addc_low(t6, t0, t2);
#endif
	fp_subc_low(t5, t4, t6);
	fp_addc_low(c[2], t5, t1);
}

void fp3_mulm_low(fp3_t c, const fp3_t a, const fp3_t b) {
	dv3_t t;

	dv3_null(t);

	RLC_TRY {
		dv3_new(t);
		fp3_muln_low(t, a, b);
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

TMPL_FPX_MUL_UNR_QUAD(fp8_muln_low, fp8, fp4, dv8, dv4, fp2, dv2, 2, 1,
		fp4_mul_unr);

#endif

/* Defining FP16_ASM leaves out the Fp16 functions, so they can be replaced. */
#ifndef FP16_ASM

TMPL_FPX_MUL_UNR_QUAD(fp16_muln_low, fp16, fp8, dv16, dv8, fp2, dv2, 4, 2,
		fp8_mul_unr);

#endif

/* Defining FP24_ASM leaves out the Fp24 functions, so they can be replaced. */
#ifndef FP24_ASM

TMPL_FPX_MUL_UNR_CUBIC(fp24_muln_low, fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_mul_unr);

void fp24_muld_low(dv24_t c, const fp24_t a, const fp24_t b) {
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

#endif

/* Defining FP12_ASM leaves out the Fp12 functions, so they can be replaced. */
#ifndef FP12_ASM

TMPL_FPX_MUL_UNR_QUAD(fp12_muln_low, fp12, fp6, dv12, dv6, fp2, dv2, 3, 1,
		fp6_mul_unr);

void fp12_muld_low(dv12_t c, const fp12_t a, const fp12_t b) {
	fp6_t t0, t1;
	dv6_t u1;

	fp6_null_all(t0, t1);
	dv6_null(u1);

	RLC_TRY {
		fp6_new_all(t0, t1);
		dv6_new(u1);

		if (ep2_curve_is_twist() == RLC_EP_DTYPE) {
			/* Lines with their y-coefficient in the prime field are cheaper. */
			if (fp_is_zero(b[0][0][1])) {
				/* t0 = a_0 * b_0. */
				fp_muln_low(c[0][0][0], a[0][0][0], b[0][0][0]);
				fp_muln_low(c[0][0][1], a[0][0][1], b[0][0][0]);
				fp_muln_low(c[0][1][0], a[0][1][0], b[0][0][0]);
				fp_muln_low(c[0][1][1], a[0][1][1], b[0][0][0]);
				fp_muln_low(c[0][2][0], a[0][2][0], b[0][0][0]);
				fp_muln_low(c[0][2][1], a[0][2][1], b[0][0][0]);
				/* t2 = b_0 + b_1. */
				fp_add(t0[0][0], b[0][0][0], b[1][0][0]);
				fp_copy(t0[0][1], b[1][0][1]);
				fp2_copy(t0[1], b[1][1]);
			} else {
				/* t0 = a_0 * b_0. */
				fp2_muln_low(c[0][0], a[0][0], b[0][0]);
				fp2_muln_low(c[0][1], a[0][1], b[0][0]);
				fp2_muln_low(c[0][2], a[0][2], b[0][0]);
			
				/* t2 = b_0 + b_1. */
				fp2_add(t0[0], b[0][0], b[1][0]);
				fp2_copy(t0[1], b[1][1]);
			}
			/* t1 = a_1 * b_1. */
			fp6_mul_dxs_unr_lazyr(u1, a[1], b[1]);
		} else {
			/* t0 = a_0 * b_0. */
			fp6_mul_dxs_unr_lazyr(c[0], a[0], b[0]);
			/* Lines with their y-coefficient in the prime field are cheaper. */
			if (fp_is_zero(b[1][1][1])) {
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
			} else {
				/* t1 = a_1 * b_1. */
				fp2_muln_low(u1[1], a[1][2], b[1][1]);
				fp2_nord_low(u1[0], u1[1]);
				fp2_muln_low(u1[1], a[1][0], b[1][1]);
				fp2_muln_low(u1[2], a[1][1], b[1][1]);
				/* t2 = b_0 + b_1. */
				fp2_copy(t0[0], b[0][0]);
				fp2_add(t0[1], b[0][1], b[1][1]);
			}
		}
		/* c_1 = (a_0 + a_1) * (b_0 + b_1) - a_0b_0 - a_1b_1. */
		fp6_add(t1, a[0], a[1]);
		fp6_mul_dxs_unr_lazyr(c[1], t1, t0);
		for (int i = 0; i < 3; i++) {
			fp2_subc_low(c[1][i], c[1][i], c[0][i]);
			fp2_subc_low(c[1][i], c[1][i], u1[i]);
		}
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_nord_low(u1[2], u1[2]);
		fp2_addc_low(c[0][0], c[0][0], u1[2]);
		fp2_addc_low(c[0][1], c[0][1], u1[0]);
		fp2_addc_low(c[0][2], c[0][2], u1[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp6_free_all(t0, t1);
		dv6_free(u1);
	}
}

#endif
