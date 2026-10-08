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
 * Implementation of multiplication in a dodecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

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

void fp12_mul_unr(dv12_t c, const fp12_t a, const fp12_t b) {
	fp6_t t0, t1;
	dv6_t u0, u1, u2, u3;

	dv6_null_all(u0, u1, u2, u3);
	fp6_null_all(t0, t1);

	RLC_TRY {
		dv6_new_all(u0, u1, u2, u3);
		fp6_new_all(t0, t1);

		/* Karatsuba algorithm. */

		/* u0 = a_0 * b_0. */
		fp6_mul_unr(u0, a[0], b[0]);
		/* u1 = a_1 * b_1. */
		fp6_mul_unr(u1, a[1], b[1]);
		/* t1 = a_0 + a_1. */
		fp6_add(t0, a[0], a[1]);
		/* t0 = b_0 + b_1. */
		fp6_add(t1, b[0], b[1]);
		/* u2 = (a_0 + a_1) * (b_0 + b_1) */
		fp6_mul_unr(u2, t0, t1);
		/* c_1 = u2 - a_0b_0 - a_1b_1. */
		for (int i = 0; i < 3; i++) {
			fp2_addc_low(u3[i], u0[i], u1[i]);
			fp2_subc_low(c[1][i], u2[i], u3[i]);
		}
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_nord_low(u2[0], u1[2]);
		fp2_addc_low(c[0][0], u0[0], u2[0]);
		fp2_addc_low(c[0][1], u0[1], u1[0]);
		fp2_addc_low(c[0][2], u0[2], u1[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv6_free_all(u0, u1, u2, u3);
		fp6_free_all(t0, t1);
	}
}

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
