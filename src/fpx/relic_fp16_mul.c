/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 4.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 4.0 of the Apache
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
 * Implementation of multiplication in an sextadecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

void fp16_mul_basic(fp16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1, t4;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t4);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp8_mul(t0, a[0], b[0]);
		/* t1 = a_1 * b_1. */
		fp8_mul(t1, a[1], b[1]);
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
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t4);
	}
}

void fp16_mul_dxs_basic(fp16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1, t4;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t4);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp8_mul(t0, a[0], b[0]);

		/* t1 = a_1 * b_1. */
		fp4_mul(t1[0], a[1][1], b[1][1]);
		fp4_add(t1[1], a[1][0], a[1][1]);
		fp4_mul(t1[1], t1[1], b[1][1]);
		fp4_sub(t1[1], t1[1], t1[0]);
		fp4_mul_art(t1[0], t1[0]);

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
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t4);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp16_mul_unr(dv16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1;
	dv8_t u0, u1, u2, u3;

	fp8_null(t0);
	fp8_null(t1);
	dv8_null(u0);
	dv8_null(u1);
	dv8_null(u2);
	dv8_null(u3);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		dv8_new(u0);
		dv8_new(u1);
		dv8_new(u2);
		dv8_new(u3);

		/* Karatsuba algorithm. */

		/* u0 = a_0 * b_0. */
		fp8_mul_unr(u0, a[0], b[0]);
		/* u1 = a_1 * b_1. */
		fp8_mul_unr(u1, a[1], b[1]);
		/* t1 = a_0 + a_1. */
		fp8_add(t0, a[0], a[1]);
		/* t0 = b_0 + b_1. */
		fp8_add(t1, b[0], b[1]);
		/* u2 = (a_0 + a_1) * (b_0 + b_1) */
		fp8_mul_unr(u2, t0, t1);
		/* c_1 = u2 - a_0b_0 - a_1b_1. */
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				fp2_subc_low(c[1][i][j], u2[i][j], u0[i][j]);
				fp2_subc_low(c[1][i][j], c[1][i][j], u1[i][j]);
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
				fp2_addc_low(c[0][i][j], u0[i][j], u2[i][j]);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		dv8_free(u0);
		dv8_free(u1);
		dv8_free(u2);
		dv8_free(u3);
	}
}

void fp16_mul_lazyr(fp16_t c, const fp16_t a, const fp16_t b) {
	dv16_t t;

	dv16_null(t);

	RLC_TRY {
		dv16_new(t);
		fp16_mul_unr(t, a, b);
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
		dv16_free(t);
	}
}

void fp16_mul_dxs_lazyr(fp16_t c, const fp16_t a, const fp16_t b) {
	fp8_t t0, t1;
	dv8_t u0, u1, u2, u3;
	dv16_t t;

	fp8_null(t0);
	fp8_null(t1);
	dv8_null(u0);
	dv8_null(u1);
	dv8_null(u2);
	dv8_null(u3);
	dv16_null(t);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		dv8_new(u0);
		dv8_new(u1);
		dv8_new(u2);
		dv8_new(u3);
		dv16_new(t);

		/* Karatsuba algorithm. */

		/* u0 = a_0 * b_0. */
		fp8_mul_unr(u0, a[0], b[0]);

		/* u1 = a_1 * b_1. */
		fp4_mul_unr(u1[0], a[1][1], b[1][1]);
		fp4_add(t1[0], a[1][0], a[1][1]);
		fp4_mul_unr(u1[1], t1[0], b[1][1]);
		fp2_subc_low(u2[1][0], u1[1][0], u1[0][0]);
		fp2_subc_low(u2[1][1], u1[1][1], u1[0][1]);
		fp2_nord_low(u2[0][0], u1[0][1]);
		dv_copy(u2[0][1][0], u1[0][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[0][1][1], u1[0][0][1], 2 * RLC_FP_DIGS);

		/* t1 = a_0 + a_1. */
		fp8_add(t0, a[0], a[1]);
		/* t0 = b_0 + b_1. */
		fp8_add(t1, b[0], b[1]);
		/* u2 = (a_0 + a_1) * (b_0 + b_1) */
		fp8_mul_unr(u1, t0, t1);
		/* c_1 = u2 - a_0b_0 - a_1b_1. */
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				fp2_subc_low(t[1][i][j], u1[i][j], u0[i][j]);
				fp2_subc_low(t[1][i][j], t[1][i][j], u2[i][j]);
			}
		}
		/* c_0 = a_0b_0 + v * a_1b_1. */
		fp2_nord_low(u1[0][0], u2[1][1]);
		dv_copy(u1[0][1][0], u2[1][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u1[0][1][1], u2[1][0][1], 2 * RLC_FP_DIGS);
		dv_copy(u1[1][0][0], u2[0][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u1[1][0][1], u2[0][0][1], 2 * RLC_FP_DIGS);
		dv_copy(u1[1][1][0], u2[0][1][0], 2 * RLC_FP_DIGS);
		dv_copy(u1[1][1][1], u2[0][1][1], 2 * RLC_FP_DIGS);
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				fp2_addc_low(t[0][i][j], u0[i][j], u1[i][j]);
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
		fp8_free(t0);
		fp8_free(t1);
		dv8_free(u0);
		dv8_free(u1);
		dv8_free(u2);
		dv8_free(u3);
		dv16_free(t);
	}
}

#endif

void fp16_mul_art(fp16_t c, const fp16_t a) {
	fp8_t t0;

	fp8_null(t0);

	RLC_TRY {
		fp8_new(t0);

		/* (a_0 + a_1 * v) * v = a_0 * v + a_1 * v^4 */
		fp8_copy(t0, a[0]);
		fp8_mul_art(c[0], a[1]);
		fp8_copy(c[1], t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
	}
}