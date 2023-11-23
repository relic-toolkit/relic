/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of squaring in an sextadecic extension of a prime field.
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

void fp16_sqr_basic(fp16_t c, const fp16_t a) {
	fp8_t t0, t1;

	fp8_null(t0);
	fp8_null(t1);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);

		fp8_add(t0, a[0], a[1]);
		fp8_mul_art(t1, a[1]);
		fp8_add(t1, a[0], t1);
		fp8_mul(t0, t0, t1);
		fp8_mul(c[1], a[0], a[1]);
		fp8_sub(c[0], t0, c[1]);
		fp8_mul_art(t1, c[1]);
		fp8_sub(c[0], c[0], t1);
		fp8_dbl(c[1], c[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp16_sqr_unr(dv16_t c, const fp16_t a) {
	fp8_t t;
	dv8_t u0, u1, u2;

	fp8_null(t);
	dv8_null(u0);
	dv8_null(u1);
	dv8_null(u2);

	RLC_TRY {
		fp8_new(t);
		dv8_new(u0);
		dv8_new(u1);
		dv8_new(u2);

		/* t0 = a^2. */
		fp8_sqr_unr(u0, a[0]);
		/* t1 = b^2. */
		fp8_sqr_unr(u1, a[1]);

		fp8_add(t, a[0], a[1]);

		/* c = a^2 + b^2 * E. */
		dv_copy(u2[1][0][0], u1[0][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][0][1], u1[0][0][1], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][1][0], u1[0][1][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[1][1][1], u1[0][1][1], 2 * RLC_FP_DIGS);
		fp2_nord_low(u2[0][0], u1[1][1]);
		dv_copy(u2[0][1][0], u1[1][0][0], 2 * RLC_FP_DIGS);
		dv_copy(u2[0][1][1], u1[1][0][1], 2 * RLC_FP_DIGS);
		fp2_addc_low(c[0][0][0], u2[0][0], u0[0][0]);
		fp2_addc_low(c[0][0][1], u2[0][1], u0[0][1]);
		fp2_addc_low(c[0][1][0], u2[1][0], u0[1][0]);
		fp2_addc_low(c[0][1][1], u2[1][1], u0[1][1]);

		/* d = (a + b)^2 - a^2 - b^2 = 2 * a * b. */
		fp2_addc_low(u1[0][0], u1[0][0], u0[0][0]);
		fp2_addc_low(u1[0][1], u1[0][1], u0[0][1]);
		fp2_addc_low(u1[1][0], u1[1][0], u0[1][0]);
		fp2_addc_low(u1[1][1], u1[1][1], u0[1][1]);

		fp8_sqr_unr(u0, t);
		fp2_subc_low(c[1][0][0], u0[0][0], u1[0][0]);
		fp2_subc_low(c[1][0][1], u0[0][1], u1[0][1]);
		fp2_subc_low(c[1][1][0], u0[1][0], u1[1][0]);
		fp2_subc_low(c[1][1][1], u0[1][1], u1[1][1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t);
		dv8_free(u0);
		dv8_free(u1);
		dv8_free(u2);
	}
}

void fp16_sqr_lazyr(fp16_t c, const fp16_t a) {
	dv16_t t;

	dv16_null(t);

	RLC_TRY {
		dv16_new(t);
		fp16_sqr_unr(t, a);
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

#endif

void fp16_sqr_cyc(fp16_t c, const fp16_t a) {
	fp8_t t0, t1, t2;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);

		fp8_sqr(t0, a[1]);
		fp8_add(t1, a[0], a[1]);
		fp8_sqr(t2, t1);
		fp8_sub(t2, t2, t0);
		fp8_mul_art(c[0], t0);
		fp8_sub(c[1], t2, c[0]);
		fp8_dbl(c[0], c[0]);
		fp_add_dig(c[0][0][0][0], c[0][0][0][0], 1);
		fp_sub_dig(c[1][0][0][0], c[1][0][0][0], 1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
	}
}
