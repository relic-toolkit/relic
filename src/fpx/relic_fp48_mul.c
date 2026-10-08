/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of multiplication in a 48-degree extension of a prime field.
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

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp48, fp24, fp24_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

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

#endif

void fp48_mul_dxs(fp48_t c, const fp48_t a, const fp48_t b) {
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

TMPL_FPX_MUL_ART_QUAD(fp48, fp24, fp24_mul_art);
