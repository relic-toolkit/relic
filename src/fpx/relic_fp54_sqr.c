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
 * Implementation of squaring in a 54-degree extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_sqr_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

void fp54_sqr_basic(fp54_t c, const fp54_t a) {
	fp18_t t0, t1, t2, t3, t4;

	fp18_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		fp18_new_all(t0, t1, t2, t3, t4);

		/* t0 = a_0^2 */
		fp18_sqr(t0, a[0]);

		/* t1 = 2 * a_1 * a_2 */
		fp18_mul(t1, a[1], a[2]);
		fp18_dbl(t1, t1);

		/* t2 = a_2^2. */
		fp18_sqr(t2, a[2]);

		/* c_2 = a_0 + a_2. */
		fp18_add(c[2], a[0], a[2]);

		/* t3 = (a_0 + a_2 + a_1)^2. */
		fp18_add(t3, c[2], a[1]);
		fp18_sqr(t3, t3);

		/* c_2 = (a_0 + a_2 - a_1)^2. */
		fp18_sub(c[2], c[2], a[1]);
		fp18_sqr(c[2], c[2]);

		/* c_2 = (c_2 + t3)/2. */
		fp18_add(c[2], c[2], t3);
		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) {
				fp_hlv(c[2][0][i][j], c[2][0][i][j]);
				fp_hlv(c[2][1][i][j], c[2][1][i][j]);
			}
		}

		/* t3 = t3 - c_2 - t1. */
		fp18_sub(t3, t3, c[2]);
		fp18_sub(t3, t3, t1);

		/* c_2 = c_2 - t0 - t2. */
		fp18_sub(c[2], c[2], t0);
		fp18_sub(c[2], c[2], t2);

		/* c_0 = t0 + t1 * E. */
		fp18_mul_art(t4, t1);
		fp18_add(c[0], t0, t4);

		/* c_1 = t3 + t2 * E. */
		fp18_mul_art(t4, t2);
		fp18_add(c[1], t3, t4);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free_all(t0, t1, t2, t3, t4);
	}
}

TMPL_SQR_CYC_CQ(fp54, fp9, fp9_mul_art);

TMPL_SQR_PCK_CQ(fp54, fp9, fp9_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

void fp54_sqr_lazyr(fp54_t c, const fp54_t a) {
	/* TODO: implement lazy reduction. */
	fp18_t t0, t1, t2, t3, t4;

	fp18_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		fp18_new_all(t0, t1, t2, t3, t4);

		/* t0 = a_0^2 */
		fp18_sqr(t0, a[0]);

		/* t1 = 2 * a_1 * a_2 */
		fp18_mul(t1, a[1], a[2]);
		fp18_dbl(t1, t1);

		/* t2 = a_2^2. */
		fp18_sqr(t2, a[2]);

		/* c_2 = a_0 + a_2. */
		fp18_add(c[2], a[0], a[2]);

		/* t3 = (a_0 + a_2 + a_1)^2. */
		fp18_add(t3, c[2], a[1]);
		fp18_sqr(t3, t3);

		/* c_2 = (a_0 + a_2 - a_1)^2. */
		fp18_sub(c[2], c[2], a[1]);
		fp18_sqr(c[2], c[2]);

		/* c_2 = (c_2 + t3)/2. */
		fp18_add(c[2], c[2], t3);
		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) {
				fp_hlv(c[2][0][i][j], c[2][0][i][j]);
				fp_hlv(c[2][1][i][j], c[2][1][i][j]);
			}
		}

		/* t3 = t3 - c_2 - t1. */
		fp18_sub(t3, t3, c[2]);
		fp18_sub(t3, t3, t1);

		/* c_2 = c_2 - t0 - t2. */
		fp18_sub(c[2], c[2], t0);
		fp18_sub(c[2], c[2], t2);

		/* c_0 = t0 + t1 * E. */
		fp18_mul_art(t4, t1);
		fp18_add(c[0], t0, t4);

		/* c_1 = t3 + t2 * E. */
		fp18_mul_art(t4, t2);
		fp18_add(c[1], t3, t4);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free_all(t0, t1, t2, t3, t4);
	}
}

TMPL_SQR_PCK_LAZYR_CQ(fp54, fp9, dv9, fp3, dv3, 3, 1, fp9_sqr_unr, fp9_mul_art);

TMPL_SQR_CYC_LAZYR_CQ(fp54, fp9, dv9, fp3, dv3, 3, 1, fp9_sqr_unr);

#endif
