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
 * Implementation of arithmetic in the nonic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp9, fp3, 3);

TMPL_FPX_BIN(fp9, fp3, 3, 9);

TMPL_FPX_CMP(fp9, fp3, 3);

TMPL_FPX_ADD(fp9, fp3, 3);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_CUBIC(fp9, fp3, fp3_mul_nor);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_CUBIC(fp9, fp3, dv9, dv3, fp3, dv3, 1, 1, fp3_muln_low);

TMPL_FPX_MUL_LAZYR(fp9, dv9, fp3, dv3, 3);

#endif

void fp9_mul_dxs(fp9_t c, const fp9_t a, const fp9_t b) {
	fp3_t v0, v1, t0, t1, t2;

	fp3_null_all(v0, v1, t0, t1, t2);

	RLC_TRY {
		fp3_new_all(v0, v1, t0, t1, t2);

		/* v0 = a_0b_0 */
		fp3_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp3_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 = 0 */

		/* t2 (c0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp3_add(t0, a[1], a[2]);
		fp3_mul(t0, t0, b[1]);
		fp3_sub(t0, t0, v1);
		fp3_mul_nor(t2, t0);
		fp3_add(t2, t2, v0);

		/* c1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp3_add(t0, a[0], a[1]);
		fp3_add(t1, b[0], b[1]);
		fp3_mul(c[1], t0, t1);
		fp3_sub(c[1], c[1], v0);
		fp3_sub(c[1], c[1], v1);

		/* c2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp3_add(t0, a[0], a[2]);
		fp3_mul(c[2], t0, b[0]);
		fp3_sub(c[2], c[2], v0);
		fp3_add(c[2], c[2], v1);

		/* c0 = t2 */
		fp3_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free_all(v0, v1, t0, t1, t2);
	}
}

TMPL_FPX_MUL_ART_CUBIC(fp9, fp3, fp3_mul_nor);

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_CUBIC(fp9, fp3, fp3_mul_nor, 3);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_CUBIC(fp9, fp3, dv9, dv3, fp3, dv3, 1, 1,
		fp3_sqrn_low, fp3_muln_low, 3);

TMPL_FPX_SQR_LAZYR(fp9, dv9, fp3, dv3, 3);

#endif

TMPL_FPX_INV_CUBIC(fp9, fp3, fp3_mul_nor);

TMPL_FPX_INV_SIM(fp9);

TMPL_FPX_EXP(fp9);

void fp9_frb(fp9_t c, const fp9_t a, int i) {
	/* Cost of two multiplication in Fp^3 per Frobenius. */
	fp9_copy(c, a);
	for (; i % 9 > 0; i--) {
		fp3_frb(c[0], c[0], 1);
		fp3_frb(c[1], c[1], 1);
		fp3_frb(c[2], c[2], 1);
		fp3_mul_frb(c[1], c[1], 1, 2);
		fp3_mul_frb(c[2], c[2], 1, 4);
	}
}
