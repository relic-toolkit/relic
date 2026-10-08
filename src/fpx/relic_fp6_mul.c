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
 * Implementation of multiplication in a sextic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_CUBIC(fp6, fp2, fp2_mul_nor);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

/* MSVC needs this to be exported, so remove inline */
TMPL_FPX_MUL_UNR_CUBIC(fp6, fp2, dv6, dv2, fp2, dv2, 1, 1, fp2_muln_low);

TMPL_FPX_MUL_LAZYR(fp6, dv6, fp2, dv2, 3);

#endif

void fp6_mul_dxs(fp6_t c, const fp6_t a, const fp6_t b) {
	fp2_t v0, v1, t0, t1, t2;

	fp2_null_all(v0, v1, t0, t1, t2);

	RLC_TRY {
		fp2_new_all(v0, v1, t0, t1, t2);

		/* v0 = a_0b_0 */
		fp2_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp2_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 = 0 */

		/* t2 (c0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp2_add(t0, a[1], a[2]);
		fp2_mul(t0, t0, b[1]);
		fp2_sub(t0, t0, v1);
		fp2_mul_nor(t2, t0);
		fp2_add(t2, t2, v0);

		/* c1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp2_add(t0, a[0], a[1]);
		fp2_add(t1, b[0], b[1]);
		fp2_mul(c[1], t0, t1);
		fp2_sub(c[1], c[1], v0);
		fp2_sub(c[1], c[1], v1);

		/* c2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp2_add(t0, a[0], a[2]);
		fp2_mul(c[2], t0, b[0]);
		fp2_sub(c[2], c[2], v0);
		fp2_add(c[2], c[2], v1);

		/* c0 = t2 */
		fp2_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free_all(v0, v1, t0, t1, t2);
	}
}

TMPL_FPX_MUL_ART_CUBIC(fp6, fp2, fp2_mul_nor);
