/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 4007-4019 RELIC Authors
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
 * Implementation of multiplication in a 24-degree extension of a prime field.
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

TMPL_FPX_MUL_CUBIC(fp24, fp8, fp8_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_mul_unr);

TMPL_FPX_MUL_LAZYR(fp24, dv24, fp2, dv2, 12);

#endif

TMPL_FPX_MUL_ART_CUBIC(fp24, fp8, fp8_mul_art);

void fp24_mul_dxs(fp24_t c, const fp24_t a, const fp24_t b) {
	fp8_t t0, t1, t2, t3, t4;

	fp8_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		fp8_new_all(t0, t1, t2, t3, t4);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0. */
		fp8_mul(t0, a[0], b[0]);
		fp8_add(t3, a[1], a[2]);
		fp8_add(t4, a[0], a[1]);

		if (fp8_is_zero(b[2])) {
			/* t1 = a_1 * b_1. */
			fp8_mul(t1, a[1], b[1]);
			/* b_2 = 0. */

			fp8_mul(t3, t3, b[1]);
			fp8_sub(t3, t3, t1);
			fp8_mul_art(t3, t3);
			fp8_add(t3, t3, t0);

			fp8_add(t2, b[0], b[1]);
			fp8_mul(t4, t4, t2);
			fp8_sub(t4, t4, t0);
			fp8_sub(c[1], t4, t1);

			fp8_add(t4, a[0], a[2]);
			fp8_mul(c[2], t4, b[0]);
			fp8_sub(c[2], c[2], t0);
			fp8_add(c[2], c[2], t1);
		} else {
			/* b_1 = 0. */
			/* t2 = a_2 * b_2. */
			fp8_mul(t1, a[2], b[2]);

			fp8_mul(t3, t3, b[2]);
			fp8_sub(t3, t3, t1);
			fp8_mul_art(t3, t3);
			fp8_add(t3, t3, t0);

			fp8_mul(t4, t4, b[0]);
			fp8_sub(t4, t4, t0);
			fp8_mul_art(t2, t1);
			fp8_add(c[1], t4, t2);

			fp8_add(t4, a[0], a[2]);
			fp8_add(t2, b[0], b[2]);
			fp8_mul(c[2], t4, t2);
			fp8_sub(c[2], c[2], t0);
			fp8_sub(c[2], c[2], t1);
		}
		
		fp8_copy(c[0], t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free_all(t0, t1, t2, t3, t4);
	}
}
