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
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp16, fp8, fp8_mul_art);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_QUAD(fp16, fp8, dv16, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr);

TMPL_FPX_SQR_LAZYR(fp16, dv16, fp2, dv2, 8);

#endif

void fp16_sqr_cyc(fp16_t c, const fp16_t a) {
	fp8_t t0, t1, t2;

	fp8_null_all(t0, t1, t2);

	RLC_TRY {
		fp8_new_all(t0, t1, t2);

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
		fp8_free_all(t0, t1, t2);
	}
}
