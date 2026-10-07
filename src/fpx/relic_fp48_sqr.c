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
 * Implementation of squaring in a dodecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_sqr_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp48, fp24, fp24_mul_art);

TMPL_SQR_CYC_QC(fp48, fp8, fp8_mul_art);

TMPL_SQR_PCK_QC(fp48, fp8, fp8_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

void fp48_sqr_lazyr(fp48_t c, const fp48_t a) {
	/* TODO: implement lazy reduction. */
	fp24_t t0, t1;

	fp24_null_all(t0, t1);

	RLC_TRY {
		fp24_new_all(t0, t1);

		fp24_add(t0, a[0], a[1]);
		fp24_mul_art(t1, a[1]);
		fp24_add(t1, a[0], t1);
		fp24_mul(t0, t0, t1);
		fp24_mul(c[1], a[0], a[1]);
		fp24_sub(c[0], t0, c[1]);
		fp24_mul_art(t1, c[1]);
		fp24_sub(c[0], c[0], t1);
		fp24_dbl(c[1], c[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free_all(t0, t1);
	}
}

TMPL_SQR_PCK_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr, fp8_mul_art);

TMPL_SQR_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr);

#endif
