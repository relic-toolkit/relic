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

void fp48_sqr_unr(dv48_t c, const fp48_t a) {
	fp24_t t;
	dv24_t u0, u1;

	fp24_null(t);
	dv24_null_all(u0, u1);

	RLC_TRY {
		fp24_new(t);
		dv24_new_all(u0, u1);

		fp24_sqr_unr(u0, a[0]);
		fp24_sqr_unr(u1, a[1]);
		fp24_add(t, a[0], a[1]);
		/* c_0 = u0 + w * u1, where w^3 = v generates Fp^8 over Fp^4. */
		TMPL_DV_NADD(fp2, dv2, 4, 2, c[0][0], u0[0], u1[2]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][1], u0[1], u1[0]);
		TMPL_DV_ADDC(fp2, dv2, 4, c[0][2], u0[2], u1[1]);
		/* c_1 = (a_0 + a_1)^2 - a_0^2 - a_1^2. */
		TMPL_DV_ADDC(fp2, dv2, 12, u1, u1, u0);
		fp24_sqr_unr(u0, t);
		TMPL_DV_SUBC(fp2, dv2, 12, c[1], u0, u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free(t);
		dv24_free_all(u0, u1);
	}
}

TMPL_FPX_SQR_LAZYR(fp48, dv48, fp2, dv2, 24);

TMPL_SQR_PCK_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr, fp8_mul_art);

TMPL_SQR_CYC_LAZYR_QC(fp48, fp8, dv8, fp2, dv2, 4, 2, fp8_sqr_unr);

#endif
