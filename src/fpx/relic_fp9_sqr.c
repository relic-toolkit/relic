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
 * Implementation of squaring in a nonic extension of a prime field.
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

TMPL_FPX_SQR_CUBIC(fp9, fp3, fp3_mul_nor, 3);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp9_sqr_unr(dv9_t c, const fp9_t a) {
	dv3_t u0, u1, u2, u3, u4, u5;
	fp3_t t0, t1, t2, t3;

	dv3_null_all(u0, u1, u2, u3, u4, u5);
	fp3_null_all(t0, t1, t2, t3);

	RLC_TRY {
		dv3_new_all(u0, u1, u2, u3, u4, u5);
		fp3_new_all(t0, t1, t2, t3);

		/* u0 = a_0^2 */
		fp3_sqrn_low(u0, a[0]);

		/* t1 = 2 * a_1 * a_2 */
		fp3_dblm_low(t0, a[1]);
		fp3_muln_low(u1, t0, a[2]);

		/* u2 = a_2^2. */
		fp3_sqrn_low(u2, a[2]);

		/* t4 = a_0 + a_2. */
		fp3_addm_low(t3, a[0], a[2]);

		/* u3 = (a_0 + a_2 + a_1)^2. */
		fp3_addm_low(t2, t3, a[1]);
		fp3_sqrn_low(u3, t2);

		/* u4 = (a_0 + a_2 - a_1)^2. */
		fp3_subm_low(t1, t3, a[1]);
		fp3_sqrn_low(u4, t1);

		/* u4 = (u4 + u3)/2. */
#ifdef RLC_FP_ROOM
		fp3_addc_low(u4, u4, u3);
#else
		fp3_addc_low(u4, u4, u3);
#endif
		fp_hlvd_low(u4[0], u4[0]);
		fp_hlvd_low(u4[1], u4[1]);
		fp_hlvd_low(u4[2], u4[2]);

		/* u3 = u3 - u4 - u1. */
		fp3_addc_low(u5, u1, u4);
		fp3_subc_low(u3, u3, u5);

		/* c2 = u4 - u0 - u2. */
		fp3_addc_low(u5, u0, u2);
		fp3_subc_low(c[2], u4, u5);

		/* c0 = u0 + u1 * E. */
		fp3_nord_low(u4, u1);
		fp3_addc_low(c[0], u0, u4);

		/* c1 = u3 + u2 * E. */
		fp3_nord_low(u4, u2);
		fp3_addc_low(c[1], u3, u4);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free_all(u0, u1, u2, u3, u4, u5);
		fp3_free_all(t0, t1, t2, t3);
	}
}

TMPL_FPX_SQR_LAZYR(fp9, dv9, fp3, dv3, 3);

#endif
