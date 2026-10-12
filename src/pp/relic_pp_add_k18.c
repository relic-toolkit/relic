/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of Miller addition for curves of embedding degree 18.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(18, ep3, fp3);

TMPL_PP_ADD_PROJC(18, ep3, fp3, projc_basic);

void pp_add_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p) {
	fp3_t t0, t1, t2, t3;
	dv3_t u0, u1;
	int one = 1, zero = 0;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	dv3_null(u0);
	dv3_null(u1);

	if (ep3_curve_is_twist() == RLC_EP_MTYPE) {
		one ^= 1;
		zero ^= 1;
	}

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		dv3_new(u0);
		dv3_new(u1);

		fp3_mul(t0, r->z, q->x);
		fp3_sub(t0, r->x, t0);
		fp3_mul(t1, r->z, q->y);
		fp3_sub(t1, r->y, t1);

		fp3_sqr(t2, t0);
		fp3_mul(r->x, t2, r->x);
		fp3_mul(t2, t0, t2);
		fp3_sqr(t3, t1);
		fp3_mul(t3, t3, r->z);
		fp3_add(t3, t2, t3);

		fp3_sub(t3, t3, r->x);
		fp3_sub(t3, t3, r->x);
		fp3_sub(r->x, r->x, t3);

		fp3_muln_low(u0, t1, r->x);
		fp3_muln_low(u1, t2, r->y);

		fp3_subc_low(u1, u0, u1);
		fp3_rdcn_low(r->y, u1);
		fp3_mul(r->x, t0, t3);
		fp3_mul(r->z, r->z, t2);

		fp_neg(t3[0], p->x);
		fp_mul(l[one][zero][0], t1[0], t3[0]);
		fp_mul(l[one][zero][1], t1[1], t3[0]);
		fp_mul(l[one][zero][2], t1[2], t3[0]);

		fp3_muln_low(u0, q->x, t1);
		fp3_muln_low(u1, q->y, t0);

		fp3_subc_low(u0, u0, u1);
		fp3_rdcn_low(l[one][one], u0);

		fp_mul(l[zero][zero][0], t0[0], p->y);
		fp_mul(l[zero][zero][1], t0[1], p->y);
		fp_mul(l[zero][zero][2], t0[2], p->y);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
		fp3_free(t3);
		dv3_free(u0);
		dv3_free(u1);
	}
}

TMPL_PP_ADD_LIT(18, ep3, fp3);
