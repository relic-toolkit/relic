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
 * Implementation of Miller addition for curves of embedding degree 12.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void pp_add_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	int one = 1, zero = 0;
	fp4_t s;
	ep4_t t;

	fp4_null(s);
	ep4_null(t);

	RLC_TRY {
		fp4_new(s);
		ep4_new(t);

		ep4_copy(t, r);
		ep4_add_slp_basic(r, s, r, q);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp_mul(l[one][zero][0], s[0], p->x);
		fp_mul(l[one][zero][1], s[1], p->x);
		fp_mul(l[one][zero][2], s[2], p->x);
		fp4_mul(l[one][one], s, t->x);
		fp4_sub(l[one][one], t->y, l[one][one]);
		fp_neg(l[zero][zero][0], p->y);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(s);
		ep4_free(t);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

#if PP_EXT == BASIC || !defined(STRIP)

void pp_add_k16_projc_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);

	if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
		one ^= 1;
		zero ^= 1;
	}

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);

		/* B = t0 = x1 - x2 * z1. */
		fp4_mul(t0, r->z, q->x);
		fp4_sub(t0, r->x, t0);
		/* A = t1 = y1 - y2 * z1. */
		fp4_mul(t1, r->z, q->y);
		fp4_sub(t1, r->y, t1);

		/* D = B^2. */
		fp4_sqr(t2, t0);
		/* G = x1 * D. */
		fp4_mul(r->x, r->x, t2);
		/* E = B^3. */
		fp4_mul(t2, t2, t0);
		/* C = A^2. */
		fp4_sqr(t3, t1);
		/* F = E + z1 * C. */
		fp4_mul(t3, t3, r->z);
		fp4_add(t3, t2, t3);

		/* l10 = - (A * xp). */
		fp_neg(t4[0], p->x);
		fp_mul(l[one][zero][0], t1[0], t4[0]);
		fp_mul(l[one][zero][1], t1[1], t4[0]);
		fp_mul(l[one][zero][2], t1[2], t4[0]);

		/* t4 = B * x2. */
		fp4_mul(t4, q->x, t1);

		/* H = F - 2 * G. */
		fp4_sub(t3, t3, r->x);
		fp4_sub(t3, t3, r->x);
		/* y3 = A * (G - H) - y1 * E. */
		fp4_sub(r->x, r->x, t3);
		fp4_mul(t1, t1, r->x);
		fp4_mul(r->y, t2, r->y);
		fp4_sub(r->y, t1, r->y);
		/* x3 = B * H. */
		fp4_mul(r->x, t0, t3);
		/* z3 = z1 * E. */
		fp4_mul(r->z, r->z, t2);

		/* l11 = J = A * x2 - B * y2. */
		fp4_mul(t2, q->y, t0);
		fp4_sub(l[one][one], t4, t2);

		/* l00 = B * yp. */
		fp_mul(l[zero][zero][0], t0[0], p->y);
		fp_mul(l[zero][zero][1], t0[1], p->y);
		fp_mul(l[zero][zero][2], t0[2], p->y);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
		fp4_free(t4);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void pp_add_k16_projc_lazyr(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3;
	dv3_t u0, u1;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	dv3_null(u0);
	dv3_null(u1);

	if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
		one ^= 1;
		zero ^= 1;
	}

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		dv3_new(u0);
		dv3_new(u1);

		fp4_mul(t0, r->z, q->x);
		fp4_sub(t0, r->x, t0);
		fp4_mul(t1, r->z, q->y);
		fp4_sub(t1, r->y, t1);

		fp4_sqr(t2, t0);
		fp4_mul(r->x, t2, r->x);
		fp4_mul(t2, t0, t2);
		fp4_sqr(t3, t1);
		fp4_mul(t3, t3, r->z);
		fp4_add(t3, t2, t3);

		fp4_sub(t3, t3, r->x);
		fp4_sub(t3, t3, r->x);
		fp4_sub(r->x, r->x, t3);

		fp2_muln_low(u0[0], t1[0], r->x[0]);
		fp2_muln_low(u0[1], t1[1], r->x[1]);
		fp2_muln_low(u1[0], t2[0], r->y[0]);
		fp2_muln_low(u1[1], t2[1], r->y[1]);

		fp2_subc_low(u1[0], u0[0], u1[0]);
		fp2_subc_low(u1[1], u0[1], u1[1]);
		fp2_rdcn_low(r->y[0], u1[0]);
		fp2_rdcn_low(r->y[1], u1[1]);
		fp4_mul(r->x, t0, t3);
		fp4_mul(r->z, r->z, t2);

		fp_neg(t3[0], p->x);
		fp_mul(l[one][zero][0], t1[0], t3[0]);
		fp_mul(l[one][zero][1], t1[1], t3[0]);
		fp_mul(l[one][zero][2], t1[2], t3[0]);

		fp2_muln_low(u0[0], q->x[0], t1[0]);
		fp2_muln_low(u0[1], q->x[1], t1[1]);
		fp2_muln_low(u1[0], q->y[0], t0[0]);
		fp2_muln_low(u1[1], q->y[1], t0[1]);

		fp2_subc_low(u0[0], u0[0], u1[0]);
		fp2_subc_low(u0[1], u0[1], u1[1]);
		fp2_rdcn_low(l[one][one][0], u0[0]);
		fp2_rdcn_low(l[one][one][1], u0[1]);

		fp_mul(l[zero][zero][0], t0[0], p->y);
		fp_mul(l[zero][zero][1], t0[1], p->y);
		fp_mul(l[zero][zero][2], t0[2], p->y);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
		dv3_free(u0);
		dv3_free(u1);
	}
}

#endif

#endif

void pp_add_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q) {
	fp_t t0, t1, t2, t3;
	int two = 2, one = 1, zero = 0;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);

		fp_mul(t0, r->z, p->x);
		fp_sub(t0, r->x, t0);
		fp_mul(t1, r->z, p->y);
		fp_sub(t1, r->y, t1);
		fp_mul(t2, p->x, t1);
		r->coord = PROJC;

		fp_mul(l[zero][zero][0], t0, p->y);
		fp_sub(l[zero][zero][0], t2, l[zero][zero][0]);

		fp_mul(l[zero][two][0], q->x[0], t1);
		fp_mul(l[zero][two][1], q->x[1], t1);
		fp_mul(l[zero][two][2], q->x[2], t1);
		fp4_neg(l[zero][two], l[zero][two]);

		fp_mul(l[one][one][0], q->y[0], t0);
		fp_mul(l[one][one][1], q->y[1], t0);
		fp_mul(l[one][one][2], q->y[2], t0);

		fp_sqr(t2, t0);
		fp_mul(r->x, t2, r->x);
		fp_mul(t2, t0, t2);
		fp_sqr(t3, t1);
		fp_mul(t3, t3, r->z);
		fp_add(t3, t2, t3);
		fp_sub(t3, t3, r->x);
		fp_sub(t3, t3, r->x);
		fp_sub(r->x, r->x, t3);
		fp_mul(t1, t1, r->x);
		fp_mul(r->y, t2, r->y);
		fp_sub(r->y, t1, r->y);
		fp_mul(r->x, t0, t3);
		fp_mul(r->z, r->z, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
	}
}
