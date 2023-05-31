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
 * Implementation of Miller doubling for curves of embedding degree 18.
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

void pp_dbl_k18_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p) {
	fp3_t s;
	ep3_t t;
	int one = 1, zero = 0;

	fp3_null(s);
	ep3_null(t);

	RLC_TRY {
		fp3_new(s);
		ep3_new(t);
		ep3_copy(t, q);
		ep3_dbl_slp_basic(r, s, q);

		if (ep3_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp_mul(l[one][zero][0], s[0], p->x);
		fp_mul(l[one][zero][1], s[1], p->x);
		fp_mul(l[one][zero][2], s[2], p->x);
		fp3_mul(l[one][one], s, t->x);
		fp3_sub(l[one][one], t->y, l[one][one]);
		fp_copy(l[zero][zero][0], p->y);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(s);
		ep3_free(t);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

#if PP_EXT == BASIC || !defined(STRIP)

void pp_dbl_k18_projc_basic(fp18_t l, ep3_t r, const ep3_t q, const ep_t p) {
	fp3_t t0, t1, t2, t3, t4, t5, t6;
	int one = 1, zero = 0;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	fp3_null(t4);
	fp3_null(t5);
	fp3_null(t6);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		fp3_new(t4);
		fp3_new(t5);
		fp3_new(t6);

		if (ep3_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* A = x1^2. */
		fp3_sqr(t0, q->x);
		/* B = y1^2. */
		fp3_sqr(t1, q->y);
		/* C = z1^2. */
		fp3_sqr(t2, q->z);
		/* D = 3bC, general b. */
		fp3_dbl(t3, t2);
		fp3_add(t3, t3, t2);
		ep3_curve_get_b(t4);
		fp3_mul(t3, t3, t4);
		/* E = (x1 + y1)^2 - A - B. */
		fp3_add(t4, q->x, q->y);
		fp3_sqr(t4, t4);
		fp3_sub(t4, t4, t0);
		fp3_sub(t4, t4, t1);

		/* F = (y1 + z1)^2 - B - C. */
		fp3_add(t5, q->y, q->z);
		fp3_sqr(t5, t5);
		fp3_sub(t5, t5, t1);
		fp3_sub(t5, t5, t2);

		/* G = 3D. */
		fp3_dbl(t6, t3);
		fp3_add(t6, t6, t3);

		/* x3 = E * (B - G). */
		fp3_sub(r->x, t1, t6);
		fp3_mul(r->x, r->x, t4);

		/* y3 = (B + G)^2 -12D^2. */
		fp3_add(t6, t6, t1);
		fp3_sqr(t6, t6);
		fp3_sqr(t2, t3);
		fp3_dbl(r->y, t2);
		fp3_dbl(t2, r->y);
		fp3_dbl(r->y, t2);
		fp3_add(r->y, r->y, t2);
		fp3_sub(r->y, t6, r->y);

		/* z3 = 4B * F. */
		fp3_dbl(r->z, t1);
		fp3_dbl(r->z, r->z);
		fp3_mul(r->z, r->z, t5);

		/* l11 = D - B. */
		fp3_sub(l[one][one], t3, t1);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[one][zero][0], p->x, t0[0]);
		fp_mul(l[one][zero][1], p->x, t0[1]);
		fp_mul(l[one][zero][2], p->x, t0[2]);

		/* l00 = F * (-yp). */
		fp_mul(l[zero][zero][0], t5[0], p->y);
		fp_mul(l[zero][zero][1], t5[1], p->y);
		fp_mul(l[zero][zero][2], t5[2], p->y);

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
		fp3_free(t4);
		fp3_free(t5);
		fp3_free(t6);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void pp_dbl_k18_projc_lazyr(fp18_t l, ep3_t r, const ep3_t q, const ep_t p) {
	fp3_t t0, t1, t2, t3, t4, t5, t6;
	dv2_t u0, u1;
	int one = 1, zero = 0;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	fp3_null(t4);
	fp3_null(t5);
	fp3_null(t6);
	dv2_null(u0);
	dv2_null(u1);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		fp3_new(t4);
		fp3_new(t5);
		fp3_new(t6);
		dv2_new(u0);
		dv2_new(u1);

		if (ep3_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* A = x1^2. */
		fp3_sqr(t0, q->x);
		/* B = y1^2. */
		fp3_sqr(t1, q->y);
		/* C = z1^2. */
		fp3_sqr(t2, q->z);
		/* D = 3bC, for general b. */
		fp3_dbl(t3, t2);
		fp3_add(t3, t3, t2);
		ep3_curve_get_b(t4);
		fp3_mul(t3, t3, t4);
		/* E = (x1 + y1)^2 - A - B. */
		fp3_add(t4, q->x, q->y);
		fp3_sqr(t4, t4);
		fp3_sub(t4, t4, t0);
		fp3_sub(t4, t4, t1);

		/* F = (y1 + z1)^2 - B - C. */
		fp3_add(t5, q->y, q->z);
		fp3_sqr(t5, t5);
		fp3_sub(t5, t5, t1);
		fp3_sub(t5, t5, t2);

		/* G = 3D. */
		fp3_dbl(t6, t3);
		fp3_add(t6, t6, t3);

		/* x3 = E * (B - G). */
		fp3_sub(r->x, t1, t6);
		fp3_mul(r->x, r->x, t4);

		/* y3 = (B + G)^2 -12D^2. */
		fp3_add(t6, t6, t1);
		fp3_sqr(t6, t6);
		fp3_sqr(t2, t3);
		fp3_dbl(r->y, t2);
		fp3_dbl(t2, r->y);
		fp3_dbl(r->y, t2);
		fp3_add(r->y, r->y, t2);
		fp3_sub(r->y, t6, r->y);

		/* z3 = 4B * F. */
		fp3_dbl(r->z, t1);
		fp3_dbl(r->z, r->z);
		fp3_mul(r->z, r->z, t5);

		/* l00 = D - B. */
		fp3_sub(l[one][one], t3, t1);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[one][zero][0], p->x, t0[0]);
		fp_mul(l[one][zero][1], p->x, t0[1]);
		fp_mul(l[one][zero][2], p->x, t0[2]);

		/* l01 = F * (-yp). */
		fp_mul(l[zero][zero][0], t5[0], p->y);
		fp_mul(l[zero][zero][1], t5[1], p->y);
		fp_mul(l[zero][zero][2], t5[2], p->y);

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
		fp3_free(t4);
		fp3_free(t5);
		fp3_free(t6);
		dv2_free(u0);
		dv2_free(u1);
	}
}

#endif

#endif

void pp_dbl_lit_k18(fp18_t l, ep_t r, const ep_t p, const ep3_t q) {
	fp_t t0, t1, t2, t3, t4, t5, t6;
	int two = 2, one = 1, zero = 0;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	fp_null(t6);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		fp_new(t6);

		fp_sqr(t0, p->x);
		fp_sqr(t1, p->y);
		fp_sqr(t2, p->z);

		fp_mul(t4, ep_curve_get_b(), t2);

		fp_dbl(t3, t4);
		fp_add(t3, t3, t4);

		fp_add(t4, p->x, p->y);
		fp_sqr(t4, t4);
		fp_sub(t4, t4, t0);
		fp_sub(t4, t4, t1);
		fp_add(t5, p->y, p->z);
		fp_sqr(t5, t5);
		fp_sub(t5, t5, t1);
		fp_sub(t5, t5, t2);
		fp_dbl(t6, t3);
		fp_add(t6, t6, t3);
		fp_sub(r->x, t1, t6);
		fp_mul(r->x, r->x, t4);
		fp_add(r->y, t1, t6);
		fp_sqr(r->y, r->y);
		fp_sqr(t4, t3);
		fp_dbl(t6, t4);
		fp_add(t6, t6, t4);
		fp_dbl(t6, t6);
		fp_dbl(t6, t6);
		fp_sub(r->y, r->y, t6);
		fp_mul(r->z, t1, t5);
		fp_dbl(r->z, r->z);
		fp_dbl(r->z, r->z);
		r->coord = PROJC;

		fp3_dbl(l[zero][two], q->x);
		fp3_add(l[zero][two], l[zero][two], q->x);
		fp_mul(l[zero][two][0], l[zero][two][0], t0);
		fp_mul(l[zero][two][1], l[zero][two][1], t0);
		fp_mul(l[zero][two][2], l[zero][two][2], t0);

		fp_sub(l[zero][zero][0], t3, t1);

		fp_mul(l[one][one][0], q->y[0], t5);
		fp_mul(l[one][one][1], q->y[1], t5);
		fp_mul(l[one][one][2], q->y[2], t5);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		fp_free(t6);
	}
}
