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
 * Implementation of Miller doubling for curves with embedding degree 48.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void pp_dbl_k48_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p) {
	fp8_t s;
	ep8_t t;

	fp8_null(s);
	ep8_null(t);

	RLC_TRY {
		fp8_new(s);
		ep8_new(t);

		ep8_copy(t, q);
		ep8_dbl_slp_basic(r, s, q);
		fp48_zero(l);

		fp_mul(l[0][1][0][0][0], p->x, s[0][0][0]);
		fp_mul(l[0][1][0][0][1], p->x, s[0][0][1]);
		fp_mul(l[0][1][0][1][0], p->x, s[0][1][0]);
		fp_mul(l[0][1][0][1][1], p->x, s[0][1][1]);
		fp_mul(l[0][1][1][0][0], p->x, s[1][0][0]);
		fp_mul(l[0][1][1][0][1], p->x, s[1][0][1]);
		fp_mul(l[0][1][1][1][0], p->x, s[1][1][0]);
		fp_mul(l[0][1][1][1][1], p->x, s[1][1][1]);

		fp8_mul(l[0][0], s, t->x);
		fp8_sub(l[0][0], t->y, l[0][0]);

		fp_copy(l[1][1][0][0][0], p->y);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(s);
		ep8_free(t);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void pp_dbl_k48_projc(fp48_t l, ep8_t r, const ep8_t q, const ep_t p) {
	fp8_t t0, t1, t2, t3, t4, t5, t6;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);
	fp8_null(t6);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);
		fp8_new(t6);

		/* A = x1^2. */
		fp8_sqr(t0, q->x);
		/* B = y1^2. */
		fp8_sqr(t1, q->y);
		/* C = z1^2. */
		fp8_sqr(t2, q->z);
		/* D = 3bC, general b. */
		fp8_dbl(t3, t2);
		fp8_add(t3, t3, t2);
		ep8_curve_get_b(t4);
		fp8_mul(t3, t3, t4);

		/* E = (x1 + y1)^2 - A - B. */
		fp8_add(t4, q->x, q->y);
		fp8_sqr(t4, t4);
		fp8_sub(t4, t4, t0);
		fp8_sub(t4, t4, t1);

		/* F = (y1 + z1)^2 - B - C. */
		fp8_add(t5, q->y, q->z);
		fp8_sqr(t5, t5);
		fp8_sub(t5, t5, t1);
		fp8_sub(t5, t5, t2);

		/* G = 3D. */
		fp8_dbl(t6, t3);
		fp8_add(t6, t6, t3);

		/* x3 = E * (B - G). */
		fp8_sub(r->x, t1, t6);
		fp8_mul(r->x, r->x, t4);

		/* y3 = (B + G)^2 -12D^2. */
		fp8_add(t6, t6, t1);
		fp8_sqr(t6, t6);
		fp8_sqr(t2, t3);
		fp8_dbl(r->y, t2);
		fp8_dbl(t2, r->y);
		fp8_dbl(r->y, t2);
		fp8_add(r->y, r->y, t2);
		fp8_sub(r->y, t6, r->y);

		/* z3 = 4B * F. */
		fp8_dbl(r->z, t1);
		fp8_dbl(r->z, r->z);
		fp8_mul(r->z, r->z, t5);

		/* l11 = D - B. */
		fp8_sub(l[0][0], t3, t1);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[0][1][0][0][0], p->x, t0[0][0][0]);
		fp_mul(l[0][1][0][0][1], p->x, t0[0][0][1]);
		fp_mul(l[0][1][0][1][0], p->x, t0[0][1][0]);
		fp_mul(l[0][1][0][1][1], p->x, t0[0][1][1]);
		fp_mul(l[0][1][1][0][0], p->x, t0[1][0][0]);
		fp_mul(l[0][1][1][0][1], p->x, t0[1][0][1]);
		fp_mul(l[0][1][1][1][0], p->x, t0[1][1][0]);
		fp_mul(l[0][1][1][1][1], p->x, t0[1][1][1]);

		/* l00 = F * (-yp). */
		fp_mul(l[1][1][0][0][0], p->y, t5[0][0][0]);
		fp_mul(l[1][1][0][0][1], p->y, t5[0][0][1]);
		fp_mul(l[1][1][0][1][0], p->y, t5[0][1][0]);
		fp_mul(l[1][1][0][1][1], p->y, t5[0][1][1]);
		fp_mul(l[1][1][1][0][0], p->y, t5[1][0][0]);
		fp_mul(l[1][1][1][0][1], p->y, t5[1][0][1]);
		fp_mul(l[1][1][1][1][0], p->y, t5[1][1][0]);
		fp_mul(l[1][1][1][1][1], p->y, t5[1][1][1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
		fp8_free(t6);
	}
}

#endif
