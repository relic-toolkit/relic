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
 * Implementation of Miller addition for curves with embedding degree 48.
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

void pp_add_k48_basic(fp48_t l, ep8_t r, const ep8_t q, const ep_t p) {
	fp8_t s;
	ep8_t t;

	fp8_null(s);
	ep8_null(t);

	RLC_TRY {
		fp8_new(s);
		ep8_new(t);

		ep8_copy(t, r);
		ep8_add_slp_basic(r, s, r, q);

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

		fp_neg(l[1][1][0][0][0], p->y);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(s);
		ep8_free(t);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void pp_add_k48_projc(fp48_t l, ep8_t r, const ep8_t q, const ep_t p) {
	fp8_t t0, t1, t2, t3, t4;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);

		/* B = t0 = x1 - x2 * z1. */
		fp8_mul(t0, r->z, q->x);
		fp8_sub(t0, r->x, t0);
		/* A = t1 = y1 - y2 * z1. */
		fp8_mul(t1, r->z, q->y);
		fp8_sub(t1, r->y, t1);

		/* D = B^2. */
		fp8_sqr(t2, t0);
		/* G = x1 * D. */
		fp8_mul(r->x, r->x, t2);
		/* E = B^3. */
		fp8_mul(t2, t2, t0);
		/* C = A^2. */
		fp8_sqr(t3, t1);
		/* F = E + z1 * C. */
		fp8_mul(t3, t3, r->z);
		fp8_add(t3, t2, t3);

		/* l10 = - (A * xp). */
		fp_neg(t4[0][0][0], p->x);
		fp_mul(l[0][1][0][0][0], t1[0][0][0], t4[0][0][0]);
		fp_mul(l[0][1][0][0][1], t1[0][0][1], t4[0][0][0]);
		fp_mul(l[0][1][0][1][0], t1[0][1][0], t4[0][0][0]);
		fp_mul(l[0][1][0][1][1], t1[0][1][1], t4[0][0][0]);
		fp_mul(l[0][1][1][0][0], t1[1][0][0], t4[0][0][0]);
		fp_mul(l[0][1][1][0][1], t1[1][0][1], t4[0][0][0]);
		fp_mul(l[0][1][1][1][0], t1[1][1][0], t4[0][0][0]);
		fp_mul(l[0][1][1][1][1], t1[1][1][1], t4[0][0][0]);

		/* t4 = B * x2. */
		fp8_mul(t4, q->x, t1);

		/* H = E + F - 2 * G. */
		fp8_sub(t3, t3, r->x);
		fp8_sub(t3, t3, r->x);
		/* y3 = A * (G - H) - y1 * E. */
		fp8_sub(r->x, r->x, t3);
		fp8_mul(t1, t1, r->x);
		fp8_mul(r->y, t2, r->y);
		fp8_sub(r->y, t1, r->y);
		/* x3 = B * H. */
		fp8_mul(r->x, t0, t3);
		/* z3 = z1 * E. */
		fp8_mul(r->z, r->z, t2);

		/* l11 = J = B * x2 - A * y2. */
		fp8_mul(t2, q->y, t0);
		fp8_sub(l[0][0], t4, t2);

		/* l00 = B * yp. */
		fp_mul(l[1][1][0][0][0], p->y, t0[0][0][0]);
		fp_mul(l[1][1][0][0][1], p->y, t0[0][0][1]);
		fp_mul(l[1][1][0][1][0], p->y, t0[0][1][0]);
		fp_mul(l[1][1][0][1][1], p->y, t0[0][1][1]);
		fp_mul(l[1][1][1][0][0], p->y, t0[1][0][0]);
		fp_mul(l[1][1][1][0][1], p->y, t0[1][0][1]);
		fp_mul(l[1][1][1][1][0], p->y, t0[1][1][0]);
		fp_mul(l[1][1][1][1][1], p->y, t0[1][1][1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
	}
}

#endif
