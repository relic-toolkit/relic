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
 * Implementation of pairing computation for curves with embedding degree 54.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_add_k54_basic(fp54_t l, ep9_t r, const ep9_t q, const ep_t p) {
	fp9_t s;
	ep9_t t;

	fp9_null(s);
	ep9_null(t);

	RLC_TRY {
		fp9_new(s);
		ep9_new(t);

		ep9_copy(t, r);
		ep9_add_slp_basic(r, s, r, q);

		fp54_zero(l);
		fp_mul(l[2][0][0][0], p->x, s[0][0]);
		fp_mul(l[2][0][0][1], p->x, s[0][1]);
		fp_mul(l[2][0][0][2], p->x, s[0][2]);
		fp_mul(l[2][0][1][0], p->x, s[1][0]);
		fp_mul(l[2][0][1][1], p->x, s[1][1]);
		fp_mul(l[2][0][1][2], p->x, s[1][2]);
		fp_mul(l[2][0][2][0], p->x, s[2][0]);
		fp_mul(l[2][0][2][1], p->x, s[2][1]);
		fp_mul(l[2][0][2][2], p->x, s[2][2]);

		fp9_mul(l[0][0], s, t->x);
		fp9_sub(l[0][0], t->y, l[0][0]);

		fp_neg(l[0][1][0][0], p->y);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp9_free(s);
		ep9_free(t);
	}
}

void pp_add_k54_projc(fp54_t l, ep9_t r, const ep9_t q, const ep_t p) {
	fp9_t t0, t1, t2, t3, t4;

	fp9_null(t0);
	fp9_null(t1);
	fp9_null(t2);
	fp9_null(t3);
	fp9_null(t4);

	RLC_TRY {
		fp9_new(t0);
		fp9_new(t1);
		fp9_new(t2);
		fp9_new(t3);
		fp9_new(t4);

		/* B = t0 = x1 - x2 * z1. */
		fp9_mul(t0, r->z, q->x);
		fp9_sub(t0, r->x, t0);
		/* A = t1 = y1 - y2 * z1. */
		fp9_mul(t1, r->z, q->y);
		fp9_sub(t1, r->y, t1);

		/* D = B^2. */
		fp9_sqr(t2, t0);
		/* G = x1 * D. */
		fp9_mul(r->x, r->x, t2);
		/* E = B^3. */
		fp9_mul(t2, t2, t0);
		/* C = A^2. */
		fp9_sqr(t3, t1);
		/* F = E + z1 * C. */
		fp9_mul(t3, t3, r->z);
		fp9_add(t3, t2, t3);

		/* l10 = - (A * xp). */
		fp_neg(t4[0][0], p->x);
		fp_mul(l[2][0][0][0], t1[0][0], t4[0][0]);
		fp_mul(l[2][0][0][1], t1[0][1], t4[0][0]);
		fp_mul(l[2][0][0][2], t1[0][2], t4[0][0]);
		fp_mul(l[2][0][1][0], t1[1][0], t4[0][0]);
		fp_mul(l[2][0][1][1], t1[1][1], t4[0][0]);
		fp_mul(l[2][0][1][2], t1[1][2], t4[0][0]);
		fp_mul(l[2][0][2][0], t1[2][0], t4[0][0]);
		fp_mul(l[2][0][2][1], t1[2][1], t4[0][0]);
		fp_mul(l[2][0][2][2], t1[2][2], t4[0][0]);

		/* t4 = A * x2. */
		fp9_mul(t4, q->x, t1);

		/* H = E + F - 2 * G. */
		fp9_sub(t3, t3, r->x);
		fp9_sub(t3, t3, r->x);
		/* y3 = A * (G - H) - y1 * E. */
		fp9_sub(r->x, r->x, t3);
		fp9_mul(t1, t1, r->x);
		fp9_mul(r->y, t2, r->y);
		fp9_sub(r->y, t1, r->y);
		/* x3 = B * H. */
		fp9_mul(r->x, t0, t3);
		/* z3 = z1 * E. */
		fp9_mul(r->z, r->z, t2);
		r->coord = PROJC;

		/* l11 = J = A * x2 - B * y2. */
		fp9_mul(t2, q->y, t0);
		fp9_sub(l[0][0], t4, t2);

		/* l00 = B * yp. */
		fp_mul(l[0][1][0][0], p->y, t0[0][0]);
		fp_mul(l[0][1][0][1], p->y, t0[0][1]);
		fp_mul(l[0][1][0][2], p->y, t0[0][2]);
		fp_mul(l[0][1][1][0], p->y, t0[1][0]);
		fp_mul(l[0][1][1][1], p->y, t0[1][1]);
		fp_mul(l[0][1][1][2], p->y, t0[1][2]);
		fp_mul(l[0][1][2][0], p->y, t0[2][0]);
		fp_mul(l[0][1][2][1], p->y, t0[2][1]);
		fp_mul(l[0][1][2][2], p->y, t0[2][2]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp9_free(t0);
		fp9_free(t1);
		fp9_free(t2);
		fp9_free(t3);
		fp9_free(t4);
	}
}
