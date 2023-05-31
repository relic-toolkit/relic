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
 * Implementation of Miller doubling for curves of embedding degree 12.
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

void pp_dbl_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t s;
	ep4_t t;
	int one = 1, zero = 0;

	fp4_null(s);
	ep4_null(t);

	RLC_TRY {
		fp4_new(s);
		ep4_new(t);
		ep4_copy(t, q);
		ep4_dbl_slp_basic(r, s, q);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp_mul(l[one][zero][0][0], s[0][0], p->x);
		fp_mul(l[one][zero][0][1], s[0][1], p->x);
		fp_mul(l[one][zero][1][0], s[1][0], p->x);
		fp_mul(l[one][zero][1][1], s[1][1], p->x);		
		fp4_mul(l[one][one], s, t->x);
		fp4_sub(l[one][one], t->y, l[one][one]);
		fp_copy(l[zero][zero][0][0], p->y);
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

void pp_dbl_k16_projc_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5, t6;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);
	fp4_null(t5);
	fp4_null(t6);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);
		fp4_new(t6);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* A = x1^2. */
		fp4_sqr(t0, q->x);
		/* B = y1^2. */
		fp4_sqr(t1, q->y);
		/* C = z1^2. */
		fp4_sqr(t2, q->z);

		if (ep_curve_opt_a() == RLC_ZERO) {
			/* D = 3bC, general b. */
			fp4_dbl(t3, t2);
			fp4_add(t3, t3, t2);
			ep4_curve_get_b(t4);
			fp4_mul(t3, t3, t4);
			/* E = (x1 + y1)^2 - A - B. */
			fp4_add(t4, q->x, q->y);
			fp4_sqr(t4, t4);
			fp4_sub(t4, t4, t0);
			fp4_sub(t4, t4, t1);

			/* F = (y1 + z1)^2 - B - C. */
			fp4_add(t5, q->y, q->z);
			fp4_sqr(t5, t5);
			fp4_sub(t5, t5, t1);
			fp4_sub(t5, t5, t2);

			/* G = 3D. */
			fp4_dbl(t6, t3);
			fp4_add(t6, t6, t3);

			/* x3 = E * (B - G). */
			fp4_sub(r->x, t1, t6);
			fp4_mul(r->x, r->x, t4);

			/* y3 = (B + G)^2 -12D^2. */
			fp4_add(t6, t6, t1);
			fp4_sqr(t6, t6);
			fp4_sqr(t2, t3);
			fp4_dbl(r->y, t2);
			fp4_dbl(t2, r->y);
			fp4_dbl(r->y, t2);
			fp4_add(r->y, r->y, t2);
			fp4_sub(r->y, t6, r->y);

			/* z3 = 4B * F. */
			fp4_dbl(r->z, t1);
			fp4_dbl(r->z, r->z);
			fp4_mul(r->z, r->z, t5);

			/* l11 = D - B. */
			fp4_sub(l[one][one], t3, t1);

			/* l10 = (3 * xp) * A. */
			fp_mul(l[one][zero][0][0], p->x, t0[0][0]);
			fp_mul(l[one][zero][0][1], p->x, t0[0][1]);
			fp_mul(l[one][zero][1][0], p->x, t0[1][0]);
			fp_mul(l[one][zero][1][1], p->x, t0[1][1]);

			/* l00 = F * (-yp). */
			fp_mul(l[zero][zero][0][0], t5[0][0], p->y);
			fp_mul(l[zero][zero][0][1], t5[0][1], p->y);
			fp_mul(l[zero][zero][1][0], t5[1][0], p->y);
			fp_mul(l[zero][zero][1][1], t5[1][1], p->y);
		} else {
			/* D = aC, general a. */
			fp4_mul_art(t3, t2);

			/* X3 = (A - D)^2, l00 = (X1 + A - D)^2 - X3 - A. */
			fp4_sub(t6, t0, t3);
			fp4_add(l[one][one], t6, q->x);
			fp4_sqr(l[one][one], l[one][one]);
			fp4_sqr(r->x, t6);
			fp4_sub(l[one][one], l[one][one], r->x);
			fp4_sub(l[one][one], l[one][one], t0);

        	/* E = 2*(A + D)^2 - X3. */
			fp4_add(t5, t0, t3);
			fp4_sqr(t5, t5);
			fp4_dbl(t5, t5)	;
			fp4_sub(t5, t5, r->x);

			/* F = ((A - D + Y1)^2 -B - X3). */
			fp4_add(t6, t6, q->y);
			fp4_sqr(t6, t6);
			fp4_sub(t6, t6, t1);
			fp4_sub(t6, t6, r->x);

			/* l = - 2*Z1*(3*A + D)*xP + 2*((Y1+Z1)^2-B-C)*yP. */
			fp4_dbl(l[one][zero], t0);
			fp4_dbl(l[one][zero], l[one][zero]);
			fp4_add(l[one][zero], l[one][zero], t3);
			fp4_mul(l[one][zero], l[one][zero], q->z);
			fp_mul(l[one][zero][0][0], l[one][zero][0][0], p->x);
			fp_mul(l[one][zero][0][1], l[one][zero][0][1], p->x);
			fp_mul(l[one][zero][1][0], l[one][zero][1][0], p->x);
			fp_mul(l[one][zero][1][1], l[one][zero][1][1], p->x);	
			fp4_dbl(l[one][zero], l[one][zero]);
			fp4_neg(l[one][zero], l[one][zero]);

			fp4_add(l[zero][zero], q->y, q->z);
			fp4_sqr(l[zero][zero], l[zero][zero]);
			fp4_sub(l[zero][zero], l[zero][zero], t1);
			fp4_sub(l[zero][zero], l[zero][zero], t2);
			fp4_dbl(l[zero][zero], l[zero][zero]);
			fp_mul(l[zero][zero][0][0], l[zero][zero][0][0], p->y);
			fp_mul(l[zero][zero][0][1], l[zero][zero][0][1], p->y);
			fp_mul(l[zero][zero][1][0], l[zero][zero][1][0], p->y);
			fp_mul(l[zero][zero][1][1], l[zero][zero][1][1], p->y);	

			/* Y3 = E*F, Z3 = 4*B. */
			fp4_mul(r->y, t5, t6);
			fp4_dbl(r->z, t1);
			fp4_dbl(r->z, r->z);
		}

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
		fp4_free(t5);
		fp4_free(t6);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void pp_dbl_k16_projc_lazyr(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5, t6;
	dv4_t u0, u1;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);
	fp4_null(t5);
	fp4_null(t6);
	dv4_null(u0);
	dv4_null(u1);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);
		fp4_new(t6);
		dv4_new(u0);
		dv4_new(u1);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* A = x1^2. */
		fp4_sqr(t0, q->x);
		/* B = y1^2. */
		fp4_sqr(t1, q->y);
		/* C = z1^2. */
		fp4_sqr(t2, q->z);
		/* D = 3bC, for general b. */
		fp4_dbl(t3, t2);
		fp4_add(t3, t3, t2);
		ep4_curve_get_b(t4);
		fp4_mul(t3, t3, t4);
		/* E = (x1 + y1)^2 - A - B. */
		fp4_add(t4, q->x, q->y);
		fp4_sqr(t4, t4);
		fp4_sub(t4, t4, t0);
		fp4_sub(t4, t4, t1);

		/* F = (y1 + z1)^2 - B - C. */
		fp4_add(t5, q->y, q->z);
		fp4_sqr(t5, t5);
		fp4_sub(t5, t5, t1);
		fp4_sub(t5, t5, t2);

		/* G = 3D. */
		fp4_dbl(t6, t3);
		fp4_add(t6, t6, t3);

		/* x3 = E * (B - G). */
		fp4_sub(r->x, t1, t6);
		fp4_mul(r->x, r->x, t4);

		/* y3 = (B + G)^2 -12D^2. */
		fp4_add(t6, t6, t1);
		fp4_sqr(t6, t6);
		fp4_sqr(t2, t3);
		fp4_dbl(r->y, t2);
		fp4_dbl(t2, r->y);
		fp4_dbl(r->y, t2);
		fp4_add(r->y, r->y, t2);
		fp4_sub(r->y, t6, r->y);

		/* z3 = 4B * F. */
		fp4_dbl(r->z, t1);
		fp4_dbl(r->z, r->z);
		fp4_mul(r->z, r->z, t5);

		/* l00 = D - B. */
		fp4_sub(l[one][one], t3, t1);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[one][zero][0][0], p->x, t0[0][0]);
		fp_mul(l[one][zero][0][1], p->x, t0[0][1]);
		fp_mul(l[one][zero][1][0], p->x, t0[1][0]);
		fp_mul(l[one][zero][1][1], p->x, t0[1][1]);

		/* l00 = F * (-yp). */
		fp_mul(l[zero][zero][0][0], t5[0][0], p->y);
		fp_mul(l[zero][zero][0][1], t5[0][1], p->y);
		fp_mul(l[zero][zero][1][0], t5[1][0], p->y);
		fp_mul(l[zero][zero][1][1], t5[1][1], p->y);

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
		fp4_free(t5);
		fp4_free(t6);
		dv4_free(u0);
		dv4_free(u1);
	}
}

#endif

#endif

void pp_dbl_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q) {
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

		fp4_dbl(l[zero][two], q->x);
		fp4_add(l[zero][two], l[zero][two], q->x);
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
